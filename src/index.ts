// opencode-shell-warden-hook — OpenCode V2 plugin entry (two-tier, ADR-0016).
// Mechanism per ADR-0013: the native substrate is the fail-closed boundary
// (permissions: shell → ask). The shim listens for published permission
// requests, spawns the one-shot shell-warden checker per request
// (letter in on stdin → verdict out on stdout, 02-letter-verdict v2.0) and
// replies programmatically:
//   allow → "once", deny → "reject" (with reason), ask → silence (human decides).
// Checker defects degrade to onCheckerError ∈ {ask, deny} — never allow.

import { mkdirSync, appendFileSync } from "node:fs"
import { Plugin } from "@opencode/plugin"
import { replyDecision, buildLetter, cacheKey, invocationIdOf, type AskData } from "./apply.ts"
import { VerdictCache } from "./cache.ts"
import { validateOptions, type Opts } from "./config.ts"
import { CheckerInvoker, RejectBudgets, verifyPin, type CheckerOptions, type CheckerOutcome } from "./checker.ts"
import { MAX_LETTER_BYTES, MAX_COMMAND_BYTES } from "./types.ts"

const PLUGIN_ID = "opencode-shell-warden-hook"

export default Plugin.define({
  id: PLUGIN_ID,
  async setup(ctx) {
    const opts = validateOptions(ctx.options)
    if (!opts.ok) {
      console.error(`[${PLUGIN_ID}] Disabled: ${opts.reason}`)
      return
    }
    const cfg: Opts = opts.config
    for (const w of opts.warns) console.error(`[${PLUGIN_ID}] warn: ${w}`)
    if (cfg.enabled === false) return

    const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const
    type Level = keyof typeof LEVELS
    const threshold = LEVELS[cfg.logLevel]
    const log = (level: Level, msg: string): void => {
      if (LEVELS[level] >= threshold) console.error(msg)
    }

    // Debug NDJSON per check (03 §3.5); default dir per 04 §4.2.
    let debugSink: ((record: Record<string, unknown>) => void) | null = null
    if (cfg.debug.enabled) {
      const dir = cfg.debug.dir ?? `${process.env.HOME ?? ""}/.local/state/shell-warden/hook`
      try { mkdirSync(dir, { recursive: true }) } catch { /* debug is best-effort */ }
      const file = `${dir}/hook.ndjson`
      debugSink = (record) => { try { appendFileSync(file, JSON.stringify(record) + "\n") } catch { /* debug is best-effort */ } }
    }

    const checkerOpts: CheckerOptions = {
      command: cfg.checker.command,
      sha256: cfg.checker.sha256,
      checkTimeoutMs: cfg.budgets.checkTimeoutMs,
      killGraceMs: cfg.budgets.killGraceMs,
      maxConcurrentSpawns: cfg.budgets.maxConcurrentSpawns,
      log,
    }
    verifyPin(checkerOpts)
    const checker = new CheckerInvoker(checkerOpts)
    const cache = new VerdictCache(cfg.cache.enabled ? cfg.cache.maxEntries : 0)
    const rejectBudgets = new RejectBudgets(cfg.rejectBudget.maxRejections, cfg.rejectBudget.windowMs)

    const myLocation = ctx.location?.directory ?? ""
    const reply = (sessionID: string, requestID: string, decision: "once" | "reject", message?: string) =>
      (ctx as any).permission.reply({
        sessionID,
        requestID,
        decision,
        ...(message !== undefined ? { message } : {}),
      })

    const controller = new AbortController()
    void (async () => {
      try {
        for await (const ev of ctx.event.subscribe({ signal: controller.signal })) {
          if ((ev as any).type !== "permission.asked") continue
          const d = (ev as any).data as AskData | undefined
          if (!d?.id || !d?.sessionID || !d?.action || !Array.isArray(d.resources) || d.resources.length === 0) continue
          // Foreign projects: this shim judges only actions of its own location.
          const loc = (ev as any).location?.directory ?? ""
          if (myLocation && loc !== myLocation) continue
          try {
            if (!(cfg.actionsAll || cfg.actions.includes(d.action))) continue
            const invocationId = invocationIdOf(d.source, d.sessionID, d.action)
            // The ask payload carries no per-command cwd; the permission event's
            // location is the only directory the shim has. Letters with an empty
            // commands[].cwd are rejected by the engine, so without one we degrade —
            // never spawn a letter the engine would refuse.
            const projectDir = loc || myLocation || ""
            if (!projectDir) {
              log("warn", `no project directory for ${invocationId} — degrade (${cfg.onCheckerError})`)
              if (cfg.onCheckerError === "deny") await reply(d.sessionID, d.id, "reject", undefined).catch(() => {})
              continue
            }
            const key = cacheKey(d.action, d.resources, projectDir)

            if (cfg.cache.enabled) {
              const cached = cache.get(key)
              if (cached !== null) {
                await reply(d.sessionID, d.id, "once", cached.message)
                continue
              }
            }

            // Pre-spawn bounds (02 §2.2): breach ⇒ local degrade, no spawn.
            const letter = buildLetter({ data: d, invocationId, projectDir })
            const letterBytes = Buffer.byteLength(JSON.stringify(letter))
            const oversize =
              letter.commands.length > cfg.budgets.maxRequestCommands ||
              letterBytes > MAX_LETTER_BYTES ||
              letter.commands.some((c) => Buffer.byteLength(c.raw) > MAX_COMMAND_BYTES)
            if (oversize) {
              log("warn", `letter bounds breach for ${invocationId} — degrade (${cfg.onCheckerError})`)
              if (cfg.onCheckerError === "deny") await reply(d.sessionID, d.id, "reject", undefined).catch(() => {})
              continue
            }

            const outcome: CheckerOutcome = await checker.check(letter)
            debugSink?.({ ts: new Date().toISOString(), invocationId, action: d.action, outcomeOk: outcome.ok })
            if (!outcome.ok) {
              log(cfg.logLevel === "debug" ? "debug" : "warn", `degrade (${outcome.reason}) for ${invocationId}`)
              if (cfg.onCheckerError === "deny") {
                await reply(d.sessionID, d.id, "reject", undefined).catch(() => { /* human resolves */ })
              }
              continue
            }

            const result = outcome.verdict
            const decision = replyDecision(result.verdict)
            if (decision === "once") {
              if (cfg.cache.enabled && cfg.cache.ttlMs > 0) cache.put(key, cfg.cache.ttlMs, result.message)
              await reply(d.sessionID, d.id, "once")
              continue
            }
            if (decision === "reject") {
              // Reject budget (ADR-0010, hook-owned): exhausted ⇒ stop answering —
              // the native ask reaches the human. Never auto-allowed.
              const ruleId = result.commands?.[0]?.ruleId ?? "unknown"
              if (!rejectBudgets.trySpend(d.sessionID, ruleId)) {
                log("info", `reject budget exhausted for ${ruleId} (${invocationId}) — left to the human`)
                continue
              }
              await reply(d.sessionID, d.id, "reject", result.message)
              continue
            }
            // verdict "ask" → stay silent: the native dialog goes to the human
          } catch (e) {
            log("warn", `ask handler error: ${String(e).slice(0, 200)} — request left to the human (fail-closed)`)
          }
        }
      } catch (e) {
        log("error", `event subscription error: ${String(e).slice(0, 200)}`)
      }
    })()

    if (cfg.asConfig.observeShell) {
      await ctx.shell.hook("create.before", (event) => {
        debugSink?.({ ts: new Date().toISOString(), phase: "create.before", command: event.command, cwd: event.cwd })
      })
    }

    return () => { controller.abort() }
  },
})
