// opencode-shell-warden-hook — OpenCode V2 plugin entry.
// Mechanism per ADR-0013: the native substrate is the fail-closed boundary
// (permissions: shell → ask). The shim listens for published permission
// requests, consults the shell-warden engine, and replies programmatically:
// allow → "once", deny → "reject" (with reason), ask → silence (human decides).
// Fail-closed: with the hook absent every ask reaches the human / headless
// auto-reject — nothing executes silently.

import { Plugin } from "@opencode/plugin"
import { replyDecision, buildCheckRequest, cacheKey, invocationIdOf, type AskData, InvocationRegistry } from "./apply.ts"
import { VerdictCache } from "./cache.ts"
import { validateOptions } from "./config.ts"
import { EngineSupervisor, type SupervisorOptions } from "./supervisor.ts"

const VERSION = "0.1.0"
const PLUGIN_ID = "opencode-shell-warden-hook"

export default Plugin.define({
  id: PLUGIN_ID,
  async setup(ctx) {
    const opts = validateOptions(ctx.options, (m) => console.error(m))
    if (!opts.ok) {
      console.error(`[${PLUGIN_ID}] Disabled: ${opts.reason}`)
      return
    }
    const cfg = opts.config
    const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const
    type Level = keyof typeof LEVELS
    const threshold = LEVELS[cfg.logLevel]
    const log = (level: Level, msg: string): void => {
      if (LEVELS[level] >= threshold) console.error(msg)
    }

    const supOpts: SupervisorOptions = {
      command: cfg.engine.command,
      protocolVersion: cfg.engine.protocolVersion,
      sha256: cfg.engine.sha256,
      cwd: cfg.engine.cwd,
      clientVersion: VERSION,
      budgets: {
        handshakeTimeoutMs: cfg.budgets.handshakeTimeoutMs,
        checkTimeoutMs: cfg.budgets.checkTimeoutMs,
        killGraceMs: cfg.budgets.killGraceMs,
        maxFrameBytes: cfg.budgets.maxFrameBytes,
        maxInFlight: cfg.budgets.maxInFlight,
        maxViolations: cfg.budgets.maxViolations,
        maxViolationsWindowMs: cfg.budgets.maxViolationsWindowMs,
        maxBackoffMs: cfg.engine.restart.maxBackoffMs,
        windowMs: cfg.engine.restart.windowMs,
        resetAfterMs: cfg.engine.restart.resetAfterMs,
      },
      log,
    }
    const supervisor = new EngineSupervisor(supOpts)
    const cache = new VerdictCache(cfg.cache.enabled ? cfg.cache.maxEntries : 0)
    const registry = new InvocationRegistry()

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
            const cwd = ""  // v0.1: no OpenCode HTTP calls from the ask handler (deadlock finding). M1: session-event cache
            const key = cacheKey(d.action, d.resources, cwd)

            if (cfg.cache.enabled) {
              const cached = cache.get(key)
              if (cached !== null) {
                await reply(d.sessionID, d.id, "once", cached.message)
                continue
              }
            }

            if (!cfg.actionsAll && d.resources.length > cfg.budgets.maxRequestCommands) {
              await reply(d.sessionID, d.id, "reject", "too many commands for one guard evaluation")
              continue
            }

            const outcome = await supervisor.check(buildCheckRequest({ data: d, invocationId, cwd }))
            if (!outcome.ok) {
              log(cfg.logLevel === "debug" ? "debug" : "warn", `degrade (${outcome.reason}) for ${invocationId}`)
              // fail-closed: onError → either reject (hard-fail mode) or silence
              if (cfg.onEngineError === "deny") {
                await reply(d.sessionID, d.id, "reject", undefined).catch(() => { /* human resolves */ })
              }
              continue
            }
            const { verdict, message } = outcome.result
            if (verdict === "allow") {
              const ttl = outcome.result.commands?.find((c) => c.index === 0)?.cacheTtlMs ?? cfg.cache.defaultTtlMs
              if (cfg.cache.enabled && ttl > 0) {
                cache.put(key, ttl, message)
                registry.remember(invocationId, key)
              }
              await reply(d.sessionID, d.id, "once")
              continue
            }
            if (verdict === "deny") {
              await reply(d.sessionID, d.id, "reject", message)
              continue
            }
            // verdict "ask" → stay silent: the dialog goes to the human (escalation by silence)
          } catch (e) {
            log("warn", `ask handler error: ${String(e).slice(0, 200)} — request left to the human (fail-closed)`)
          }
        }
      } catch (e) {
        log("error", `event subscription error: ${String(e).slice(0, 200)}`)
      }
    })()

    if (cfg.observeShell) {
      await ctx.shell.hook("create.before", (event) => {
        supervisor.observe({ phase: "create.before", command: event.command, cwd: event.cwd })
      })
    }
    await ctx.tool.hook("execute.after", (event) => {
      const source = (event as { source?: { messageID?: string; id?: string } }).source
      if (source?.messageID === undefined || source.id === undefined) return
      const key = registry.keyFor(`${source.messageID}:${source.id}`)
      if (key !== undefined) registry.remember(`${source.messageID}:${source.id}`, key)
    })

    return () => { controller.abort(); supervisor.dispose() }
  },
})
