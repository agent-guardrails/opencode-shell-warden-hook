// opencode-shell-warden-hook — OpenCode V2 plugin entry.
// Registers the permission evaluate hook and forwards verdicts from the
// shell-warden engine. Fail-closed: every transport anomaly degrades to
// onEngineError ("ask" | "deny"), never "allow".

import { Plugin } from "@opencode/plugin"
import { buildCheckRequest, cacheKey, invocationIdOf, InvocationRegistry, tighten } from "./apply.ts"
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

    const resolveCwd = async (sessionID: string): Promise<string> => {
      try {
        const res = await ctx.session.get({ sessionID })
        const dir = (res as { directory?: string } | undefined)?.directory
        return typeof dir === "string" && dir.length > 0 ? dir : ""
      } catch {
        return ""
      }
    }

    const isWatched = (action: string): boolean => cfg.actionsAll || cfg.actions.includes(action)

    await ctx.permission.hook("evaluate", async (ev) => {
      if (!isWatched(ev.action)) return
      if (ev.effect === "deny") return // final; never touch
      const invocationId = invocationIdOf(ev)
      const cwd = await resolveCwd(ev.sessionID)
      const key = cacheKey(ev.action, ev.resources, cwd, ev.agent)

      if (cfg.cache.enabled) {
        const cached = cache.get(key)
        if (cached !== null) {
          tighten(ev, cached.verdict, cached.message)
          return
        }
      }

      if (!cfg.actionsAll && ev.resources.length > cfg.budgets.maxRequestCommands) {
        tighten(ev, cfg.onEngineError)
        return
      }

      const outcome = await supervisor.check(buildCheckRequest({ ev, invocationId, cwd }))
      if (!outcome.ok) {
        log(cfg.logLevel === "debug" ? "debug" : "warn", `degrade (${outcome.reason}) for ${invocationId}`)
        tighten(ev, cfg.onEngineError)
        return
      }
      const { verdict, message } = outcome.result
      if (verdict === "allow") {
        const ttl = outcome.result.commands?.find((c) => c.index === 0)?.cacheTtlMs ?? cfg.cache.defaultTtlMs
        if (cfg.cache.enabled && ttl > 0) {
          cache.put(key, ttl, message)
          registry.remember(invocationId, key)
        }
      }
      tighten(ev, verdict, message)
    })

    if (cfg.observeShell) {
      await ctx.shell.hook("create.before", (event) => {
        supervisor.observe({
          phase: "create.before",
          command: event.command,
          cwd: event.cwd,
        })
      })
    }

    await ctx.tool.hook("execute.after", (event) => {
      const source = (event as { source?: { messageID?: string; id?: string } }).source
      if (source?.messageID === undefined || source.id === undefined) return
      const key = registry.keyFor(`${source.messageID}:${source.id}`)
      if (key !== undefined) registry.remember(`${source.messageID}:${source.id}`, key)
    })

    return () => supervisor.dispose()
  },
})
