// Shim options validation — docs/policyd-plugin-design/04-shim-config.md
// Semantics: unknown keys => warn + ignore; budgets out of clamp => warn + clamp;
// fatal defects (engine.command, protocolVersion, onEngineError:"allow") => plugin disables itself.

export interface ResolvedBudgets {
  handshakeTimeoutMs: number
  checkTimeoutMs: number
  killGraceMs: number
  maxFrameBytes: number
  maxInFlight: number
  maxRequestCommands: number
  maxViolations: number
  maxViolationsWindowMs: number
}

export interface ResolvedConfig {
  engine: {
    command: string[]
    protocolVersion: number
    sha256: string | null
    cwd: string | null
    restart: { maxBackoffMs: number; windowMs: number; resetAfterMs: number }
  }
  budgets: ResolvedBudgets
  onEngineError: "ask" | "deny"
  actions: string[]
  actionsAll: boolean
  cache: { enabled: boolean; maxEntries: number; defaultTtlMs: number }
  observeShell: boolean
  logLevel: "debug" | "info" | "warn" | "error"
}

export type ValidateResult =
  | { ok: true; config: ResolvedConfig; warns: string[] }
  | { ok: false; reason: string; warns: string[] }

const KNOWN_ACTIONS = new Set([
  "read", "edit", "glob", "grep", "shell", "subagent", "skill", "question",
  "webfetch", "websearch", "external_directory", "execute",
])

const KNOWN_KEYS = new Set(["enabled", "engine", "budgets", "onEngineError", "actions", "cache", "observeShell", "logLevel"])

const clampInt = (v: unknown, min: number, max: number, def: number, label: string, warns: string[]): number => {
  if (typeof v !== "number" || !Number.isFinite(v)) return def
  const n = Math.floor(v)
  if (n < min || n > max) {
    warns.push(`budgets.${label}: ${n} out of clamp [${min}, ${max}], using ${Math.min(Math.max(n, min), max)}`)
    return Math.min(Math.max(n, min), max)
  }
  return n
}

/** Resolves `{env:NAME}` members; returns null when substitution fails. */
export function resolveEnvMember(s: string): string | null {
  const m = /^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(s)
  if (!m) return s
  const v = process.env[m[1] as string]
  return v === undefined || v === "" ? null : v
}

export function validateOptions(raw: unknown, warn: (m: string) => void = () => {}): ValidateResult {
  const warns: string[] = []
  if (raw === null || raw === undefined || typeof raw !== "object") {
    // Empty options are valid: everything defaults except engine.command.
    raw = {}
  }
  const o = raw as Record<string, unknown>
  for (const key of Object.keys(o)) {
    if (!KNOWN_KEYS.has(key)) warns.push(`unknown option "${key}" ignored`)
  }
  if (o.enabled === false) return { ok: false, reason: "disabled by options.enabled=false", warns }

  // --- engine (fatal on defects) ---
  const eng = (o.engine ?? {}) as Record<string, unknown>
  const rawCommand = eng.command
  if (!Array.isArray(rawCommand) || rawCommand.length === 0 || rawCommand.some((m) => typeof m !== "string")) {
    return { ok: false, reason: 'engine.command must be a non-empty string array', warns }
  }
  const command: string[] = []
  for (const member of rawCommand as string[]) {
    const resolved = resolveEnvMember(member)
    if (resolved === null) {
      return { ok: false, reason: `engine.command member "${member}" failed {env:…} substitution`, warns }
    }
    command.push(resolved)
  }
  if (command[0] === "" || !command[0]!.startsWith("/")) {
    return { ok: false, reason: `engine.command[0] must be an absolute path, got "${command[0]}"`, warns }
  }
  const protocolVersion = typeof eng.protocolVersion === "number" ? eng.protocolVersion : 1
  if (!Number.isInteger(protocolVersion) || protocolVersion < 1) {
    return { ok: false, reason: `engine.protocolVersion must be a positive integer, got ${String(eng.protocolVersion)}`, warns }
  }
  const sha256 = typeof eng.sha256 === "string" && /^[0-9a-f]{64}$/.test(eng.sha256) ? eng.sha256 : null
  if (eng.sha256 !== undefined && eng.sha256 !== null && sha256 === null) {
    return { ok: false, reason: "engine.sha256 must be null or 64 hex chars", warns }
  }
  const cwd = typeof eng.cwd === "string" && eng.cwd.startsWith("/") ? eng.cwd : null

  // --- restart (clamp) ---
  const rs = (eng.restart ?? {}) as Record<string, unknown>
  const restart = {
    maxBackoffMs: clampInt(rs.maxBackoffMs, 1_000, 300_000, 30_000, "restart.maxBackoffMs", warns),
    windowMs: clampInt(rs.windowMs, 10_000, 3_600_000, 300_000, "restart.windowMs", warns),
    resetAfterMs: clampInt(rs.resetAfterMs, 10_000, 3_600_000, 300_000, "restart.resetAfterMs", warns),
  }

  // --- budgets (clamp) ---
  const b = (o.budgets ?? {}) as Record<string, unknown>
  const budgets: ResolvedBudgets = {
    handshakeTimeoutMs: clampInt(b.handshakeTimeoutMs, 100, 60_000, 5_000, "handshakeTimeoutMs", warns),
    checkTimeoutMs: clampInt(b.checkTimeoutMs, 1, 30_000, 5_000, "checkTimeoutMs", warns),
    killGraceMs: clampInt(b.killGraceMs, 50, 2_000, 250, "killGraceMs", warns),
    maxFrameBytes: clampInt(b.maxFrameBytes, 4_096, 1_048_576, 65_536, "maxFrameBytes", warns),
    maxInFlight: clampInt(b.maxInFlight, 1, 64, 8, "maxInFlight", warns),
    maxRequestCommands: clampInt(b.maxRequestCommands, 1, 128, 32, "maxRequestCommands", warns),
    maxViolations: clampInt(b.maxViolations, 1, 10, 3, "maxViolations", warns),
    maxViolationsWindowMs: clampInt(b.maxViolationsWindowMs, 5_000, 3_600_000, 60_000, "maxViolationsWindowMs", warns),
  }

  // --- onEngineError (fatal on "allow") ---
  const onEngineError = o.onEngineError
  if (onEngineError === "allow") {
    return { ok: false, reason: 'onEngineError must be "ask" or "deny" — "allow" is never valid (fail-closed)', warns }
  }
  const degrade = onEngineError === "deny" ? "deny" : "ask"

  // --- actions ---
  let actions: string[] = []
  let actionsAll = false
  const rawActions = o.actions
  if (Array.isArray(rawActions) && rawActions.length > 0) {
    for (const a of rawActions) {
      if (a === "*") actionsAll = true
      else if (typeof a === "string" && KNOWN_ACTIONS.has(a)) actions.push(a)
      else warns.push(`actions: unknown action "${String(a)}" dropped`)
    }
  }
  if (!actionsAll && actions.length === 0) actions = ["shell"]

  // --- cache ---
  const c = (o.cache ?? {}) as Record<string, unknown>
  const cache = {
    enabled: c.enabled !== false,
    maxEntries: clampInt(c.maxEntries, 16, 100_000, 1_024, "cache.maxEntries", warns),
    defaultTtlMs: clampInt(c.defaultTtlMs, 0, 3_600_000, 0, "cache.defaultTtlMs", warns),
  }

  const logLevel = o.logLevel === "debug" || o.logLevel === "info" || o.logLevel === "error" ? o.logLevel : "warn"

  for (const w of warns) warn(`[opencode-shell-warden-hook] ${w}`)

  return {
    ok: true,
    warns,
    config: {
      engine: { command, protocolVersion, sha256, cwd, restart },
      budgets,
      onEngineError: degrade,
      actions: actionsAll ? ["*"] : actions,
      actionsAll,
      cache,
      observeShell: o.observeShell === true,
      logLevel,
    },
  }
}
