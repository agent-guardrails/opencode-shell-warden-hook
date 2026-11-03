// Hook options — docs/spec/shell-warden/04-shim-config.md (v2.0, one-shot per-check).
// Unknown keys ⇒ warn + ignore; clamps warn + apply; ONLY checker.command / sha256 /
// onCheckerError:"allow" are fatal (plugin disables itself — the honest fail-closed
// posture for load-time misconfiguration).

type Resolved = { ok: true; config: Opts; warns: string[] } | { ok: false; reason: string }

export interface CheckerOpts {
  command: string[]
  sha256: string | null
}

export interface BudgetsOpts {
  checkTimeoutMs: number   // 100..30_000, def 2_000 — verdict deadline (SIGTERM → killGraceMs → SIGKILL)
  killGraceMs: number      // 50..2_000,  def 250 — SIGTERM → SIGKILL
  maxRequestCommands: number // 1..128, def 32 — breach ⇒ local degrade, no spawn (02 §2.2)
  maxConcurrentSpawns: number // 1..64, def 8 — excess ⇒ local degrade, never queued
}

export interface OptionsOpts {
  enabled: boolean
  checker: CheckerOpts
  budgets: BudgetsOpts
  onCheckerError: "ask" | "deny"   // degrade verdict; "allow" is not a valid value (I3)
  actions: string[]
  actionsAll: boolean              // actions includes "*"
  cache: { enabled: boolean; maxEntries: number; ttlMs: number }
  rejectBudget: { maxRejections: number; windowMs: number }
  asConfig: { observeShell: boolean }
  debug: { enabled: boolean; dir: string | null }
  logLevel: "debug" | "info" | "warn" | "error"
}
export type Opts = OptionsOpts

function isInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) }

function clampInt(v: unknown, min: number, max: number, def: number, name: string, warns: string[]): number {
  let x = isInt(v) ? v : def
  if (!isInt(v) && v !== undefined) warns.push(`omit/wrong type for ${name}, using ${def}`)
  if (x < min) { warns.push(`${name} ${x} < ${min}, clamped to ${min}`); x = min }
  if (x > max) { warns.push(`${name} ${x} > ${max}, clamped to ${max}`); x = max }
  return x
}

/** "{env:NAME}" member substitution resolved at setup; unresolved is fatal (I2). */
function substituteEnv(member: string): string | null {
  const m = /^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(member)
  if (!m) return member
  const value = process.env[m[1] ?? ""]
  return value === undefined || value === "" ? null : value
}

const KNOWN_KEYS = new Set(["enabled", "checker", "budgets", "onCheckerError", "actions", "cache", "rejectBudget", "asConfig", "debug", "logLevel"])
const CHECKER_KEYS = new Set(["command", "sha256"])
const BUDGET_KEYS = new Set(["checkTimeoutMs", "killGraceMs", "maxRequestCommands", "maxConcurrentSpawns"])
const CACHE_KEYS = new Set(["enabled", "maxEntries", "ttlMs"])
const REJECT_KEYS = new Set(["maxRejections", "windowMs"])
const ASKEYS = new Set(["observeShell"])
const DEBUG_KEYS = new Set(["enabled", "dir"])

function warnUnknown(scope: string, keys: object, known: Set<string>, warns: string[]): void {
  for (const k of Object.keys(keys ?? {})) if (!known.has(k)) warns.push(`${scope}: unknown key "${k}" ignored`)
}

export function validateOptions(o: unknown): Resolved {
  const warns: string[] = []
  if (o === null || typeof o !== "object" || Array.isArray(o)) o = {}
  const rec = o as Record<string, unknown>
  warnUnknown("", rec, KNOWN_KEYS, warns)

  const enabled = rec.enabled === undefined ? true : rec.enabled === true

  // ── checker (fatal on defects) ──
  const rawChecker = (rec.checker ?? {}) as Record<string, unknown>
  if (rec.checker !== undefined && (typeof rec.checker !== "object")) return { ok: false, reason: "checker must be an object" }
  warnUnknown("checker", rawChecker, CHECKER_KEYS, warns)
  const rawCommand = rawChecker.command
  if (!Array.isArray(rawCommand) || rawCommand.length === 0 || rawCommand.some((m) => typeof m !== "string")) {
    return { ok: false, reason: "checker.command must be a non-empty string array" }
  }
  const command: string[] = []
  for (const member of rawCommand as string[]) {
    const resolved = substituteEnv(member)
    if (resolved === null) return { ok: false, reason: `checker.command member "${member}" failed {env:…} substitution` }
    command.push(resolved)
  }
  if (!command[0]?.startsWith("/")) return { ok: false, reason: `checker.command[0] must be an absolute path, got "${command[0]}"` }
  const sha256raw = rawChecker.sha256
  if (sha256raw !== undefined && sha256raw !== null && !/^[0-9a-f]{64}$/.test(String(sha256raw))) {
    return { ok: false, reason: "checker.sha256 must be null or 64 hex chars" }
  }
  const sha256 = sha256raw === undefined ? null : (sha256raw as string | null)

  // ── budgets ──
  const rawBudgets = (rec.budgets ?? {}) as Record<string, unknown>
  warnUnknown("budgets", rawBudgets, BUDGET_KEYS, warns)
  const budgets = {
    checkTimeoutMs: clampInt(rawBudgets.checkTimeoutMs, 100, 30_000, 2_000, "checkTimeoutMs", warns),
    killGraceMs: clampInt(rawBudgets.killGraceMs, 50, 2_000, 250, "killGraceMs", warns),
    maxRequestCommands: clampInt(rawBudgets.maxRequestCommands, 1, 128, 32, "maxRequestCommands", warns),
    maxConcurrentSpawns: clampInt(rawBudgets.maxConcurrentSpawns, 1, 64, 8, "maxConcurrentSpawns", warns),
  }

  // ── onCheckerError ──
  const onError = (rec.onCheckerError ?? "ask") as string
  if (onError === "allow") return { ok: false, reason: "onCheckerError must be 'ask' or 'deny' — never 'allow' (I3)" }
  if (onError !== "ask" && onError !== "deny") {
    warns.push(`onCheckerError "${onError}" is not ask|deny, using ask`)
  }
  const onCheckerError: "ask" | "deny" = onError === "deny" ? "deny" : "ask"

  // ── actions ──
  const actionsAll: boolean = rec.actions === "*" || (Array.isArray(rec.actions) && rec.actions.includes("*"))
  const actions = Array.isArray(rec.actions)
    ? (rec.actions as unknown[]).filter((a): a is string => typeof a === "string" && a !== "*")
    : ["shell"]
  if (!Array.isArray(rec.actions) && rec.actions !== undefined && rec.actions !== "*") warns.push("actions must be an array, using [shell]")

  // ── cache ──
  const rawCache = (rec.cache ?? {}) as Record<string, unknown>
  warnUnknown("cache", rawCache, CACHE_KEYS, warns)
  const cache = {
    enabled: rawCache.enabled === undefined ? true : rawCache.enabled === true,
    maxEntries: clampInt(rawCache.maxEntries, 16, 100_000, 1_024, "cache.maxEntries", warns),
    ttlMs: clampInt(rawCache.ttlMs, 0, 3_600_000, 0, "cache.ttlMs", warns),
  }

  // ── rejectBudget ──
  const rawReject = (rec.rejectBudget ?? {}) as Record<string, unknown>
  warnUnknown("rejectBudget", rawReject, REJECT_KEYS, warns)
  const rejectBudget = {
    maxRejections: clampInt(rawReject.maxRejections, 1, 10, 3, "rejectBudget.maxRejections", warns),
    windowMs: clampInt(rawReject.windowMs, 60_000, 86_400_000, 1_800_000, "rejectBudget.windowMs", warns),
  }

  // ── asConfig / debug / logLevel ──
  const rawAs = (rec.asConfig ?? {}) as Record<string, unknown>
  warnUnknown("asConfig", rawAs, ASKEYS, warns)
  const asConfig = { observeShell: rawAs.observeShell === true }

  const rawDebug = (rec.debug ?? {}) as Record<string, unknown>
  warnUnknown("debug", rawDebug, DEBUG_KEYS, warns)
  let debugDir: string | null = typeof rawDebug.dir === "string" ? rawDebug.dir : null
  if (debugDir !== null && !debugDir.startsWith("/")) { warns.push("debug.dir must be absolute, ignored"); debugDir = null }
  const debug = { enabled: rawDebug.enabled === true, dir: debugDir }

  const LEVELS = ["debug", "info", "warn", "error"] as const
  const logLevel = LEVELS.includes(rec.logLevel as (typeof LEVELS)[number]) ? (rec.logLevel as OptionsOpts["logLevel"]) : "warn"
  if (rec.logLevel !== undefined && !LEVELS.includes(rec.logLevel as (typeof LEVELS)[number])) warns.push("logLevel invalid, using warn")

  return {
    ok: true,
    warns,
    config: { enabled, checker: { command, sha256 }, budgets, onCheckerError, actions, actionsAll, cache, rejectBudget, asConfig, debug, logLevel },
  }
}
