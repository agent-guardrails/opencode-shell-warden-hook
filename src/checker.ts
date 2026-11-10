// One-shot checker invoker — docs/spec/shell-warden/02-letter-verdict.md (v2.0).
// Spawn the checker for each check with an EMPTY environment (I1), feed exactly
// one letter, read exactly one verdict. Any deviation (exit≠0, timeout, non-JSON,
// shape mismatch, oversize) is a checker defect ⇒ degrade (§2.4 / 09 §9.4):
// the hook never parses garbage into a verdict.

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import type { Letter, LetterVerdict, Verdict } from "./types.ts"
import { MAX_VERDICT_BYTES, MAX_FACTS_BYTES, MAX_MESSAGE_CHARS } from "./types.ts"

export interface CheckerOptions {
  command: string[]
  sha256: string | null
  checkTimeoutMs: number
  killGraceMs: number
  maxConcurrentSpawns: number
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void
}

export type CheckerOutcome = { ok: true; verdict: LetterVerdict } | { ok: false; reason: string }

// Binary pin (I8): sha256 of checker.command[0]; mismatch = fatal for every spawn.
let pinState: "unverified" | "ok" | "mismatch" | "unreadable" = "unverified"

export function verifyPin(o: CheckerOptions): void {
  if (o.sha256 === null) { pinState = "ok"; return }
  try {
    const digest = createHash("sha256").update(readFileSync(o.command[0] ?? "")).digest("hex")
    pinState = digest === o.sha256 ? "ok" : "mismatch"
  } catch {
    pinState = "unreadable"
  }
  if (pinState !== "ok") o.log("warn", `checker sha256 pin (${pinState}) — every check will degrade`)
}

export class CheckerInvoker {
  private inflight = 0
  private readonly opts: CheckerOptions

  constructor(opts: CheckerOptions) {
    this.opts = opts
  }

  async check(letter: Letter): Promise<CheckerOutcome> {
    if (this.inflight >= this.opts.maxConcurrentSpawns) return { ok: false, reason: "spawn budget exceeded (local degrade)" }
    if (pinState === "mismatch" || pinState === "unreadable") return { ok: false, reason: `checker sha256 pin ${pinState}` }
    this.inflight++
    try {
      return await this.runOnce(letter)
    } finally {
      this.inflight--
    }
  }

  private runOnce(letter: Letter): Promise<CheckerOutcome> {
    const { command, checkTimeoutMs, killGraceMs, log } = this.opts
    return new Promise<CheckerOutcome>((resolve) => {
      const bin = command[0] ?? ""
      const child = spawn(bin, command.slice(1), {
        env: {},             // I1: empty environment — no PATH, no variables
        stdio: ["pipe", "pipe", "pipe"],
      })

      let out = ""
      const kill = setTimeout(() => {
        child.kill("SIGTERM")
        setTimeout(() => { try { child.kill("SIGKILL") } catch { /* already dead */ } }, killGraceMs)
      }, checkTimeoutMs)

      child.stdout?.setEncoding("utf8")
      child.stdout?.on("data", (chunk: string) => {
        out += chunk
        if (out.length > MAX_VERDICT_BYTES) {
          try { child.kill("SIGTERM") } catch { /* already dead */ }
        }
      })

      child.on("error", (err) => {
        clearTimeout(kill)
        resolve({ ok: false, reason: `spawn failure: ${err.message}` })
      })
      child.stdin?.on("error", () => { /* EPIPE on early exit — close handler decides */ })
      child.stdio[2]?.on("data", (chunk: string) => log("debug", `checker: ${String(chunk).trim()}`))

      child.stdin?.end(JSON.stringify(letter))

      let settled = false
      const done = (o: CheckerOutcome) => {
        if (settled) return
        settled = true
        clearTimeout(kill)
        resolve(o)
      }
      child.on("close", (code) => {
        if (code !== 0) { done({ ok: false, reason: `checker exit ${code ?? "signal"}` }); return }
        if (out.length === 0) { done({ ok: false, reason: "checker produced no verdict" }); return }
        const parsed = parseVerdict(letter, out)
        done(parsed.ok ? { ok: true, verdict: parsed.value } : { ok: false, reason: parsed.reason ?? "verdict shape" })
      })
    })
  }
}

function parseVerdict(letter: Letter, raw: string): { ok: true; value: LetterVerdict } | { ok: false; reason: string } {
  let value: unknown
  try {
    value = JSON.parse(raw.trim())
  } catch (e) {
    return { ok: false, reason: `unparseable verdict: ${e instanceof Error ? e.message.slice(0, 120) : "not json"}` }
  }
  if (value === null || typeof value !== "object") return { ok: false, reason: "verdict is not an object" }
  const v = value as Record<string, unknown>

  if (v.invocationId !== letter.invocation.id) return { ok: false, reason: "verdict.invocationId mismatch" }
  const verdict = v.verdict
  if (verdict !== "allow" && verdict !== "ask" && verdict !== "deny") return { ok: false, reason: `verdict "${String(verdict)}" invalid` }
  if (typeof v.message !== "undefined") {
    if (typeof v.message !== "string" || v.message.length > MAX_MESSAGE_CHARS) return { ok: false, reason: "verdict.message overbound" }
    if (verdict === "deny" && v.message.length === 0) return { ok: false, reason: "deny without prescriptive message" }
  } else if (verdict === "deny") {
    return { ok: false, reason: "deny without prescriptive message" }
  }

  // commands[]: exactly one entry per letter command, indexes match.
  const cmds = v.commands
  if (!Array.isArray(cmds) || cmds.length !== letter.commands.length) {
    return { ok: false, reason: "verdict.commands must cover every letter command" }
  }
  for (let i = 0; i < letter.commands.length; i++) {
    const c = cmds[i]
    if (c === null || typeof c !== "object") return { ok: false, reason: `verdict.commands[${i}] is not an object` }
    const cv = c as Record<string, unknown>
    if (cv.index !== letter.commands[i]?.index) return { ok: false, reason: `verdict.commands[${i}].index mismatch` }
    if (cv.verdict !== "allow" && cv.verdict !== "ask" && cv.verdict !== "deny") {
      return { ok: false, reason: `commands[${i}].verdict invalid` }
    }
    if (cv.classification !== "static" && cv.classification !== "opaque") {
      return { ok: false, reason: `commands[${i}].classification invalid` }
    }
    if (cv.match !== "argv" && cv.match !== "raw") {
      return { ok: false, reason: `commands[${i}].match invalid` }
    }
    if (cv.match === "raw" && cv.verdict === "allow") {
      return { ok: false, reason: `commands[${i}].raw match cannot allow` }
    }
    if (cv.facts !== undefined) {
      const bytes = JSON.stringify(cv.facts).length
      if (bytes > MAX_FACTS_BYTES) return { ok: false, reason: `commands[${i}].facts overbound` }
    }
  }
  return { ok: true, value: { invocationId: v.invocationId as string, verdict: verdict as Verdict, ...(typeof v.message === "string" ? { message: v.message } : {}) } }
}

/** Reject-budget per ruleId per session (ADR-0010 / 04 §4.2): on exhaustion the hook
 * stops answering — the ask flows to the human; never auto-allowed. */
export class RejectBudgets {
  private readonly maxRejections: number
  private readonly windowMs: number
  private spend = new Map<string, { count: number; until: number }>()

  constructor(maxRejections: number, windowMs: number) {
    this.maxRejections = maxRejections
    this.windowMs = windowMs
  }

  /** Returns false when the rule is exhausted for this session. */
  trySpend(sessionID: string, ruleId: string, now = Date.now()): boolean {
    if (this.maxRejections <= 0) return false
    const key = `${sessionID}\u0000${ruleId}`
    const cur = this.spend.get(key)
    if (cur === undefined || cur.until <= now) {
      this.spend.set(key, { count: 1, until: now + this.windowMs })
      return true
    }
    cur.count++
    if (cur.count > this.maxRejections) {
      cur.until = now + this.windowMs
      return false
    }
    return true
  }
}
