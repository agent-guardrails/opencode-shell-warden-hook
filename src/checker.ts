// One-shot checker invoker — docs/spec/shell-warden/02-letter-verdict.md (v2.0).
// Spawn the checker for each check with an EMPTY environment (I1), feed exactly
// one letter, read exactly one verdict. Any deviation (exit≠0, timeout, non-JSON,
// shape mismatch, oversize) is a checker defect ⇒ degrade (§2.4 / 09 §9.4):
// the hook never parses garbage into a verdict.

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import { TextDecoder } from "node:util"
import type { Letter } from "./types.ts"
import { MAX_VERDICT_BYTES } from "./types.ts"
import { parseV2Envelope } from "./verdict-v2.ts"
import type { V2Result } from "./types.ts"

export interface CheckerOptions {
  command: string[]
  sha256: string | null
  checkTimeoutMs: number
  killGraceMs: number
  maxConcurrentSpawns: number
  log: (level: "debug" | "info" | "warn" | "error", msg: string) => void
}

export type CheckerOutcome = { ok: true; verdict: V2Result } | { ok: false; reason: string }

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

      const output = Buffer.allocUnsafe(MAX_VERDICT_BYTES)
      let retainedBytes = 0
      let settled = false
      let anomaly: { readonly ok: false; readonly reason: string } | undefined
      let deadlineTimer: ReturnType<typeof setTimeout> | undefined
      let killTimer: ReturnType<typeof setTimeout> | undefined
      const done = (o: CheckerOutcome) => {
        if (settled) return
        settled = true
        if (deadlineTimer !== undefined) clearTimeout(deadlineTimer)
        if (killTimer !== undefined) clearTimeout(killTimer)
        resolve(o)
      }
      const terminate = (reason: string) => {
        if (anomaly !== undefined) return
        anomaly = { ok: false, reason }
        child.kill("SIGTERM")
        killTimer = setTimeout(() => { child.kill("SIGKILL") }, killGraceMs)
      }

      deadlineTimer = setTimeout(() => { terminate("checker timed out") }, checkTimeoutMs)

      child.stdout?.on("data", (chunk: Buffer) => {
        if (anomaly !== undefined) return
        const available = MAX_VERDICT_BYTES - retainedBytes
        if (chunk.length <= available) {
          chunk.copy(output, retainedBytes)
          retainedBytes += chunk.length
          return
        }
        if (available > 0) {
          chunk.copy(output, retainedBytes, 0, available)
          retainedBytes += available
        }
        terminate("verdict exceeds the 64 KiB output bound")
      })

      child.on("error", (err) => {
        if (anomaly !== undefined) {
          log("debug", `checker termination error: ${err.message}`)
          return
        }
        done({ ok: false, reason: `spawn failure: ${err.message}` })
      })
      child.stdin?.on("error", () => { /* EPIPE on early exit — close handler decides */ })
      child.stdio[2]?.on("data", (chunk: Buffer) => log("debug", `checker: ${String(chunk).trim()}`))

      child.stdin?.end(JSON.stringify(letter))

      child.on("close", (code) => {
        if (anomaly !== undefined) { done(anomaly); return }
        if (code !== 0) { done({ ok: false, reason: `checker exit ${code ?? "signal"}` }); return }
        if (retainedBytes === 0) { done({ ok: false, reason: "checker produced no verdict" }); return }
        let out: string
        try {
          out = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(output.subarray(0, retainedBytes))
        } catch (error) {
          if (!(error instanceof TypeError)) throw error
          done({ ok: false, reason: "checker produced invalid UTF-8" })
          return
        }
        // One parser, one response version (02 §2.8, ADR-0023): exact v2 only.
        // No fallback, no v1 read — every anomaly is a checker defect.
        const parsed = parseV2Envelope(letter, out)
        done(parsed.ok ? { ok: true, verdict: parsed.value } : { ok: false, reason: parsed.reason })
      })
    })
  }
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
