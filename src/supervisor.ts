// Engine supervisor — docs/policyd-plugin-design/03-shim.md §3.3, 02-protocol.md §2.7
// Lazy spawn (empty env, absolute argv), exact-version handshake, per-check
// deadlines, violation/restart ladder, unhealthy cooldown, fail-closed dispose.

import { spawn } from "node:child_process"
import type { ChildProcess } from "node:child_process"
import { createHash } from "node:crypto"
import { createReadStream } from "node:fs"
import { FrameParser, IdPool, encodeMessage } from "./protocol.ts"
import type { CheckParams, CheckResult, WireMessage } from "./types.ts"
import type { CheckOutcome } from "./apply.ts"

export interface SupervisorOptions {
  command: string[]
  protocolVersion: number
  sha256: string | null
  cwd: string | null
  clientVersion: string
  budgets: {
    handshakeTimeoutMs: number
    checkTimeoutMs: number
    killGraceMs: number
    maxFrameBytes: number
    maxInFlight: number
    maxViolations: number
    maxViolationsWindowMs: number
    maxBackoffMs: number
    windowMs: number
    resetAfterMs: number
  }
  log?: (level: "debug" | "info" | "warn" | "error", msg: string) => void
}

type Waiter = {
  resolve: (o: CheckOutcome) => void
  timer: ReturnType<typeof setTimeout>
  id: number | null
  params: CheckParams
}

const MAX_QUEUED = 64
const FATAL_COOLDOWN_MS = 15 * 60_000
const KILL_KINDS = new Set(["frame-limit", "parse", "version-mismatch", "handshake-timeout", "timeout", "exit", "spawn"])

export class EngineSupervisor {
  private state: "cold" | "spawning" | "handshaking" | "ready" | "restarting" | "unhealthy" | "disposed" = "cold"
  private child: ChildProcess | null = null
  private parser: FrameParser
  private ids = new IdPool()
  private pending = new Map<number, Waiter>()
  private queue: Waiter[] = []
  private handshakeId: number | null = null
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null
  private violations = { count: 0, windowStart: 0 }
  private restartsAt: number[] = []
  private backoffLevel = 0
  private unhealthyUntil = 0
  private lastReadyAt = 0
  private spawnTimer: ReturnType<typeof setTimeout> | null = null
  private graceTimer: ReturnType<typeof setTimeout> | null = null
  private stderrRing: string[] = []
  private stderrBytes = 0
  private disposed = false

  private readonly opts: SupervisorOptions
  private readonly now: () => number

  constructor(opts: SupervisorOptions, now: () => number = Date.now) {
    this.opts = opts
    this.now = now
    this.parser = new FrameParser(opts.budgets.maxFrameBytes)
  }

  get currentState(): string {
    return this.state
  }

  lastStderr(): string {
    return this.stderrRing.join("")
  }

  async check(params: CheckParams): Promise<CheckOutcome> {
    if (this.disposed || this.state === "disposed") return { ok: false, reason: "disposed" }
    if (this.now() < this.unhealthyUntil) return { ok: false, reason: "unhealthy" }
    void this.ensureEngine()
    return new Promise<CheckOutcome>((resolve) => {
      if (this.state === "ready" && this.child !== null && this.pending.size < this.opts.budgets.maxInFlight) {
        this.sendCheck(resolve, params)
        return
      }
      if (this.queue.length >= MAX_QUEUED) {
        resolve({ ok: false, reason: "backpressure" })
        return
      }
      const waiter: Waiter = {
        resolve,
        id: null,
        params,
        timer: setTimeout(() => this.failWaiter(waiter, "timeout"), this.opts.budgets.checkTimeoutMs),
      }
      this.queue.push(waiter)
    })
  }

  /** Fire-and-forget audit notification (policy/observe); dropped unless ready. */
  observe(notification: Record<string, unknown>): void {
    if (this.state !== "ready" || this.child === null) return
    try {
      this.child.stdin?.write(encodeMessage({ jsonrpc: "2.0", method: "policy/observe", params: notification }, this.opts.budgets.maxFrameBytes))
    } catch {
      /* audit must never throw */
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.state = "disposed"
    this.clearTimers()
    this.rejectPending("disposed")
    this.rejectQueued("disposed")
    if (this.child !== null) {
      try {
        this.child.kill("SIGKILL")
      } catch {
        /* already gone */
      }
      this.child = null
    }
  }

  // ---------- internal ----------

  private ensureEngine(): void {
    if (this.disposed || this.state !== "cold") return
    if (this.now() < this.unhealthyUntil) {
      this.rejectQueued("unhealthy")
      return
    }
    if (this.lastReadyAt !== 0 && this.now() - this.lastReadyAt >= this.opts.budgets.resetAfterMs) {
      this.restartsAt = []
      this.backoffLevel = 0
    }
    this.state = "spawning"
    void this.spawnNow()
  }

  private async spawnNow(): Promise<void> {
    if (this.disposed || this.state !== "spawning") return
    if (this.opts.sha256 !== null) {
      const ok = await this.verifySha256(this.opts.sha256)
      if (!ok) {
        this.markFatal("engine binary sha256 mismatch")
        return
      }
    }
    const [cmd, ...args] = this.opts.command
    const child = spawn(cmd as string, args, {
      env: {},
      cwd: this.opts.cwd ?? undefined,
      stdio: ["pipe", "pipe", "pipe"],
    })
    this.child = child
    this.parser = new FrameParser(this.opts.budgets.maxFrameBytes)
    this.ids.reset()
    this.handshakeId = null
    this.state = "handshaking"
    child.on("error", (err: Error & { code?: string }) => {
      this.protocolViolation(`spawn:${err.code ?? "error"}`)
    })
    child.stdout?.setEncoding("utf8")
    child.stdout?.on("data", (chunk: string) => {
      this.parser.push(chunk)
      if (this.parser.fatal !== null) {
        this.protocolViolation(`frame:${this.parser.fatal}`)
        return
      }
      for (const msg of this.parser.drain()) this.route(msg)
    })
    child.stderr?.setEncoding("utf8")
    child.stderr?.on("data", (chunk: string) => {
      this.stderrRing.push(chunk)
      this.stderrBytes += chunk.length
      while (this.stderrBytes > 8 * 1024 && this.stderrRing.length > 0) {
        const head = this.stderrRing.shift() as string
        this.stderrBytes -= head.length
      }
    })
    child.on("exit", (code, signal) => this.onExit(code, signal))
    this.sendHandshake()
  }

  private sendHandshake(): void {
    const id = this.ids.take()
    this.handshakeId = id
    this.handshakeTimer = setTimeout(() => {
      this.handshakeId = null
      this.protocolViolation("handshake-timeout")
    }, this.opts.budgets.handshakeTimeoutMs)
    this.write({
      jsonrpc: "2.0",
      id,
      method: "initialize",
      params: { protocolVersion: this.opts.protocolVersion, client: { name: "opencode-shell-warden-hook", version: this.opts.clientVersion } },
    })
  }

  private completeHandshake(result: unknown): void {
    if (this.handshakeTimer !== null) clearTimeout(this.handshakeTimer)
    this.handshakeTimer = null
    this.handshakeId = null
    if (this.state !== "handshaking") return
    const r = result as { protocolVersion?: number } | null
    if (r === null || typeof r !== "object" || r.protocolVersion !== this.opts.protocolVersion) {
      this.protocolViolation("version-mismatch")
      return
    }
    this.state = "ready"
    this.log("info", `engine ready: ${JSON.stringify((result as InitializeLike).engine ?? {})}`)
    this.flushQueue()
  }

  private flushQueue(): void {
    while (this.state === "ready" && this.queue.length > 0 && this.pending.size < this.opts.budgets.maxInFlight) {
      const waiter = this.queue.shift()
      if (waiter === undefined) break
      this.sendCheck(waiter.resolve, waiter.params, waiter)
    }
  }

  private sendCheck(resolve: (o: CheckOutcome) => void, params: CheckParams, existing?: Waiter): void {
    let waiter: Waiter
    if (existing !== undefined) {
      waiter = existing
    } else {
      const w: Waiter = { resolve, params, id: null, timer: null! }
      w.timer = setTimeout(() => this.failWaiter(w, "timeout"), this.opts.budgets.checkTimeoutMs)
      waiter = w
    }
    const id = this.ids.take()
    waiter.id = id
    this.pending.set(id, waiter)
    this.write({ jsonrpc: "2.0", id, method: "policy/check", params })
  }

  private route(msg: WireMessage): void {
    if ("method" in msg && !("id" in msg)) {
      if (msg.method === "audit/event") this.log("info", `audit: ${JSON.stringify(msg.params ?? {})}`)
      return // unknown notifications ignored (forward compatibility)
    }
    if ("error" in msg) {
      if (msg.id === null) return
      const waiter = this.pending.get(msg.id)
      if (waiter !== undefined) {
        this.pending.delete(msg.id)
        clearTimeout(waiter.timer)
        waiter.resolve({ ok: false, reason: "engine-error" })
      }
      if (msg.error.data?.fatal === true) this.markFatal(`engine fatal: ${msg.error.message}`)
      return
    }
    if (!("result" in msg)) return
    const id = msg.id
    if (id === this.handshakeId) {
      this.completeHandshake(msg.result)
      return
    }
    const waiter = this.pending.get(id)
    if (waiter === undefined) return // unknown/late id — ignore
    this.pending.delete(id)
    clearTimeout(waiter.timer)
    const result = msg.result as CheckResult | null
    if (result === null || typeof result !== "object" || typeof (result as CheckResult).verdict !== "string") {
      this.protocolViolation("bad-result-shape")
      waiter.resolve({ ok: false, reason: "malformed-response" })
      return
    }
    waiter.resolve({ ok: true, result })
  }

  private failWaiter(waiter: Waiter, reason: string): void {
    if (waiter.id !== null) this.pending.delete(waiter.id)
    else this.queue = this.queue.filter((w) => w !== waiter)
    waiter.resolve({ ok: false, reason })
    if (reason === "timeout") this.protocolViolation("timeout")
  }

  private onExit(_code: number | null, _signal: string | null): void {
    if (this.graceTimer !== null) clearTimeout(this.graceTimer)
    this.graceTimer = null
    if (this.disposed || this.state === "restarting" || this.state === "unhealthy" || this.state === "disposed") return
    this.rejectPending("engine-exited")
    this.protocolViolation("exit")
  }

  private protocolViolation(kind: string): void {
    if (this.disposed) return
    this.log("warn", `violation: ${kind}`)
    const now = this.now()
    if (now - this.violations.windowStart > this.opts.budgets.maxViolationsWindowMs) {
      this.violations = { count: 1, windowStart: now }
    } else {
      this.violations.count += 1
    }
    if (this.violations.count >= this.opts.budgets.maxViolations) {
      this.violations = { count: 0, windowStart: 0 }
      this.killAndRestart(`violations:${kind}`)
      return
    }
    if (KILL_KINDS.has(kind) || kind.startsWith("spawn:")) this.killAndRestart(kind)
  }

  private killAndRestart(reason: string): void {
    if (this.disposed) return
    const now = this.now()
    this.restartsAt.push(now)
    this.restartsAt = this.restartsAt.filter((t) => now - t <= this.opts.budgets.windowMs)
    this.state = "restarting"
    this.rejectPending("engine-restarting")
    this.killChild()
    if (this.restartsAt.length > this.opts.budgets.maxViolations) {
      this.unhealthyUntil = now + this.opts.budgets.windowMs
      this.state = "unhealthy"
      this.rejectQueued("unhealthy")
      this.log("error", `engine unhealthy until ${new Date(this.unhealthyUntil).toISOString()} (${reason})`)
      return
    }
    const delay = Math.min(250 * 2 ** this.backoffLevel, this.opts.budgets.maxBackoffMs)
    this.backoffLevel += 1
    this.log("warn", `restart #${this.restartsAt.length} in ${delay}ms (${reason})`)
    this.spawnTimer = setTimeout(() => {
      this.spawnTimer = null
      this.state = "cold"
      void this.ensureEngine()
    }, delay)
  }

  private killChild(): void {
    const child = this.child
    this.child = null
    if (child === null) return
    try {
      child.kill("SIGTERM")
    } catch {
      /* already gone */
    }
    this.graceTimer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        /* already gone */
      }
    }, this.opts.budgets.killGraceMs)
  }

  private markFatal(reason: string): void {
    this.unhealthyUntil = this.now() + FATAL_COOLDOWN_MS
    this.state = "unhealthy"
    this.rejectPending("unhealthy")
    this.rejectQueued("unhealthy")
    this.killChild()
    this.log("error", `fatal: ${reason}`)
  }

  private rejectPending(reason: string): void {
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer)
      waiter.resolve({ ok: false, reason })
    }
    this.pending.clear()
  }

  private rejectQueued(reason: string): void {
    for (const waiter of this.queue) {
      clearTimeout(waiter.timer)
      waiter.resolve({ ok: false, reason })
    }
    this.queue = []
  }

  private clearTimers(): void {
    if (this.handshakeTimer !== null) clearTimeout(this.handshakeTimer)
    if (this.spawnTimer !== null) clearTimeout(this.spawnTimer)
    if (this.graceTimer !== null) clearTimeout(this.graceTimer)
  }

  private write(msg: WireMessage): void {
    if (this.child === null) return
    try {
      this.child.stdin?.write(encodeMessage(msg, this.opts.budgets.maxFrameBytes))
    } catch {
      this.protocolViolation("frame-limit")
    }
  }

  private log(level: "debug" | "info" | "warn" | "error", msg: string): void {
    this.opts.log?.(level, `[opencode-shell-warden-hook] ${msg}`)
  }

  private async verifySha256(expected: string): Promise<boolean> {
    const path = this.opts.command[0] as string
    return new Promise((resolve) => {
      const hash = createHash("sha256")
      const stream = createReadStream(path)
      stream.on("data", (chunk) => hash.update(chunk))
      stream.on("end", () => resolve(hash.digest("hex") === expected))
      stream.on("error", () => resolve(false))
    })
  }
}

type InitializeLike = { engine?: { name?: string; version?: string } }
