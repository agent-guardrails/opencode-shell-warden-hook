// NDJSON JSON-RPC framing — docs/policyd-plugin-design/02-protocol.md §2.1–2.2
// One UTF-8 JSON value per \n-terminated line; lines over the byte cap are a
// protocol violation; unparseable lines are a protocol violation.

import type { WireMessage } from "./types.ts"

export class FrameError extends Error {
  readonly kind: "frame-limit" | "parse"
  constructor(kind: "frame-limit" | "parse") {
    super(`protocol violation: ${kind}`)
    this.kind = kind
  }
}

export function encodeMessage(msg: WireMessage, maxFrameBytes: number): string {
  const line = JSON.stringify(msg)
  if (Buffer.byteLength(line, "utf8") + 1 > maxFrameBytes) {
    throw new FrameError("frame-limit")
  }
  return line + "\n"
}

/**
 * Incremental line parser for a byte stream. After `fatal` is set the parser
 * stops consuming input; the caller must treat the connection as violated.
 */
export class FrameParser {
  private buf = ""
  private queue: WireMessage[] = []
  fatal: string | null = null

  private readonly maxFrameBytes: number
  constructor(maxFrameBytes: number) {
    this.maxFrameBytes = maxFrameBytes
  }

  push(chunk: Buffer | string): void {
    if (this.fatal !== null) return
    this.buf += typeof chunk === "string" ? chunk : chunk.toString("utf8")
    for (;;) {
      const nl = this.buf.indexOf("\n")
      if (nl === -1) {
        if (Buffer.byteLength(this.buf, "utf8") > this.maxFrameBytes) this.fatal = "frame-limit"
        return
      }
      const line = this.buf.slice(0, nl)
      this.buf = this.buf.slice(nl + 1)
      if (Buffer.byteLength(line, "utf8") > this.maxFrameBytes) {
        this.fatal = "frame-limit"
        return
      }
      if (line.trim().length === 0) {
        this.fatal = "parse" // blank lines are not valid NDJSON
        return
      }
      let msg: unknown
      try {
        msg = JSON.parse(line)
      } catch {
        this.fatal = "parse"
        return
      }
      if (msg === null || typeof msg !== "object") {
        this.fatal = "parse"
        return
      }
      this.queue.push(msg as WireMessage)
    }
  }

  drain(): WireMessage[] {
    const q = this.queue
    this.queue = []
    return q
  }
}

/** Monotonic JSON-RPC id source; reset per engine connection. */
export class IdPool {
  private next = 1
  take(): number {
    return this.next++
  }
  reset(): void {
    this.next = 1
  }
}
