// Reply automation per ADR-0013 — the shim resolves published permission
// requests programmatically (the same right the human exercises):
//   engine allow → reply "once" (command runs)
//   engine deny  → reply "reject" (with reason)
//   engine ask   → no reply (escalation by silence — the human decides)
// The shim never mutates permission events (the evaluate-allow path is not
// honored by OpenCode v2.2.x anyway — live-proven).

import { createHash } from "node:crypto"
import type { CheckParams, CheckResult, Verdict } from "./types.ts"

export type CheckOutcome = { ok: true; result: CheckResult } | { ok: false; reason: string }

export interface AskData {
  id?: string                          // requestID, assigned at publication
  sessionID?: string
  action?: string
  resources?: readonly string[]
  source?: { type: "tool"; messageID: string; id: string }
}

export function invocationIdOf(source?: { messageID: string; id: string }, sessionID?: string, action?: string): string {
  return source ? `${source.messageID}:${source.id}` : `anon:${sessionID ?? ""}:${action ?? ""}`
}

export function cacheKey(action: string, resources: readonly string[], cwd: string, agent?: string): string {
  return createHash("sha256")
    .update(action)
    .update("\u0000")
    .update((resources ?? []).join("\u0000"))
    .update("\u0000")
    .update(cwd)
    .update("\u0000")
    .update(agent ?? "")
    .digest("hex")
}

export function buildCheckRequest(args: {
  data: AskData
  invocationId: string
  cwd: string
  projectDir?: string
}): CheckParams {
  const { data, invocationId, cwd, projectDir } = args
  return {
    invocation: {
      id: invocationId,
      sessionID: data.sessionID ?? "",
      hook: "permission.asked",
      ...(projectDir !== undefined ? { projectDir } : {}),
      startedAt: new Date().toISOString(),
    },
    action: data.action ?? "",
    commands: (data.resources ?? []).map((raw, index) => ({ index, raw, cwd })),
    context: {
      ...(data.source !== undefined ? { source: data.source } : {}),
    },
  }
}

/** Maps a verdict to the reply decision: `"once"` | `"reject"` | `null` (silence). */
export function replyDecision(v: Verdict): "once" | "reject" | null {
  if (v === "allow") return "once"
  if (v === "deny") return "reject"
  return null
}

/** Best-effort per-invocation cache eviction registry (bounded). */
export class InvocationRegistry {
  private readonly cap: number
  private map = new Map<string, string>()
  constructor(cap = 256) {
    this.cap = cap
  }
  remember(invocationId: string, key: string): void {
    this.map.set(invocationId, key)
    while (this.map.size > this.cap) {
      const oldest = this.map.keys().next()
      if (oldest.done === true) break
      this.map.delete(oldest.value)
    }
  }
  keyFor(invocationId: string): string | undefined {
    return this.map.get(invocationId)
  }
}
