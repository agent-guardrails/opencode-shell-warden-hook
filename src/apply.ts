// Verdict application — docs/policyd-plugin-design/03-shim.md §3.2 (revised v1.1)
// The engine is the policy authority: its verdict REPLACES the accumulated
// effect (it may automate an ask into an allow — that is the product).
// The only protection: never loosen an existing deny (future coexistence with
// other hook plugins; explicit config denies never reach hooks at all).

import { createHash } from "node:crypto"
import type { CheckParams, CheckResult, PermissionEvaluation, Verdict } from "./types.ts"

const RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 }

export type CheckOutcome = { ok: true; result: CheckResult } | { ok: false; reason: string }

/** `${messageID}:${callID}` from the hook source, or a synthetic key. */
export function invocationIdOf(ev: PermissionEvaluation): string {
  const s = ev.source
  return s ? `${s.messageID}:${s.id}` : `anon:${ev.sessionID}:${ev.action}`
}

export function cacheKey(action: string, resources: readonly string[], cwd: string, agent?: string): string {
  return createHash("sha256")
    .update(action)
    .update("\u0000")
    .update(resources.join("\u0000"))
    .update("\u0000")
    .update(cwd)
    .update("\u0000")
    .update(agent ?? "")
    .digest("hex")
}

export function buildCheckRequest(args: {
  ev: PermissionEvaluation
  invocationId: string
  cwd: string
  projectDir?: string
}): CheckParams {
  const { ev, invocationId, cwd, projectDir } = args
  return {
    invocation: {
      id: invocationId,
      sessionID: ev.sessionID,
      ...(ev.agent !== undefined ? { agent: ev.agent } : {}),
      hook: "permission.evaluate",
      ...(projectDir !== undefined ? { projectDir } : {}),
      startedAt: new Date().toISOString(),
    },
    action: ev.action,
    commands: ev.resources.map((raw, index) => ({ index, raw, cwd })),
    context: {
      ...(ev.source !== undefined ? { source: ev.source } : {}),
      ...(ev.metadata !== undefined ? { metadata: ev.metadata } : {}),
    },
  }
}

/**
 * Applies the engine verdict to the evaluate event.
 * - An existing `deny` is never loosened (only its message may be refined).
 * - `message` is attached whenever provided (append/replace composition is the
 *   engine's job in v1.1; the shim just carries the final string).
 * Returns true when the event was changed.
 */
export function applyToEvent(ev: PermissionEvaluation, verdict: Verdict, message?: string): boolean {
  if (ev.effect === "deny" && verdict !== "deny") return false
  ev.effect = verdict
  if (message !== undefined) ev.message = message
  return true
}

/** Best-effort per-invocation cache eviction registry (bounded). */
export class InvocationRegistry {
  private readonly cap: number
  private map = new Map<string, string>()
  constructor(cap = 256) {
    this.cap = cap
  }
  remember(invocationId: string, cacheKey: string): void {
    this.map.set(invocationId, cacheKey)
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
