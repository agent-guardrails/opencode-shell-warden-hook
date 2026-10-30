// Verdict application — docs/policyd-plugin-design/03-shim.md §3.2
// Tighten-only mapping of engine outcomes onto the evaluate event (invariant I5).

import { createHash } from "node:crypto"
import type { CheckParams, CheckResult, PermissionEvaluation, Verdict } from "./types.ts"

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
 * Tighten-only: writes the verdict only when its rank is strictly higher than
 * the current effect (never loosens). Message is attached only on tighten.
 * Returns true when the event was changed.
 */
export function tighten(ev: PermissionEvaluation, verdict: Verdict, message?: string): boolean {
  const RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 }
  if (RANK[verdict] <= RANK[ev.effect]) return false
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
