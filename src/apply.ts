// Reply automation per ADR-0013 — the shim resolves published permission
// requests programmatically (the same right the human exercises):
//   checker allow → reply "once" (command runs)
//   checker deny  → reply "reject" (with the prescriptive reason)
//   checker ask   → no reply (escalation by silence — the human decides)
// The shim never mutates permission events and never synthesizes allow.

import { createHash } from "node:crypto"
import type { Letter, V2Result } from "./types.ts"

export type { AskData, Verdict } from "./types.ts"
import type { AskData } from "./types.ts"

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

/** Letter per 02-letter-verdict.md §2.2 — exactly the schema fields, no extras.
 * `projectDir` is required and non-empty: the engine invalidates every letter whose
 * commands[].cwd is empty ("letter commands[0].cwd must be 1..4096 chars"), and the
 * ask payload carries no per-command cwd — the permission request's directory is the
 * only cwd the shim has. Callers without a directory must degrade before calling. */
export function buildLetter(args: {
  data: AskData
  invocationId: string
  projectDir: string
  agent?: string
}): Letter {
  const { data, invocationId, projectDir, agent } = args
  if (!projectDir) throw new Error("buildLetter: projectDir is required — the engine rejects letters with an empty commands[].cwd")
  return {
    version: 1,
    invocation: {
      id: invocationId,
      sessionID: data.sessionID ?? "",
      ...(agent !== undefined ? { agent } : {}),
      projectDir,
    },
    action: data.action ?? "",
    commands: (data.resources ?? []).map((raw, index) => ({ index, raw, cwd: projectDir })),
  }
}

/** Maps a verdict to the reply decision: `"once"` | `"reject"` | `null` (silence). */
export function replyDecision(v: V2Result["verdict"]): "once" | "reject" | null {
  if (v === "allow") return "once"
  if (v === "deny") return "reject"
  return null
}
