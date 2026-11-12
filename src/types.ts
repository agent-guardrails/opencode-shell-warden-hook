// Letter & verdict types — mirror of docs/spec/shell-warden/02-letter-verdict.md
// (v2.2) and schemas/shell-warden.letter.v1.schema.json (letter only). The
// response contract is the closed verdict v2 envelope
// (schemas/shell-warden.verdict.v2.schema.json, ADR-0023): see verdict-v2.ts.
// Keep in sync with the schemas.

export type Verdict = "allow" | "ask" | "deny"

export interface LetterInvocation {
  id: string                       // `${messageID}:${callID}` — unique per tool call
  sessionID: string
  agent?: string
  projectDir?: string
}

export interface LetterCommand {
  index: number
  raw: string                      // command text exactly as OpenCode produced it, ≤ 8 KiB
  cwd: string
}

export interface Letter {
  version: 1
  invocation: LetterInvocation
  action: string
  commands: LetterCommand[]
}

// ── Verdict v2 response contract (02 §2.7/§2.8, ADR-0023) ───────────────────

export type V2Evidence = "complete" | "opaque" | "invalid"
export type V2Classification = "static" | "opaque" | "invalid"
export type V2Match = "argv" | "raw"

export interface V2RejectedAllow {
  ruleId: string
  reasons: string[]                // closed coverage vocabulary, sorted + unique
}

export interface V2FullDiagnostics {
  evidence: V2Evidence
  reasons: string[]                // closed reason vocabulary, sorted + unique
  selectedProfiles: string[]
  matched: string[]                // sorted + unique
  qualified: string[]              // sorted + unique, ⊆ matched, each with an allow vote
  rejected: V2RejectedAllow[]      // one canonical entry per ruleId
  votes: string[]                  // emitted votes "{action}:{ruleId}" in evaluation order
}

export interface V2TruncatedDiagnostics {
  evidence: V2Evidence
  reasons: string[]                // ≤ 8, sorted + unique, evidence anchor retained
  diagnostics: "truncated-after-decision"
}

export type V2Diagnostics = V2FullDiagnostics | V2TruncatedDiagnostics

export interface V2CommandVerdict {
  index: number                    // equal to its commands[] array position
  verdict: Verdict
  ruleId?: string                  // required on deny; UTF-8-smallest winning vote
  classification: V2Classification
  match: V2Match
  facts?: V2Diagnostics
}

export interface V2Result {
  invocationId: string             // echo of letter.invocation.id
  verdict: Verdict                 // most-restrictive command verdict (deny > ask > allow)
  message?: string                 // required on deny; ≤ 512 chars; ignored for allow/ask
  commands: V2CommandVerdict[]
}

export interface V2Envelope {
  protocol: "shell-warden.verdict.v2"
  result: V2Result
}

// Bounds from 02-letter-verdict.md §2.2/§2.7 (hook enforces before spawning)
export const MAX_LETTER_BYTES = 64 * 1024
export const MAX_COMMAND_BYTES = 8 * 1024
export const MAX_VERDICT_BYTES = 64 * 1024
export const MAX_FACTS_BYTES = 16 * 1024
export const MAX_FACTS_DEPTH = 8
export const MAX_MESSAGE_CHARS = 512

// OpenCode V2 permission.asked event payload (relevant subset)
export interface AskData {
  id: string                          // requestID, assigned at publication
  sessionID: string
  action: string
  resources: readonly string[]
  source?: { type: "tool"; messageID: string; id: string }
}

// shell.create.before hook event (audit-only usage)
export interface ShellCreateBefore {
  command: string
  cwd: string
  timeout: number
  shell: string
  env: Record<string, string | undefined>
}

export const VERDICT_RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 }
