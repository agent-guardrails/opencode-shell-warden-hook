// Letter & verdict types — mirror of docs/spec/shell-warden/02-letter-verdict.md (v2.0)
// and schemas/shell-warden.letter.v1.schema.json / shell-warden.verdict.v1.schema.json.
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

export interface LetterCommandVerdict {
  index: number
  verdict: Verdict
  ruleId?: string
  classification?: "static" | "opaque"
  match?: "argv" | "raw"
  facts?: Record<string, unknown>
}

export interface LetterVerdict {
  invocationId: string             // echo of letter.invocation.id
  verdict: Verdict                 // aggregate — authoritative, hook applies tighten-only
  message?: string                 // required on deny; ≤ 512 chars
  commands?: LetterCommandVerdict[]
}

// Bounds from 02-letter-verdict.md §2.2/§2.3 (hook enforces before spawning)
export const MAX_LETTER_BYTES = 64 * 1024
export const MAX_COMMAND_BYTES = 8 * 1024
export const MAX_VERDICT_BYTES = 64 * 1024
export const MAX_FACTS_BYTES = 16 * 1024
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
