// Wire protocol types — mirror of docs/policyd-plugin-design/02-protocol.md (v1)
// and schemas/wire.v1.schema.json. Keep in sync with the schema.

export type Verdict = "allow" | "ask" | "deny"

export interface InitializeParams {
  protocolVersion: number
  client: { name: string; version: string; opencode?: string }
}

export interface InitializeResult {
  protocolVersion: number
  engine: { name: string; version: string }
  capabilities?: Record<string, unknown>
  config?: { source?: string; stages?: string[]; loadedAt?: string }
}

export interface CheckCommand {
  index: number
  raw: string
  cwd: string
}

export interface CheckParams {
  invocation: {
    id: string
    sessionID: string
    agent?: string
    hook: string
    projectDir?: string
    startedAt?: string
  }
  action: string
  commands: CheckCommand[]
  context?: {
    source?: { type: "tool"; messageID?: string; id?: string }
    metadata?: Record<string, unknown>
  }
}

export interface CheckCommandResult {
  index: number
  verdict: Verdict
  stage?: string | null
  ruleId?: string | null
  reason?: string
  classification?: "static" | "opaque"
  cacheTtlMs?: number
}

export interface CheckResult {
  invocationId: string
  verdict: Verdict
  message?: string
  commands?: CheckCommandResult[]
  engine?: { checkMs?: number }
}

export type WireMessage =
  | { jsonrpc: "2.0"; id: number; method: string; params: unknown }
  | { jsonrpc: "2.0"; id: number; result: unknown }
  | { jsonrpc: "2.0"; id: number | null; error: { code: number; message: string; data?: { fatal?: boolean } } }
  | { jsonrpc: "2.0"; method: string; params?: unknown }

// OpenCode V2 permission evaluate hook event (mutable: effect, message)
export interface PermissionEvaluation {
  readonly sessionID: string
  readonly agent?: string
  readonly action: string
  readonly resources: readonly string[]
  readonly metadata?: Record<string, unknown>
  readonly source?: { type: "tool"; messageID: string; id: string }
  effect: Verdict
  message?: string
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
