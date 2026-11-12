import type { CheckerOptions } from "../../src/checker.ts"
import type { Letter } from "../../src/types.ts"

export const NODE = process.execPath
export const MOCK = new URL("./mock-checker.mjs", import.meta.url).pathname

export const letter: Letter = {
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: [{ index: 0, raw: "git status", cwd: "" }],
}

export const V2_PROTOCOL = "shell-warden.verdict.v2"

export const command = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  index: 0,
  verdict: "allow",
  ruleId: "git/allow-status",
  classification: "static",
  match: "argv",
  facts: {
    evidence: "complete",
    reasons: ["complete"],
    selectedProfiles: ["git"],
    matched: ["git/allow-status"],
    qualified: ["git/allow-status"],
    rejected: [],
    votes: ["allow:git/allow-status"],
  },
  ...over,
})

export const verdictBody = (over: Record<string, unknown> = {}, commandOver: Record<string, unknown> = {}): string =>
  JSON.stringify({
    protocol: V2_PROTOCOL,
    result: { invocationId: "msg:call", verdict: "allow", commands: [command(commandOver)], ...over },
  })

export const makeOpts = (over: Partial<CheckerOptions> = {}): CheckerOptions => ({
  command: [NODE, MOCK, "--behavior", JSON.stringify({})],
  sha256: null,
  checkTimeoutMs: 2_000,
  killGraceMs: 100,
  maxConcurrentSpawns: 8,
  log: () => {},
  ...over,
})
