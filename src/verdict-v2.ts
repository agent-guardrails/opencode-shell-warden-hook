// Verdict v2 consumer — the closed response parser (02-letter-verdict.md
// §2.7/§2.8, ADR-0023: verdict v2 only).
//
// One parser, one response version: the hook accepts ONLY the exact
// `shell-warden.verdict.v2` envelope. A flat v1 response, an absent, unknown,
// non-string, or malformed `protocol`, a schema-violating or semantically
// invalid v2 result, and oversize output are checker anomalies (§2.8): the
// caller degrades through `onCheckerError`. There is no v1 parser, no
// fallback, no translation, and allow is never synthesized.
//
// Validation order: 64 KiB cap → one JSON value → closed schema shape (the
// schema-equivalent checks below) → semantic invariants against the expected
// letter context (invocation echo, positional contiguous indexes, aggregate
// reduction `deny > ask > allow`, diagnostics coherence, canonical ordering,
// vote/ruleId selection, and the 16 KiB / depth-8 facts bounds).

import {
  MAX_FACTS_BYTES,
  MAX_FACTS_DEPTH,
  MAX_MESSAGE_CHARS,
  MAX_VERDICT_BYTES,
  type Letter,
  type V2CommandVerdict,
  type V2Diagnostics,
  type V2Evidence,
  type V2FullDiagnostics,
  type V2RejectedAllow,
  type V2Result,
  type V2TruncatedDiagnostics,
  type Verdict,
} from "./types.ts"

export const V2_PROTOCOL = "shell-warden.verdict.v2"

// Closed vocabularies (07 §7.3; mirror of the v2 schema enums).
const STABLE_REASONS: ReadonlySet<string> = new Set([
  "complete",
  "opaque-expansion",
  "unknown-option",
  "option-value-missing",
  "invalid-inline-option",
  "unsupported-syntax",
  "empty-command",
  "evidence-limit",
  "allow-evidence-not-complete",
  "allow-coverage-missing",
  "required-option-missing",
  "option-not-repeatable",
  "option-not-allowed",
  "option-value-uncovered",
  "option-value-position-uncovered",
  "remainder-uncovered",
  "redirect-policy-uncovered",
])
const INVALID_REASONS: ReadonlySet<string> = new Set([
  "unknown-option",
  "option-value-missing",
  "invalid-inline-option",
  "unsupported-syntax",
  "empty-command",
  "evidence-limit",
])
const COVERAGE_REASONS: ReadonlySet<string> = new Set([
  "allow-evidence-not-complete",
  "allow-coverage-missing",
  "required-option-missing",
  "option-not-repeatable",
  "option-not-allowed",
  "option-value-uncovered",
  "option-value-position-uncovered",
  "remainder-uncovered",
  "redirect-policy-uncovered",
])
const FULL_FACT_FIELDS = ["evidence", "reasons", "selectedProfiles", "matched", "qualified", "rejected", "votes"]
const TRUNCATED_FACT_FIELDS = ["evidence", "reasons", "diagnostics"]
const RESERVED_DIAGNOSTIC_KEYS = [...FULL_FACT_FIELDS, "diagnostics"]

type ParseOutcome = { ok: true; value: V2Result } | { ok: false; reason: string }

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v)

const isIdentifier = (v: unknown): v is string =>
  typeof v === "string" && v.length >= 1 && v.length <= 128 && !/\s/u.test(v)

const isVerdict = (v: unknown): v is Verdict => v === "allow" || v === "ask" || v === "deny"

const rank = (v: Verdict): number => (v === "deny" ? 2 : v === "ask" ? 1 : 0)

const isInvalidCause = (r: string): boolean => INVALID_REASONS.has(r)

function utf8Less(a: string, b: string): boolean {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")) < 0
}

function isSortedUnique(values: readonly string[]): boolean {
  return values.every((v, i) => i === 0 || utf8Less(values[i - 1] ?? "", v))
}

function exactKeys(v: Record<string, unknown>, fields: readonly string[]): boolean {
  return Object.keys(v).sort().join("\0") === [...fields].sort().join("\0")
}

function jsonDepth(value: unknown, stop = Number.POSITIVE_INFINITY): number {
  if (!isObject(value) && !Array.isArray(value)) return 0
  let max = 0
  const stack: Array<{ v: unknown; d: number }> = [{ v: value, d: 1 }]
  const seen = new Set<object>()
  while (stack.length > 0) {
    const { v, d } = stack.pop() ?? { v: null, d: 0 }
    if (!isObject(v) && !Array.isArray(v)) continue
    if (seen.has(v)) continue
    seen.add(v)
    max = Math.max(max, d)
    if (max > stop) return max
    for (const child of Array.isArray(v) ? v : Object.values(v)) {
      if (isObject(child) || Array.isArray(child)) stack.push({ v: child, d: d + 1 })
    }
  }
  return max
}

// ── Closed schema-equivalent validation ─────────────────────────────────────

function parseDiagnostics(facts: unknown, where_: string): V2Diagnostics | string {
  if (!isObject(facts)) return `${where_}.facts must be an object`
  // recognized full or truncated shape — v2 has no legacy-opaque pass-through
  if (exactKeys(facts, FULL_FACT_FIELDS)) return parseFullDiagnostics(facts, where_)
  if (exactKeys(facts, TRUNCATED_FACT_FIELDS)) return parseTruncatedDiagnostics(facts, where_)
  const reserved = Object.keys(facts).some((k) => RESERVED_DIAGNOSTIC_KEYS.includes(k))
  return reserved
    ? `${where_}.facts must use exactly the full or truncated diagnostic key set`
    : `${where_}.facts is not a recognized diagnostics shape`
}

function parseFullDiagnostics(facts: Record<string, unknown>, where_: string): V2FullDiagnostics | string {
  const evidence = facts.evidence
  if (evidence !== "complete" && evidence !== "opaque" && evidence !== "invalid") {
    return `${where_}.facts.evidence invalid`
  }
  const reasons = facts.reasons
  if (
    !Array.isArray(reasons) ||
    reasons.length > 17 ||
    !reasons.every((r) => typeof r === "string" && STABLE_REASONS.has(r))
  ) {
    return `${where_}.facts.reasons invalid`
  }
  const identifierArray = (v: unknown, max: number, unique: boolean): boolean =>
    Array.isArray(v) && v.length <= max && v.every(isIdentifier) && (!unique || new Set(v).size === v.length)
  if (!identifierArray(facts.selectedProfiles, 1024, false)) return `${where_}.facts.selectedProfiles invalid`
  if (!identifierArray(facts.matched, 4096, false)) return `${where_}.facts.matched invalid`
  if (!identifierArray(facts.qualified, 4096, true)) return `${where_}.facts.qualified invalid`
  const rejected: V2RejectedAllow[] = []
  const rawRejected = facts.rejected
  if (!Array.isArray(rawRejected) || rawRejected.length > 4096) return `${where_}.facts.rejected invalid`
  for (const entry of rawRejected) {
    if (!isObject(entry) || !exactKeys(entry, ["ruleId", "reasons"])) {
      return `${where_}.facts.rejected entry must carry exactly ruleId and reasons`
    }
    if (!isIdentifier(entry.ruleId)) return `${where_}.facts.rejected.ruleId invalid`
    if (
      !Array.isArray(entry.reasons) ||
      entry.reasons.length < 1 ||
      entry.reasons.length > 9 ||
      !entry.reasons.every((r) => typeof r === "string" && COVERAGE_REASONS.has(r))
    ) {
      return `${where_}.facts.rejected.reasons invalid`
    }
    rejected.push({ ruleId: entry.ruleId, reasons: entry.reasons })
  }
  const votes = facts.votes
  if (!Array.isArray(votes) || votes.length > 4096) return `${where_}.facts.votes invalid`
  for (const vote of votes) {
    if (typeof vote !== "string" || !/^(allow|ask|deny):\S{1,128}$/u.test(vote)) {
      return `${where_}.facts.votes entry invalid`
    }
  }
  return {
    evidence,
    reasons: reasons as string[],
    selectedProfiles: facts.selectedProfiles as string[],
    matched: facts.matched as string[],
    qualified: facts.qualified as string[],
    rejected,
    votes: votes as string[],
  }
}

function parseTruncatedDiagnostics(
  facts: Record<string, unknown>,
  where_: string,
): V2TruncatedDiagnostics | string {
  const evidence = facts.evidence
  if (evidence !== "complete" && evidence !== "opaque" && evidence !== "invalid") {
    return `${where_}.facts.evidence invalid`
  }
  const reasons = facts.reasons
  if (
    !Array.isArray(reasons) ||
    reasons.length > 8 ||
    !reasons.every((r) => typeof r === "string" && STABLE_REASONS.has(r))
  ) {
    return `${where_}.facts.reasons invalid`
  }
  if (facts.diagnostics !== "truncated-after-decision") {
    return `${where_}.facts.diagnostics must be "truncated-after-decision"`
  }
  return { evidence, reasons, diagnostics: "truncated-after-decision" }
}

function parseCommand(raw: unknown, position: number): V2CommandVerdict | string {
  const where_ = `commands[${position}]`
  if (!isObject(raw)) return `${where_} is not an object`
  const allowedCommandKeys = new Set(["index", "verdict", "classification", "match", "ruleId", "facts"])
  if (!Object.keys(raw).every((k) => allowedCommandKeys.has(k))) {
    return `${where_} carries unknown fields`
  }
  const index = raw.index
  if (typeof index !== "number" || !Number.isInteger(index) || index < 0) return `${where_}.index invalid`
  if (!isVerdict(raw.verdict)) return `${where_}.verdict invalid`
  const classification = raw.classification
  if (classification !== "static" && classification !== "opaque" && classification !== "invalid") {
    return `${where_}.classification invalid`
  }
  const match = raw.match
  if (match !== "argv" && match !== "raw") return `${where_}.match invalid`
  // legal tuple combinations (02 §2.7): exactly one classification arm
  const tupleOk =
    (classification === "static" && match === "argv") ||
    ((classification === "opaque" || classification === "invalid") && match === "raw" && raw.verdict !== "allow")
  if (!tupleOk) return `${where_} has an impossible classification/match/verdict combination`
  let ruleId: string | undefined
  if (raw.ruleId !== undefined) {
    if (!isIdentifier(raw.ruleId)) return `${where_}.ruleId invalid`
    ruleId = raw.ruleId
  }
  if (raw.verdict === "deny" && ruleId === undefined) return `${where_} deny without ruleId`
  let facts: V2Diagnostics | undefined
  if (raw.facts !== undefined) {
    const parsed = parseDiagnostics(raw.facts, where_)
    if (typeof parsed === "string") return parsed
    facts = parsed
  }
  return { index, verdict: raw.verdict, ruleId, classification, match, facts }
}

// ── Semantic invariants against the expected letter (02 §2.8) ───────────────

function semanticErrors(result: V2Result, letter: Letter): string[] {
  const errors: string[] = []
  if (result.invocationId !== letter.invocation.id) {
    errors.push("result.invocationId does not echo the letter invocation id")
  }
  if (result.commands.length !== letter.commands.length) {
    errors.push("result.commands must cover every letter command")
  }
  let strongest: Verdict = "allow"
  result.commands.forEach((command, position) => {
    if (command.index !== position) {
      errors.push(`commands[${position}].index must equal its array position`)
    }
    const facts = command.facts
    if (facts !== undefined) {
      const depth = jsonDepth(facts, MAX_FACTS_DEPTH)
      if (depth > MAX_FACTS_DEPTH) {
        errors.push(`commands[${position}].facts exceed depth ${MAX_FACTS_DEPTH}`)
      } else {
        const bytes = Buffer.byteLength(JSON.stringify(facts), "utf8")
        if (bytes > MAX_FACTS_BYTES) {
          errors.push(`commands[${position}].facts exceed ${MAX_FACTS_BYTES} bytes`)
        }
      }
      const classErrors = coherenceErrors(command, facts, position)
      errors.push(...classErrors)
      if ("diagnostics" in facts) {
        // truncated: reasons already member-checked; anchor/coherence above
      } else {
        errors.push(...fullDiagnosticsErrors(command, facts, position))
      }
    }
    if (rank(command.verdict) > rank(strongest)) strongest = command.verdict
  })
  if (result.verdict !== strongest) {
    errors.push("result.verdict must be the most restrictive command verdict (deny > ask > allow)")
  }
  return errors
}

function coherenceErrors(command: V2CommandVerdict, facts: V2Diagnostics, position: number): string[] {
  const errors: string[] = []
  if (!isSortedUnique(facts.reasons)) {
    errors.push(`commands[${position}].facts.reasons must be sorted and unique`)
  }
  const reasons = facts.reasons
  if (facts.evidence === "complete") {
    if (!reasons.includes("complete")) errors.push(`commands[${position}].facts complete evidence requires the complete anchor`)
    if (reasons.some((r) => r === "opaque-expansion" || r === "allow-evidence-not-complete" || isInvalidCause(r))) {
      errors.push(`commands[${position}].facts complete evidence carries incompatible reasons`)
    }
  } else if (facts.evidence === "opaque") {
    if (!reasons.includes("opaque-expansion")) errors.push(`commands[${position}].facts opaque evidence requires the opaque-expansion anchor`)
    if (reasons.some(isInvalidCause)) errors.push(`commands[${position}].facts opaque evidence carries an invalid-cause reason`)
  } else if (!reasons.some(isInvalidCause)) {
    errors.push(`commands[${position}].facts invalid evidence requires an invalid-cause reason`)
  }
  const expectedEvidence: V2Evidence =
    command.classification === "static" ? "complete" : (command.classification as V2Evidence)
  if (facts.evidence !== expectedEvidence) {
    errors.push(`commands[${position}].facts.evidence does not match the classification`)
  }
  return errors
}

function fullDiagnosticsErrors(
  command: V2CommandVerdict,
  facts: V2FullDiagnostics,
  position: number,
): string[] {
  const errors: string[] = []
  const matched = new Set(facts.matched)
  const qualified = new Set(facts.qualified)
  const votes = facts.votes.map((v) => {
    const [action, ruleId] = [v.slice(0, v.indexOf(":")), v.slice(v.indexOf(":") + 1)]
    return { action: action as Verdict, ruleId }
  })
  if (!isSortedUnique(facts.matched)) errors.push(`commands[${position}].facts.matched must be sorted and unique`)
  if (!isSortedUnique(facts.qualified)) errors.push(`commands[${position}].facts.qualified must be sorted and unique`)
  facts.rejected.forEach((entry, entryPosition) => {
    if (!isSortedUnique(entry.reasons)) {
      errors.push(`commands[${position}].facts.rejected[${entryPosition}].reasons must be sorted and unique`)
    }
    if (!matched.has(entry.ruleId)) {
      errors.push(`commands[${position}].facts.rejected[${entryPosition}] rule is not matched`)
    }
  })
  const rejectedIds = facts.rejected.map((r) => r.ruleId)
  if (new Set(rejectedIds).size !== rejectedIds.length) {
    errors.push(`commands[${position}].facts.rejected carries duplicate ruleId entries`)
  }
  for (const rule of qualified) {
    if (!matched.has(rule)) errors.push(`commands[${position}].facts.qualified rule is not matched`)
    if (!votes.some((v) => v.action === "allow" && v.ruleId === rule)) {
      errors.push(`commands[${position}].facts.qualified rule has no allow vote`)
    }
  }
  for (const vote of votes) {
    if (!matched.has(vote.ruleId)) errors.push(`commands[${position}].facts vote is not matched`)
    if (vote.action === "allow" && !qualified.has(vote.ruleId)) {
      errors.push(`commands[${position}].facts allow vote is not qualified`)
    }
  }
  const strongestVote = votes.reduce<Verdict | undefined>(
    (acc, v) => (acc === undefined || rank(v.action) > rank(acc) ? v.action : acc),
    undefined,
  )
  if (strongestVote !== undefined && rank(command.verdict) < rank(strongestVote)) {
    errors.push(`commands[${position}] verdict is less restrictive than an emitted vote`)
  }
  if (
    command.classification === "static" &&
    command.match === "argv" &&
    command.verdict === "allow" &&
    !votes.some((v) => v.action === "allow")
  ) {
    errors.push(`commands[${position}] full static/argv/allow diagnostics require an emitted allow vote`)
  }
  const winning = votes
    .filter((v) => v.action === command.verdict)
    .map((v) => v.ruleId)
    .sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")))
    .slice(0, 1)
  const winner = winning[0]
  if (winner !== undefined) {
    if (command.ruleId !== winner) {
      errors.push(`commands[${position}].ruleId must be the UTF-8 byte-order smallest winning vote (${winner})`)
    }
  } else if (command.ruleId !== undefined) {
    errors.push(`commands[${position}].ruleId must be absent when no emitted vote wins`)
  }
  return errors
}

// ── Entry point ─────────────────────────────────────────────────────────────

/**
 * Parse and validate one checker stdout payload against the expected letter.
 * Accepts only the exact v2 envelope; every deviation is a checker anomaly.
 */
export function parseV2Envelope(letter: Letter, raw: string): ParseOutcome {
  // 64 KiB pre-parse cap (02 §2.7): oversize output never reaches JSON.parse
  if (Buffer.byteLength(raw, "utf8") > MAX_VERDICT_BYTES) {
    return { ok: false, reason: "verdict exceeds the 64 KiB output bound" }
  }
  let value: unknown
  try {
    value = JSON.parse(raw)
  } catch (e) {
    return {
      ok: false,
      reason: `unparseable verdict: ${e instanceof Error ? e.message.slice(0, 120) : "not json"}`,
    }
  }
  if (!isObject(value)) return { ok: false, reason: "verdict is not an object" }
  if (!exactKeys(value, ["protocol", "result"])) {
    return { ok: false, reason: "verdict root must carry exactly protocol and result" }
  }
  if (value.protocol !== V2_PROTOCOL) {
    return { ok: false, reason: `verdict protocol must be exactly ${V2_PROTOCOL}` }
  }
  const result = value.result
  if (!isObject(result)) return { ok: false, reason: "verdict.result is not an object" }
  const allowedResultKeys = new Set(["invocationId", "verdict", "message", "commands"])
  if (!Object.keys(result).every((k) => allowedResultKeys.has(k))) {
    return { ok: false, reason: "verdict.result carries unknown fields" }
  }
  if (typeof result.invocationId !== "string" || result.invocationId.length < 1 || result.invocationId.length > 256) {
    return { ok: false, reason: "verdict.result.invocationId invalid" }
  }
  if (!isVerdict(result.verdict)) return { ok: false, reason: "verdict.result.verdict invalid" }
  let message: string | undefined
  if (result.message !== undefined) {
    if (
      typeof result.message !== "string" ||
      result.message.length < 1 ||
      result.message.length > MAX_MESSAGE_CHARS
    ) {
      return { ok: false, reason: "verdict.result.message invalid" }
    }
    message = result.message
  }
  if (result.verdict === "deny" && message === undefined) {
    return { ok: false, reason: "aggregate deny without message" }
  }
  if (!Array.isArray(result.commands) || result.commands.length < 1 || result.commands.length > 128) {
    return { ok: false, reason: "verdict.result.commands invalid" }
  }
  const commands: V2CommandVerdict[] = []
  for (const [position, rawCommand] of result.commands.entries()) {
    const command = parseCommand(rawCommand, position)
    if (typeof command === "string") return { ok: false, reason: command }
    commands.push(command)
  }
  const v2Result: V2Result = {
    invocationId: result.invocationId,
    verdict: result.verdict,
    ...(message !== undefined ? { message } : {}),
    commands,
  }
  const semantic = semanticErrors(v2Result, letter)
  if (semantic.length > 0) return { ok: false, reason: `verdict failed semantic validation: ${semantic[0]}` }
  return { ok: true, value: v2Result }
}
