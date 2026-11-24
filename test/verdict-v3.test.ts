// Active v3 hook conformance: canonical shared vectors plus hook-boundary
// anomalies. Historical versions are rejected, never read as a fallback.

import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync, readdirSync } from "node:fs"
import { parseV3Envelope, V3_PROTOCOL } from "../src/verdict-v3.ts"
import type { Letter } from "../src/types.ts"
import { MAX_VERDICT_BYTES } from "../src/types.ts"

const FIXTURES = new URL("./verdict-v3/", import.meta.url)

interface Vector {
  path: string
  valid: boolean
  expectedInvocationId: string
  positionalIndexes: number[]
}

function manifest(): Vector[] {
  const raw = JSON.parse(readFileSync(new URL("manifest.json", FIXTURES), "utf8"))
  assert.ok(Array.isArray(raw.fixtures), "fixture manifest must contain a fixtures array")
  return raw.fixtures
}

function letterFor(vector: Vector): Letter {
  return {
    version: 1,
    invocation: { id: vector.expectedInvocationId, sessionID: "ses_conformance" },
    action: "shell",
    commands: vector.positionalIndexes.map((index) => ({ index, raw: "git status", cwd: "/repo" })),
  }
}

test("the v3 mirror contains exactly the manifest's vectors", () => {
  const paths = manifest().map((vector) => vector.path)
  assert.equal(new Set(paths).size, paths.length, "manifest paths must be unique")
  assert.deepEqual(readdirSync(FIXTURES).sort(), ["invalid", "manifest.json", "valid"])
  const files = ["invalid", "valid"].flatMap((kind) =>
    readdirSync(new URL(`${kind}/`, FIXTURES)).map((name) => `${kind}/${name}`))
  assert.deepEqual(files.sort(), paths.sort(), "no missing or unlisted vectors")
})

test("every shared v3 vector is consumed without a version fallback", async (t) => {
  const vectors = manifest()
  assert.equal(vectors.length, 62)
  for (const vector of vectors) {
    await t.test(vector.path, () => {
      const text = readFileSync(new URL(vector.path, FIXTURES), "utf8")
      const outcome = parseV3Envelope(letterFor(vector), text)
      if (vector.valid) {
        assert.equal(outcome.ok, true, `${vector.path} must validate: ${JSON.stringify(outcome)}`)
        if (outcome.ok) assert.equal(outcome.value.invocationId, vector.expectedInvocationId)
      } else {
        assert.equal(outcome.ok, false, `${vector.path} must fail closed`)
      }
    })
  }
})

// ── Hook-specific anomaly requirements ──────────────────────────────────────

const baseLetter: Letter = {
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: [{ index: 0, raw: "git status", cwd: "/repo" }],
}

const v3Command = {
  index: 0,
  verdict: "allow",
  ruleId: "hook/allow",
  classification: "static",
  match: "argv",
  facts: {
    uncertain: [],
    evidence: "complete",
    reasons: ["complete"],
    selectedProfiles: ["base"],
    matched: ["hook/allow"],
    qualified: ["hook/allow"],
    rejected: [],
    votes: ["allow:hook/allow"],
  },
}

const v3Body = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    protocol: V3_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [v3Command],
      ...over,
    },
  })

// A supported evidence state cannot carry this cause at either diagnostic level,
// even for ask/deny. Other coverage failures do not veto a qualified allow.
test("supported evidence excludes allow-evidence-not-complete in full and truncated facts", () => {
  for (const classification of ["static", "parameter"] as const) {
    for (const verdict of ["allow", "ask", "deny"] as const) {
      for (const truncated of [false, true]) {
        const evidence = classification === "static" ? "complete" : "parameter"
        const anchor = classification === "static" ? "complete" : "parameter-expansion"
        const facts = {
          ...v3Command.facts, evidence, reasons: [anchor],
          qualified: verdict === "allow" ? ["hook/allow"] : [],
          votes: [`${verdict}:hook/allow`],
        }
        const envelope = (reasons: string[]) => v3Body({
          verdict, ...(verdict === "deny" ? { message: "Denied." } : {}),
          commands: [{
            ...v3Command, classification, verdict,
            match: classification === "static" ? "argv" : "expression",
            facts: truncated
              ? { evidence, reasons, diagnostics: "truncated-after-decision" }
              : { ...facts, reasons },
          }],
        })
        const label = `${classification}/${verdict}/${truncated ? "truncated" : "full"}`
        assert.equal(parseV3Envelope(baseLetter, envelope([anchor])).ok, true, label)
        assert.equal(parseV3Envelope(baseLetter,
          envelope(["allow-evidence-not-complete", anchor])).ok, false, label)
      }
    }
  }
})

test("every rejected coverage reason must be aggregated for every evidence state", () => {
  const coverageReasons = [
    "allow-coverage-missing", "required-option-missing", "option-not-repeatable",
    "option-not-allowed", "option-value-uncovered", "option-value-position-uncovered",
    "remainder-uncovered", "redirect-policy-uncovered", "allow-evidence-not-complete",
  ]
  for (const evidence of ["complete", "parameter", "opaque", "invalid"] as const) {
    const anchor = {
      complete: "complete", parameter: "parameter-expansion",
      opaque: "opaque-expansion", invalid: "unsupported-syntax",
    }[evidence]
    for (const reason of coverageReasons) {
      const envelope = (aggregate: boolean) => v3Body({
        verdict: "ask",
        commands: [{
          index: 0, verdict: "ask",
          classification: evidence === "complete" ? "static" : evidence,
          match: evidence === "complete" ? "argv" : evidence === "parameter" ? "expression" : "raw",
          facts: {
            ...v3Command.facts, evidence,
            reasons: aggregate ? [anchor, reason].sort() : [anchor],
            qualified: [], votes: [],
            rejected: [{ ruleId: "hook/allow", reasons: [reason] }],
          },
        }],
      })
      const label = `${evidence}/${reason}`
      assert.equal(parseV3Envelope(baseLetter, envelope(false)).ok, false, label)
      const compatible = reason !== "allow-evidence-not-complete" ||
        evidence === "opaque" || evidence === "invalid"
      assert.equal(parseV3Envelope(baseLetter, envelope(true)).ok, compatible, label)
    }
  }
})

test("flat v1 response (even exact-valid) is rejected without fallback", () => {
  const flatV1 = JSON.stringify({
    invocationId: "msg:call",
    verdict: "allow",
    commands: [{ index: 0, verdict: "allow", ruleId: "hook/allow", classification: "static", match: "argv" }],
  })
  const outcome = parseV3Envelope(baseLetter, flatV1)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /protocol/)
})

test("absent protocol is an anomaly", () => {
  const body = JSON.stringify({ result: JSON.parse(v3Body()).result })
  assert.equal(parseV3Envelope(baseLetter, body).ok, false)
})

test("unknown protocol is an anomaly", () => {
  const body = v3Body().replace(V3_PROTOCOL, "shell-warden.verdict.v4")
  assert.equal(parseV3Envelope(baseLetter, body).ok, false)
})

test("non-string protocol is an anomaly", () => {
  const body = v3Body().replace(`"protocol":"${V3_PROTOCOL}"`, '"protocol":42')
  assert.equal(parseV3Envelope(baseLetter, body).ok, false)
})

test("malformed v3 never falls back to a retired read", () => {
  // An envelope with a missing result cannot be re-read as a retired format.
  const body = JSON.stringify({ protocol: V3_PROTOCOL })
  const outcome = parseV3Envelope(baseLetter, body)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /result/)
})

test("oversize output fails the 64 KiB cap before JSON parsing", () => {
  const filler = "x".repeat(MAX_VERDICT_BYTES)
  const oversize = JSON.stringify({
    protocol: V3_PROTOCOL,
    result: { invocationId: "msg:call", verdict: "ask", commands: [{ index: 0, verdict: "ask", classification: "invalid", match: "raw" }], message: filler },
  })
  assert.ok(Buffer.byteLength(oversize, "utf8") > MAX_VERDICT_BYTES)
  const outcome = parseV3Envelope(baseLetter, oversize)
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /64 KiB/)
})

test("valid v3 envelope returns the nested result to the application path", () => {
  const outcome = parseV3Envelope(baseLetter, v3Body())
  assert.equal(outcome.ok, true)
  if (outcome.ok) {
    assert.equal(outcome.value.verdict, "allow")
    assert.equal(outcome.value.commands[0]?.ruleId, "hook/allow")
  }
})

// ── Letter positional index validation (02 §2.8) ────────────────────────────
// The expected letter context carries contiguous positional indexes 0..N-1
// equal to their array positions; a malformed letter must fail closed before
// any result-command comparison (no checker output may rescue it).

const letterWithIndexes = (...indexes: number[]): Letter => ({
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: indexes.map((index) => ({ index, raw: "git status", cwd: "/repo" })),
})

const twoCommandBody = (): string =>
  JSON.stringify({
    protocol: V3_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [
        { index: 0, verdict: "allow", classification: "static", match: "argv" },
        { index: 1, verdict: "allow", classification: "static", match: "argv" },
      ],
    },
  })

test("contiguous letter indexes validate against the matching result", () => {
  assert.equal(parseV3Envelope(letterWithIndexes(0, 1), twoCommandBody()).ok, true)
})

test("duplicate letter command index fails closed", () => {
  const outcome = parseV3Envelope(letterWithIndexes(0, 0), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[1\]\.index/)
})

test("skipped letter command index fails closed", () => {
  const outcome = parseV3Envelope(letterWithIndexes(0, 2), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[1\]\.index/)
})

test("negative letter command index fails closed", () => {
  const outcome = parseV3Envelope(letterWithIndexes(-1), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[0\]\.index/)
})

test("out-of-position letter command index fails closed", () => {
  const outcome = parseV3Envelope(letterWithIndexes(1, 0), twoCommandBody())
  assert.equal(outcome.ok, false)
  assert.match(outcome.ok ? "" : outcome.reason, /letter\.commands\[0\]\.index/)
})

// ── String bounds count Unicode code points, not UTF-16 units ───────────────
// The v2 schema measures maxLength/minLength in code points; String.length and
// regex quantifiers count UTF-16 code units, so supplementary characters (one
// emoji = 2 units) would push schema-valid verdicts into onCheckerError.

const EMOJI = "\u{1F600}"

const ruleEnvelope = (ruleId: string): string =>
  JSON.stringify({
    protocol: V3_PROTOCOL,
    result: {
      invocationId: "msg:call",
      verdict: "allow",
      commands: [{
        index: 0,
        verdict: "allow",
        ruleId,
        classification: "static",
        match: "argv",
        facts: {
          uncertain: [],
          evidence: "complete",
          reasons: ["complete"],
          selectedProfiles: ["base"],
          matched: [ruleId],
          qualified: [ruleId],
          rejected: [],
          votes: [`allow:${ruleId}`],
        },
      }],
    },
  })

test("message bounds count code points — 300 emoji (600 UTF-16 units) is valid", () => {
  // the reported false-negative: under UTF-16 counting 300 emoji read as 600
  // chars and a schema-valid verdict degraded through onCheckerError
  const outcome = parseV3Envelope(baseLetter, v3Body({ message: EMOJI.repeat(300) }))
  assert.equal(outcome.ok, true)
  if (outcome.ok) assert.equal(outcome.value.message, EMOJI.repeat(300))
})

test("message at the 512 code-point boundary — 512 emoji valid, 513 invalid", () => {
  assert.equal(parseV3Envelope(baseLetter, v3Body({ message: EMOJI.repeat(512) })).ok, true)
  const over = parseV3Envelope(baseLetter, v3Body({ message: EMOJI.repeat(513) }))
  assert.equal(over.ok, false)
  assert.match(over.ok ? "" : over.reason, /message/)
})

test("ruleId and its vote entry count code points — 128 emoji valid, 129 invalid", () => {
  // `allow:` + 128 emoji is 129 UTF-16 units: the old {1,128} quantifier and
  // the identifier length check both rejected it although the schema allows it
  assert.equal(parseV3Envelope(baseLetter, ruleEnvelope(EMOJI.repeat(128))).ok, true)
  const over = parseV3Envelope(baseLetter, ruleEnvelope(EMOJI.repeat(129)))
  assert.equal(over.ok, false)
})

test("invocationId counts code points — 256 emoji valid, 257 invalid", () => {
  const id256 = EMOJI.repeat(256)
  const letter: Letter = { ...baseLetter, invocation: { id: id256, sessionID: "ses_1" } }
  const atBound = JSON.stringify({
    protocol: V3_PROTOCOL,
    result: { invocationId: id256, verdict: "allow", commands: [v3Command] },
  })
  assert.equal(parseV3Envelope(letter, atBound).ok, true)
  const letterOver: Letter = { ...baseLetter, invocation: { id: EMOJI.repeat(257), sessionID: "ses_1" } }
  const over = parseV3Envelope(letterOver, JSON.stringify({
    protocol: V3_PROTOCOL,
    result: { invocationId: EMOJI.repeat(257), verdict: "allow", commands: [v3Command] },
  }))
  assert.equal(over.ok, false)
  // the schema bound fires before the echo check — overlong ids fail closed
  assert.match(over.ok ? "" : over.reason, /^verdict\.result\.invocationId invalid$/)
})
