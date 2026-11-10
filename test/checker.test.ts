import { test } from "node:test"
import assert from "node:assert/strict"
import { CheckerInvoker, RejectBudgets, verifyPin, type CheckerOptions } from "../src/checker.ts"
import type { Letter } from "../src/types.ts"
import { writeFileSync } from "node:fs"

const NODE = process.execPath
const MOCK = new URL("./helpers/mock-checker.mjs", import.meta.url).pathname

const letter: Letter = {
  version: 1,
  invocation: { id: "msg:call", sessionID: "ses_1" },
  action: "shell",
  commands: [{ index: 0, raw: "git status", cwd: "/work/repo" }],
}

const verdictBody = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({ invocationId: "msg:call", verdict: "allow", commands: [{ index: 0, verdict: "allow", classification: "static", match: "argv" }], ...over })

const makeOpts = (over: Partial<CheckerOptions> = {}): CheckerOptions => ({
  command: [NODE, MOCK, "--behavior", JSON.stringify({})],
  sha256: null,
  checkTimeoutMs: 2_000,
  killGraceMs: 100,
  maxConcurrentSpawns: 8,
  log: () => {},
  ...over,
})

test("valid verdict passes through", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody() })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.verdict.verdict, "allow")
})

test("complete opaque ask verdict with raw match passes through", async () => {
  const body = verdictBody({ verdict: "ask", commands: [{ index: 0, verdict: "ask", ruleId: "r/opaque", classification: "opaque", match: "raw" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.verdict.verdict, "ask")
})

test("verdict missing command classification degrades", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow", match: "argv" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "commands[0].classification invalid" })
})

test("verdict missing command match degrades", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow", classification: "static" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "commands[0].match invalid" })
})

test("unknown command classification degrades", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow", classification: "invalid", match: "argv" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "commands[0].classification invalid" })
})

test("unknown command match degrades", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow", classification: "static", match: "unknown" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "commands[0].match invalid" })
})

test("raw command match cannot allow", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow", classification: "opaque", match: "raw" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "commands[0].raw match cannot allow" })
})

test("deny with prescriptive message passes", async () => {
  const body = verdictBody({ verdict: "deny", message: "history rewrite", commands: [{ index: 0, verdict: "deny", ruleId: "r/1", classification: "static", match: "argv" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, true)
  if (out.ok) assert.equal(out.verdict.message, "history rewrite")
})

test("ask verdict passes (hook escalates by silence)", async () => {
  const body = verdictBody({ verdict: "ask", commands: [{ index: 0, verdict: "ask", ruleId: "r/2", classification: "static", match: "argv" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  assert.equal((await invoker.check(letter)).ok, true)
})

test("non-zero exit degrades; stdout ignored", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), exit: 3 })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "checker exit 3" })
})

test("non-json output degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: "banana" })] }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
})

test("trailing bytes after the one verdict degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody() + "…" })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("invocationId mismatch degrades (fail-closed, I10)", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody({ invocationId: "other:1" }) })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("deny without message degrades", async () => {
  const body = verdictBody({ verdict: "deny", commands: [{ index: 0, verdict: "deny" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("commands count mismatch degrades", async () => {
  const body = verdictBody({ commands: [{ index: 0, verdict: "allow" }, { index: 5, verdict: "allow" }] })
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: body })] }))
  assert.equal((await invoker.check(letter)).ok, false)
})

test("timeout degrades (SIGTERM densify is the checker's problem)", async () => {
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), sleepMs: 1_000 })],
    checkTimeoutMs: 150, killGraceMs: 50,
  }))
  const out = await invoker.check(letter)
  assert.equal(out.ok, false)
  assert.match(out.ok === false ? out.reason : "", /exit/)
})

test("empty stdout degrades", async () => {
  const invoker = new CheckerInvoker(makeOpts({ command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: "" })] }))
  const out = await invoker.check(letter)
  assert.deepEqual(out, { ok: false, reason: "checker produced no verdict" })
})

test("spawn budget exhausted degrades locally", async () => {
  const opts = makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdout: verdictBody(), sleepMs: 700 })],
    maxConcurrentSpawns: 1,
  })
  const invoker = new CheckerInvoker(opts)
  const [a, b] = await Promise.all([invoker.check(letter), invoker.check(letter)])
  const reasons = [a, b].map((x) => (x.ok ? "ok" : x.reason))
  assert.equal(reasons.filter((r) => r.includes("spawn budget")).length, 1)
})

test("sha256 pin mismatch refuses every spawn", async () => {
  writeFileSync("/tmp/sw-pin-probe", "x")
  const opts = makeOpts({ command: ["/tmp/sw-pin-probe"], sha256: "a".repeat(64) })
  verifyPin(opts)
  const invoker = new CheckerInvoker(opts)
  const out = await invoker.check(letter)
  assert.match(out.ok === false ? out.reason : "", /pin/)
})

test("reject budget spends then exhausts per rule+session", () => {
  const rb = new RejectBudgets(2, 60_000)
  assert.equal(rb.trySpend("s1", "r1"), true)
  assert.equal(rb.trySpend("s1", "r1"), true)
  assert.equal(rb.trySpend("s1", "r1"), false)
  assert.equal(rb.trySpend("s2", "r1"), true) // another session independent
  assert.equal(rb.trySpend("s1", "r9"), true)
})
