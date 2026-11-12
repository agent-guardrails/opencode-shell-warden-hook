import { test } from "node:test"
import assert from "node:assert/strict"
import { CheckerInvoker } from "../src/checker.ts"
import { MAX_VERDICT_BYTES } from "../src/types.ts"
import { MOCK, NODE, letter, makeOpts, verdictBody } from "./helpers/checker-fixture.ts"

test("malformed UTF-8 inside an otherwise valid allow verdict degrades", async () => {
  // Given
  const marker = "malformed-byte-marker"
  const valid = Buffer.from(verdictBody({ message: marker }), "utf8")
  const markerOffset = valid.indexOf(marker)
  assert.notEqual(markerOffset, -1)
  valid[markerOffset] = 0xff
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdoutBase64: valid.toString("base64") })],
  }))

  // When
  const out = await invoker.check(letter)

  // Then
  assert.deepEqual(out, { ok: false, reason: "checker produced invalid UTF-8" })
})

test("a UTF-8 BOM before an otherwise valid allow verdict degrades", async () => {
  // Given
  const output = Buffer.concat([
    Buffer.from([0xef, 0xbb, 0xbf]),
    Buffer.from(verdictBody(), "utf8"),
  ])
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({ stdoutBase64: output.toString("base64") })],
  }))

  // When
  const out = await invoker.check(letter)

  // Then
  assert.equal(out.ok, false)
})

test("valid allow emitted after the deadline degrades despite a zero exit", async () => {
  // Given
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({
      hold: true,
      stdout: "",
      stdoutOnSigterm: verdictBody(),
    })],
    checkTimeoutMs: 750,
    killGraceMs: 50,
  }))

  // When
  const out = await invoker.check(letter)

  // Then
  assert.deepEqual(out, { ok: false, reason: "checker timed out" })
})

test("oversize output bounds retention and starts kill grace immediately", { timeout: 2_000 }, async () => {
  // Given
  const invoker = new CheckerInvoker(makeOpts({
    command: [NODE, MOCK, "--behavior", JSON.stringify({
      hold: true,
      ignoreSigterm: true,
      stdoutBytes: MAX_VERDICT_BYTES * 128,
    })],
    checkTimeoutMs: 10_000,
    killGraceMs: 50,
  }))

  // When
  const out = await invoker.check(letter)

  // Then
  assert.deepEqual(out, { ok: false, reason: "verdict exceeds the 64 KiB output bound" })
})
