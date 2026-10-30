import { test } from "node:test"
import assert from "node:assert/strict"
import { encodeMessage, FrameError, FrameParser, IdPool } from "../src/protocol.ts"

test("encode/parse roundtrip across split chunks", () => {
  const a = encodeMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: 1 } }, 65536)
  const b = encodeMessage({ jsonrpc: "2.0", id: 2, result: { protocolVersion: 1 } }, 65536)
  const parser = new FrameParser(65536)
  const stream = a + b
  for (let i = 0; i < stream.length; i += 3) parser.push(stream.slice(i, i + 3))
  const msgs = parser.drain()
  assert.equal(msgs.length, 2)
  assert.deepEqual((msgs[0] as { id: number }).id, 1)
  assert.deepEqual((msgs[1] as { id: number }).id, 2)
  assert.equal(parser.fatal, null)
})

test("frame over byte cap is a violation", () => {
  assert.throws(() => encodeMessage({ jsonrpc: "2.0", method: "x", params: { pad: "y".repeat(200) } }, 64), FrameError)
  const parser = new FrameParser(16)
  parser.push("very long line without newline")
  assert.equal(parser.fatal, "frame-limit")
})

test("oversize complete line is a violation", () => {
  const parser = new FrameParser(16)
  parser.push('{"a":1}\n' + "x".repeat(64) + "\n")
  assert.equal(parser.fatal, "frame-limit")
  // the valid first frame was already parsed before the violation
  assert.equal(parser.drain().length, 1)
})

test("unparseable line is a violation", () => {
  const parser = new FrameParser(65536)
  parser.push("not json\n")
  assert.equal(parser.fatal, "parse")
})

test("blank line is a violation", () => {
  const parser = new FrameParser(65536)
  parser.push("\n")
  assert.equal(parser.fatal, "parse")
})

test("parser stops consuming after fatal", () => {
  const parser = new FrameParser(65536)
  parser.push("bad\n")
  parser.push('{"jsonrpc":"2.0"}\n')
  assert.equal(parser.fatal, "parse")
  assert.equal(parser.drain().length, 0)
})

test("id pool is monotonic and resettable", () => {
  const pool = new IdPool()
  assert.deepEqual([pool.take(), pool.take(), pool.take()], [1, 2, 3])
  pool.reset()
  assert.deepEqual(pool.take(), 1)
})
