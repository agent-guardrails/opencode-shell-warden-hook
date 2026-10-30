import { test } from "node:test"
import assert from "node:assert/strict"
import { VerdictCache } from "../src/cache.ts"

test("put/get roundtrip with ttl", () => {
  let now = 1_000
  const c = new VerdictCache(16, () => now)
  c.put("k", 500, "why")
  assert.deepEqual(c.get("k"), { verdict: "allow", message: "why", expiresAt: 1_500 })
  now = 1_400
  assert.notEqual(c.get("k"), null)
  now = 1_501
  assert.equal(c.get("k"), null)
})

test("ttl 0 is never stored", () => {
  const c = new VerdictCache(16)
  c.put("k", 0)
  assert.equal(c.get("k"), null)
})

test("expired entries are dropped", () => {
  let now = 0
  const c = new VerdictCache(16, () => now)
  c.put("a", 10)
  now = 11
  c.put("b", 10)
  assert.equal(c.get("a"), null)
  assert.notEqual(c.get("b"), null)
})

test("LRU eviction respects maxEntries", () => {
  const c = new VerdictCache(2)
  c.put("a", 100)
  c.put("b", 100)
  c.get("a") // touch a → b becomes LRU
  c.put("c", 100)
  assert.notEqual(c.get("a"), null)
  assert.equal(c.get("b"), null)
  assert.notEqual(c.get("c"), null)
})

test("invalidate clears everything", () => {
  const c = new VerdictCache(16)
  c.put("a", 100)
  c.invalidate()
  assert.equal(c.get("a"), null)
})
