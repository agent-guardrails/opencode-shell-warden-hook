import { test } from "node:test"
import assert from "node:assert/strict"
import { buildCheckRequest, cacheKey, InvocationRegistry, invocationIdOf, tighten } from "../src/apply.ts"
import type { PermissionEvaluation } from "../src/types.ts"

const ev = (over: Partial<PermissionEvaluation> = {}): PermissionEvaluation => ({
  sessionID: "ses_1",
  action: "shell",
  resources: ["git status", "npm test"],
  effect: "ask",
  source: { type: "tool", messageID: "msg_1", id: "call_1" },
  ...over,
})

test("invocationIdOf uses source ids when present", () => {
  assert.equal(invocationIdOf(ev()), "msg_1:call_1")
  assert.match(invocationIdOf(ev({ source: undefined })), /^anon:/)
})

test("cacheKey is stable and sensitive to inputs", () => {
  const k1 = cacheKey("shell", ["git status"], "/repo", "build")
  const k2 = cacheKey("shell", ["git status"], "/repo", "build")
  assert.equal(k1, k2)
  assert.notEqual(k1, cacheKey("shell", ["git status"], "/repo", "plan"))
  assert.notEqual(k1, cacheKey("shell", ["git push"], "/repo", "build"))
})

test("buildCheckRequest maps the evaluate event", () => {
  const req = buildCheckRequest({ ev: ev(), invocationId: "msg_1:call_1", cwd: "/repo" })
  assert.equal(req.invocation.id, "msg_1:call_1")
  assert.equal(req.invocation.sessionID, "ses_1")
  assert.equal(req.invocation.hook, "permission.evaluate")
  assert.equal(req.action, "shell")
  assert.deepEqual(req.commands, [
    { index: 0, raw: "git status", cwd: "/repo" },
    { index: 1, raw: "npm test", cwd: "/repo" },
  ])
})

test("tighten never loosens (invariant I5)", () => {
  const e = ev({ effect: "deny" })
  assert.equal(tighten(e, "allow", "nope"), false)
  assert.equal(e.effect, "deny")
  assert.equal(e.message, undefined)
})

test("tighten escalates and attaches message only on tighten", () => {
  const e = ev({ effect: "allow" })
  assert.equal(tighten(e, "allow", "same rank"), false)
  assert.equal(tighten(e, "ask", "engine says ask"), true)
  assert.equal(e.effect, "ask")
  assert.equal(e.message, "engine says ask")
  assert.equal(tighten(e, "deny"), true)
  assert.equal(e.effect, "deny")
})

test("InvocationRegistry remembers and evicts oldest", () => {
  const r = new InvocationRegistry(2)
  r.remember("i1", "k1")
  r.remember("i2", "k2")
  r.remember("i3", "k3")
  assert.equal(r.keyFor("i1"), undefined)
  assert.equal(r.keyFor("i2"), "k2")
  assert.equal(r.keyFor("i3"), "k3")
})
