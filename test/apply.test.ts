import { test } from "node:test"
import assert from "node:assert/strict"
import { buildCheckRequest, cacheKey, invocationIdOf, replyDecision, type AskData, InvocationRegistry } from "../src/apply.ts"

const data = (over: Partial<AskData> = {}): AskData => ({
  id: "per_1",
  sessionID: "ses_1",
  action: "shell",
  resources: ["git status", "npm test"],
  source: { type: "tool", messageID: "msg_1", id: "call_1" },
  ...over,
})

test("invocationIdOf uses the request source ids", () => {
  assert.equal(invocationIdOf(data().source, "ses_1", "shell"), "msg_1:call_1")
  assert.match(invocationIdOf(undefined, "ses_1", "shell"), /^anon:/)
})

test("cacheKey is stable and sensitive to inputs", () => {
  const k1 = cacheKey("shell", ["git status"], "/repo", "build")
  const k2 = cacheKey("shell", ["git status"], "/repo", "build")
  assert.equal(k1, k2)
  assert.notEqual(k1, cacheKey("shell", ["git status"], "/repo", "plan"))
  assert.notEqual(k1, cacheKey("shell", ["git push"], "/repo", "build"))
})

test("buildCheckRequest maps the published ask", () => {
  const req = buildCheckRequest({ data: data(), invocationId: "msg_1:call_1", cwd: "/repo" })
  assert.equal(req.invocation.id, "msg_1:call_1")
  assert.equal(req.invocation.sessionID, "ses_1")
  assert.equal(req.invocation.hook, "permission.asked")
  assert.equal(req.action, "shell")
  assert.deepEqual(req.commands, [
    { index: 0, raw: "git status", cwd: "/repo" },
    { index: 1, raw: "npm test", cwd: "/repo" },
  ])
  assert.equal(req.context?.source?.messageID, "msg_1")
})

test("replyDecision maps verdicts to published-request actions", () => {
  assert.equal(replyDecision("allow"), "once")
  assert.equal(replyDecision("deny"), "reject")
  assert.equal(replyDecision("ask"), null) // escalation by silence → the human decides
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
