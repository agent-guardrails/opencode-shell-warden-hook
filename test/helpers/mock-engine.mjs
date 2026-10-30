// Scripted engine used by supervisor contract tests.
// Usage: node mock-engine.mjs <scenario>
// Scenarios: ok | bad-version | slow-handshake | slow-check | garbage |
//            crash-after-init | crash-on-check | fatal | exit-immediately

import { createInterface } from "node:readline"

const scenario = process.argv[2] ?? "ok"
const send = (obj) => process.stdout.write(JSON.stringify(obj) + "\n")

if (scenario === "exit-immediately") process.exit(1)

const rl = createInterface({ input: process.stdin })
rl.on("line", (line) => {
  if (scenario === "garbage") {
    process.stdout.write("not json at all\n")
    return
  }
  let msg
  try {
    msg = JSON.parse(line)
  } catch {
    return
  }
  if (msg.method === "initialize") {
    if (scenario === "slow-handshake") return // never answers
    const pv = scenario === "bad-version" ? 99 : 1
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: { protocolVersion: pv, engine: { name: "mock", version: "0.0.0" }, capabilities: {} },
    })
    if (scenario === "crash-after-init") process.exit(1)
    return
  }
  if (msg.method === "policy/check") {
    if (scenario === "slow-check") return // never answers
    if (scenario === "crash-on-check") process.exit(1)
    if (scenario === "fatal") {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "config invalid", data: { fatal: true } } })
      return
    }
    const deny = msg.params.commands.some((c) => /rm\s+-rf/.test(c.raw))
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        invocationId: msg.params.invocation.id,
        verdict: deny ? "deny" : "allow",
        message: deny ? "denied by mock" : undefined,
        commands: msg.params.commands.map((c) => ({
          index: c.index,
          verdict: deny ? "deny" : "allow",
          cacheTtlMs: deny ? 0 : 60000,
        })),
      },
    })
  }
})
