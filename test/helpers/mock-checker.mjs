// Test-only checker stub — behaves per docs/spec/shell-warden/10-testing.md.
// Usage: node mock-checker.mjs --behavior '<json>'
//   { stdout?: string, stdoutBase64?: string, stdoutBytes?: number,
//     stdoutOnSigterm?: string, ignoreSigterm?: boolean, hold?: boolean,
//     exit?: number, sleepMs?: number }
// Reads one letter line from stdin (ignores its content), emits stdout, exits.

const argIndex = process.argv.indexOf("--behavior")
const def = argIndex === -1 ? {} : JSON.parse(process.argv[argIndex + 1] ?? "{}")
if (def.stdoutOnSigterm !== undefined) {
  process.on("SIGTERM", () => {
    process.stdout.write(def.stdoutOnSigterm)
    process.exit(0)
  })
} else if (def.ignoreSigterm) {
  process.on("SIGTERM", () => {})
}
let buf = ""
process.stdin.setEncoding("utf8")
process.stdin.on("data", (c) => { buf += c })
process.stdin.on("end", () => {
  const run = () => {
    const stdout = def.stdoutBase64 !== undefined
      ? Buffer.from(def.stdoutBase64, "base64")
      : def.stdoutBytes !== undefined
        ? Buffer.alloc(def.stdoutBytes, 0x78)
        : def.stdout ?? buf
    process.stdout.write(stdout)
    if (def.hold) setInterval(() => {}, 60_000)
    else process.exit(def.exit ?? 0)
  }
  if (def.sleepMs) setTimeout(run, def.sleepMs)
  else run()
})
