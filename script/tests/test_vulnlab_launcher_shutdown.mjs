import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', '..', 'src')
const serverPath = join(appDir, 'dist', 'server.js')
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-launcher-shutdown-'))
const port = await new Promise((resolvePort, rejectPort) => {
  const server = createServer()
  server.once('error', rejectPort)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? rejectPort(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
  })
})
const baseUrl = `http://127.0.0.1:${port}`
let output = ''
const child = spawn(process.execPath, [serverPath], {
  cwd: appDir,
  env: {
    ...process.env,
    NODE_ENV: 'test',
    VULNLAB_HOST: '127.0.0.1',
    VULNLAB_PORT: String(port),
    VULNLAB_DATA_DIR: dataDir,
    VULNLAB_AUTO_INSTALL_BUILTINS: '0',
    VULNLAB_MYSQLD_BIN: 'vulnlab-test-missing-mysqld',
    VULNLAB_LAUNCHER_CONTROL: '1',
  },
  stdio: ['pipe', 'pipe', 'pipe'],
})
child.stdout.setEncoding('utf8').on('data', chunk => { output += chunk })
child.stderr.setEncoding('utf8').on('data', chunk => { output += chunk })
const exited = new Promise(resolveExit => child.once('exit', (code, signal) => resolveExit({ code, signal })))
const wait = milliseconds => new Promise(resolveWait => {
  const timer = setTimeout(resolveWait, milliseconds)
  timer.unref()
})

try {
  let ready = false
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`VulnLab exited before readiness (${child.exitCode}).`)
    if (await fetch(`${baseUrl}/healthz`).then(response => response.ok, () => false)) { ready = true; break }
    await wait(100)
  }
  assert.equal(ready, true, 'VulnLab did not become ready')

  child.stdin.write('stop\n')
  const exit = await Promise.race([exited, wait(30_000).then(() => null)])
  assert.ok(exit, `launcher control did not stop VulnLab\n${output}`)
  assert.equal(exit.code, 0, JSON.stringify(exit))
  assert.equal(await fetch(`${baseUrl}/healthz`).then(response => response.ok, () => false), false)
  console.log('VulnLab launcher shutdown test passed: stdin stop closes the server and releases its listener.')
} finally {
  if (child.exitCode === null) {
    child.stdin.write('stop\n')
    await Promise.race([exited, wait(5_000).then(() => { child.kill(); return undefined })])
  }
  await rm(dataDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 })
}
