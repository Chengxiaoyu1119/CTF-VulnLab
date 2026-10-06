import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', 'src')
const serverPath = join(appDir, 'dist', 'server.js')
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-oa-startup-modes-'))
const port = await new Promise((resolvePort, rejectPort) => {
  const server = createServer()
  server.once('error', rejectPort)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? rejectPort(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
  })
})
const baseUrl = `http://127.0.0.1:${port}`
const child = spawn(process.execPath, [serverPath], {
  cwd: appDir,
  env: {
    ...process.env,
    PATH: '',
    NODE_ENV: 'test',
    VULNLAB_HOST: '127.0.0.1',
    VULNLAB_PORT: String(port),
    VULNLAB_DATA_DIR: dataDir,
    VULNLAB_AUTO_INSTALL_BUILTINS: '0',
    VULNLAB_MYSQLD_BIN: 'vulnlab-test-missing-mysqld',
  },
  stdio: 'ignore',
})
const wait = milliseconds => new Promise(resolveWait => setTimeout(resolveWait, milliseconds))
const request = async (path, options = {}) => {
  const response = await fetch(`${baseUrl}${path}`, options)
  return { response, body: await response.json().catch(() => ({})) }
}

try {
  let ready = false
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`VulnLab exited before readiness (${child.exitCode}).`)
    if (await fetch(`${baseUrl}/healthz`).then(response => response.ok, () => false)) { ready = true; break }
    await wait(100)
  }
  assert.equal(ready, true, 'VulnLab did not become ready')

  const login = await request('/api/auth/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userName: 'vulnlab', password: 'vulnlab' }),
  })
  assert.equal(login.response.status, 200)
  const cookie = login.response.headers.getSetCookie()[0]?.split(';', 1)[0]
  assert.ok(cookie)
  const headers = { cookie, 'x-csrf-token': login.body.csrfToken }
  const labsResponse = await request('/api/labs', { headers })
  const lab = labsResponse.body.find(item => item.slug === 'oa-vuln-labs')
  assert.ok(lab)

  const start = await request(`/api/labs/${lab.id}/instances`, {
    method: 'POST', headers: { ...headers, 'content-type': 'application/json' }, body: JSON.stringify({ mode: 'docker' }),
  })
  assert.equal(start.response.status, 202, JSON.stringify(start.body))

  let finishedJob
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const jobs = await request('/api/import-jobs', { headers })
    finishedJob = jobs.body.find(item => item.labId === lab.id)
    if (finishedJob?.stage === 'start-failed' || finishedJob?.status === 'error') break
    await wait(100)
  }
  assert.equal(finishedJob?.status, 'completed', JSON.stringify(finishedJob))
  assert.equal(finishedJob?.stage, 'start-failed')
  assert.match(finishedJob?.error ?? '', /Docker CLI|Docker 模式不可用/)

  const currentLabs = await request('/api/labs', { headers })
  const oa = currentLabs.body.find(item => item.id === lab.id)
  assert.equal(oa?.status, 'ready', 'missing Docker must not invalidate prepared OA resources')
  const instances = await request('/api/instances', { headers })
  assert.equal(instances.body.some(item => item.labId === lab.id && item.status === 'running'), false, 'missing Docker must not fall back to local mode')
  console.log('OA startup mode integration passed: missing Docker leaves OA resources ready, records a Docker-mode failure and never falls back to local mode.')
} finally {
  if (child.exitCode === null) {
    const exited = new Promise(resolveExit => child.once('exit', resolveExit))
    child.kill('SIGTERM')
    await Promise.race([exited, wait(5_000).then(() => { child.kill(); return undefined })])
  }
  await rm(dataDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 })
}
