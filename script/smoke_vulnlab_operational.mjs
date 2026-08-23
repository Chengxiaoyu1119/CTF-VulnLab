import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', 'src', 'VulnLab')
const serverPath = resolve(appDir, 'dist', 'server.js')
const wait = milliseconds => new Promise(resolvePromise => setTimeout(resolvePromise, milliseconds))

const startServer = async ({ port, dataDir, nodeEnv = 'test', host = '127.0.0.1', publicUrl = '', production = false, usePersistedHostPort = false }) => {
  const env = {
    ...process.env,
    NODE_ENV: nodeEnv,
    VULNLAB_HOST: host,
    VULNLAB_PORT: String(port),
    VULNLAB_DATA_DIR: dataDir,
    VULNLAB_PUBLIC_URL: publicUrl,
  }
  if (production) {
    env.VULNLAB_COOKIE_SECRET = '0123456789abcdef0123456789abcdef'
    env.VULNLAB_ADMIN_PASSWORD = 'ProductionAdmin-2026!'
    env.VULNLAB_LEARNER_PASSWORD = 'ProductionLearner-2026!'
  }
  if (usePersistedHostPort) {
    delete env.VULNLAB_HOST
    delete env.VULNLAB_PORT
    delete env.PORT
  }
  const child = spawn(process.execPath, [serverPath], { cwd: appDir, env, stdio: 'ignore' })
  const baseUrl = `http://127.0.0.1:${port}`
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      if ((await fetch(`${baseUrl}/healthz`)).ok) return { child, baseUrl }
    } catch {}
    await wait(100)
  }
  child.kill('SIGTERM')
  throw new Error(`VulnLab did not start on ${baseUrl}`)
}

const stopServer = async child => {
  if (child.exitCode !== null) return
  const exited = new Promise(resolvePromise => child.once('exit', resolvePromise))
  child.kill('SIGTERM')
  await Promise.race([exited, wait(5000).then(() => { child.kill(); return undefined })])
}

const request = async (baseUrl, path, options = {}) => {
  const response = await fetch(`${baseUrl}${path}`, options)
  const body = await response.json().catch(() => ({}))
  assert.ok(response.ok, `${path} failed: ${response.status} ${body.message ?? ''}`)
  return { response, body }
}

const login = async baseUrl => {
  const result = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userName: 'vulnlab-admin', password: 'VulnLabAdmin123!' }),
  })
  return { cookie: result.response.headers.getSetCookie()[0].split(';', 1)[0], csrfToken: result.body.csrfToken }
}

const root = await mkdtemp(join(tmpdir(), 'vulnlab-operational-'))
try {
  const sessionDir = join(root, 'session')
  let server = await startServer({ port: 6741, dataDir: sessionDir })
  const session = await login(server.baseUrl)
  const sessionAfterLogin = await fetch(`${server.baseUrl}/api/auth/session`, { headers: { cookie: session.cookie } })
  assert.equal((await sessionAfterLogin.json()).userName, 'vulnlab-admin')
  await stopServer(server.child)
  server = await startServer({ port: 6741, dataDir: sessionDir })
  const runtimeSettings = await request(server.baseUrl, '/api/settings', { headers: { cookie: session.cookie } })
  const settingsUpdate = await request(server.baseUrl, '/api/settings', { method: 'PUT', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken, 'content-type': 'application/json' }, body: JSON.stringify({ bindHost: runtimeSettings.body.bindHost, port: '6744' }) })
  assert.equal(settingsUpdate.body.port, '6744')
  await stopServer(server.child)
  server = await startServer({ port: 6744, dataDir: sessionDir, usePersistedHostPort: true })
  const sessionAfterRestart = await fetch(`${server.baseUrl}/api/auth/session`, { headers: { cookie: session.cookie } })
  assert.equal((await sessionAfterRestart.json()).userName, 'vulnlab-admin')
  const logout = await request(server.baseUrl, '/api/auth/logout', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  assert.deepEqual(logout.body, { ok: true })
  await stopServer(server.child)

  const endpointDir = join(root, 'endpoint')
  server = await startServer({ port: 6742, dataDir: endpointDir, host: '0.0.0.0', publicUrl: 'https://lab.example.com' })
  const endpointSession = await login(server.baseUrl)
  const labs = (await request(server.baseUrl, '/api/labs', { headers: { cookie: endpointSession.cookie } })).body
  const previewLab = labs.find(lab => lab.runtimeKind === 'container' && lab.status === 'cataloged')
  const blockedStart = await fetch(`${server.baseUrl}/api/labs/${previewLab.id}/instances`, { method: 'POST', headers: { cookie: endpointSession.cookie, 'x-csrf-token': endpointSession.csrfToken } })
  assert.equal(blockedStart.status, 409)
  assert.equal((await blockedStart.json()).code, 'LAB_NOT_READY')
  const preview = await fetch(`${server.baseUrl}/lab-preview/${previewLab.slug}`)
  assert.equal(preview.status, 200)
  assert.match(await preview.text(), new RegExp(previewLab.title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  await stopServer(server.child)

  const productionDir = join(root, 'production')
  server = await startServer({ port: 6743, dataDir: productionDir, nodeEnv: 'production', production: true })
  const productionLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab-admin', password: 'ProductionAdmin-2026!' }) })
  assert.equal(productionLogin.status, 200)
  const cookieHeader = productionLogin.headers.getSetCookie()[0]
  assert.match(cookieHeader, /Secure/)
  assert.match(cookieHeader, /HttpOnly/)
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const failedLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab-admin', password: 'wrong-password' }) })
    assert.equal(failedLogin.status, 401)
  }
  const limitedLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab-admin', password: 'wrong-password' }) })
  assert.equal(limitedLogin.status, 429)
  await stopServer(server.child)
} finally {
  await rm(root, { recursive: true, force: true })
}

console.log('VulnLab operational smoke passed: SQLite sessions, runtime readiness guard, secure production cookie and persistent login limit.')
