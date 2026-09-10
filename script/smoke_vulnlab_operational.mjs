import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', 'src')
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
    VULNLAB_AUTO_INSTALL_BUILTINS: '0',
    // 该脚本验证服务生命周期；项目 PHP/MySQL 生命周期由独立测试覆盖。
    VULNLAB_MYSQLD_BIN: 'vulnlab-test-missing-mysqld',
  }
  if (production) {
    env.VULNLAB_COOKIE_SECRET = '0123456789abcdef0123456789abcdef'
    env.VULNLAB_ADMIN_PASSWORD = 'ProductionAdmin-2026!'
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

const seedRelocatedState = async dataDir => {
  const { VulnLabDatabase } = await import(new URL('../src/dist/db.js', import.meta.url))
  const database = new VulnLabDatabase(dataDir)
  const manifestFor = (lab, localPath) => ({
    adapterId: 'github-git',
    sourceUrl: lab.sourceUrl,
    sourceRef: lab.sourceRef,
    resolvedRef: lab.sourceRef,
    revision: lab.version,
    archiveSha256: 'b'.repeat(64),
    localPath,
    fileCount: 1,
    totalBytes: 1,
    licenseFiles: [],
    topLevelEntries: [],
    warnings: [],
    importedAt: new Date().toISOString(),
  })
  try {
    const uploadLabs = database.getLabBySlug('upload-labs')
    const dvwa = database.getLabBySlug('dvwa')
    const mutillidae = database.getLabBySlug('mutillidae')
    assert.ok(uploadLabs)
    assert.ok(dvwa)
    assert.ok(mutillidae)
    await mkdir(join(dataDir, 'labs', uploadLabs.slug, uploadLabs.version), { recursive: true })
    const uploadJob = database.claimJob(database.createJob(uploadLabs.id, uploadLabs.sourceUrl).id)
    assert.ok(uploadJob)
    database.completeJob(uploadJob.id, manifestFor(uploadLabs, join(dataDir, 'old-project', 'labs', uploadLabs.slug, uploadLabs.version)))
    const dvwaJob = database.claimJob(database.createJob(dvwa.id, dvwa.sourceUrl).id)
    assert.ok(dvwaJob)
    database.completeJob(dvwaJob.id, manifestFor(dvwa, join(dataDir, 'old-project', 'labs', dvwa.slug, dvwa.version)))
    const brokenSource = join(dataDir, 'old-project', 'labs', mutillidae.slug, 'broken-source')
    await mkdir(join(dataDir, 'old-project', 'labs', mutillidae.slug), { recursive: true })
    await writeFile(brokenSource, 'not a directory')
    const mutillidaeJob = database.claimJob(database.createJob(mutillidae.id, mutillidae.sourceUrl).id)
    assert.ok(mutillidaeJob)
    database.completeJob(mutillidaeJob.id, manifestFor(mutillidae, brokenSource))
  } finally {
    database.close()
  }
}

const request = async (baseUrl, path, options = {}) => {
  const response = await fetch(`${baseUrl}${path}`, options)
  const body = await response.json().catch(() => ({}))
  assert.ok(response.ok, `${path} failed: ${response.status} ${body.message ?? ''}`)
  return { response, body }
}

const getCookiePath = setCookieHeader => {
  const pathAttribute = setCookieHeader.split(';').map(attribute => attribute.trim()).find(attribute => attribute.toLowerCase().startsWith('path='))
  assert.ok(pathAttribute, `Set-Cookie is missing Path: ${setCookieHeader}`)
  return pathAttribute.slice('path='.length)
}

const cookiePathMatches = (cookiePath, requestPath) => requestPath === cookiePath || (
  requestPath.startsWith(cookiePath) && (cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/')
)

const login = async baseUrl => {
  const result = await request(baseUrl, '/api/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userName: 'vulnlab', password: 'vulnlab' }),
  })
  const setCookie = result.response.headers.getSetCookie()[0]
  assert.ok(setCookie, 'login did not set vulnlab_session')
  return { cookie: setCookie.split(';', 1)[0], csrfToken: result.body.csrfToken, setCookie }
}

const root = await mkdtemp(join(tmpdir(), 'vulnlab-operational-'))
let server = null
try {
  const sessionDir = join(root, 'session')
  server = await startServer({ port: 6741, dataDir: sessionDir })
  const session = await login(server.baseUrl)
  const invitation = await request(server.baseUrl, '/api/auth/invitations', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  assert.match(invitation.body.code, /^[A-Za-z0-9_-]{32}$/)
  const registeredUserName = 'student-' + Date.now()
  const registration = await fetch(server.baseUrl + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: registeredUserName, password: 'Student-2026!', passwordConfirm: 'Student-2026!', inviteCode: invitation.body.code }) })
  assert.equal(registration.status, 200)
  assert.deepEqual(await registration.json(), { ok: true, message: '注册成功' })
  const registeredLogin = await fetch(server.baseUrl + '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: registeredUserName, password: 'Student-2026!' }) })
  assert.equal(registeredLogin.status, 200)
  assert.equal((await registeredLogin.json()).userName, registeredUserName)
  const duplicateInvitation = await request(server.baseUrl, '/api/auth/invitations', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  const duplicateRegistration = await fetch(server.baseUrl + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: registeredUserName, password: 'Student-2026!', passwordConfirm: 'Student-2026!', inviteCode: duplicateInvitation.body.code }) })
  const reservedRegistration = await fetch(server.baseUrl + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab', password: 'Student-2026!', passwordConfirm: 'Student-2026!', inviteCode: duplicateInvitation.body.code }) })
  assert.equal(duplicateRegistration.status, 400)
  assert.equal(reservedRegistration.status, 400)
  const unavailableBody = { code: 'REGISTRATION_UNAVAILABLE', message: '注册失败，请检查注册信息后重试。' }
  assert.deepEqual(await duplicateRegistration.json(), unavailableBody)
  assert.deepEqual(await reservedRegistration.json(), unavailableBody)
  const reusedInvitation = await fetch(server.baseUrl + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'second-student', password: 'Student-2026!', passwordConfirm: 'Student-2026!', inviteCode: invitation.body.code }) })
  assert.equal(reusedInvitation.status, 400)
  const revocableInvitation = await request(server.baseUrl, '/api/auth/invitations', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  const revoke = await fetch(server.baseUrl + '/api/auth/invitations/' + revocableInvitation.body.id, { method: 'DELETE', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  assert.equal(revoke.status, 200)
  const revokedRegistration = await fetch(server.baseUrl + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'revoked-student', password: 'Student-2026!', passwordConfirm: 'Student-2026!', inviteCode: revocableInvitation.body.code }) })
  assert.equal(revokedRegistration.status, 400)
  const sessionCookiePath = getCookiePath(session.setCookie)
  assert.equal(sessionCookiePath, '/api')
  assert.equal(cookiePathMatches(sessionCookiePath, '/api/auth/session'), true)
  assert.equal(cookiePathMatches(sessionCookiePath, '/lab-runtime/fixture/'), false)
  const sessionAfterLogin = await fetch(`${server.baseUrl}/api/auth/session`, { headers: { cookie: session.cookie } })
  assert.equal((await sessionAfterLogin.json()).userName, 'vulnlab')
  const runtimeStatus = await request(server.baseUrl, '/api/runtime-status', { headers: { cookie: session.cookie } })
  assert.equal('runtimeDir' in runtimeStatus.body.project, false)
  assert.equal('php' in runtimeStatus.body.project && 'binary' in runtimeStatus.body.project.php, false)
  assert.equal('node' in runtimeStatus.body.project && 'binary' in runtimeStatus.body.project.node, false)
  for (const toolchain of runtimeStatus.body.project.toolchains) assert.equal('installedPath' in toolchain, false)
  assert.doesNotMatch(JSON.stringify(runtimeStatus.body.project), /[A-Za-z]:[\\/]\\S+/)
  await stopServer(server.child)
  server = await startServer({ port: 6741, dataDir: sessionDir })
  const runtimeSettings = await request(server.baseUrl, '/api/settings', { headers: { cookie: session.cookie } })
  const settingsUpdate = await request(server.baseUrl, '/api/settings', { method: 'PUT', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken, 'content-type': 'application/json' }, body: JSON.stringify({ bindHost: runtimeSettings.body.bindHost, port: '6744' }) })
  assert.equal(settingsUpdate.body.port, '6744')
  await stopServer(server.child)
  server = await startServer({ port: 6744, dataDir: sessionDir, usePersistedHostPort: true })
  const sessionAfterRestart = await fetch(`${server.baseUrl}/api/auth/session`, { headers: { cookie: session.cookie } })
  assert.equal((await sessionAfterRestart.json()).userName, 'vulnlab')
  const logout = await request(server.baseUrl, '/api/auth/logout', { method: 'POST', headers: { cookie: session.cookie, 'x-csrf-token': session.csrfToken } })
  assert.deepEqual(logout.body, { ok: true })
  const clearCookie = logout.response.headers.getSetCookie()[0]
  assert.ok(clearCookie, 'logout did not clear vulnlab_session')
  assert.equal(getCookiePath(clearCookie), sessionCookiePath)
  assert.equal(clearCookie.split(';', 1)[0], 'vulnlab_session=')
  assert.match(clearCookie, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/i)
  await stopServer(server.child)

  const endpointDir = join(root, 'endpoint')
  await seedRelocatedState(endpointDir)
  server = await startServer({ port: 6742, dataDir: endpointDir, host: '0.0.0.0', publicUrl: 'https://lab.example.com' })
  const endpointSession = await login(server.baseUrl)
  let labs = (await request(server.baseUrl, '/api/labs', { headers: { cookie: endpointSession.cookie } })).body
  const dvwa = labs.find(lab => lab.slug === 'dvwa')
  assert.ok(dvwa)
  const repairedUploadLabs = labs.find(lab => lab.slug === 'upload-labs')
  assert.equal(repairedUploadLabs?.status, 'ready')
  assert.equal(repairedUploadLabs?.localPath, join(endpointDir, 'labs', 'upload-labs', repairedUploadLabs.version))
  assert.equal(dvwa.status, 'cataloged')
  assert.equal(dvwa.localPath, null)
  for (let attempt = 0; attempt < 50 && labs.find(lab => lab.slug === 'mutillidae')?.status !== 'error'; attempt += 1) {
    await wait(100)
    labs = (await request(server.baseUrl, '/api/labs', { headers: { cookie: endpointSession.cookie } })).body
  }
  assert.equal(labs.find(lab => lab.slug === 'mutillidae')?.status, 'error')
  const preparingStart = await fetch(`${server.baseUrl}/api/labs/${dvwa.id}/instances`, { method: 'POST', headers: { cookie: endpointSession.cookie, 'x-csrf-token': endpointSession.csrfToken } })
  assert.equal(preparingStart.status, 202)
  assert.equal((await preparingStart.json()).status, 'preparing')
  await stopServer(server.child)
  server = await startServer({ port: 6742, dataDir: endpointDir, host: '0.0.0.0', publicUrl: 'https://lab.example.com' })
  let resumedJob = null
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const jobs = (await request(server.baseUrl, '/api/import-jobs', { headers: { cookie: endpointSession.cookie } })).body
    const current = jobs.find(job => job.labId === dvwa.id)
    if (current && current.status !== 'queued') { resumedJob = current; break }
    await wait(100)
  }
  assert.ok(resumedJob, 'queued import was not resumed after restart')
  await stopServer(server.child)

  const productionDir = join(root, 'production')
  server = await startServer({ port: 6743, dataDir: productionDir, nodeEnv: 'production', production: true })
  const productionLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab', password: 'ProductionAdmin-2026!' }) })
  assert.equal(productionLogin.status, 200)
  const cookieHeader = productionLogin.headers.getSetCookie()[0]
  assert.match(cookieHeader, /Secure/)
  assert.match(cookieHeader, /HttpOnly/)
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const failedLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab', password: 'wrong-password' }) })
    assert.equal(failedLogin.status, 401)
  }
  const limitedLogin = await fetch(`${server.baseUrl}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab', password: 'wrong-password' }) })
  assert.equal(limitedLogin.status, 429)
  await stopServer(server.child)
} finally {
  if (server?.child) await stopServer(server.child).catch(() => undefined)
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}

console.log('VulnLab operational smoke passed: SQLite sessions, runtime readiness guard, secure production cookie and persistent login limit.')
