import assert from 'node:assert/strict'

const baseUrl = process.env.VULNLAB_BASE_URL ?? 'http://127.0.0.1:6710'
let cookie = ''
let csrfToken = ''

async function request(path, options = {}) {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers ?? {}) }
  if (cookie) headers.cookie = cookie
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken && !path.endsWith('/auth/login')) headers['x-csrf-token'] = csrfToken
  const response = await fetch(`${baseUrl}${path}`, { ...options, method, headers })
  const setCookies = response.headers.getSetCookie?.() ?? []
  if (setCookies.length) cookie = setCookies.map(value => value.split(';', 1)[0]).join('; ')
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) assert.fail(`${method} ${path} failed: ${response.status} ${payload?.message ?? ''}`)
  return payload
}

const health = await request('/healthz')
assert.equal(health.product, 'VulnLab')
assert.equal(health.runtime, 'node-fastify')
assert.equal(await request('/api/auth/session'), null)

const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab-admin', password: 'VulnLabAdmin123!' }) })
csrfToken = session.csrfToken
assert.equal(session.role, 'admin')
assert.match(cookie, /^vulnlab_session=[^;]+\.[^;]+$/, 'session cookie should be signed')
const tamperedCookie = `${cookie.slice(0, -1)}${cookie.endsWith('0') ? '1' : '0'}`
const tamperedSession = await fetch(`${baseUrl}/api/auth/session`, { headers: { cookie: tamperedCookie } })
assert.equal(tamperedSession.status, 200)
assert.equal(await tamperedSession.json(), null)
const labs = await request('/api/labs')
assert.equal(labs.length, 9, 'built-in lab catalog must contain exactly nine entries')
assert.deepEqual(labs.map(lab => lab.slug), ['dvwa', 'pikachu', 'sqli-labs', 'upload-labs', 'vulnhub', 'juice-shop', 'webgoat', 'mutillidae', 'pygoat'])
const dvwa = labs.find(lab => lab.slug === 'dvwa')
assert.ok(dvwa, 'DVWA seed is missing')
const malformedRuntime = await fetch(`${baseUrl}/lab-runtime/%E0%A4%A`)
assert.equal(malformedRuntime.status, 400)

const settings = await request('/api/settings')
assert.equal(Object.hasOwn(settings, 'provider'), false)
const temporaryMaxInstances = settings.maxInstances === '9' ? '8' : '9'
const updatedSettings = await request('/api/settings', { method: 'PUT', body: JSON.stringify({ maxInstances: temporaryMaxInstances }) })
assert.equal(updatedSettings.maxInstances, temporaryMaxInstances)
const restoredSettings = await request('/api/settings', { method: 'PUT', body: JSON.stringify({ maxInstances: settings.maxInstances }) })
assert.equal(restoredSettings.maxInstances, settings.maxInstances)

const audit = await request('/api/audit')
assert.ok(audit.length >= 3, 'audit trail is incomplete')
const learnerLogin = await fetch(`${baseUrl}/api/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ userName: 'vulnlab-learner', password: 'VulnLabLearner123!' }) })
assert.equal(learnerLogin.status, 200)
const learnerCookie = learnerLogin.headers.getSetCookie()[0].split(';', 1)[0]
const learnerSession = await learnerLogin.json()
const learnerLabs = await (await fetch(`${baseUrl}/api/labs`, { headers: { cookie: learnerCookie } })).json()
assert.ok(learnerLabs.every(lab => lab.localPath === null))
const learnerJobs = await (await fetch(`${baseUrl}/api/import-jobs`, { headers: { cookie: learnerCookie } })).json()
assert.ok(learnerJobs.every(job => !job.manifest || job.manifest.localPath === ''))
const learnerSettingsRead = await fetch(`${baseUrl}/api/settings`, { headers: { cookie: learnerCookie } })
assert.equal(learnerSettingsRead.status, 200)
assert.equal((await learnerSettingsRead.json()).dataDir, '—')
const learnerSettingsWrite = await fetch(`${baseUrl}/api/settings`, { method: 'PUT', headers: { cookie: learnerCookie, 'x-csrf-token': learnerSession.csrfToken, 'Content-Type': 'application/json' }, body: JSON.stringify({ maxInstances: '2' }) })
assert.equal(learnerSettingsWrite.status, 403)
const learnerAuditRead = await fetch(`${baseUrl}/api/audit`, { headers: { cookie: learnerCookie } })
assert.equal(learnerAuditRead.status, 403)
assert.deepEqual(await request('/api/auth/logout', { method: 'POST' }), { ok: true })
assert.equal(await request('/api/auth/session'), null)

console.log(`VulnLab Node smoke passed: ${labs.length} built-in labs, settings, access control and audit.`)
