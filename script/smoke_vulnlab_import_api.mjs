import assert from 'node:assert/strict'

const baseUrl = process.env.VULNLAB_BASE_URL ?? 'http://127.0.0.1:6710'
let cookie = ''
let csrfToken = ''

const pause = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))

async function request(path, options = {}) {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers ?? {}) }
  if (cookie) headers.cookie = cookie
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken && !path.endsWith('/auth/login')) headers['x-csrf-token'] = csrfToken
  const response = await fetch(`${baseUrl}${path}`, { ...options, method, headers })
  const setCookies = response.headers.getSetCookie?.() ?? []
  if (setCookies.length) cookie = setCookies.map(value => value.split(';', 1)[0]).join('; ')
  const payload = await response.json().catch(() => ({}))
  assert.ok(response.ok, `${method} ${path} failed: ${response.status} ${payload?.message ?? ''}`)
  return payload
}

const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab-admin', password: 'VulnLabAdmin123!' }) })
csrfToken = session.csrfToken
const labs = await request('/api/labs')
const dvwa = labs.find(lab => lab.slug === 'dvwa')
assert.ok(dvwa, 'DVWA seed is missing')

const queued = await request(`/api/labs/${dvwa.id}/import`, { method: 'POST' })
const started = await request(`/api/import-jobs/${queued.job.id}/run`, { method: 'POST' })
assert.equal(started.job.status, 'importing')

let completed = null
for (let attempt = 0; attempt < 90; attempt += 1) {
  const jobs = await request('/api/import-jobs')
  const current = jobs.find(job => job.id === queued.job.id)
  if (current?.status === 'completed' || current?.status === 'error') { completed = current; break }
  await pause(1000)
}
assert.ok(completed, 'import job did not finish within 90 seconds')
assert.equal(completed.status, 'completed', completed.error ?? completed.message)
assert.ok(completed.manifest?.revision)
assert.match(completed.manifest.archiveSha256, /^[a-f0-9]{64}$/)
assert.ok(completed.manifest.fileCount > 0)

const importedLab = (await request('/api/labs')).find(lab => lab.id === dvwa.id)
assert.equal(importedLab.status, 'ready')
assert.equal(importedLab.localPath, completed.manifest.localPath)

console.log(`VulnLab GitHub import smoke passed: DVWA ${completed.manifest.resolvedRef}, ${completed.manifest.fileCount} files, sha256 ${completed.manifest.archiveSha256}.`)
