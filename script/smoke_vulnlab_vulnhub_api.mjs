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
const vulnhub = labs.find(lab => lab.slug === 'vulnhub')
assert.ok(vulnhub, 'VulnHub seed is missing')
const installation = vulnhub.status === 'ready' ? null : await request(`/api/labs/${vulnhub.id}/install`, { method: 'POST' })
const matchingCompletedJob = jobs => jobs.find(job => job.labId === vulnhub.id
  && job.status === 'completed'
  && (!vulnhub.localPath || job.manifest?.localPath === vulnhub.localPath)) ?? null
let completed = installation ? null : matchingCompletedJob(await request('/api/import-jobs'))
for (let attempt = 0; !completed && attempt < 60; attempt += 1) {
  const jobs = await request('/api/import-jobs')
  const current = installation ? jobs.find(job => job.id === installation.job.id) : matchingCompletedJob(jobs)
  if (current?.status === 'completed' || current?.status === 'error') { completed = current; break }
  await pause(1000)
}

assert.ok(completed, 'VulnHub import job did not finish within 60 seconds')
assert.equal(completed.status, 'completed', completed.error ?? completed.message)
assert.equal(completed.manifest?.adapterId, 'vulnhub-catalog')
assert.ok(completed.manifest?.fileCount > 0)
assert.ok(completed.manifest?.localPath.endsWith('catalog.json'))
assert.match(completed.manifest.localPath.replaceAll('\\', '/'), /\/labs\/vulnhub\/catalog-v1\/catalog\.json$/)
const importedLab = (await request('/api/labs')).find(lab => lab.id === vulnhub.id)
assert.equal(importedLab.status, 'ready')
const catalog = await request(`/api/labs/${vulnhub.id}/catalog`)
assert.equal(catalog.labId, vulnhub.id)
assert.equal(catalog.entries.length, completed.manifest.fileCount)
assert.ok(catalog.entries[0]?.url.startsWith('https://www.vulnhub.com/entry/'))
assert.ok(catalog.entries.every(entry => entry.title !== 'Details'))
assert.ok(catalog.entries[0]?.downloadUrls.every(url => url.startsWith('https://download.vulnhub.com/')))
assert.ok(catalog.entries.every(entry => entry.downloadUrls.every(url => !url.endsWith('/checksum.txt'))))
const vmDownloads = await request('/api/vm-downloads')
assert.ok(Array.isArray(vmDownloads))

const blockedVmStart = await fetch(`${baseUrl}/api/labs/${vulnhub.id}/instances`, { method: 'POST', headers: { cookie, 'x-csrf-token': csrfToken } })
assert.equal(blockedVmStart.status, 409)
const blockedVmPayload = await blockedVmStart.json()
assert.equal(blockedVmPayload.code, vmDownloads.some(download => download.labId === vulnhub.id && download.status === 'completed') ? 'RUNTIME_DEPENDENCY_MISSING' : 'VM_IMAGE_NOT_READY')

console.log(`VulnLab VulnHub API smoke passed: ${catalog.entries.length} machines readable, ${completed.manifest.archiveSha256}.`)
