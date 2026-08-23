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
const queued = await request(`/api/labs/${vulnhub.id}/import`, { method: 'POST' })
await request(`/api/import-jobs/${queued.job.id}/run`, { method: 'POST' })

let completed = null
for (let attempt = 0; attempt < 60; attempt += 1) {
  const jobs = await request('/api/import-jobs')
  const current = jobs.find(job => job.id === queued.job.id)
  if (current?.status === 'completed' || current?.status === 'error') { completed = current; break }
  await pause(1000)
}

assert.ok(completed, 'VulnHub import job did not finish within 60 seconds')
assert.equal(completed.status, 'completed', completed.error ?? completed.message)
assert.equal(completed.manifest?.adapterId, 'vulnhub-catalog')
assert.ok(completed.manifest?.fileCount > 0)
assert.ok(completed.manifest?.localPath.endsWith('catalog.json'))
const importedLab = (await request('/api/labs')).find(lab => lab.id === vulnhub.id)
assert.equal(importedLab.status, 'ready')
const catalog = await request(`/api/labs/${vulnhub.id}/catalog`)
assert.equal(catalog.labId, vulnhub.id)
assert.equal(catalog.entries.length, completed.manifest.fileCount)
assert.ok(catalog.entries[0]?.url.startsWith('https://www.vulnhub.com/entry/'))
assert.ok(catalog.entries[0]?.downloadUrls.every(url => url.startsWith('https://download.vulnhub.com/')))
const vmDownloads = await request('/api/vm-downloads')
assert.ok(Array.isArray(vmDownloads))

const originalSettings = await request('/api/settings')
try {
  await request('/api/settings', { method: 'PUT', body: JSON.stringify({ provider: 'qemu-vm' }) })
  const blockedVmStart = await fetch(`${baseUrl}/api/labs/${vulnhub.id}/instances`, { method: 'POST', headers: { cookie, 'x-csrf-token': csrfToken } })
  assert.equal(blockedVmStart.status, 409)
  assert.equal((await blockedVmStart.json()).code, 'VM_IMAGE_NOT_READY')
} finally {
  await request('/api/settings', { method: 'PUT', body: JSON.stringify({ provider: originalSettings.provider }) })
}

console.log(`VulnLab VulnHub API smoke passed: ${catalog.entries.length} machines readable, ${completed.manifest.archiveSha256}.`)
