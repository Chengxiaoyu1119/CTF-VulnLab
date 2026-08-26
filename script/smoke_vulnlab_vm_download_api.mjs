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

const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab', password: 'vulnlab' }) })
csrfToken = session.csrfToken
const lab = (await request('/api/labs')).find(item => item.slug === 'vulnhub')
assert.ok(lab, 'VulnHub seed is missing')
const catalog = await request(`/api/labs/${lab.id}/catalog`)
const entryIndex = catalog.entries.findIndex(entry => entry.downloadUrls.length > 0)
assert.ok(entryIndex >= 0, 'VulnHub catalog has no downloadable machine')

const started = await request(`/api/labs/${lab.id}/catalog/entries/${entryIndex}/download`, {
  method: 'POST',
  body: JSON.stringify({ downloadIndex: 0 }),
})
assert.ok(['downloading', 'completed'].includes(started.download.status))

let current = started.download
for (let attempt = 0; attempt < 60 && current.status === 'downloading'; attempt += 1) {
  await pause(500)
  current = (await request(`/api/labs/${lab.id}/catalog`)).downloads.find(item => item.id === current.id)
}
assert.ok(current, 'VM download disappeared from catalog')
assert.equal(current.status, 'error', 'Set VULNLAB_VM_MAX_BYTES to a small fixture limit for this smoke test')
assert.match(current.error, /大小上限|下载/)

console.log(`VulnLab VM download API smoke passed: ${current.status} ${current.error}`)
