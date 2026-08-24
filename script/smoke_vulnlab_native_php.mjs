import assert from 'node:assert/strict'

const baseUrl = process.env.VULNLAB_BASE_URL ?? 'http://127.0.0.1:6710'
const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds))
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
  const body = await response.json().catch(() => ({}))
  assert.ok(response.ok, `${method} ${path} failed: ${response.status} ${body.message ?? ''}`)
  return body
}

const login = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab-admin', password: 'VulnLabAdmin123!' }) })
csrfToken = login.csrfToken
const labs = await request('/api/labs')
const uploadLabs = labs.find(lab => lab.slug === 'upload-labs')
assert.ok(uploadLabs, 'Upload-Labs seed is missing')
assert.equal(uploadLabs.runtimeKind, 'native-php')

if (uploadLabs.status !== 'ready') {
  const installation = await request(`/api/labs/${uploadLabs.id}/install`, { method: 'POST' })
  let completed = null
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const jobs = await request('/api/import-jobs')
    const current = jobs.find(job => job.id === installation.job?.id)
    if (current?.status === 'completed' || current?.status === 'error') { completed = current; break }
    await wait(500)
  }
  assert.ok(completed, 'Upload-Labs installation did not finish within 60 seconds')
  assert.equal(completed.status, 'completed', completed.error ?? completed.message)
}

const readyLab = (await request('/api/labs')).find(lab => lab.id === uploadLabs.id)
assert.equal(readyLab.status, 'ready')
const instance = await request(`/api/labs/${uploadLabs.id}/instances`, { method: 'POST' })
assert.equal(instance.status, 'running')
assert.equal(instance.provider, 'native-php')
assert.equal(instance.endpoint, `${baseUrl}/lab-runtime/${instance.id}/`)
const page = await fetch(instance.endpoint)
assert.equal(page.status, 200)
assert.match(await page.text(), /Upload|upload/i)
const passPage = await fetch(`${instance.endpoint}Pass-01/index.php`)
assert.equal(passPage.status, 200)
const form = new FormData()
form.append('upload_file', new Blob(['VulnLab native PHP fixture'], { type: 'image/jpeg' }), 'vulnlab-fixture.jpg')
const upload = await fetch(`${instance.endpoint}Pass-01/index.php`, { method: 'POST', body: form })
assert.equal(upload.status, 200)

const renewed = await request(`/api/instances/${instance.id}/renew`, { method: 'POST' })
assert.equal(renewed.status, 'running')
const destroyed = await request(`/api/instances/${instance.id}`, { method: 'DELETE' })
assert.equal(destroyed.status, 'destroyed')
const stopped = await fetch(instance.endpoint)
assert.equal(stopped.status, 404, 'native PHP endpoint should stop after instance destruction')

console.log(`VulnLab native PHP smoke passed: Upload-Labs installed, served at ${instance.endpoint}, renewed and stopped.`)
