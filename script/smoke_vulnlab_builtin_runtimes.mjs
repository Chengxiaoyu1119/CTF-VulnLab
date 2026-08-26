import assert from 'node:assert/strict'

const baseUrl = process.env.VULNLAB_BASE_URL ?? 'http://127.0.0.1:6710'
let cookie = ''
let csrfToken = ''

const request = async (path, options = {}) => {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = { ...(options.body ? { 'content-type': 'application/json' } : {}), ...(options.headers ?? {}) }
  if (cookie) headers.cookie = cookie
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && csrfToken && !path.endsWith('/auth/login')) headers['x-csrf-token'] = csrfToken
  const response = await fetch(`${baseUrl}${path}`, { ...options, method, headers })
  const setCookies = response.headers.getSetCookie?.() ?? []
  if (setCookies.length) cookie = setCookies.map(value => value.split(';', 1)[0]).join('; ')
  const payload = await response.json().catch(() => ({}))
  assert.ok(response.ok, `${method} ${path} failed: ${response.status} ${payload.message ?? ''}`)
  return payload
}

const probes = {
  'upload-labs': { path: '', pattern: /upload/i, redirect: 'manual' },
  'juice-shop': { path: '', pattern: /juice shop/i, redirect: 'manual' },
  webgoat: { path: 'login', pattern: /webgoat/i, redirect: 'manual' },
  pygoat: { path: '', pattern: /pygoat|django/i, redirect: 'follow' },
}

const login = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab', password: 'vulnlab' }) })
csrfToken = login.csrfToken
const labs = await request('/api/labs')
const results = []

for (const [slug, probe] of Object.entries(probes)) {
  const lab = labs.find(item => item.slug === slug)
  assert.ok(lab, `${slug} is missing`)
  assert.equal(lab.status, 'ready', `${slug} is not installed`)
  let instance = null
  try {
    instance = await request(`/api/labs/${lab.id}/instances`, { method: 'POST' })
    assert.equal(instance.status, 'running')
    assert.equal(instance.provider, lab.providerId)
    const response = await fetch(new URL(probe.path, instance.endpoint), { redirect: probe.redirect })
    const html = await response.text()
    assert.equal(response.status, 200, `${slug} probe returned ${response.status}`)
    assert.match(html, probe.pattern, `${slug} response does not match its application shell`)
    results.push(`${slug}=${response.status}`)
  } finally {
    if (instance) {
      const stopped = await request(`/api/instances/${instance.id}`, { method: 'DELETE' })
      assert.equal(stopped.status, 'destroyed')
    }
  }
}

console.log(`VulnLab built-in runtime smoke passed: ${results.join(', ')}`)
