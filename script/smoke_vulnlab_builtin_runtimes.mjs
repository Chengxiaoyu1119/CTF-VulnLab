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
  dvwa: [{ path: 'login.php', pattern: /DVWA/i, redirect: 'manual' }],
  pikachu: [{ path: 'index.php', pattern: /pikachu|皮卡丘/i, redirect: 'follow' }],
  'sqli-labs': [{ path: 'Less-1/index.php?id=1', pattern: /Dumb|Login name/i, redirect: 'manual' }],
  'upload-labs': [{ path: '', pattern: /upload/i, redirect: 'manual' }],
  xvwa: [
    { path: '', pattern: /XVWA/i, redirect: 'manual' },
    { path: 'setup/?action=do', pattern: /Setup finished/i, redirect: 'manual' },
  ],
  'juice-shop': [{ path: '', pattern: /juice shop/i, redirect: 'manual' }],
  webgoat: [{ path: 'login', pattern: /webgoat/i, redirect: 'manual', webwolf: true }],
  mutillidae: [{ path: 'index.php', pattern: /Mutillidae/i, redirect: 'manual' }],
  pygoat: [{ path: '', pattern: /pygoat|django/i, redirect: 'follow' }],
}

const webWolfPort = instance => {
  const line = instance.logs.find(item => /WebWolf\s+端口=(\d+)/i.test(item))
  return line ? Number(line.match(/WebWolf\s+端口=(\d+)/i)?.[1]) : 0
}

const probeInstance = async (instance, checks) => {
  const results = []
  for (const check of checks) {
    const response = await fetch(new URL(check.path, instance.endpoint), { redirect: check.redirect })
    const html = await response.text()
    assert.equal(response.status, 200, `${instance.labId} ${check.path || '/'} probe returned ${response.status}`)
    assert.match(html, check.pattern, `${instance.labId} ${check.path || '/'} response does not match its application shell`)
    results.push(response.status)
    if (check.webwolf) {
      const port = webWolfPort(instance)
      assert.ok(port > 0, 'WebGoat instance did not report a WebWolf port')
      const webWolfResponse = await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual' })
      assert.ok(webWolfResponse.status >= 100 && webWolfResponse.status < 500, `WebWolf probe returned ${webWolfResponse.status}`)
    }
  }
  return results
}

const assertEndpointStopped = async (endpoint, label) => {
  try {
    const response = await fetch(endpoint, { redirect: 'manual' })
    assert.equal(response.status, 404, `${label} endpoint remained available after stop`)
  } catch (error) {
    assert.equal(error?.cause?.code, 'ECONNREFUSED', `${label} endpoint stop failed: ${error}`)
  }
}

const login = await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ userName: 'vulnlab', password: 'vulnlab' }) })
csrfToken = login.csrfToken
const labs = await request('/api/labs')
const results = []

for (const [slug, checks] of Object.entries(probes)) {
  const lab = labs.find(item => item.slug === slug)
  assert.ok(lab, `${slug} is missing`)
  assert.equal(lab.status, 'ready', `${slug} is not installed`)
  let instance = null
  try {
    const concurrentStarts = await Promise.all([
      request(`/api/labs/${lab.id}/instances`, { method: 'POST' }),
      request(`/api/labs/${lab.id}/instances`, { method: 'POST' }),
    ])
    instance = concurrentStarts[0]
    assert.equal(concurrentStarts[0].status, 'running')
    assert.equal(concurrentStarts[1].status, 'running')
    assert.equal(concurrentStarts[0].id, concurrentStarts[1].id, `${slug} concurrent start created duplicate instances`)
    assert.equal(instance.status, 'running')
    assert.equal(instance.provider, lab.providerId)
    const runningInstances = (await request('/api/instances')).filter(item => item.labId === lab.id && item.status === 'running')
    assert.equal(runningInstances.length, 1, `${slug} has more than one running instance`)
    const renewed = await request(`/api/instances/${instance.id}/renew`, { method: 'POST' })
    assert.equal(renewed.status, 'running')
    assert.equal(renewed.id, instance.id)
    assert.ok(Date.parse(renewed.expiresAt) > Date.parse(instance.expiresAt), `${slug} renewal did not extend the lease`)
    const statuses = await probeInstance(instance, checks)
    const stopped = await request(`/api/instances/${instance.id}`, { method: 'DELETE' })
    assert.equal(stopped.status, 'destroyed')
    await assertEndpointStopped(instance.endpoint, slug)
    instance = null

    const restarted = await request(`/api/labs/${lab.id}/instances`, { method: 'POST' })
    instance = restarted
    assert.equal(restarted.status, 'running')
    assert.notEqual(restarted.id, stopped.id, `${slug} restart reused a destroyed instance`)
    await probeInstance(restarted, checks)
    const restartedStop = await request(`/api/instances/${restarted.id}`, { method: 'DELETE' })
    assert.equal(restartedStop.status, 'destroyed')
    await assertEndpointStopped(restarted.endpoint, `${slug} restarted`)
    instance = null
    results.push(`${slug}=200 lifecycle=${statuses.join('/')}`)
  } finally {
    if (instance) {
      const stopped = await request(`/api/instances/${instance.id}`, { method: 'DELETE' })
      assert.equal(stopped.status, 'destroyed')
    }
  }
}

console.log(`VulnLab built-in runtime smoke passed: ${results.join(', ')}`)
