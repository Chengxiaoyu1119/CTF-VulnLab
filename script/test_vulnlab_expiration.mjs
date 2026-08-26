import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-expiration-'))
process.env.NODE_ENV = 'test'
process.env.VULNLAB_NO_LISTEN = '1'
process.env.VULNLAB_DATA_DIR = dataDir
process.env.VULNLAB_HOST = '127.0.0.1'
process.env.VULNLAB_PORT = '6791'
process.env.VULNLAB_INSTANCE_MINUTES = '0.01'

const { app, database } = await import(new URL('../src/VulnLab/dist/server.js', import.meta.url))
try {
  const lab = database.createLab({
    slug: 'expiration-fixture',
    title: 'Expiration Fixture',
    category: 'Web',
    difficulty: '入门',
    sourceType: 'git',
    sourceUrl: 'https://github.com/fixture/expiration',
    sourceRef: 'fixture/expiration@main',
    license: 'MIT',
    runtimeKind: 'native-php',
    summary: 'Lifecycle test fixture.',
    tags: ['fixture'],
    status: 'ready',
  })

  const login = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { userName: 'vulnlab', password: 'vulnlab' } })
  assert.equal(login.statusCode, 200)
  const cookieHeader = login.headers['set-cookie']
  const cookie = (Array.isArray(cookieHeader) ? cookieHeader[0] : cookieHeader)?.split(';', 1)[0]
  assert.ok(cookie)
  const instanceId = 'expired-native-instance'
  const started = database.createInstance({
    id: instanceId,
    lab,
    provider: 'native-php',
    endpoint: 'http://127.0.0.1:6998/',
    createdAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
    logs: ['fixture started'],
  })
  assert.equal(started?.status, 'running')

  const instances = await app.inject({ method: 'GET', url: '/api/instances', headers: { cookie } })
  assert.equal(instances.statusCode, 200)
  const instance = instances.json().find(item => item.id === instanceId)
  assert.equal(instance?.status, 'expired')
  const overview = await app.inject({ method: 'GET', url: '/api/overview', headers: { cookie } })
  assert.equal(overview.json().runningInstanceCount, 0)
  assert.ok(database.listAudit().some(item => item.action === 'instance.expired' && item.target === 'Expiration Fixture'))

  const unknownProviderId = 'unknown-provider-instance'
  const unknownProviderInstance = database.createInstance({
    id: unknownProviderId,
    lab,
    provider: 'provider-from-future-release',
    endpoint: 'http://127.0.0.1:6999/',
    createdAt: new Date(Date.now() - 120_000).toISOString(),
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
    logs: [],
  })
  assert.equal(unknownProviderInstance?.status, 'running')
  const afterUnknownProvider = await app.inject({ method: 'GET', url: '/api/instances', headers: { cookie } })
  assert.equal(afterUnknownProvider.statusCode, 200)
  assert.equal(database.getInstance(unknownProviderId)?.status, 'running')
} finally {
  await app.close()
  database.close()
  await rm(dataDir, { recursive: true, force: true })
}

console.log('VulnLab expiration integration test passed: expired runtime entries are reclaimed through the server lifecycle.')
