import assert from 'node:assert/strict'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { VulnLabDatabase } = await import(new URL('../src/VulnLab/dist/db.js', import.meta.url))
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-database-'))
const database = new VulnLabDatabase(dataDir)
try {
  const lab = database.getLabBySlug('upload-labs')
  assert.ok(lab)
  const timestamp = new Date(Date.now() - 60_000).toISOString()
  const instance = database.createInstance({
    id: 'expired-instance-fixture',
    lab,
    provider: 'native-php',
    endpoint: 'http://127.0.0.1:6800/',
    createdAt: timestamp,
    expiresAt: timestamp,
    logs: ['fixture started'],
  })
  assert.equal(instance?.status, 'running')

  const expired = database.expireInstances()
  assert.equal(expired.length, 1)
  assert.equal(expired[0].id, instance.id)
  assert.equal(expired[0].status, 'expired')
  assert.match(expired[0].logs.at(-1), /自动标记为已过期/)
  assert.equal(database.expireInstances().length, 0)
  assert.equal(database.overview().runningInstanceCount, 0)

  const retryInstance = database.createInstance({
    id: 'retry-expired-instance-fixture',
    lab,
    provider: 'native-php',
    endpoint: 'http://127.0.0.1:6801/',
    createdAt: timestamp,
    expiresAt: timestamp,
    logs: ['fixture started'],
  })
  assert.equal(retryInstance?.status, 'running')
  const candidates = database.listExpiredInstances()
  assert.equal(candidates.length, 1)
  assert.equal(candidates[0].id, retryInstance.id)
  const marked = database.expireInstance(retryInstance.id, 'fixture provider stopped')
  assert.equal(marked?.status, 'expired')
  assert.match(marked?.logs.at(-1), /fixture provider stopped/)
} finally {
  database.close()
  await rm(dataDir, { recursive: true, force: true })
}

console.log('VulnLab database lifecycle test passed: expired instances are claimed once and removed from running capacity.')
