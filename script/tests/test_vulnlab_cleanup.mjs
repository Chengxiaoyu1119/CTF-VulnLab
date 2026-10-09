import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const { VulnLabDatabase } = await import(new URL('../../src/dist/db.js', import.meta.url))
const { dataPaths } = await import(new URL('../../src/dist/paths.js', import.meta.url))
const { processPendingCleanup } = await import(new URL('../../src/dist/cleanup.js', import.meta.url))
const require = createRequire(new URL('../../src/package.json', import.meta.url))
const SQLiteDatabase = require('better-sqlite3')
const root = await mkdtemp(join(tmpdir(), 'vulnlab-cleanup-'))
const dataDir = join(root, 'data')
let database = new VulnLabDatabase(dataDir)
let sequence = 0

const createLab = (title) => database.createLab({
  slug: `cleanup-fixture-${++sequence}`,
  title,
  category: 'Web',
  difficulty: '简单',
  sourceType: 'archive',
  sourceUrl: 'bundle://cleanup-fixture',
  sourceRef: 'fixture',
  license: 'MIT',
  runtimeKind: 'native-php',
  status: 'ready',
  summary: '',
  tags: [],
})

const makeDue = () => {
  const connection = new SQLiteDatabase(dataPaths(dataDir).database)
  connection.prepare('UPDATE cleanup_jobs SET next_attempt_at = ?').run(new Date(0).toISOString())
  connection.close()
}

try {
  const paths = dataPaths(dataDir)
  const retryLab = createLab('清理重试夹具')
  const retryPath = paths.lab(retryLab.slug, retryLab.version)
  await mkdir(retryPath, { recursive: true })
  await writeFile(join(retryPath, 'payload.txt'), 'retry')
  const deletion = database.deleteCustomLab(retryLab.id, [retryPath])
  assert.ok(deletion)
  assert.equal(database.getLab(retryLab.id), null)
  assert.equal(database.hasPendingCleanup(deletion.batchId), true)

  let failOnce = true
  const firstPass = await processPendingCleanup(database, dataDir, async () => {
    if (failOnce) {
      failOnce = false
      throw new Error('simulated remove failure')
    }
  })
  assert.deepEqual(firstPass, { completed: 0, failed: 1 })
  database.close()
  database = new VulnLabDatabase(dataDir)
  assert.equal(database.hasPendingCleanup(deletion.batchId), true)
  makeDue()
  const retryPass = await processPendingCleanup(database, dataDir)
  assert.deepEqual(retryPass, { completed: 1, failed: 0 })
  assert.equal(database.hasPendingCleanup(deletion.batchId), false)
  assert.deepEqual(await processPendingCleanup(database, dataDir), { completed: 0, failed: 0 })
  await assert.rejects(readFile(join(retryPath, 'payload.txt')))

  const outside = join(root, 'outside')
  await mkdir(outside, { recursive: true })
  await writeFile(join(outside, 'keep.txt'), 'keep')
  const linkPath = join(paths.labs, 'linked')
  await mkdir(paths.labs, { recursive: true })
  await symlink(outside, linkPath, 'junction')
  const escapeLab = createLab('越界清理夹具')
  const escapePath = join(linkPath, 'payload')
  const escapeDeletion = database.deleteCustomLab(escapeLab.id, [escapePath])
  assert.ok(escapeDeletion)
  const escapePass = await processPendingCleanup(database, dataDir)
  assert.deepEqual(escapePass, { completed: 0, failed: 1 })
  assert.equal(database.hasPendingCleanup(escapeDeletion.batchId), true)
  assert.equal(await readFile(join(outside, 'keep.txt'), 'utf8'), 'keep')
  await rm(linkPath, { recursive: true, force: true })
  makeDue()
  const recoveredPass = await processPendingCleanup(database, dataDir)
  assert.deepEqual(recoveredPass, { completed: 1, failed: 0 })

  const invalidLab = createLab('非法清理路径夹具')
  assert.throws(() => database.deleteCustomLab(invalidLab.id, [outside]), /必须位于 VulnLab 数据目录内/)
  assert.ok(database.getLab(invalidLab.id))

  console.log('VulnLab cleanup test passed: transactional queue, retry, restart recovery, idempotence and path containment.')
} finally {
  database.close()
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
