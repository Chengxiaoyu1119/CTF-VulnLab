import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

const { VulnLabDatabase } = await import(new URL('../src/VulnLab/dist/db.js', import.meta.url))
const { dataPaths } = await import(new URL('../src/VulnLab/dist/paths.js', import.meta.url))
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-database-'))
const database = new VulnLabDatabase(dataDir)
try {
  const paths = dataPaths(dataDir)
  assert.equal(paths.root, resolve(dataDir))
  assert.equal(paths.database, join(dataDir, 'vulnlab.sqlite'))
  assert.equal(paths.lab('upload-labs', 'fixture'), join(dataDir, 'labs', 'upload-labs', 'fixture'))
  assert.equal(paths.importJob('job-fixture'), join(dataDir, 'imports', 'job-fixture'))
  assert.equal(paths.labDownload('upload-labs', 'fixture'), join(dataDir, 'downloads', 'upload-labs', 'fixture'))
  assert.equal(paths.runtimeInstance('instance-fixture'), join(dataDir, 'runtime', 'instance-fixture'))
  assert.throws(() => paths.lab('bad/slug', 'fixture'), /不是有效的路径片段/)
  assert.throws(() => paths.runtimeInstance('../escape'), /不是有效的路径片段/)

  const lab = database.getLabBySlug('upload-labs')
  assert.ok(lab)
  const manifestFor = (item, localPath, adapterId = 'github-git') => ({
    adapterId,
    sourceUrl: item.sourceUrl,
    sourceRef: item.sourceRef,
    resolvedRef: item.sourceRef,
    revision: item.version,
    archiveSha256: 'a'.repeat(64),
    localPath,
    fileCount: 1,
    totalBytes: 1,
    licenseFiles: [],
    topLevelEntries: [],
    warnings: [],
    importedAt: new Date().toISOString(),
  })

  await mkdir(join(dataDir, 'labs', lab.slug, lab.version), { recursive: true })
  const oldUploadPath = join(dataDir, 'old-project', 'labs', lab.slug, lab.version)
  const uploadJob = database.claimJob(database.createJob(lab.id, lab.sourceUrl).id)
  assert.ok(uploadJob)
  database.completeJob(uploadJob.id, manifestFor(lab, oldUploadPath))

  const webgoat = database.getLabBySlug('webgoat')
  assert.ok(webgoat)
  const webgoatRoot = join(dataDir, 'labs', webgoat.slug, webgoat.version)
  const webgoatJar = join(webgoatRoot, 'webgoat-2023.8.jar')
  await mkdir(webgoatRoot, { recursive: true })
  await writeFile(webgoatJar, 'fixture')
  const oldWebgoatPath = join(dataDir, 'old-project', 'labs', webgoat.slug, webgoat.version, 'webgoat-2023.8.jar')
  const webgoatJob = database.claimJob(database.createJob(webgoat.id, webgoat.sourceUrl).id)
  assert.ok(webgoatJob)
  database.completeJob(webgoatJob.id, manifestFor(webgoat, oldWebgoatPath, 'builtin-release'))

  const dvwa = database.getLabBySlug('dvwa')
  assert.ok(dvwa)
  const oldDvwaPath = join(dataDir, 'old-project', 'labs', dvwa.slug, dvwa.version)
  const dvwaJob = database.claimJob(database.createJob(dvwa.id, dvwa.sourceUrl).id)
  assert.ok(dvwaJob)
  database.completeJob(dvwaJob.id, manifestFor(dvwa, oldDvwaPath))

  const reconciliation = database.reconcileBuiltinPaths(dataDir)
  assert.ok(reconciliation.repaired.includes('upload-labs'))
  assert.ok(reconciliation.repaired.includes('webgoat'))
  assert.ok(reconciliation.reset.includes('dvwa'))
  assert.equal(database.getLabBySlug('upload-labs')?.localPath, join(dataDir, 'labs', 'upload-labs', lab.version))
  assert.equal(database.getJob(uploadJob.id)?.manifest?.localPath, join(dataDir, 'labs', 'upload-labs', lab.version))
  assert.equal(database.getLabBySlug('webgoat')?.localPath, webgoatJar)
  assert.equal(database.getJob(webgoatJob.id)?.manifest?.localPath, webgoatJar)
  assert.equal(database.getLabBySlug('dvwa')?.status, 'cataloged')
  assert.equal(database.getLabBySlug('dvwa')?.localPath, null)
  assert.equal(database.getJob(dvwaJob.id)?.manifest, null)
  assert.equal(database.getJob(dvwaJob.id)?.status, 'error')
  assert.deepEqual(database.reconcileBuiltinPaths(dataDir), { repaired: [], reset: [] })

  const pikachu = database.getLabBySlug('pikachu')
  assert.ok(pikachu)
  await mkdir(join(dataDir, 'labs', pikachu.slug, pikachu.version), { recursive: true })
  const pikachuJob = database.claimJob(database.createJob(pikachu.id, pikachu.sourceUrl).id)
  assert.ok(pikachuJob)
  database.completeJob(pikachuJob.id, manifestFor(pikachu, join(dataDir, 'old-project', 'labs', pikachu.slug, pikachu.version)))
  const xvwa = database.getLabBySlug('xvwa')
  assert.ok(xvwa)
  const malformedJob = database.claimJob(database.createJob(xvwa.id, xvwa.sourceUrl).id)
  assert.ok(malformedJob)
  database.completeJob(malformedJob.id, { ...manifestFor(xvwa, 42), localPath: 42 })
  database.db.prepare("UPDATE labs SET version = '.' WHERE slug = 'xvwa'").run()
  const partialReconciliation = database.reconcileBuiltinPaths(dataDir)
  assert.ok(partialReconciliation.repaired.includes('pikachu'))
  assert.ok(partialReconciliation.reset.includes('xvwa'))
  assert.equal(database.getLabBySlug('pikachu')?.localPath, join(dataDir, 'labs', 'pikachu', pikachu.version))
  assert.equal(database.getLabBySlug('xvwa')?.status, 'cataloged')
  assert.equal(database.getJob(malformedJob.id)?.manifest, null)
  for (const readyLab of database.listLabs().filter(item => item.status === 'ready')) {
    assert.ok(readyLab.localPath)
    assert.ok(readyLab.localPath === paths.root || readyLab.localPath.startsWith(`${paths.root}${sep}`))
  }
  assert.deepEqual(database.reconcileBuiltinPaths(dataDir), { repaired: [], reset: [] })

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
