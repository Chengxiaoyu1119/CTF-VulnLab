import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

const { VulnLabDatabase } = await import(new URL('../src/dist/db.js', import.meta.url))
const { dataPaths } = await import(new URL('../src/dist/paths.js', import.meta.url))
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-database-'))
const database = new VulnLabDatabase(dataDir)
const firstRecordPage = { limit: 100, cursor: null }
try {
  const paths = dataPaths(dataDir)
  assert.equal(paths.root, resolve(dataDir))
  assert.equal(paths.database, join(dataDir, 'vulnlab.sqlite'))
  assert.equal(paths.lab('upload-labs', 'fixture'), join(dataDir, 'labs', 'upload-labs', 'fixture'))
  assert.equal(paths.importJob('job-fixture'), join(dataDir, 'imports', 'job-fixture'))
  assert.equal(paths.labDownload('upload-labs', 'fixture'), join(dataDir, 'downloads', 'upload-labs', 'fixture'))
  assert.equal(paths.runtimeInstance('instance-fixture'), join(dataDir, 'runtime', 'instance-fixture'))
  assert.equal(paths.runtimeToolchain('php', '8.3.33', 'win32', 'x64'), join(dataDir, 'runtime', 'toolchains', 'php', '8.3.33', 'win32-x64'))
assert.equal(paths.runtimeManifest('php-8.3.33-win32-x64.json'), join(dataDir, 'runtime', 'manifests', 'php-8.3.33-win32-x64.json'))
assert.equal(paths.runtimeStaging, join(dataDir, 'runtime', '.staging'))
assert.equal(paths.runtimePhp, join(dataDir, 'runtime', 'php'))
  assert.equal(paths.runtimeMysql, join(dataDir, 'runtime', 'mysql'))
  assert.throws(() => paths.lab('bad/slug', 'fixture'), /不是有效的路径片段/)
  assert.throws(() => paths.runtimeInstance('../escape'), /不是有效的路径片段/)

  const invitation = database.createInvitation('invite-fixture', 'code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(invitation.usedAt, null)
  assert.equal(database.registerUserWithInvitation('student-fixture', 'scrypt-fixture-hash', 'code-hash-fixture'), 'created')
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === invitation.id)?.status, 'used')
  assert.equal(database.getUser('STUDENT-FIXTURE')?.userName, 'student-fixture')
  assert.equal(database.getUser('student-fixture')?.passwordHash, 'scrypt-fixture-hash')
  assert.equal(database.registerUserWithInvitation('another-student', 'scrypt-fixture-hash', 'code-hash-fixture'), 'invalid_invitation')
  const unavailableInvitation = database.createInvitation('unavailable-invite-fixture', 'unavailable-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.registerUserWithInvitation('VULNLAB', 'scrypt-fixture-hash', 'unavailable-code-hash-fixture', ['vulnlab']), 'user_exists')
  assert.equal(database.registerUserWithInvitation('VULNLAB', 'scrypt-fixture-hash', 'missing-code-hash-fixture', ['vulnlab']), 'invalid_invitation')
  assert.equal(database.registerUserWithInvitation('student-fixture', 'scrypt-fixture-hash', 'missing-code-hash-fixture', ['vulnlab']), 'invalid_invitation')
  const duplicateInvitation = database.createInvitation('duplicate-invite-fixture', 'duplicate-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.registerUserWithInvitation('STUDENT-FIXTURE', 'scrypt-fixture-hash', 'duplicate-code-hash-fixture', ['vulnlab']), 'user_exists')
  assert.equal(database.registerUserWithInvitation('available-student', 'scrypt-fixture-hash', 'missing-code-hash-fixture-2', ['vulnlab']), 'invalid_invitation')
  assert.equal(database.registerUserWithInvitation('available-student', 'scrypt-fixture-hash', 'duplicate-code-hash-fixture', ['vulnlab']), 'created')
  const listedUsers = database.listRegisteredUsers(firstRecordPage).items
  assert.ok(listedUsers.some(item => item.userName === 'student-fixture'))
  assert.ok(listedUsers.every(item => Object.keys(item).sort().join(',') === 'createdAt,userName'))
  database.createSession('student-session-a', 'student-fixture', 'admin', 'csrf-fixture-a', Date.now() + 86_400_000)
  database.createSession('student-session-b', 'student-fixture', 'admin', 'csrf-fixture-b', Date.now() + 86_400_000)
  database.createSession('available-session', 'available-student', 'admin', 'csrf-fixture-c', Date.now() + 86_400_000)
  database.addAudit('student-fixture', 'account.delete', 'account', 'account deletion is retained in audit history')
  assert.equal(database.deleteRegisteredUsers(['available-student', 'missing-student']), 0)
  assert.ok(database.getUser('available-student'))
  assert.equal(database.deleteRegisteredUsers(['STUDENT-FIXTURE']), 1)
  assert.equal(database.getUser('student-fixture'), null)
  assert.equal(database.getSession('student-session-a'), null)
  assert.equal(database.getSession('student-session-b'), null)
  assert.ok(database.getSession('available-session'))
  assert.ok(database.listAudit(firstRecordPage).items.some(item => item.detail === 'account deletion is retained in audit history'))
  const revoked = database.createInvitation('revoked-invite-fixture', 'revoked-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.revokeInvitation(revoked.id), true)
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === revoked.id)?.status, 'revoked')
  assert.equal(database.registerUserWithInvitation('revoked-student', 'scrypt-fixture-hash', 'revoked-code-hash-fixture'), 'invalid_invitation')
  const expiredInvitation = database.createInvitation('expired-invite-fixture', 'expired-code-hash-fixture', 'vulnlab', new Date(Date.now() - 1_000).toISOString())
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === expiredInvitation.id)?.status, 'expired')
  assert.equal(database.registerUserWithInvitation('expired-student', 'scrypt-fixture-hash', 'expired-code-hash-fixture'), 'invalid_invitation')
  assert.equal(database.revokeInvitation(expiredInvitation.id), true)
  assert.equal(database.revokeInvitation(expiredInvitation.id), false)
  const deletableInvitation = database.createInvitation('deletable-invite-fixture', 'deletable-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.deleteInvitation(deletableInvitation.id), true)
  assert.equal(database.deleteInvitation(deletableInvitation.id), false)
  const batchInvitations = ['batch-invite-a', 'batch-invite-b'].map(id => database.createInvitation(id, `${id}-hash-fixture`, 'vulnlab', new Date(Date.now() + 86_400_000).toISOString()))
  assert.equal(database.deleteInvitations(batchInvitations.map(item => item.id)), 2)
  assert.equal(database.deleteInvitations(batchInvitations.map(item => item.id)), 0)
  database.addAudit('vulnlab', 'test.record', 'fixture', 'deletable audit')
  const deletableAudit = database.listAudit(firstRecordPage).items.find(item => item.detail === 'deletable audit')
  assert.ok(deletableAudit)
  assert.equal(database.deleteAudit(deletableAudit.id), true)
  assert.equal(database.deleteAudit(deletableAudit.id), false)
  database.addAudit('vulnlab', 'test.record', 'fixture', 'batch audit a')
  database.addAudit('vulnlab', 'test.record', 'fixture', 'batch audit b')
  const batchAudits = database.listAudit(firstRecordPage).items.filter(item => item.detail?.startsWith('batch audit '))
  assert.equal(database.deleteAudits(batchAudits.map(item => item.id)), 2)
  assert.equal(database.deleteAudits(batchAudits.map(item => item.id)), 0)

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

  const pagedInvitationIds = []
  const pagedUserNames = []
  const pagedAuditDetails = []
  for (let index = 0; index < 51; index += 1) {
    const suffix = String(index).padStart(2, '0')
    const invitationId = `page-invitation-${suffix}`
    const codeHash = `page-code-hash-${suffix}`
    const userName = `page-user-${suffix}`
    database.createInvitation(invitationId, codeHash, 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
    assert.equal(database.registerUserWithInvitation(userName, 'scrypt-fixture-hash', codeHash), 'created')
    const detail = `pagination audit ${suffix}`
    database.addAudit('vulnlab', 'instance.renew', 'fixture', detail)
    pagedInvitationIds.push(invitationId)
    pagedUserNames.push(userName)
    pagedAuditDetails.push(detail)
  }

  const assertSecondPage = (first, second, expected, key) => {
    assert.equal(first.items.length, 50)
    assert.ok(first.nextCursor)
    assert.equal(new Set([...first.items, ...second.items].map(item => item[key])).size, first.items.length + second.items.length)
    const loaded = new Set([...first.items, ...second.items].map(item => item[key]))
    expected.forEach(value => assert.ok(loaded.has(value), `missing paged record: ${value}`))
  }
  const invitationPage = database.listInvitations({ limit: 50, cursor: null })
  const invitationNextPage = database.listInvitations({ limit: 50, cursor: invitationPage.nextCursor })
  assertSecondPage(invitationPage, invitationNextPage, pagedInvitationIds, 'id')
  assert.ok(invitationPage.total >= pagedInvitationIds.length)

  const userPage = database.listRegisteredUsers({ limit: 50, cursor: null })
  const userNextPage = database.listRegisteredUsers({ limit: 50, cursor: userPage.nextCursor })
  assertSecondPage(userPage, userNextPage, pagedUserNames, 'userName')
  assert.ok(userPage.total >= pagedUserNames.length)

  const auditPage = database.listAudit({ limit: 50, cursor: null })
  const auditNextPage = database.listAudit({ limit: 50, cursor: auditPage.nextCursor })
  assertSecondPage(auditPage, auditNextPage, pagedAuditDetails, 'detail')
  assert.ok(auditPage.total >= pagedAuditDetails.length)
} finally {
  database.close()
  await rm(dataDir, { recursive: true, force: true })
}

console.log('VulnLab database lifecycle test passed: expired instances are claimed once and paged records remain complete.')
