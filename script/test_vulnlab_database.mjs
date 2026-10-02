import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

const { VulnLabDatabase } = await import(new URL('../src/dist/db.js', import.meta.url))
const { dataPaths } = await import(new URL('../src/dist/paths.js', import.meta.url))
const require = createRequire(new URL('../src/package.json', import.meta.url))
const SQLiteDatabase = require('better-sqlite3')
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
  assert.equal(invitation.usedByUserName, null)
  assert.equal(database.registerUserWithInvitation('student-fixture', 'scrypt-fixture-hash', 'code-hash-fixture'), 'created')
  const consumedInvitation = database.listInvitations(firstRecordPage).items.find(item => item.id === invitation.id)
  assert.equal(consumedInvitation?.status, 'used')
  assert.equal(consumedInvitation?.usedByUserName, 'student-fixture')
  assert.equal(database.getUser('STUDENT-FIXTURE')?.userName, 'student-fixture')
  assert.equal(database.getUser('student-fixture')?.passwordHash, 'scrypt-fixture-hash')
  assert.equal(database.registerUserWithInvitation('another-student', 'scrypt-fixture-hash', 'code-hash-fixture'), 'invalid_invitation')
  const unavailableInvitation = database.createInvitation('unavailable-invite-fixture', 'unavailable-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.registerUserWithInvitation('VULNLAB', 'scrypt-fixture-hash', 'unavailable-code-hash-fixture', ['vulnlab']), 'user_exists')
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === unavailableInvitation.id)?.usedByUserName, null)
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === unavailableInvitation.id)?.status, 'active')
  assert.equal(database.registerUserWithInvitation('VULNLAB', 'scrypt-fixture-hash', 'missing-code-hash-fixture', ['vulnlab']), 'invalid_invitation')
  assert.equal(database.registerUserWithInvitation('student-fixture', 'scrypt-fixture-hash', 'missing-code-hash-fixture', ['vulnlab']), 'invalid_invitation')
  const duplicateInvitation = database.createInvitation('duplicate-invite-fixture', 'duplicate-code-hash-fixture', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString())
  assert.equal(database.registerUserWithInvitation('STUDENT-FIXTURE', 'scrypt-fixture-hash', 'duplicate-code-hash-fixture', ['vulnlab']), 'user_exists')
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === duplicateInvitation.id)?.usedByUserName, null)
  assert.equal(database.registerUserWithInvitation('available-student', 'scrypt-fixture-hash', 'missing-code-hash-fixture-2', ['vulnlab']), 'invalid_invitation')
  assert.equal(database.registerUserWithInvitation('available-student', 'scrypt-fixture-hash', 'duplicate-code-hash-fixture', ['vulnlab']), 'created')
  const listedUsers = database.listRegisteredUsers(firstRecordPage).items
  assert.ok(listedUsers.some(item => item.userName === 'student-fixture'))
  assert.ok(listedUsers.every(item => Object.keys(item).sort().join(',') === 'createdAt,disabled,userName' && item.disabled === false))
  database.createSession('student-session-a', 'student-fixture', 'admin', 'csrf-fixture-a', Date.now() + 86_400_000)
  database.createSession('student-session-b', 'student-fixture', 'admin', 'csrf-fixture-b', Date.now() + 86_400_000)
  database.createSession('available-session', 'available-student', 'admin', 'csrf-fixture-c', Date.now() + 86_400_000)
  database.createSession('available-session-2', 'available-student', 'admin', 'csrf-fixture-d', Date.now() + 86_400_000)
  assert.equal(database.setRegisteredUserDisabled('vulnlab', true), false)
  assert.equal(database.setRegisteredUserDisabled('AVAILABLE-STUDENT', true), true)
  assert.equal(database.getUser('available-student')?.disabled, true)
  assert.equal(database.listRegisteredUsers(firstRecordPage).items.find(item => item.userName === 'available-student')?.disabled, true)
  assert.equal(database.createSession('blocked-session', 'available-student', 'admin', 'csrf-fixture-e', Date.now() + 86_400_000, true), false)
  assert.equal(database.getSession('blocked-session'), null)
  assert.equal(database.getSession('available-session'), null)
  assert.equal(database.getSession('available-session-2'), null)
  assert.equal(database.setRegisteredUserDisabled('available-student', false), true)
  assert.equal(database.getUser('available-student')?.disabled, false)
  assert.equal(database.createSession('available-session', 'available-student', 'admin', 'csrf-fixture-c', Date.now() + 86_400_000, true), true)
  database.addAudit('student-fixture', 'account.delete', 'account', 'account deletion is retained in audit history')
  assert.equal(database.deleteRegisteredUsers(['available-student', 'missing-student']), 0)
  assert.ok(database.getUser('available-student'))
  assert.equal(database.deleteRegisteredUsers(['STUDENT-FIXTURE']), 1)
  assert.equal(database.getUser('student-fixture'), null)
  assert.equal(database.listInvitations(firstRecordPage).items.find(item => item.id === invitation.id)?.usedByUserName, 'student-fixture')
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
  assert.equal(database.deleteInvitation(deletableInvitation.id), 'deleted')
  assert.equal(database.deleteInvitation(deletableInvitation.id), 'not_found')
  assert.equal(database.deleteInvitation(invitation.id), 'used')
  const mixedDeleteInvitations = [
    database.createInvitation('mixed-delete-unused', 'mixed-delete-unused-hash', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString()),
    invitation,
  ]
  assert.deepEqual(database.deleteInvitations(mixedDeleteInvitations.map(item => item.id)), { deleted: 0, blockedByUsed: true })
  assert.ok(database.listInvitations(firstRecordPage).items.some(item => item.id === mixedDeleteInvitations[0].id))
  assert.deepEqual(database.deleteInvitations([invitation.id]), { deleted: 0, blockedByUsed: true })
  const batchInvitations = ['batch-invite-a', 'batch-invite-b'].map(id => database.createInvitation(id, `${id}-hash-fixture`, 'vulnlab', new Date(Date.now() + 86_400_000).toISOString()))
  assert.deepEqual(database.deleteInvitations(batchInvitations.map(item => item.id)), { deleted: 2, blockedByUsed: false })
  assert.deepEqual(database.deleteInvitations(batchInvitations.map(item => item.id)), { deleted: 0, blockedByUsed: false })
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
  const customLab = database.createLab({
    slug: 'fixture-custom-lab',
    title: 'Fixture 自定义靶场',
    category: 'Web',
    difficulty: '简单',
    sourceType: 'archive',
    sourceUrl: 'bundle://fixture-custom-lab/source.zip',
    sourceRef: 'fixture@local',
    license: 'MIT',
    runtimeKind: 'native-php',
    runtimeConfig: { profile: 'static-php', documentRoot: 'public', entryPath: 'public/index.php' },
    summary: '自定义靶场持久化夹具。',
    tags: ['fixture', 'custom'],
  })
  assert.equal(customLab.builtin, false)
  assert.equal(customLab.status, 'queued')
  assert.equal(customLab.runtimeConfig.profile, 'static-php')
  assert.equal(customLab.runtimeConfig.documentRoot, 'public')
  assert.equal(customLab.runtimeConfig.entryPath, 'public/index.php')
  assert.equal(database.getLabBySlug('fixture-custom-lab')?.title, 'Fixture 自定义靶场')
  assert.deepEqual(database.getLabBySlug('fixture-custom-lab')?.tags, ['fixture', 'custom'])
  const reopenedDatabase = new VulnLabDatabase(dataDir)
  try {
    assert.equal(reopenedDatabase.getLabBySlug('fixture-custom-lab')?.sourceUrl, 'bundle://fixture-custom-lab/source.zip')
    assert.equal(reopenedDatabase.getLabBySlug('fixture-custom-lab')?.builtin, false)
    assert.equal(reopenedDatabase.getLabBySlug('fixture-custom-lab')?.runtimeConfig.profile, 'static-php')
    assert.equal(reopenedDatabase.getLabBySlug('fixture-custom-lab')?.runtimeConfig.documentRoot, 'public')
    assert.equal(reopenedDatabase.getLabBySlug('fixture-custom-lab')?.runtimeConfig.entryPath, 'public/index.php')
  } finally {
    reopenedDatabase.close()
  }
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
  const uploadImportedAt = database.getLab(lab.id)?.importedAt
  database.updateLabStatus(lab.id, 'error')
  database.restoreLabReady(lab.id)
  assert.equal(database.getLab(lab.id)?.status, 'ready')
  assert.equal(database.getLab(lab.id)?.importedAt, uploadImportedAt)

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

  const localTimestamp = offset => {
    const value = new Date()
    value.setHours(offset === 0 ? 0 : 12, 0, 0, 0)
    value.setDate(value.getDate() + offset)
    return value.toISOString()
  }
  const activityInsert = database.db.prepare('INSERT INTO audit (id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)')
  activityInsert.run('activity-today-a', 'vulnlab', 'instance.start', 'DVWA', 'activity-a', localTimestamp(0))
  activityInsert.run('activity-today-b', 'vulnlab', 'instance.start', 'DVWA', 'activity-b', localTimestamp(0))
  activityInsert.run('activity-yesterday', 'vulnlab', 'instance.start', 'Upload-Labs', 'activity-c', localTimestamp(-1))
  activityInsert.run('activity-old', 'vulnlab', 'instance.start', 'DVWA', 'activity-old', localTimestamp(-400))
  activityInsert.run('activity-failed', 'vulnlab', 'instance.start.failed', 'DVWA', 'activity-failed', localTimestamp(0))
  const localDate = value => {
    const parsed = new Date(value)
    const pad = part => String(part).padStart(2, '0')
    return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())}`
  }
  const activityOverview = database.overviewActivity()
  assert.equal(activityOverview.daily.length, 365)
  assert.equal(activityOverview.launchCount, 3)
  assert.equal(activityOverview.activeDays, 2)
  assert.equal(activityOverview.currentStreak, 2)
  assert.equal(activityOverview.longestStreak, 2)
  assert.equal(activityOverview.daily.at(-1)?.count, 2)
  assert.equal(activityOverview.daily.at(-2)?.count, 1)
  assert.deepEqual(activityOverview.ranking.slice(0, 2).map(item => [item.title, item.count]), [['DVWA', 2], ['Upload-Labs', 1]])
  const todayAudit = database.listAudit({ limit: 50, cursor: null }, { date: localDate(localTimestamp(0)), action: 'instance.start' })
  assert.equal(todayAudit.total, 2)
  assert.equal(todayAudit.items.length, 2)
  assert.ok(todayAudit.items.every(item => item.action === 'instance.start'))
  assert.equal(database.listAudit({ limit: 50, cursor: null }, { date: localDate(localTimestamp(-1)), action: 'instance.start' }).total, 1)
  assert.equal(database.listAudit({ limit: 50, cursor: null }, { date: '2024-02-29', action: 'instance.start' }).total, 0)
  const leapTimestamp = new Date(2024, 1, 29, 12, 0, 0, 0).toISOString()
  const marchTimestamp = new Date(2024, 2, 1, 12, 0, 0, 0).toISOString()
  activityInsert.run('activity-leap-day', 'vulnlab', 'instance.start', 'DVWA', 'activity-leap-day', leapTimestamp)
  activityInsert.run('activity-after-leap-day', 'vulnlab', 'instance.start', 'DVWA', 'activity-after-leap-day', marchTimestamp)
  assert.equal(database.listAudit({ limit: 50, cursor: null }, { date: localDate(leapTimestamp), action: 'instance.start' }).total, 1)
  assert.equal(database.listAudit({ limit: 50, cursor: null }, { date: localDate(marchTimestamp), action: 'instance.start' }).total, 1)

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

  const filteredPageDate = localDate(localTimestamp(-3))
  for (let index = 0; index < 51; index += 1) {
    activityInsert.run(`filtered-page-${index}`, 'vulnlab', 'instance.start', 'Filtered Fixture', `filtered page ${index}`, localTimestamp(-3))
  }
  const filteredPage = database.listAudit({ limit: 50, cursor: null }, { date: filteredPageDate, action: 'instance.start' })
  const filteredNextPage = database.listAudit({ limit: 50, cursor: filteredPage.nextCursor }, { date: filteredPageDate, action: 'instance.start' })
  assert.equal(filteredPage.total, 51)
  assert.equal(filteredPage.items.length, 50)
  assert.equal(filteredNextPage.items.length, 1)
  assert.equal(filteredNextPage.total, 51)
  assert.equal(new Set([...filteredPage.items, ...filteredNextPage.items].map(item => item.id)).size, 51)

  const legacyDataDir = join(dataDir, 'legacy')
  await mkdir(legacyDataDir, { recursive: true })
  const legacyDb = new SQLiteDatabase(join(legacyDataDir, 'vulnlab.sqlite'))
  legacyDb.exec(`CREATE TABLE users (
    user_name TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`)
  legacyDb.exec(`CREATE TABLE invitations (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_by TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
  )`)
  const legacyUsedAt = new Date().toISOString()
  legacyDb.prepare('INSERT INTO users VALUES (?, ?, ?, ?)').run('legacy-user', 'legacy-hash', 'admin', legacyUsedAt)
  legacyDb.prepare('INSERT INTO invitations VALUES (?, ?, ?, ?, ?, ?, ?)').run('legacy-used', 'legacy-used-hash', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString(), legacyUsedAt, null, legacyUsedAt)
  legacyDb.prepare('INSERT INTO invitations VALUES (?, ?, ?, ?, ?, ?, ?)').run('legacy-unused', 'legacy-unused-hash', 'vulnlab', new Date(Date.now() + 86_400_000).toISOString(), null, null, new Date().toISOString())
  legacyDb.close()
  const migratedDatabase = new VulnLabDatabase(legacyDataDir)
  try {
    const migratedInvitations = migratedDatabase.listInvitations(firstRecordPage).items
    assert.deepEqual(migratedDatabase.listRegisteredUsers(firstRecordPage).items.find(item => item.userName === 'legacy-user'), { userName: 'legacy-user', createdAt: legacyUsedAt, disabled: false })
    assert.equal(migratedDatabase.getUser('legacy-user')?.disabled, false)
    assert.equal(migratedInvitations.find(item => item.id === 'legacy-used')?.status, 'used')
    assert.equal(migratedInvitations.find(item => item.id === 'legacy-used')?.usedByUserName, null)
    assert.equal(migratedInvitations.find(item => item.id === 'legacy-unused')?.status, 'active')
    assert.equal(migratedInvitations.find(item => item.id === 'legacy-unused')?.usedByUserName, null)
  } finally {
    migratedDatabase.close()
  }
} finally {
  database.close()
  await rm(dataDir, { recursive: true, force: true })
}

console.log('VulnLab database lifecycle test passed: expired instances are claimed once and paged records remain complete.')
