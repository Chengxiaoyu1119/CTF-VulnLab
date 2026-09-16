import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { zipSync } from '../src/node_modules/fflate/esm/index.mjs'
import { installBuiltinAsset } from '../src/dist/builtin-assets.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-assets-'))
try {
  const content = 'console.log("fixture")\n'
  const archive = Buffer.from(zipSync({ 'juice-shop-fixture/build/app.js': Buffer.from(content) }))
  const sha256 = createHash('sha256').update(archive).digest('hex')
  const fixtureAsset = {
    url: 'https://fixture.invalid/juice-shop.zip',
    sha256,
    kind: 'zip',
    filename: 'juice-shop-20.2.0_node22_win32_x64.zip',
  }
  const fetchImpl = async () => new Response(archive, { status: 200, headers: { 'content-length': String(archive.length) } })
  const stages = []
  const manifest = await installBuiltinAsset({
    lab: {
      id: 'fixture', slug: 'juice-shop', title: 'OWASP Juice Shop', category: 'Web', difficulty: '中等', sourceType: 'git',
      sourceUrl: 'https://github.com/juice-shop/juice-shop', sourceRef: 'fixture', license: 'MIT', runtimeKind: 'native-node',
      providerId: 'native-node', builtin: true, version: 'fixture', status: 'importing', summary: '', tags: [], localPath: null,
      importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    },
    jobId: 'fixture-job',
    dataDir: root,
    fetchImpl,
    assetOverride: fixtureAsset,
    onProgress: (_progress, stage) => stages.push(stage),
  })
  assert.equal(await readFile(join(manifest.localPath, 'build', 'app.js'), 'utf8'), content)
  assert.equal(manifest.adapterId, 'builtin-release')
  assert.equal(manifest.archiveSha256, createHash('sha256').update(archive).digest('hex'))
  assert.equal(JSON.parse(await readFile(join(manifest.localPath, 'vulnlab.manifest.json'), 'utf8')).localPath, 'labs/juice-shop/fixture')
  await assert.rejects(stat(join(root, 'downloads')))
  assert.ok(stages.includes('download'))
  assert.ok(stages.includes('extract'))
  assert.ok(stages.includes('completed'))

  const bundleDir = join(root, 'bundle')
  const bundleArchive = join(bundleDir, 'labs', 'juice-shop', 'offline', 'juice-shop-20.2.0_node22_win32_x64.zip')
  await mkdir(join(bundleDir, 'labs', 'juice-shop', 'offline'), { recursive: true })
  await writeFile(bundleArchive, archive)
  const offlineManifest = await installBuiltinAsset({
    lab: {
      id: 'offline', slug: 'juice-shop', title: 'OWASP Juice Shop', category: 'Web', difficulty: '中等', sourceType: 'git',
      sourceUrl: 'https://github.com/juice-shop/juice-shop', sourceRef: 'fixture', license: 'MIT', runtimeKind: 'native-node',
      providerId: 'native-node', builtin: true, version: 'offline', status: 'importing', summary: '', tags: [], localPath: null,
      importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    },
    jobId: 'offline-job',
    dataDir: root,
    bundleDir,
    offline: true,
    assetOverride: fixtureAsset,
    fetchImpl: async () => { throw new Error('离线模式不应联网') },
  })
  assert.equal(await readFile(join(offlineManifest.localPath, 'build', 'app.js'), 'utf8'), content)

  const unsafeArchive = Buffer.from(zipSync({ '../outside.txt': Buffer.from('blocked') }))
  const unsafeSha256 = createHash('sha256').update(unsafeArchive).digest('hex')
  await assert.rejects(() => installBuiltinAsset({
    lab: { ...manifest, id: 'unsafe', slug: 'juice-shop', title: 'unsafe', category: 'Web', difficulty: '中等', sourceType: 'git', sourceUrl: '', license: '', runtimeKind: 'native-node', providerId: 'native-node', builtin: true, version: 'unsafe', status: 'importing', summary: '', tags: [], importedAt: null, createdAt: '', updatedAt: '' },
    jobId: 'unsafe-job',
    dataDir: root,
    fetchImpl: async () => new Response(unsafeArchive, { headers: { 'content-length': String(unsafeArchive.length) } }),
    assetOverride: { ...fixtureAsset, sha256: unsafeSha256 },
  }), /路径/)

  await assert.rejects(() => installBuiltinAsset({
    lab: { ...manifest, id: 'pinned', slug: 'juice-shop', version: '20.2.0', title: 'pinned', category: 'Web', difficulty: '中等', sourceType: 'git', sourceUrl: '', license: '', runtimeKind: 'native-node', providerId: 'native-node', builtin: true, status: 'importing', summary: '', tags: [], importedAt: null, createdAt: '', updatedAt: '' },
    jobId: 'pinned-job',
    dataDir: root,
    fetchImpl: async () => new Response(archive, { headers: { 'content-length': String(archive.length) } }),
  }), /SHA-256/)

  await assert.rejects(() => installBuiltinAsset({
    lab: {
      id: 'webgoat-hash', slug: 'webgoat', title: 'OWASP WebGoat', category: 'Web', difficulty: '中等', sourceType: 'git',
      sourceUrl: 'https://github.com/WebGoat/WebGoat', sourceRef: 'fixture', license: 'GPL-2.0-or-later', runtimeKind: 'native-java',
      providerId: 'native-java', builtin: true, version: '2023.8', status: 'importing', summary: '', tags: [], localPath: null,
      importedAt: null, createdAt: '', updatedAt: '',
    },
    jobId: 'webgoat-hash-job',
    dataDir: root,
    fetchImpl: async () => new Response(Buffer.from('unexpected jar'), { headers: { 'content-length': '14' } }),
  }), /SHA-256/)
  console.log('VulnLab builtin asset tests passed.')
} finally {
  await rm(root, { recursive: true, force: true })
}
