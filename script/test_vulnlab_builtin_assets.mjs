import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { gzipSync } from 'node:zlib'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { zipSync } from '../src/VulnLab/node_modules/fflate/esm/index.mjs'
import { installBuiltinAsset } from '../src/VulnLab/dist/builtin-assets.js'

const tarArchive = (name, contents) => {
  const body = Buffer.from(contents)
  const header = Buffer.alloc(512)
  header.write(name, 0, 100, 'utf8')
  header.write('0000644\0', 100, 8, 'ascii')
  header.write('0000000\0', 108, 8, 'ascii')
  header.write('0000000\0', 116, 8, 'ascii')
  header.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
  header.write('00000000000\0', 136, 12, 'ascii')
  header.fill(0x20, 148, 156)
  header.write('0', 156, 1, 'ascii')
  header.write('ustar\0', 257, 6, 'ascii')
  header.write('00', 263, 2, 'ascii')
  const checksum = header.reduce((sum, byte) => sum + byte, 0)
  header.write(`${checksum.toString(8).padStart(6, '0')}\0 `, 148, 8, 'ascii')
  const padding = Buffer.alloc((512 - body.length % 512) % 512)
  return gzipSync(Buffer.concat([header, body, padding, Buffer.alloc(1024)]))
}

const root = await mkdtemp(join(tmpdir(), 'vulnlab-assets-'))
try {
  const content = 'console.log("fixture")\n'
  const archive = process.platform === 'win32'
    ? Buffer.from(zipSync({ 'juice-shop-fixture/build/app.js': Buffer.from(content) }))
    : tarArchive('juice-shop-fixture/build/app.js', content)
  const md5 = createHash('md5').update(archive).digest('hex')
  const fetchImpl = async url => String(url).endsWith('.md5')
    ? new Response(md5, { status: 200, headers: { 'content-type': 'text/plain' } })
    : new Response(archive, { status: 200, headers: { 'content-length': String(archive.length) } })
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
    onProgress: (_progress, stage) => stages.push(stage),
  })
  assert.equal(await readFile(join(manifest.localPath, 'build', 'app.js'), 'utf8'), content)
  assert.equal(manifest.adapterId, 'builtin-release')
  assert.equal(manifest.archiveSha256, createHash('sha256').update(archive).digest('hex'))
  assert.ok(stages.includes('download'))
  assert.ok(stages.includes('extract'))
  assert.ok(stages.includes('completed'))

  const unsafeArchive = process.platform === 'win32'
    ? Buffer.from(zipSync({ '../outside.txt': Buffer.from('blocked') }))
    : tarArchive('../outside.txt', 'blocked')
  const unsafeMd5 = createHash('md5').update(unsafeArchive).digest('hex')
  await assert.rejects(() => installBuiltinAsset({
    lab: { ...manifest, id: 'unsafe', slug: 'juice-shop', title: 'unsafe', category: 'Web', difficulty: '中等', sourceType: 'git', sourceUrl: '', license: '', runtimeKind: 'native-node', providerId: 'native-node', builtin: true, version: 'unsafe', status: 'importing', summary: '', tags: [], importedAt: null, createdAt: '', updatedAt: '' },
    jobId: 'unsafe-job',
    dataDir: root,
    fetchImpl: async url => String(url).endsWith('.md5') ? new Response(unsafeMd5) : new Response(unsafeArchive, { headers: { 'content-length': String(unsafeArchive.length) } }),
  }), /路径/)

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
