import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const { downloadVmImage, vmDownloadInternals } = await import(new URL('../src/VulnLab/dist/vm-download.js', import.meta.url))
const { VulnLabDatabase } = await import(new URL('../src/VulnLab/dist/db.js', import.meta.url))

const payload = new TextEncoder().encode('VulnLab VM fixture')
const md5 = createHash('md5').update(payload).digest('hex')
const sha1 = createHash('sha1').update(payload).digest('hex')
const sha256 = createHash('sha256').update(payload).digest('hex')
const entry = {
  title: 'Fixture Earth',
  url: 'https://www.vulnhub.com/entry/fixture-earth,1/',
  author: 'Fixture',
  difficulty: 'Easy',
  downloadUrls: ['https://download.vulnhub.com/fixture/Earth.ova'],
  filename: 'Earth.ova',
  fileSize: `${payload.byteLength} B`,
  md5,
  sha1,
}

const createDownload = overrides => ({
  id: 'download-fixture-1',
  labId: 'lab-fixture-1',
  entryIndex: 0,
  title: entry.title,
  sourceUrl: entry.url,
  downloadUrl: entry.downloadUrls[0],
  filename: entry.filename,
  status: 'downloading',
  message: 'fixture',
  progress: 0,
  bytesDownloaded: 0,
  totalBytes: null,
  expectedMd5: entry.md5,
  expectedSha1: entry.sha1,
  sha256: null,
  localPath: null,
  error: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...overrides,
})

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-vm-download-'))
try {
  const progress = []
  const result = await downloadVmImage({
    download: createDownload(),
    entry,
    dataDir,
    maxBytes: 1024 * 1024,
    fetchImpl: async () => new Response(payload, { status: 200, headers: { 'content-length': String(payload.byteLength) } }),
    onProgress: value => progress.push(value),
  })
  assert.equal(result.bytesDownloaded, payload.byteLength)
  assert.equal(result.md5, md5)
  assert.equal(result.sha1, sha1)
  assert.equal(result.sha256, sha256)
  assert.equal(result.checksumVerified, true)
  assert.deepEqual(await readFile(result.localPath), Buffer.from(payload))
  assert.ok(progress.at(-1)?.message)

  await assert.rejects(
    downloadVmImage({
      download: createDownload({ id: 'download-fixture-oversize' }),
      entry,
      dataDir,
      maxBytes: payload.byteLength - 1,
      fetchImpl: async () => new Response(payload, { status: 200, headers: { 'content-length': String(payload.byteLength) } }),
    }),
    /超过大小上限/,
  )

  let vmBodyCancelled = false
  const oversizedResponse = new Response(new ReadableStream({
    start(controller) { controller.enqueue(payload) },
    cancel() { vmBodyCancelled = true },
  }), { status: 200, headers: { 'content-length': String(payload.byteLength) } })
  await assert.rejects(
    downloadVmImage({
      download: createDownload({ id: 'download-fixture-oversize-stream' }),
      entry,
      dataDir,
      maxBytes: payload.byteLength - 1,
      fetchImpl: async () => oversizedResponse,
    }),
    /超过大小上限/,
  )
  assert.equal(vmBodyCancelled, true)

  await assert.rejects(
    downloadVmImage({
      download: createDownload({ id: 'download-fixture-mismatch' }),
      entry: { ...entry, sha1: '0'.repeat(40) },
      dataDir,
      maxBytes: 1024 * 1024,
      fetchImpl: async () => new Response(payload, { status: 200, headers: { 'content-length': String(payload.byteLength) } }),
    }),
    /SHA1 校验失败/,
  )
  assert.deepEqual((await readdir(join(dataDir, 'vm-images', 'lab-fixture-1'))).sort(), ['001-Earth.ova'])
  assert.equal(vmDownloadInternals.officialDownloadUrl(entry.downloadUrls[0]), entry.downloadUrls[0])
  assert.throws(() => vmDownloadInternals.officialDownloadUrl('https://example.com/Earth.ova'), /官方 HTTPS/)
} finally {
  await rm(dataDir, { recursive: true, force: true })
}

const databaseDir = await mkdtemp(join(tmpdir(), 'vulnlab-vm-download-db-'))
const database = new VulnLabDatabase(databaseDir)
try {
  const lab = database.getLabBySlug('vulnhub')
  assert.ok(lab)
  const queued = database.createVmDownload({ labId: lab.id, entryIndex: 0, title: entry.title, sourceUrl: entry.url, downloadUrl: entry.downloadUrls[0], filename: entry.filename, expectedMd5: entry.md5, expectedSha1: entry.sha1 })
  assert.equal(queued.status, 'queued')
  const claimed = database.claimVmDownload(queued.id)
  assert.equal(claimed?.status, 'downloading')
  database.updateVmDownload(queued.id, { progress: 50, bytesDownloaded: 9, totalBytes: payload.byteLength, message: 'fixture progress' })
  const completed = database.completeVmDownload(queued.id, { localPath: 'C:/fixture/Earth.ova', sha256, actualMd5: md5, actualSha1: sha1, checksumVerified: true, bytesDownloaded: payload.byteLength, totalBytes: payload.byteLength, message: 'fixture complete' })
  assert.equal(completed?.status, 'completed')
  assert.equal(completed?.checksumVerified, true)
  assert.equal(completed?.actualSha1, sha1)
} finally {
  database.close()
  await rm(databaseDir, { recursive: true, force: true })
}

console.log('VulnLab VM download test passed: size gate, official-host gate, disk-safe file write and MD5/SHA1/SHA-256 verification.')
