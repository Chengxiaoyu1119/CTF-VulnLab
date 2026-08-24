import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const { importVulnHubCatalog } = await import('../src/VulnLab/dist/vulnhub.js')
const sourceUrl = process.env.VULNLAB_VULNHUB_URL ?? 'https://www.vulnhub.com/'
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-vulnhub-smoke-'))

try {
  const manifest = await importVulnHubCatalog({
    sourceUrl,
    sourceRef: 'vulnhub.com',
    jobId: 'vulnhub-smoke',
    dataDir,
  })
  assert.equal(manifest.adapterId, 'vulnhub-catalog')
  assert.ok(manifest.fileCount > 0, 'VulnHub catalog has no machine entries')
  assert.match(manifest.archiveSha256, /^[a-f0-9]{64}$/)
  const catalog = JSON.parse(await readFile(resolve(manifest.localPath), 'utf8'))
  assert.ok(Array.isArray(catalog.entries))
  assert.ok(catalog.entries.every(entry => entry.title !== 'Details'), 'VulnHub catalog contains placeholder titles')
  assert.ok(catalog.entries.every(entry => entry.downloadUrls?.every(url => !url.endsWith('/checksum.txt'))), 'VulnHub catalog contains checksum links as machine downloads')
  assert.ok(catalog.entries.some(entry => entry.downloadUrls?.length > 0), 'VulnHub catalog has no download metadata')
  assert.ok(catalog.entries.some(entry => entry.md5 || entry.sha1), 'VulnHub catalog has no checksum metadata')
  console.log(`VulnLab VulnHub smoke passed: ${manifest.fileCount} machines, ${manifest.warnings.length} warnings, sha256 ${manifest.archiveSha256}.`)
} finally {
  await rm(dataDir, { recursive: true, force: true }).catch(() => undefined)
}
