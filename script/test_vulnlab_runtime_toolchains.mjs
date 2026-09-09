import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { zipSync, strToU8 } from '../src/node_modules/fflate/esm/index.mjs'
import { RuntimeToolchainInstaller } from '../src/dist/runtime-toolchains.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-runtime-toolchains-'))
try {
  const archive = zipSync({
    'php.exe': strToU8('fixture-php'),
    'ext/php_mysqli.dll': strToU8('fixture-extension'),
  })
  const sha256 = createHash('sha256').update(archive).digest('hex')
  const fixturePackage = {
    id: 'php',
    label: 'PHP Fixture',
    version: '8.3-fixture',
    platform: 'win32',
    arch: 'x64',
    url: 'https://fixture.invalid/php.zip',
    sha256,
    filename: 'php-fixture.zip',
    kind: 'zip',
    stripComponents: 0,
    maxArchiveBytes: 1024 * 1024,
    maxExtractedBytes: 1024 * 1024,
    executables: { php: 'php.exe' },
  }
  const nodeArchive = zipSync({
    'node.exe': strToU8('fixture-node'),
  })
  const nodeFixturePackage = {
    id: 'node',
    label: 'Node.js Fixture',
    version: '22-fixture',
    platform: 'win32',
    arch: 'x64',
    url: 'https://fixture.invalid/node.zip',
    sha256: createHash('sha256').update(nodeArchive).digest('hex'),
    filename: 'node-fixture.zip',
    kind: 'zip',
    stripComponents: 0,
    maxArchiveBytes: 1024 * 1024,
    maxExtractedBytes: 1024 * 1024,
    executables: { node: 'node.exe' },
  }
  const installer = new RuntimeToolchainInstaller(join(root, 'runtime'), {
    packages: [fixturePackage, nodeFixturePackage],
    fetchImpl: async url => url.endsWith('node.zip')
      ? new Response(nodeArchive, { status: 200, headers: { 'content-length': String(nodeArchive.byteLength) } })
      : new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } }),
  })
  let statuses = await installer.inspect()
  assert.equal(statuses[0]?.state, 'missing')
  statuses = await installer.installMissing()
  assert.equal(statuses[0]?.state, 'ready')
  assert.equal(statuses[0]?.sha256Verified, true)
  assert.ok((statuses[0]?.installedBytes ?? 0) > 0)
  const binaries = await installer.binaries()
  assert.equal(await readFile(binaries.php, 'utf8'), 'fixture-php')
  assert.equal(await readFile(binaries.node, 'utf8'), 'fixture-node')
  assert.equal((await stat(join(root, 'runtime', 'downloads'))).isDirectory(), true)

  const fresh = new RuntimeToolchainInstaller(join(root, 'runtime'), {
    packages: [fixturePackage], fetchImpl: async () => { throw new Error('不应重复下载') },
  })
  assert.equal((await fresh.inspect())[0]?.state, 'ready')
  const manifestPath = join(root, 'runtime', 'manifests', `php-${fixturePackage.version}-win32-x64.json`)
  const manifest = await readFile(manifestPath, 'utf8')
  await writeFile(manifestPath, `\uFEFF${manifest}`, 'utf8')
  const bomManifest = new RuntimeToolchainInstaller(join(root, 'runtime'), {
    packages: [fixturePackage], fetchImpl: async () => { throw new Error('不应重复下载带 BOM 的清单') },
  })
  assert.equal((await bomManifest.inspect())[0]?.state, 'ready')

  const badRoot = join(root, 'bad-checksum')
  const bad = new RuntimeToolchainInstaller(badRoot, {
    packages: [{ ...fixturePackage, sha256: '0'.repeat(64) }],
    fetchImpl: async () => new Response(archive, { status: 200 }),
  })
  await assert.rejects(bad.installMissing(), /SHA-256 校验失败/)
  assert.equal(bad.getStatuses()[0]?.state, 'error')
  await assert.rejects(stat(join(badRoot, 'toolchains', 'php', fixturePackage.version, 'win32-x64', 'php.exe')))

  const bundleRoot = join(root, 'bundle')
  await mkdir(join(bundleRoot, 'runtime'), { recursive: true })
  await writeFile(join(bundleRoot, 'runtime', fixturePackage.filename), archive)
  const offline = new RuntimeToolchainInstaller(join(root, 'offline-runtime'), {
    packages: [fixturePackage],
    bundleDir: bundleRoot,
    offline: true,
    fetchImpl: async () => { throw new Error('离线模式不应联网') },
  })
  assert.equal((await offline.installMissing())[0]?.state, 'ready')
  assert.equal(await readFile((await offline.binaries()).php, 'utf8'), 'fixture-php')

  const offlineMissing = new RuntimeToolchainInstaller(join(root, 'offline-missing'), {
    packages: [fixturePackage],
    offline: true,
    fetchImpl: async () => { throw new Error('离线模式不应联网') },
  })
  await assert.rejects(offlineMissing.installMissing(), /离线模式未找到/)

  console.log('VulnLab Windows runtime toolchain test passed: ZIP/TGZ download, checksum, safe extraction, manifest reuse, and failure cleanup.')
} finally {
  await rm(root, { recursive: true, force: true })
}
