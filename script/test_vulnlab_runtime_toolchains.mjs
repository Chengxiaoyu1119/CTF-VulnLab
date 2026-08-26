import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFile as execFileCallback } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { zipSync, strToU8 } from '../src/VulnLab/node_modules/fflate/esm/index.mjs'
import { RuntimeToolchainInstaller } from '../src/VulnLab/dist/runtime-toolchains.js'

const execFile = promisify(execFileCallback)
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
    platform: 'win32',
    arch: 'x64',
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

  const tarSource = join(root, 'tar-source', 'node-v22-fixture')
  await mkdir(join(tarSource, 'bin'), { recursive: true })
  await writeFile(join(tarSource, 'bin', 'node'), 'fixture-linux-node', 'utf8')
  const tarArchivePath = join(root, 'node-fixture.tar.xz')
  await execFile('tar', ['-cJf', tarArchivePath, '-C', join(root, 'tar-source'), 'node-v22-fixture'])
  const tarArchive = await readFile(tarArchivePath)
  const linuxFixturePackage = {
    id: 'node',
    label: 'Node.js Linux Fixture',
    version: '22-linux-fixture',
    platform: 'linux',
    arch: 'x64',
    url: 'https://fixture.invalid/node.tar.xz',
    sha256: createHash('sha256').update(tarArchive).digest('hex'),
    filename: 'node-linux-fixture.tar.xz',
    kind: 'txz',
    stripComponents: 1,
    maxArchiveBytes: 1024 * 1024,
    maxExtractedBytes: 1024 * 1024,
    executables: { node: 'bin/node' },
  }
  const linuxInstaller = new RuntimeToolchainInstaller(join(root, 'linux-runtime'), {
    platform: 'linux',
    arch: 'x64',
    packages: [linuxFixturePackage],
    fetchImpl: async () => new Response(tarArchive, { status: 200, headers: { 'content-length': String(tarArchive.byteLength) } }),
  })
  const linuxStatuses = await linuxInstaller.installMissing()
  assert.equal(linuxStatuses[0]?.state, 'ready')
  assert.equal(linuxStatuses[0]?.sha256Verified, true)
  const linuxBinaries = await linuxInstaller.binaries()
  assert.equal(await readFile(linuxBinaries.node, 'utf8'), 'fixture-linux-node')

  const fresh = new RuntimeToolchainInstaller(join(root, 'runtime'), {
    platform: 'win32', arch: 'x64', packages: [fixturePackage], fetchImpl: async () => { throw new Error('不应重复下载') },
  })
  assert.equal((await fresh.inspect())[0]?.state, 'ready')
  const manifestPath = join(root, 'runtime', 'manifests', `php-${fixturePackage.version}-win32-x64.json`)
  const manifest = await readFile(manifestPath, 'utf8')
  await writeFile(manifestPath, `\uFEFF${manifest}`, 'utf8')
  const bomManifest = new RuntimeToolchainInstaller(join(root, 'runtime'), {
    platform: 'win32', arch: 'x64', packages: [fixturePackage], fetchImpl: async () => { throw new Error('不应重复下载带 BOM 的清单') },
  })
  assert.equal((await bomManifest.inspect())[0]?.state, 'ready')

  const badRoot = join(root, 'bad-checksum')
  const bad = new RuntimeToolchainInstaller(badRoot, {
    platform: 'win32', arch: 'x64', packages: [{ ...fixturePackage, sha256: '0'.repeat(64) }],
    fetchImpl: async () => new Response(archive, { status: 200 }),
  })
  await assert.rejects(bad.installMissing(), /SHA-256 校验失败/)
  assert.equal(bad.getStatuses()[0]?.state, 'error')
  await assert.rejects(stat(join(badRoot, 'toolchains', 'php', fixturePackage.version, 'win32-x64', 'php.exe')))

  console.log('VulnLab runtime toolchain test passed: ZIP/TAR.XZ download, checksum, safe extraction, manifest reuse, and failure cleanup.')
} finally {
  await rm(root, { recursive: true, force: true })
}
