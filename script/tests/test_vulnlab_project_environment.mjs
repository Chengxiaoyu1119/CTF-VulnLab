import assert from 'node:assert/strict'
import { mkdtemp, rm, stat, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { mysqlDataDirectoryMatches, ProjectEnvironmentManager } from '../../src/dist/project-environment.js'
import { RuntimeToolchainInstaller } from '../../src/dist/runtime-toolchains.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-project-environment-'))
try {
  const mysqlDataDir = join(root, 'runtime', 'mysql', 'data-mariadb')
  assert.equal(mysqlDataDirectoryMatches(`${mysqlDataDir}\\`, mysqlDataDir), true)
  assert.equal(mysqlDataDirectoryMatches(join(root, 'preview-primary-db', 'data-mariadb'), mysqlDataDir), false)
  assert.equal(mysqlDataDirectoryMatches('', mysqlDataDir), false)

  const manager = new ProjectEnvironmentManager({
    dataDir: root,
    phpBinary: 'vulnlab-missing-php',
    mysqlBinary: 'vulnlab-missing-mysql',
    mysqlServerBinary: 'vulnlab-missing-mysqld',
  })
  const prepared = await manager.prepare()
  assert.equal(prepared.status.php.source, 'missing')
  assert.equal(prepared.status.mysql.source, 'missing')
  assert.equal(prepared.status.mysql.available, false)
  assert.equal(prepared.status.node.available, true)
  assert.equal(await (await stat(join(root, 'runtime'))).isDirectory(), true)
  assert.strictEqual(await manager.prepare(), prepared)
  await manager.stop()

  const external = new ProjectEnvironmentManager({
    dataDir: root,
    phpBinary: 'vulnlab-missing-php',
    mysqlConfig: { host: '127.0.0.1', port: 1, adminUser: 'fixture', adminPassword: 'fixture', appHost: '127.0.0.1', mysqlBinary: 'mysql' },
  })
  const externalPrepared = await external.prepare()
  assert.equal(externalPrepared.status.mysql.source, 'external')
  assert.equal(externalPrepared.status.mysql.managed, false)
  assert.equal(externalPrepared.mysql?.adminUser, 'fixture')
  await external.stop()

  const mariadbRoot = join(import.meta.dirname, '..', '..', 'src', 'data', 'runtime', 'toolchains', 'mariadb', '11.4.10', 'win32-x64', 'bin')
  const mariadbServer = join(mariadbRoot, 'mariadbd.exe')
  const mariadbClient = join(mariadbRoot, 'mariadb.exe')
  if (await stat(mariadbServer).then(item => item.isFile()).catch(() => false)
    && await stat(mariadbClient).then(item => item.isFile()).catch(() => false)) {
    const probe = createServer()
    const port = await new Promise((resolve, reject) => {
      probe.once('error', reject)
      probe.listen(0, '127.0.0.1', () => {
        const address = probe.address()
        probe.close(error => error ? reject(error) : resolve(typeof address === 'object' && address ? address.port : 0))
      })
    })
    const collisionData = join(root, 'port-collision')
    const first = new ProjectEnvironmentManager({ dataDir: collisionData, mysqlBinary: mariadbClient, mysqlServerBinary: mariadbServer, nodeBinary: process.execPath, mysqlPort: port })
    const firstPrepared = await first.prepare()
    assert.ok(firstPrepared.mysql && firstPrepared.status.mysql.available)
    await first.stop()
    await writeFile(join(collisionData, 'runtime', 'mysql', 'mariadb-runtime.json'), JSON.stringify({
      host: '127.0.0.1',
      port,
      adminUser: firstPrepared.mysql.adminUser,
      adminPassword: firstPrepared.mysql.adminPassword,
      dataDir: join(collisionData, 'runtime', 'mysql', 'data-mariadb'),
      initializedAt: new Date().toISOString(),
      pid: Number.MAX_SAFE_INTEGER,
    }), 'utf8')

    const foreign = createServer(socket => socket.end())
    await new Promise((resolve, reject) => {
      foreign.once('error', reject)
      foreign.listen(port, '127.0.0.1', resolve)
    })
    const second = new ProjectEnvironmentManager({ dataDir: collisionData, mysqlBinary: mariadbClient, mysqlServerBinary: mariadbServer, nodeBinary: process.execPath, mysqlPort: port })
    try {
      const secondPrepared = await second.prepare(true)
      assert.ok(secondPrepared.mysql && secondPrepared.status.mysql.available)
      assert.notEqual(secondPrepared.mysql.port, port)
      assert.equal(foreign.listening, true)
    } finally {
      await second.stop()
      await new Promise(resolve => foreign.close(resolve))
    }
  }

  const originalInstallMissing = RuntimeToolchainInstaller.prototype.installMissing
  RuntimeToolchainInstaller.prototype.installMissing = async () => {
    throw new Error('fixture toolchain download failed')
  }
  const failed = new ProjectEnvironmentManager({ dataDir: join(root, 'failed') })
  try {
    await assert.rejects(failed.prepare(true, true), /fixture toolchain download failed/)
  } finally {
    await failed.stop()
    RuntimeToolchainInstaller.prototype.installMissing = originalInstallMissing
  }
  console.log('VulnLab project environment test passed: project paths, missing dependencies, cache, and external override.')
} finally {
  await rm(root, { recursive: true, force: true })
}
