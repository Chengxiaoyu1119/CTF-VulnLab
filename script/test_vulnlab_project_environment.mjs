import assert from 'node:assert/strict'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { ProjectEnvironmentManager } from '../src/VulnLab/dist/project-environment.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-project-environment-'))
try {
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
  console.log('VulnLab project environment test passed: project paths, missing dependencies, cache, and external override.')
} finally {
  await rm(root, { recursive: true, force: true })
}
