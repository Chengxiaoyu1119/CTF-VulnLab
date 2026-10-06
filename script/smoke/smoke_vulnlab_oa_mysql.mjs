import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import { mkdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { strFromU8, unzipSync } from '../../src/node_modules/fflate/esm/index.mjs'
import { CliMySqlManager } from '../../src/dist/mysql.js'
import { ProjectEnvironmentManager } from '../../src/dist/project-environment.js'
import { adaptOaSeed } from '../../src/dist/oa/seed.js'

const appDir = resolve(import.meta.dirname, '..', '..', 'src')
const require = createRequire(new URL('../../src/package.json', import.meta.url))
const createPool = require('mysql2/promise').createPool
const dataDir = join(tmpdir(), `vulnlab-oa-mysql-smoke-${randomUUID()}`)
const mariadbRoot = join(appDir, 'data', 'runtime', 'toolchains', 'mariadb', '11.4.10', 'win32-x64')
const mysqlServerBinary = join(mariadbRoot, 'bin', 'mariadbd.exe')
const mysqlBinary = join(mariadbRoot, 'bin', 'mariadb.exe')
const port = await new Promise((resolvePort, reject) => {
  const server = createServer()
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? reject(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
  })
})

const environment = new ProjectEnvironmentManager({ dataDir, mysqlBinary, mysqlServerBinary, nodeBinary: process.execPath, mysqlPort: port, offline: true })
const manager = new CliMySqlManager()
let resource
let pool
try {
  await mkdir(dataDir, { recursive: true })
  const prepared = await environment.prepare(true, false)
  const mysqlStatus = environment.getStatus().mysql
  assert.ok(prepared.mysql && mysqlStatus.managed && mysqlStatus.available, mysqlStatus.detail)
  assert.equal(prepared.mysql.host, '127.0.0.1')
  resource = await manager.provision({ labSlug: 'oa-vuln-labs', instanceId: 'smoke-test', config: prepared.mysql })
  const archivePath = join(appDir, 'assets', 'labs', 'oa-vuln-labs', '1.0.0-beta', 'source.zip')
  const archive = unzipSync(await readFile(archivePath))
  const seedEntry = Object.entries(archive).find(([name]) => name.replaceAll('\\', '/').endsWith('database/init.sql'))
  assert.ok(seedEntry, 'OA SQL seed exists in the packaged asset')
  const seed = adaptOaSeed(strFromU8(seedEntry[1]))
  await manager.initializeSql(resource, seed)
  await manager.verify(resource)
  pool = createPool({ host: resource.host, port: resource.port, user: resource.user, password: resource.password, database: resource.database, connectionLimit: 2 })
  const [users] = await pool.query('SELECT username FROM users ORDER BY id')
  assert.deepEqual(users.map(user => user.username), ['admin', 'manager', 'user', 'zhangsan', 'lisi', 'test'])
  const [counts] = await pool.query('SELECT (SELECT COUNT(*) FROM departments) departments,(SELECT COUNT(*) FROM announcements) announcements,(SELECT COUNT(*) FROM tickets) tickets,(SELECT COUNT(*) FROM approvals) approvals,(SELECT COUNT(*) FROM notification_templates) templates')
  for (const [name, count] of Object.entries(counts[0])) assert.ok(Number(count) > 0, `${name} seed data exists`)
  console.log(`VulnLab OA MariaDB smoke passed: isolated MariaDB ${port}, 6 default users and business seed counts ${JSON.stringify(counts[0])}.`)
} finally {
  await pool?.end().catch(() => undefined)
  if (resource) await manager.destroy(resource).catch(() => undefined)
  await environment.stop().catch(() => undefined)
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
