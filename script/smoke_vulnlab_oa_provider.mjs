import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { randomUUID } from 'node:crypto'
import { createServer } from 'node:net'
import { mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { unzipSync } from '../src/node_modules/fflate/esm/index.mjs'
import { NativeOaProvider } from '../src/dist/providers.js'
import { mysqlResourceNames } from '../src/dist/mysql.js'
import { ProjectEnvironmentManager } from '../src/dist/project-environment.js'

const appDir = resolve(import.meta.dirname, '..', 'src')
const appDataDir = join(appDir, 'data')
const dataDir = join(appDataDir, `.oa-provider-smoke-${randomUUID()}`)
const projectNodeRoot = await realpath(join(appDataDir, 'runtime', 'toolchains', 'node'))
const projectMariaRoot = await realpath(join(appDataDir, 'runtime', 'toolchains', 'mariadb'))
const mariaSource = join(projectMariaRoot, '11.4.10', 'win32-x64')
const archivePath = join(appDir, 'assets', 'labs', 'oa-vuln-labs', '1.0.0-beta', 'source.zip')
const instanceId = `oa-smoke-${randomUUID().replaceAll('-', '').slice(0, 16)}`
const sourceRoot = join(dataDir, 'labs', 'oa-vuln-labs', 'smoke')
const toolchainRoot = join(dataDir, 'runtime', 'toolchains')
const nodeAliasRoot = join(toolchainRoot, 'node')
const mariaAliasRoot = join(toolchainRoot, 'mariadb')
const nodeBinary = join(nodeAliasRoot, '22.23.1', 'win32-x64', 'node.exe')
const mysqlBinary = join(mariaAliasRoot, '11.4.10', 'win32-x64', 'bin', 'mariadb.exe')
const mysqlServerBinary = join(mariaAliasRoot, '11.4.10', 'win32-x64', 'bin', 'mariadbd.exe')

const port = await new Promise((resolvePort, reject) => {
  const server = createServer()
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? reject(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
  })
})

const environment = new ProjectEnvironmentManager({ dataDir, mysqlBinary, mysqlServerBinary, nodeBinary, mysqlPort: port, offline: true })
const provider = new NativeOaProvider()
let runtimeConfig
let started
let adminPool
let lab

try {
  await mkdir(toolchainRoot, { recursive: true })
  await symlink(projectNodeRoot, nodeAliasRoot, 'junction')
  await symlink(projectMariaRoot, mariaAliasRoot, 'junction')
  const archive = unzipSync(await readFile(archivePath))
  await mkdir(sourceRoot, { recursive: true })
  for (const [name, bytes] of Object.entries(archive)) {
    const normalized = name.replaceAll('\\', '/')
    const segments = normalized.split('/').filter(Boolean)
    if (!segments.length || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || segments.some(segment => segment === '.' || segment === '..' || segment.includes(':'))) throw new Error(`Unsafe packaged asset path: ${name}`)
    const path = join(sourceRoot, ...segments)
    if (normalized.endsWith('/')) await mkdir(path, { recursive: true })
    else {
      await mkdir(join(path, '..'), { recursive: true })
      await writeFile(path, bytes)
    }
  }

  const prepared = await environment.prepare(true, false)
  assert.ok(prepared.mysql && environment.getStatus().mysql.managed && environment.getStatus().mysql.available)
  runtimeConfig = {
    bindHost: '0.0.0.0', portStart: 6800, portEnd: 6899,
    phpBinary: 'php', nodeBinary, oaNodeBinary: nodeBinary, javaBinary: 'java', pythonBinary: 'python',
    mysql: prepared.mysql, mysqlManaged: true,
  }
  lab = {
    id: 'lab-oa-smoke', slug: 'oa-vuln-labs', title: 'OA Smoke', category: 'Web', difficulty: '中等',
    sourceType: 'archive', sourceUrl: 'bundle://oa-vuln-labs/source.zip', sourceRef: 'smoke', license: '未声明',
    runtimeKind: 'native-oa', providerId: 'oa-project', builtin: true, version: 'smoke', status: 'ready',
    summary: 'provider smoke fixture', tags: ['Web'], localPath: sourceRoot, importedAt: null,
    createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }
  started = await provider.start({
    instanceId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir, runtime: runtimeConfig,
  })
  const baseUrl = started.endpoint.replace(/\/$/, '')
  const page = await fetch(started.endpoint)
  assert.equal(page.status, 200)
  const html = await page.text()
  assert.match(html, /<div id="root"><\/div>/)
  assert.match(html, /\/assets\/index-[^" ]+\.js/)
  const scriptPath = html.match(/src="([^"]+\.js)"/)?.[1]
  assert.ok(scriptPath)
  assert.equal((await fetch(new URL(scriptPath, started.endpoint))).status, 200)
  const info = await fetch(`${baseUrl}/api/debug/env`)
  assert.equal(info.status, 200)
  assert.match((await info.json()).data.cwd, /oa-smoke-/)

  const login = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'ZSD@admin2025!' }),
  })
  assert.equal(login.status, 200)
  const adminToken = (await login.json()).data.token
  assert.ok(adminToken)

  const sendReset = await fetch(`${baseUrl}/api/auth/send-reset-code`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'admin@company.com' }),
  })
  assert.equal(sendReset.status, 200)
  assert.equal((await sendReset.json()).data.code, '123456')
  const reset = await fetch(`${baseUrl}/api/auth/reset-password`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', email: 'admin@company.com', code: '123456', password: 'smoke-reset-password' }),
  })
  assert.equal(reset.status, 200)
  assert.equal((await reset.json()).code, 0)

  const sameInstance = await fetch(`${baseUrl}/api/system/check-url`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ url: `${baseUrl}/api/debug/env` }),
  })
  assert.equal(sameInstance.status, 200)
  assert.equal((await sameInstance.json()).data.status, 200)

  const other = await new Promise((resolvePort, reject) => {
    const server = createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close(error => error ? reject(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
    })
  })
  const denied = await fetch(`${baseUrl}/api/system/check-url`, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${adminToken}` },
    body: JSON.stringify({ url: `http://127.0.0.1:${other}/` }),
  })
  assert.equal(denied.status, 403)
  assert.match((await denied.json()).message, /本实例 Web/)

  const require = createRequire(new URL('../src/package.json', import.meta.url))
  adminPool = require('mysql2/promise').createPool({ host: prepared.mysql.host, port: prepared.mysql.port, user: prepared.mysql.adminUser, password: prepared.mysql.adminPassword, connectionLimit: 1 })
  const databaseName = mysqlResourceNames(lab.slug, instanceId).database
  await provider.stop({ lab, instance: { id: instanceId, labId: lab.id, labTitle: lab.title, provider: 'oa-project', endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }, runtime: runtimeConfig, dataDir })
  assert.equal((await fetch(`${baseUrl}/api/debug/env`).catch(() => null)), null, 'stopped OA endpoint is closed')
  assert.equal(await import('node:fs/promises').then(fs => fs.stat(join(dataDir, 'runtime', instanceId)).then(() => true, () => false)), false, 'instance directory is removed')
  const [remaining] = await adminPool.query('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?', [databaseName])
  assert.equal(remaining.length, 0, 'instance database is removed')
  console.log(`VulnLab OA provider smoke passed: browser entry and compiled frontend, project Node/MariaDB, login, cached password reset, same-instance SSRF, cross-port rejection, and complete stop cleanup on ${new URL(started.endpoint).port}.`)
} finally {
  await adminPool?.end().catch(() => undefined)
  if (started && lab && runtimeConfig) {
    await provider.stop({ lab, instance: { id: instanceId, labId: lab.id, labTitle: lab.title, provider: 'oa-project', endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }, runtime: runtimeConfig, dataDir }).catch(() => undefined)
  }
  await provider.shutdown().catch(() => undefined)
  await environment.stop().catch(() => undefined)
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
