import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createConnection } from 'node:net'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { ProjectEnvironmentManager } from '../src/VulnLab/dist/project-environment.js'

const execute = promisify(execFile)
const root = await mkdtemp(join(tmpdir(), 'vulnlab-project-toolchains-smoke-'))
const manager = new ProjectEnvironmentManager({ dataDir: root, mysqlPort: 7430 })
const tcp = (host, port) => new Promise(resolve => {
  const socket = createConnection({ host, port })
  const finish = value => { socket.destroy(); resolve(value) }
  socket.once('connect', () => finish(true))
  socket.once('error', () => finish(false))
  socket.setTimeout(1000, () => finish(false))
})

try {
  const prepared = await manager.prepare(true, true)
  assert.equal(prepared.status.php.source, 'project')
  assert.equal(prepared.status.php.available, true)
  assert.equal(prepared.status.mysql.source, 'project')
  assert.equal(prepared.status.mysql.available, true)
  assert.equal(prepared.status.node.source, 'project')
  assert.equal(prepared.status.node.available, true)
  assert.equal(prepared.status.java.source, 'project')
  assert.equal(prepared.status.java.available, true)
  assert.equal(prepared.status.python.source, 'project')
  assert.equal(prepared.status.python.available, true)
  assert.ok(prepared.mysql)
  assert.equal(prepared.status.toolchains.every(item => item.state === 'ready' && item.sha256Verified), true)
  const node = await execute(prepared.nodeBinary, ['--version'])
  assert.match(node.stdout, /^v22\.23\.1/)
  const php = await execute(prepared.phpBinary, ['-c', prepared.phpIni, '-r', 'echo PHP_VERSION."|".(extension_loaded("mysqli")?"mysqli":"missing");'])
  assert.match(php.stdout, /^8\.3\.33\|mysqli$/)
  const mysql = await execute(prepared.mysql.mysqlBinary, [
    '--protocol=tcp', '--host', prepared.mysql.host, '--port', String(prepared.mysql.port), '--user', prepared.mysql.adminUser,
    '--batch', '--skip-column-names', '--execute', 'SELECT VERSION();',
  ], { env: { ...process.env, MYSQL_PWD: prepared.mysql.adminPassword } })
  assert.match(mysql.stdout, /^11\.4\.10-MariaDB/m)
  const java = await execute(prepared.javaBinary, ['-version'])
  assert.match(`${java.stdout} ${java.stderr}`, /21\.0\.12/)
  const python = await execute(prepared.pythonBinary, ['--version'])
  assert.match(python.stdout, /^Python 3\.11\.16/)
  const venvRoot = join(root, 'python-venv-check')
  await execute(prepared.pythonBinary, ['-m', 'venv', venvRoot])
  const venvPython = process.platform === 'win32' ? join(venvRoot, 'Scripts', 'python.exe') : join(venvRoot, 'bin', 'python')
  const pip = await execute(venvPython, ['-m', 'pip', '--version'])
  assert.match(pip.stdout, /^pip /)
  assert.equal(await tcp(prepared.mysql.host, prepared.mysql.port), true)
  await manager.stop()
  assert.equal(await tcp(prepared.mysql.host, prepared.mysql.port), false)
  console.log('VulnLab project toolchain smoke passed: PHP, MariaDB, Node.js, Java, Python venv, SHA-256, and process cleanup.')
} finally {
  await manager.stop().catch(() => undefined)
  await rm(root, { recursive: true, force: true })
}
