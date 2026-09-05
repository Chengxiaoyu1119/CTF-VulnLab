import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativePhpProvider, NativeProcessProvider, ProviderError, ProviderRegistry } from '../src/VulnLab/dist/providers.js'

const lab = {
  id: 'lab-dvwa',
  slug: 'dvwa',
  title: 'DVWA',
  category: 'Web',
  difficulty: '入门',
  sourceType: 'git',
  sourceUrl: 'https://github.com/digininja/DVWA',
  sourceRef: 'digininja/DVWA@fixture',
  license: 'GPL-3.0',
  runtimeKind: 'native-php',
  providerId: 'native-php',
  builtin: true,
  version: 'fixture',
  status: 'cataloged',
  summary: 'fixture',
  tags: ['Web'],
  localPath: null,
  importedAt: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
}

const native = new NativePhpProvider()
const nativeNode = new NativeProcessProvider('native-node')
const nativeJava = new NativeProcessProvider('native-java')
const nativePython = new NativeProcessProvider('native-python')
const registry = new ProviderRegistry([native, nativeNode, nativeJava, nativePython])

assert.equal(registry.get('native-php'), native)
assert.equal(registry.resolve('native-php', 'native-php'), native)
assert.equal(registry.resolve('native-node', 'native-node'), nativeNode)
assert.equal(registry.resolve('native-java', 'native-java'), nativeJava)
assert.equal(registry.resolve('native-python', 'native-python'), nativePython)
assert.throws(() => registry.resolve('native-php', 'native-node'), error => error instanceof ProviderError && error.code === 'PROVIDER_RUNTIME_UNSUPPORTED')
assert.throws(() => registry.resolve('missing', 'native-php'), error => error instanceof ProviderError && error.code === 'PROVIDER_NOT_FOUND')
assert.throws(() => new ProviderRegistry([native, native]), /Provider ID 重复/)

const instance = {
  id: 'instance-1', labId: lab.id, labTitle: lab.title, provider: 'native-php', endpoint: 'http://127.0.0.1:6800/', status: 'running',
  createdAt: new Date(Date.now() - 60_000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(), logs: [],
}
const recoveries = []
const managedNative = new NativePhpProvider({
  mysqlManager: {
    provision: async () => { throw new Error('not used in recovery fixture') },
    verify: async () => undefined,
    destroy: async () => undefined,
    destroyForInstance: async input => { recoveries.push(input) },
  },
})
const mysqlConfig = { host: '127.0.0.1', port: 3306, adminUser: 'admin', adminPassword: 'secret', appHost: '127.0.0.1', mysqlBinary: 'mysql' }
await managedNative.recover({ lab, instance, runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', mysql: mysqlConfig } })
assert.equal(recoveries.length, 1)
assert.equal(recoveries[0].labSlug, 'dvwa')
assert.equal(recoveries[0].instanceId, instance.id)

const xvwaRoot = await mkdtemp(join(tmpdir(), 'vulnlab-xvwa-provider-'))
try {
  const sourceRoot = join(xvwaRoot, 'labs', 'xvwa', 'fixture')
  await mkdir(join(sourceRoot, 'setup'), { recursive: true })
  await writeFile(join(sourceRoot, 'config.php'), '<?php $host = "localhost"; $conn = new mysqli($host); ?>\n')
  await writeFile(join(sourceRoot, 'setup', 'home.php'), "<?php $sql = 'DROP TABLE '. $tables[$i].';'; echo mysql_error(); ?>\n")
  const databaseCalls = []
  const phpSpawn = (_binary, args, options) => {
    const serverArg = args[args.indexOf('-S') + 1]
    const port = Number(serverArg.split(':').at(-1))
    const script = "const { createServer } = require('node:http'); const port = Number(process.argv.at(-1)); const server = createServer((_req, res) => { res.writeHead(200, {'content-type': 'text/html'}); res.end('Setup finished'); }); server.listen(port, '127.0.0.1');"
    return spawn(process.execPath, ['-e', script, String(port)], options)
  }
  const xvwaProvider = new NativePhpProvider({
    spawnImpl: phpSpawn,
    allocatePort: async () => 6891,
    mysqlManager: {
      provision: async () => { databaseCalls.push('provision'); return { host: '127.0.0.1', port: 3306, user: 'app', password: 'generated', database: 'vulnlab_xvwa' } },
      verify: async () => { databaseCalls.push('verify') },
      destroy: async () => { databaseCalls.push('destroy') },
      destroyForInstance: async () => { databaseCalls.push('destroyForInstance') },
    },
  })
  const xvwaLab = { ...lab, id: 'lab-xvwa', slug: 'xvwa', title: 'XVWA', sourceRef: 's4n7h0/xvwa@fixture' }
  const started = await xvwaProvider.start({
    instanceId: 'xvwa-fixture',
    lab: { ...xvwaLab, localPath: sourceRoot },
    publicOrigin: 'http://127.0.0.1:6711',
    proxyEndpoint: 'http://127.0.0.1:6711/lab-runtime/xvwa-fixture/',
    lifetimeMinutes: 5,
    dataDir: xvwaRoot,
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', mysql: { host: '127.0.0.1', port: 3306, adminUser: 'admin', adminPassword: 'secret', appHost: '127.0.0.1', mysqlBinary: 'mysql' } },
  })
  assert.equal(started.endpoint, 'http://127.0.0.1:6711/lab-runtime/xvwa-fixture/xvwa/')
  const runtimeConfig = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'config.php'), 'utf8')
  const runtimeSetup = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'setup', 'home.php'), 'utf8')
  assert.match(runtimeConfig, /getenv\('DB_DATABASE'\)/)
  assert.match(runtimeConfig, /new PDO\(/)
  assert.match(runtimeSetup, /DROP TABLE IF EXISTS/)
  assert.doesNotMatch(runtimeSetup, /mysql_error\s*\(/)
  await xvwaProvider.stop({ lab: { ...xvwaLab, localPath: sourceRoot }, instance: { ...instance, id: 'xvwa-fixture', labId: xvwaLab.id, labTitle: 'XVWA', provider: 'native-php' }, dataDir: xvwaRoot })
  await assert.rejects(stat(join(xvwaRoot, 'runtime', 'xvwa-fixture')))
  assert.deepEqual(databaseCalls, ['provision', 'verify', 'destroy'])
} finally {
  await rm(xvwaRoot, { recursive: true, force: true })
}

const nativeRecoveryRoot = await mkdtemp(join(tmpdir(), 'vulnlab-native-recovery-'))
try {
  const recoveryId = 'native-recovery'
  const runtimeRoot = join(nativeRecoveryRoot, 'runtime', recoveryId)
  await mkdir(runtimeRoot, { recursive: true })
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore', windowsHide: true })
  await new Promise((resolveSpawn, rejectSpawn) => {
    child.once('spawn', resolveSpawn)
    child.once('error', rejectSpawn)
  })
  assert.ok(child.pid)
  await writeFile(join(runtimeRoot, 'vulnlab-runtime.json'), JSON.stringify({ pid: child.pid, provider: 'native-node' }))
  const exited = new Promise(resolveExit => child.once('exit', resolveExit))
  await nativeNode.recover({
    lab: { ...lab, runtimeKind: 'native-node', providerId: 'native-node' },
    instance: { ...instance, id: recoveryId, provider: 'native-node' },
    dataDir: nativeRecoveryRoot,
  })
  await Promise.race([exited, new Promise((_, rejectTimeout) => setTimeout(() => rejectTimeout(new Error('recovered process did not exit')), 5_000))])
  await assert.rejects(stat(runtimeRoot))
  await assert.rejects(readFile(join(runtimeRoot, 'vulnlab-runtime.json')))
} finally {
  await rm(nativeRecoveryRoot, { recursive: true, force: true })
}

console.log('VulnLab provider test passed: native Provider resolution, MySQL cleanup and process recovery.')
