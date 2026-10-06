import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { PassThrough } from 'node:stream'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { DockerOaProvider, NativeOaProvider, NativePhpProvider, NativeProcessProvider, ProviderError, ProviderRegistry } from '../../src/dist/providers.js'

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
const nativeOa = new NativeOaProvider()
const dockerOa = new DockerOaProvider()
const registry = new ProviderRegistry([native, nativeNode, nativeJava, nativePython, nativeOa, dockerOa])

assert.equal(registry.get('native-php'), native)
assert.equal(registry.resolve('native-php', 'native-php'), native)
assert.equal(registry.resolve('native-node', 'native-node'), nativeNode)
assert.equal(registry.resolve('native-java', 'native-java'), nativeJava)
assert.equal(registry.resolve('native-python', 'native-python'), nativePython)
assert.equal(registry.resolve('oa-local', 'native-oa'), nativeOa)
assert.equal(registry.resolve('oa-project', 'native-oa'), nativeOa)
assert.equal(registry.resolve('oa-appcontainer', 'native-oa'), nativeOa)
assert.equal(registry.resolve('oa-docker', 'native-oa'), dockerOa)
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

const oaCleanupRoot = await mkdtemp(join(tmpdir(), 'vulnlab-oa-provider-recovery-'))
try {
  let oaCleanupCount = 0
  const oaProvider = new NativeOaProvider({
    mysqlManager: {
      provision: async () => { throw new Error('not used in recovery fixture') },
      verify: async () => undefined,
      destroy: async () => undefined,
      destroyForInstance: async () => { oaCleanupCount += 1 },
    },
  })
  await oaProvider.stop({
    lab: { ...lab, id: 'lab-oa', slug: 'oa-vuln-labs', title: 'OA', runtimeKind: 'native-oa', providerId: 'oa-appcontainer' },
    instance: { ...instance, id: 'oa-recovery', provider: 'oa-appcontainer' },
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', nodeBinary: 'node', javaBinary: 'java', pythonBinary: 'python', mysql: mysqlConfig, mysqlManaged: true },
    dataDir: oaCleanupRoot,
  })
  assert.equal(oaCleanupCount, 1)
} finally {
  await rm(oaCleanupRoot, { recursive: true, force: true })
}

const oaBoundaryRoot = await mkdtemp(join(tmpdir(), 'vulnlab-oa-project-boundary-'))
try {
  const toolchainRoot = join(oaBoundaryRoot, 'runtime', 'toolchains')
  const nodeRoot = join(toolchainRoot, 'node', '22.23.1', 'win32-x64')
  const mariaRoot = join(toolchainRoot, 'mariadb', '11.4.10', 'win32-x64', 'bin')
  await mkdir(nodeRoot, { recursive: true })
  await mkdir(mariaRoot, { recursive: true })
  const nodeBinary = join(nodeRoot, 'node.exe')
  const mysqlBinary = join(mariaRoot, 'mariadb.exe')
  await writeFile(nodeBinary, 'fixture')
  await writeFile(mysqlBinary, 'fixture')
  let provisions = 0
  const boundaryProvider = new NativeOaProvider({
    mysqlManager: {
      provision: async () => { provisions += 1; throw new Error('must not provision on rejected runtime') },
      verify: async () => undefined,
      destroy: async () => undefined,
      destroyForInstance: async () => undefined,
    },
  })
  const base = {
    instanceId: 'oa-boundary-test',
    lab: { ...lab, id: 'lab-oa-boundary', slug: 'oa-vuln-labs', runtimeKind: 'native-oa', localPath: oaBoundaryRoot },
    publicOrigin: 'http://127.0.0.1:6710',
    lifetimeMinutes: 5,
    dataDir: oaBoundaryRoot,
    runtime: {
      bindHost: '0.0.0.0', portStart: 6800, portEnd: 6899, phpBinary: 'php', nodeBinary: 'node',
      oaNodeBinary: nodeBinary, javaBinary: 'java', pythonBinary: 'python', mysqlManaged: true,
      mysql: { host: '10.0.0.8', port: 3306, adminUser: 'admin', adminPassword: 'secret', appHost: '127.0.0.1', mysqlBinary },
    },
  }
  await assert.rejects(boundaryProvider.start(base), error => error.code === 'NATIVE_OA_MYSQL_LOOPBACK_ONLY')
  assert.equal(provisions, 0, 'OA must reject a non-loopback database before provisioning resources')
  const localDatabase = { ...base.runtime.mysql, host: '127.0.0.1' }
  await assert.rejects(boundaryProvider.start({ ...base, runtime: { ...base.runtime, mysql: localDatabase, oaNodeBinary: process.execPath } }), error => error.code === 'NATIVE_OA_NODE_NOT_PROJECT_MANAGED')
  assert.equal(provisions, 0, 'OA must reject a system Node.js runtime before provisioning resources')
  await assert.rejects(
    boundaryProvider.start({ ...base, runtime: { ...base.runtime, mysql: localDatabase, oaNodeBinary: nodeBinary } }),
    error => error.code === 'NATIVE_OA_START_FAILED' && !/AppContainer|SANDBOX/.test(error.message),
  )
  assert.equal(provisions, 1, 'local OA startup must not require AppContainer before project-managed database provisioning')
} finally {
  await rm(oaBoundaryRoot, { recursive: true, force: true })
}

const xvwaRoot = await mkdtemp(join(tmpdir(), 'vulnlab-xvwa-provider-'))
try {
  const sourceRoot = join(xvwaRoot, 'labs', 'xvwa', 'fixture')
  await mkdir(join(sourceRoot, 'setup'), { recursive: true })
  await mkdir(join(sourceRoot, 'vulnerabilities', 'fileupload'), { recursive: true })
  await writeFile(join(sourceRoot, 'config.php'), '<?php $host = "localhost"; $conn = new mysqli($host); ?>\n')
  await writeFile(join(sourceRoot, 'setup', 'home.php'), "<?php $sql = 'DROP TABLE '. $tables[$i].';'; $pic = '/xvwa/img/item.png'; echo mysql_error(); ?>\n")
  await writeFile(join(sourceRoot, 'header.php'), `<a href="/xvwa/">XVWA</a>\n<?php echo $XVWA_WEBROOT."/xvwa/login.php"; ?>\n`)
  await writeFile(join(sourceRoot, 'login.php'), '<?php header("Location: /xvwa/"); ?>\n')
  await writeFile(join(sourceRoot, 'vulnerabilities', 'fileupload', 'home.php'), "<?php $path = $_SERVER['DOCUMENT_ROOT'].'/xvwa/img/uploads/'; $rpath = '/xvwa/img/uploads/'.basename($_FILES['image']['name']); ?>\n")
  const databaseCalls = []
  const phpSpawnEnvironments = []
  const phpSpawn = (_binary, args, options) => {
    phpSpawnEnvironments.push(options.env)
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
  const renewed = await xvwaProvider.renew({
    lab: { ...xvwaLab, localPath: sourceRoot },
    instance: { ...instance, id: 'xvwa-fixture', labId: xvwaLab.id, labTitle: 'XVWA', provider: 'native-php', expiresAt: started.expiresAt },
    lifetimeMinutes: 5,
  })
  assert.ok(Date.parse(renewed.expiresAt) >= Date.parse(started.expiresAt) + 5 * 60_000 - 1_000)
  const runtimeConfig = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'config.php'), 'utf8')
  const runtimeSetup = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'setup', 'home.php'), 'utf8')
  const runtimeHeader = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'header.php'), 'utf8')
  const runtimeLogin = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'login.php'), 'utf8')
  const runtimeUpload = await readFile(join(xvwaRoot, 'runtime', 'xvwa-fixture', 'xvwa', 'vulnerabilities', 'fileupload', 'home.php'), 'utf8')
  assert.match(runtimeConfig, /getenv\('DB_DATABASE'\)/)
  assert.match(runtimeConfig, /new PDO\(/)
  assert.match(runtimeConfig, /\$XVWA_WEBROOT = "\/lab-runtime\/xvwa-fixture";/)
  assert.match(runtimeSetup, /DROP TABLE IF EXISTS/)
  assert.match(runtimeSetup, /\/lab-runtime\/xvwa-fixture\/xvwa\/img\/item\.png/)
  assert.doesNotMatch(runtimeSetup, /mysql_error\s*\(/)
  assert.match(runtimeHeader, /href="\/lab-runtime\/xvwa-fixture\/xvwa\/"/)
  assert.match(runtimeHeader, /\$XVWA_WEBROOT\."\/xvwa\/login\.php"/)
  assert.match(runtimeLogin, /Location: \/lab-runtime\/xvwa-fixture\/xvwa\//)
  assert.match(runtimeUpload, /\$path = \$_SERVER\['DOCUMENT_ROOT'\]\.'\/xvwa\/img\/uploads\//)
  assert.match(runtimeUpload, /\$rpath = '\/lab-runtime\/xvwa-fixture\/xvwa\/img\/uploads\//)
  assert.ok(phpSpawnEnvironments.length >= 2)
  for (const environment of phpSpawnEnvironments) {
    assert.equal(Object.keys(environment).some(key => key.startsWith('VULNLAB_')), false)
    assert.equal(environment.DB_PASSWORD, 'generated')
  }
  await xvwaProvider.stop({ lab: { ...xvwaLab, localPath: sourceRoot }, instance: { ...instance, id: 'xvwa-fixture', labId: xvwaLab.id, labTitle: 'XVWA', provider: 'native-php' }, dataDir: xvwaRoot })
  await assert.rejects(stat(join(xvwaRoot, 'runtime', 'xvwa-fixture')))
  assert.deepEqual(databaseCalls, ['provision', 'verify', 'destroy'])
} finally {
  await rm(xvwaRoot, { recursive: true, force: true })
}

const xssLabsRoot = await mkdtemp(join(tmpdir(), 'vulnlab-xss-provider-'))
try {
  const sourceRoot = join(xssLabsRoot, 'labs', 'xss-labs', 'fixture')
  await mkdir(sourceRoot, { recursive: true })
  const originalLevel = '<iframe src="http://www.exifviewer.org/"></iframe><a href=/xss/level15.php?src=1.gif>level15</a>\n'
  await writeFile(join(sourceRoot, 'index.php'), '<?php echo "XSS挑战"; ?>\n')
  await writeFile(join(sourceRoot, 'level1.php'), '<?php echo $_GET["name"]; ?>\n')
  await writeFile(join(sourceRoot, 'level14.php'), originalLevel)
  await writeFile(join(sourceRoot, 'level15.php'), '<?php echo "level15"; ?>\n')
  const phpSpawn = (_binary, args, options) => {
    const port = Number(args[args.indexOf('-S') + 1].split(':').at(-1))
    const script = "const server=require('node:http').createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end(req.url.includes('level14')?'<a href=level15.php>level15</a>':req.url.includes('level1')?'VulnLabSmoke':'XSS挑战');});server.listen(Number(process.argv.at(-1)),'127.0.0.1');"
    return spawn(process.execPath, ['-e', script, String(port)], options)
  }
  const xssProvider = new NativePhpProvider({ spawnImpl: phpSpawn, allocatePort: async () => 6894 })
  const xssLab = { ...lab, id: 'lab-xss-labs', slug: 'xss-labs', title: 'XSS-Labs', localPath: sourceRoot }
  const started = await xssProvider.start({
    instanceId: 'xss-labs-fixture', lab: xssLab, publicOrigin: 'http://127.0.0.1:6711', lifetimeMinutes: 5,
    dataDir: xssLabsRoot,
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php' },
  })
  const runtimeLevel = await readFile(join(xssLabsRoot, 'runtime', 'xss-labs-fixture', 'level14.php'), 'utf8')
  assert.match(runtimeLevel, /src="about:blank"/)
  assert.match(runtimeLevel, /href=level15\.php\?src=1\.gif/)
  assert.equal(await readFile(join(sourceRoot, 'level14.php'), 'utf8'), originalLevel, 'XSS-Labs installation source must remain unchanged')
  const smoke = await fetch(`${started.endpoint}level1.php?name=VulnLabSmoke`)
  assert.equal(smoke.status, 200)
  assert.match(await smoke.text(), /VulnLabSmoke/)
  await xssProvider.stop({ lab: xssLab, instance: { ...instance, id: 'xss-labs-fixture', labId: xssLab.id, labTitle: xssLab.title, provider: 'native-php' }, dataDir: xssLabsRoot })
  await assert.rejects(stat(join(xssLabsRoot, 'runtime', 'xss-labs-fixture')))
} finally {
  await rm(xssLabsRoot, { recursive: true, force: true })
}

const pikachuRoot = await mkdtemp(join(tmpdir(), 'vulnlab-pikachu-provider-'))
try {
  const sourceRoot = join(pikachuRoot, 'labs', 'pikachu', 'fixture')
  await mkdir(join(sourceRoot, 'inc'), { recursive: true })
  await writeFile(join(sourceRoot, 'inc', 'config.inc.php'), "<?php\ndefine('DBHOST', getenv('DB_SERVER') ?: '127.0.0.1');\ndefine('DBUSER', getenv('DB_USER') ?: 'vulnlab');\ndefine('DBPW', getenv('DB_PASSWORD') ?: '');\ndefine('DBNAME', getenv('DB_DATABASE') ?: 'vulnlab');\ndefine('DBPORT', getenv('DB_PORT') ?: '3306');\n")
  await writeFile(join(sourceRoot, 'install.php'), '<?php\nif(isset($_POST[\'submit\'])) {\n$link=mysqli_connect(DBHOST, DBUSER, DBPW, DBNAME, DBPORT);\n$drop_db = "SELECT 1";\n$create_db = "SELECT 1";\n}\n')
  const ports = [6892, 6893]
  const databaseCalls = []
  const phpSpawn = (_binary, args, options) => {
    const port = Number(args[args.indexOf('-S') + 1].split(':').at(-1))
    const script = "const server=require('node:http').createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end(req.url==='/install.php'?'好了，可以开搞了':'Pikachu');});server.listen(Number(process.argv.at(-1)),'127.0.0.1');"
    return spawn(process.execPath, ['-e', script, String(port)], options)
  }
  const pikachuProvider = new NativePhpProvider({
    spawnImpl: phpSpawn,
    allocatePort: async () => ports.shift(),
    mysqlManager: {
      provision: async () => ({ host: '127.0.0.1', port: 3306, user: 'app', password: 'generated', database: 'vulnlab_pikachu' }),
      verify: async () => { databaseCalls.push('verify') },
      destroy: async () => { databaseCalls.push('destroy') },
      destroyForInstance: async () => undefined,
    },
  })
  const pikachuLab = { ...lab, id: 'lab-pikachu', slug: 'pikachu', title: 'Pikachu', sourceRef: 'zhuifengshaonianhanlu/pikachu@fixture' }
  const started = await pikachuProvider.start({
    instanceId: 'pikachu-fixture', lab: { ...pikachuLab, localPath: sourceRoot }, publicOrigin: 'http://127.0.0.1:6711',
    lifetimeMinutes: 5, dataDir: pikachuRoot,
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', mysql: mysqlConfig },
  })
  const configuredInstall = await readFile(join(pikachuRoot, 'runtime', 'pikachu-fixture', 'install.php'), 'utf8')
  assert.match(configuredInstall, /mysqli_connect\(DBHOST, DBUSER, DBPW, DBNAME, DBPORT\)/)
  assert.match(configuredInstall, /\$drop_db = "SELECT 1";/)
  assert.match(configuredInstall, /\$create_db = "SELECT 1";/)
  assert.equal((await fetch(pikachuProvider.getProxyTarget('pikachu-fixture'))).status, 200)
  await pikachuProvider.stop({ lab: { ...pikachuLab, localPath: sourceRoot }, instance: { ...instance, id: 'pikachu-fixture', labId: pikachuLab.id, labTitle: 'Pikachu', endpoint: started.endpoint }, dataDir: pikachuRoot })
  await assert.rejects(stat(join(pikachuRoot, 'runtime', 'pikachu-fixture')))
  assert.deepEqual(databaseCalls, ['verify', 'destroy'])
} finally {
  await rm(pikachuRoot, { recursive: true, force: true })
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

// 辅助端口耗尽时，WebGoat 的主端口必须可在下一次尝试中重新分配。
// 这个夹具让主端口始终返回 6800、辅助端口始终失败；若主端口泄漏，
// 第二次调用会错误地变成主端口耗尽，而不是继续报告辅助端口耗尽。
const auxiliaryPortRoot = await mkdtemp(join(tmpdir(), 'vulnlab-java-port-cleanup-'))
try {
  const sourceRoot = join(auxiliaryPortRoot, 'labs', 'webgoat', 'fixture')
  await mkdir(sourceRoot, { recursive: true })
  const javaPortProvider = new NativeProcessProvider('native-java', {
    allocatePort: async (_host, start, end) => {
      if (start === 6800 && end === 6801) return 6800
      throw new ProviderError('FIXTURE_PORT_UNAVAILABLE', 'fixture port unavailable', 409)
    },
  })
  const javaInput = {
    instanceId: 'java-port-cleanup',
    lab: {
      ...lab,
      id: 'lab-webgoat',
      slug: 'webgoat',
      title: 'WebGoat',
      runtimeKind: 'native-java',
      providerId: 'native-java',
      runtimeConfig: { profile: 'webgoat' },
      localPath: sourceRoot,
    },
    publicOrigin: 'http://127.0.0.1:6710',
    lifetimeMinutes: 5,
    dataDir: auxiliaryPortRoot,
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6801, phpBinary: 'php', nodeBinary: 'node', javaBinary: 'java', pythonBinary: 'python' },
  }
  await assert.rejects(javaPortProvider.start(javaInput), error => error instanceof ProviderError && error.code === 'NATIVE_JAVA_AUX_PORT_EXHAUSTED')
  await assert.rejects(javaPortProvider.start({ ...javaInput, instanceId: 'java-port-cleanup-2' }), error => error instanceof ProviderError && error.code === 'NATIVE_JAVA_AUX_PORT_EXHAUSTED')
} finally {
  await rm(auxiliaryPortRoot, { recursive: true, force: true })
}

const pygoatCompatRoot = await mkdtemp(join(tmpdir(), 'vulnlab-pygoat-compat-'))
const pygoatInstanceId = 'pygoat-account-middleware'
const pygoatSourceRoot = join(pygoatCompatRoot, 'labs', 'pygoat', 'fixture')
const pygoatSettings = join(pygoatSourceRoot, 'pygoat', 'settings.py')
const originalFetch = globalThis.fetch
try {
  await mkdir(join(pygoatSourceRoot, 'pygoat'), { recursive: true })
  await writeFile(join(pygoatSourceRoot, 'manage.py'), '', 'utf8')
  await writeFile(pygoatSettings, [
    'import django_heroku',
    'MIDDLEWARE = [',
    "    'django.contrib.auth.middleware.AuthenticationMiddleware',",
    ']',
    'django_heroku.settings(locals())',
  ].join('\n'), 'utf8')
  globalThis.fetch = async () => ({ body: null })
  const spawnCalls = []
  const provider = new NativeProcessProvider('native-python', {
    allocatePort: async () => 6820,
    spawnImpl: (_binary, args) => {
      spawnCalls.push(args)
      const child = new EventEmitter()
      child.stdout = new PassThrough()
      child.stderr = new PassThrough()
      child.pid = 4200
      child.exitCode = null
      child.kill = () => {
        child.exitCode = 0
        child.emit('exit', 0, null)
        return true
      }
      if (args.includes('migrate')) {
        setImmediate(() => {
          child.exitCode = 0
          child.emit('exit', 0, null)
        })
      } else {
        setImmediate(() => child.emit('spawn'))
      }
      return child
    },
  })
  const started = await provider.start({
    instanceId: pygoatInstanceId,
    lab: {
      ...lab,
      id: 'lab-pygoat',
      slug: 'pygoat',
      title: 'PyGoat',
      runtimeKind: 'native-python',
      providerId: 'native-python',
      runtimeConfig: { profile: 'pygoat', entryPath: 'manage.py', settingsPath: 'pygoat/settings.py' },
      localPath: pygoatSourceRoot,
    },
    publicOrigin: 'http://127.0.0.1:6710',
    lifetimeMinutes: 5,
    dataDir: pygoatCompatRoot,
    runtime: { bindHost: '127.0.0.1', portStart: 6820, portEnd: 6820, phpBinary: 'php', nodeBinary: 'node', javaBinary: 'java', pythonBinary: 'python' },
  })
  const runtimeSettings = await readFile(join(pygoatCompatRoot, 'runtime', pygoatInstanceId, 'pygoat', 'settings.py'), 'utf8')
  assert.match(runtimeSettings, /'allauth\.account\.middleware\.AccountMiddleware'/)
  assert.doesNotMatch(runtimeSettings, /django_heroku/)
  assert.match(await readFile(pygoatSettings, 'utf8'), /django_heroku/)
  assert.equal(spawnCalls.length, 2)
  await provider.stop({ instance: { id: pygoatInstanceId }, lab: {}, dataDir: pygoatCompatRoot, runtime: {} })
  assert.ok(started.endpoint.endsWith('/'))
} finally {
  globalThis.fetch = originalFetch
  await rm(pygoatCompatRoot, { recursive: true, force: true })
}

console.log('VulnLab provider test passed: native Provider resolution, MySQL cleanup and process recovery.')
