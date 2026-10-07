import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { createOaDockerComposeConfig, DockerOaProvider, oaDockerProjectName } from '../../src/dist/runtime/providers.js'
import { inspectOaDockerAsset, oaDockerAssetPath } from '../../src/dist/labs/oa-vuln-labs/docker-assets.js'
import { inspectOaDockerRuntime } from '../../src/dist/labs/oa-vuln-labs/docker-runtime.js'
import { dataPaths } from '../../src/dist/paths.js'

const projectName = oaDockerProjectName('oa-test-instance-123')
assert.match(projectName, /^vulnlab-oa-[a-f0-9]{24}$/)

const compose = createOaDockerComposeConfig({
  projectName,
  buildContext: 'C:/vulnlab/data/runtime/oa-test-instance-123/build-context',
  mysqlContext: 'C:/vulnlab/data/runtime/oa-test-instance-123/mysql-context',
  ingressContext: 'C:/vulnlab/data/runtime/oa-test-instance-123/ingress-context',
  port: 6831,
  databasePassword: 'db-secret',
  redisPassword: 'redis-secret',
  jwtSecret: 'jwt-secret',
  instanceId: 'oa-test-instance-123',
})
assert.equal(compose.name, projectName)
assert.deepEqual(compose.services.ingress.ports, [{ target: 9090, published: '6831', host_ip: '127.0.0.1', protocol: 'tcp' }])
assert.equal('ports' in compose.services.web, false)
assert.equal(compose.services.ingress.user, '65532:65532')
assert.equal(compose.services.ingress.read_only, true)
assert.deepEqual(compose.services.ingress.networks, ['oa-internal', 'oa-ingress'])
assert.equal('ports' in compose.services.mysql, false)
assert.equal('ports' in compose.services.redis, false)
assert.equal(compose.services.mysql.image, 'vulnlab/oa-mysql:1.0.0-beta')
assert.equal(compose.services.mysql.build.context, 'C:/vulnlab/data/runtime/oa-test-instance-123/mysql-context')
assert.deepEqual(compose.services.mysql.volumes, [{ type: 'volume', source: 'mysql-data', target: '/var/lib/mysql' }])
assert.equal(compose.networks['oa-internal'].internal, true)
assert.equal(compose.networks['oa-ingress'].internal, undefined)
assert.ok(Object.keys(compose.volumes).every(name => ['mysql-data', 'redis-data', 'uploads-data'].includes(name)))
for (const service of Object.values(compose.services)) {
  assert.equal(service.privileged, undefined)
  assert.equal(service.network_mode, undefined)
  for (const volume of service.volumes ?? []) {
    assert.doesNotMatch(volume.source, /docker\.sock/i)
    assert.notEqual(volume.type, 'bind', 'OA containers must not mount host paths')
  }
}
assert.equal(compose.services.web.platform, 'linux/amd64')
assert.deepEqual(compose.services.web.cap_drop, ['ALL'])
assert.equal(compose.services.web.read_only, true)
assert.deepEqual(compose.services.web.tmpfs, ['/tmp:rw,noexec,nosuid,size=16m'])
assert.deepEqual(compose.services.ingress.tmpfs, ['/tmp:rw,noexec,nosuid,size=8m'])
assert.match(await readFile(join(import.meta.dirname, '..', '..', 'src', 'labs', 'oa-vuln-labs', 'native', 'Dockerfile'), 'utf8'), /USER 65532:65532/)
assert.match(await readFile(join(import.meta.dirname, '..', '..', 'src', 'runtime', 'providers.ts'), 'utf8'), /TCP-LISTEN:9090,fork,reuseaddr.*TCP:web:9090/)
assert.match(await readFile(join(import.meta.dirname, '..', '..', 'src', 'runtime', 'providers.ts'), 'utf8'), /COPY init\.sql \/docker-entrypoint-initdb\.d\/01-init\.sql/)

const missingDocker = await inspectOaDockerRuntime(async args => ({
  ok: false, stdout: '', stderr: '', code: null, errorCode: args[0] === '--version' ? 'ENOENT' : undefined,
}))
assert.equal(missingDocker.available, false)
assert.deepEqual(missingDocker.missing, ['Docker CLI'])
assert.match(missingDocker.cli.detail, /未找到 Docker CLI/)

const noCompose = await inspectOaDockerRuntime(async args => {
  if (args[0] === '--version') return { ok: true, stdout: 'Docker version fixture', stderr: '', code: 0 }
  if (args[0] === 'compose') return { ok: false, stdout: '', stderr: 'compose plugin missing', code: 1 }
  if (args[0] === 'context') return { ok: true, stdout: '"npipe:////./pipe/dockerDesktopLinuxEngine"', stderr: '', code: 0 }
  return { ok: true, stdout: 'linux/x86_64', stderr: '', code: 0 }
})
assert.equal(noCompose.available, false)
assert.deepEqual(noCompose.missing, ['Docker Compose v2'])

const readyDocker = await inspectOaDockerRuntime(async args => ({
  ok: true,
  stdout: args[0] === '--version' ? 'Docker version 29.8.0' : args[0] === 'compose' ? '5.5.1' : args[0] === 'context' ? '"npipe:////./pipe/dockerDesktopLinuxEngine"' : 'linux/x86_64',
  stderr: '', code: 0,
}))
assert.equal(readyDocker.available, true)
const remoteDocker = await inspectOaDockerRuntime(async args => ({
  ok: true,
  stdout: args[0] === '--version' ? 'Docker version fixture' : args[0] === 'compose' ? '5.5.1' : args[0] === 'context' ? '"tcp://docker-host.example:2376"' : 'linux/x86_64',
  stderr: '', code: 0,
}))
assert.equal(remoteDocker.available, false)
assert.ok(remoteDocker.missing.includes('本机 Docker Engine'))
const asset = await inspectOaDockerAsset()
assert.equal(asset.available, true)

const root = await mkdtemp(join(tmpdir(), 'vulnlab-oa-docker-provider-'))
const lab = {
  id: 'lab-oa-docker', slug: 'oa-vuln-labs', title: 'OA Docker', category: 'Web', difficulty: '中等',
  sourceType: 'archive', sourceUrl: 'bundle://oa-vuln-labs/source.zip', sourceRef: 'fixture', license: 'unknown',
  runtimeKind: 'native-oa', providerId: 'oa-local', runtimeConfig: { profile: 'oa-project' }, builtin: true,
  version: '1.0.0-beta', status: 'ready', summary: '', tags: [], localPath: join(root, 'labs', 'oa-vuln-labs'),
  importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
}
await import('node:fs/promises').then(fs => fs.mkdir(lab.localPath, { recursive: true }))

const freePort = async () => {
  const server = createServer()
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', resolveListen)
  })
  const address = server.address()
  const port = typeof address === 'object' && address ? address.port : 0
  await new Promise(resolveClose => server.close(resolveClose))
  return port
}

const makeRunner = ({ failFirstDown = false, failUp = false, deferUp = false } = {}) => {
  const commands = []
  let webServer
  let downAttempts = 0
  let upStarted = false
  let releaseUp = () => undefined
  const run = async (args) => {
    commands.push([...args])
    if (args[0] === '--version') return { ok: true, stdout: 'Docker version fixture', stderr: '', code: 0 }
    if (args[0] === 'compose' && args[1] === 'version') return { ok: true, stdout: '5.5.1', stderr: '', code: 0 }
    if (args[0] === 'context') return { ok: true, stdout: '"npipe:////./pipe/dockerDesktopLinuxEngine"', stderr: '', code: 0 }
    if (args[0] === 'info') return { ok: true, stdout: 'linux/x86_64', stderr: '', code: 0 }
    const operation = args.find(value => ['up', 'down'].includes(value))
    const projectArg = args.indexOf('--project-name')
    assert.ok(projectArg >= 0)
    if (operation === 'up') {
      const composeArg = args.indexOf('--file')
      const config = JSON.parse(await readFile(args[composeArg + 1], 'utf8'))
      assert.equal(config.networks['oa-internal'].internal, true)
      const port = Number(config.services.ingress.ports[0].published)
      webServer = createServer((_request, response) => { response.writeHead(200, { 'content-type': 'text/html' }); response.end('simulated OA') })
      await new Promise((resolveListen, rejectListen) => {
        webServer.once('error', rejectListen)
        webServer.listen(port, '127.0.0.1', resolveListen)
      })
      if (deferUp) await new Promise(resolveUp => { releaseUp = resolveUp; upStarted = true })
      else upStarted = true
      if (failUp) return { ok: false, stdout: '', stderr: 'image build failed', code: 1 }
      return { ok: true, stdout: 'started', stderr: '', code: 0 }
    }
    if (operation === 'down') {
      downAttempts += 1
      if (failFirstDown && downAttempts === 1) return { ok: false, stdout: '', stderr: 'Docker Engine unavailable', code: 1 }
      if (webServer?.listening) await new Promise(resolveClose => webServer.close(resolveClose))
      return { ok: true, stdout: 'removed', stderr: '', code: 0 }
    }
    return { ok: true, stdout: '', stderr: '', code: 0 }
  }
  return { commands, run, get downAttempts() { return downAttempts }, get upStarted() { return upStarted }, releaseUp: () => releaseUp() }
}

try {
  const port = await freePort()
  const fakeDocker = makeRunner()
  const provider = new DockerOaProvider({ runDocker: fakeDocker.run, allocatePort: async () => port })
  const runtime = { bindHost: '127.0.0.1', portStart: port, portEnd: port, phpBinary: 'php', nodeBinary: 'node', javaBinary: 'java', pythonBinary: 'python' }
  const started = await provider.start({
    instanceId: 'oa-docker-provider-test', lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir: root, runtime,
  })
  const page = await fetch(started.endpoint)
  assert.equal(await page.text(), 'simulated OA')
  const instanceRoot = dataPaths(root).runtimeInstance('oa-docker-provider-test')
  const generatedCompose = JSON.parse(await readFile(join(instanceRoot, 'compose.json'), 'utf8'))
  assert.equal(generatedCompose.services.web.environment.JWT_SECRET.length >= 32, true)
  assert.ok(generatedCompose.services.mysql.environment.MYSQL_ROOT_PASSWORD !== '123456')
  const instance = { id: 'oa-docker-provider-test', labId: lab.id, labTitle: lab.title, provider: 'oa-docker', endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }
  await provider.stop({ lab, instance, runtime, dataDir: root })
  assert.equal(await stat(instanceRoot).then(() => true, () => false), false)
  const down = fakeDocker.commands.find(command => command.includes('down'))
  assert.ok(down.includes('--volumes'))
  assert.ok(down.includes('--remove-orphans'))
  assert.equal(fakeDocker.commands.filter(command => command[0] === 'compose' && command.includes('--project-name')).every(command => command[command.indexOf('--project-name') + 1] === projectName || command[command.indexOf('--project-name') + 1] === oaDockerProjectName('oa-docker-provider-test')), true)

  const startingPort = await freePort()
  const startingDocker = makeRunner({ deferUp: true })
  const startingProvider = new DockerOaProvider({ runDocker: startingDocker.run, allocatePort: async () => startingPort })
  const startingId = 'oa-docker-starting-test'
  const startingRoot = dataPaths(root).runtimeInstance(startingId)
  let startTask
  try {
    startTask = startingProvider.start({
      instanceId: startingId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir: root,
      runtime: { ...runtime, portStart: startingPort, portEnd: startingPort },
    })
    for (let attempt = 0; attempt < 100 && !startingDocker.upStarted; attempt += 1) await new Promise(resolveWait => setTimeout(resolveWait, 20))
    assert.equal(startingDocker.upStarted, true, 'deferred Compose up did not start')
    assert.equal(JSON.parse(await readFile(join(startingRoot, 'oa-docker.json'), 'utf8')).cleanupPending, false)
    assert.deepEqual(await startingProvider.recoverPending(root, new Set()), [])
    assert.equal(startingDocker.downAttempts, 0, 'background recovery must not stop an instance while it is starting')
    assert.equal(await stat(startingRoot).then(() => true, () => false), true)
  } finally {
    startingDocker.releaseUp()
  }
  const startingResult = await startTask
  await startingProvider.stop({
    lab,
    instance: { id: startingId, labId: lab.id, labTitle: lab.title, provider: 'oa-docker', endpoint: startingResult.endpoint, status: 'running', createdAt: startingResult.createdAt, expiresAt: startingResult.expiresAt, logs: startingResult.logs },
    runtime, dataDir: root,
  })
  assert.equal(await stat(startingRoot).then(() => true, () => false), false)
  await startingProvider.shutdown()

  const failedPort = await freePort()
  const failingDocker = makeRunner({ failFirstDown: true, failUp: true })
  const failingProvider = new DockerOaProvider({ runDocker: failingDocker.run, allocatePort: async () => failedPort })
  await assert.rejects(failingProvider.start({
    instanceId: 'oa-docker-cleanup-test', lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir: root,
    runtime: { ...runtime, portStart: failedPort, portEnd: failedPort },
  }), error => error.code === 'OA_DOCKER_START_FAILED' && /待重试/.test(error.message))
  const pendingRoot = dataPaths(root).runtimeInstance('oa-docker-cleanup-test')
  const pending = JSON.parse(await readFile(join(pendingRoot, 'oa-docker.json'), 'utf8'))
  assert.equal(pending.cleanupPending, true)
  assert.equal(await failingProvider.recoverPending(root, new Set(['oa-docker-cleanup-test'])).then(ids => ids.includes('oa-docker-cleanup-test')), true)
  assert.equal(await stat(pendingRoot).then(() => true, () => false), false)
  assert.equal(failingDocker.downAttempts, 2)
  await failingProvider.shutdown()

  const corrupted = join(root, 'corrupted-docker.zip')
  const bytes = await readFile(oaDockerAssetPath())
  await writeFile(corrupted, bytes.subarray(0, bytes.length - 1))
  assert.equal((await inspectOaDockerAsset(corrupted)).available, false)
  console.log('OA Docker provider test passed: Compose isolation contract, missing CLI/Compose diagnostics, verified assets, loopback-only start, instance volume cleanup, and retryable failed cleanup.')
} finally {
  await rm(root, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 })
}
