import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeComposeProvider, nativeComposeProjectName } from '../../src/dist/runtime/providers.js'
import { dataPaths } from '../../src/dist/paths.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-native-compose-'))
const runtime = {
  bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899,
  phpBinary: 'php', nodeBinary: process.execPath, javaBinary: 'java', pythonBinary: 'python',
}
let portSequence = 6800
let rejectedSequence = 0

const makeDocker = ({ model, upOk = true, downFailures = 0 } = {}) => {
  const commands = []
  let failures = downFailures
  const run = async args => {
    commands.push(args)
    if (args[0] === '--version') return { ok: true, stdout: 'Docker version fixture', stderr: '', code: 0 }
    if (args[0] === 'context') return { ok: true, stdout: '"npipe:////./pipe/dockerDesktopLinuxEngine"', stderr: '', code: 0 }
    if (args[0] === 'info') return { ok: true, stdout: 'linux/x86_64', stderr: '', code: 0 }
    if (args[0] === 'compose' && args.includes('version')) return { ok: true, stdout: '5.5.1', stderr: '', code: 0 }
    if (args.includes('config')) return { ok: true, stdout: JSON.stringify(model), stderr: '', code: 0 }
    if (args.includes('up')) return { ok: upOk, stdout: '', stderr: upOk ? '' : 'fixture startup failure', code: upOk ? 0 : 1 }
    if (args.includes('down')) {
      if (failures > 0) { failures -= 1; return { ok: false, stdout: '', stderr: 'fixture cleanup failure', code: 1 } }
      return { ok: true, stdout: '', stderr: '', code: 0 }
    }
    return { ok: true, stdout: '', stderr: '', code: 0 }
  }
  return { commands, run }
}

const fixture = (projectRoot, extra = {}) => ({
  services: {
    web: {
      build: { context: projectRoot, dockerfile: 'Dockerfile' },
      ports: [{ target: 8080, published: '8080', host_ip: '0.0.0.0', protocol: 'tcp' }],
      volumes: [{ type: 'volume', source: 'web-data', target: '/app/data' }],
      networks: ['default'],
      ...extra.web,
    },
    database: {
      image: 'mariadb:11.4',
      volumes: [{ type: 'volume', source: 'db-data', target: '/var/lib/mysql' }],
      networks: ['default'],
      ...extra.database,
    },
  },
  networks: { default: { driver: 'bridge' } },
  volumes: { 'web-data': {}, 'db-data': {} },
  ...extra.model,
})

const createLab = async (projectRoot, id = 'compose-fixture') => ({
  id: `lab-${id}`, slug: id, title: 'Compose fixture', category: 'Web', difficulty: '中等',
  sourceType: 'archive', sourceUrl: 'bundle://compose-fixture', sourceRef: 'fixture', license: 'MIT',
  runtimeKind: 'native-compose', providerId: 'native-compose', runtimeConfig: { profile: 'compose-project', composeFile: 'compose.yaml', webService: 'web', webPort: 8080 },
  builtin: false, version: 'fixture', status: 'ready', summary: '', tags: [], localPath: projectRoot,
  importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
})

const startInput = (instanceId, lab, dataDir) => ({
  instanceId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir, runtime,
})

const assertRejectedPolicy = async (dataDir, projectRoot, model, code) => {
  const docker = makeDocker({ model })
  const provider = new NativeComposeProvider({ runDocker: docker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  const id = `reject-policy-${++rejectedSequence}`
  await assert.rejects(provider.start(startInput(id, await createLab(projectRoot, id), dataDir)), error => error.code === code)
  assert.equal(docker.commands.some(args => args.includes('up')), false)
}

try {
  const paths = dataPaths(root)
  const projectRoot = join(paths.labs, 'compose-fixture')
  await mkdir(projectRoot, { recursive: true })
  await writeFile(join(projectRoot, 'compose.yaml'), 'services: {}\n')
  await writeFile(join(projectRoot, 'Dockerfile'), 'FROM nginx:alpine\n')

  const projectName = nativeComposeProjectName('compose-test-instance')
  assert.match(projectName, /^vulnlab-[a-f0-9]{24}$/)
  assert.notEqual(projectName, nativeComposeProjectName('compose-test-instance-two'))

  const docker = makeDocker({ model: fixture(projectRoot) })
  const provider = new NativeComposeProvider({ runDocker: docker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  const lab = await createLab(projectRoot)
  const started = await provider.start(startInput('compose-test-instance', lab, root))
  const instanceRoot = paths.runtimeInstance('compose-test-instance')
  const compose = JSON.parse(await readFile(join(instanceRoot, 'compose.json'), 'utf8'))
  const hostMappings = Object.entries(compose.services).flatMap(([name, service]) => (service.ports ?? []).map(port => ({ name, port })))
  assert.equal(hostMappings.length, 1)
  assert.equal(hostMappings[0].name, 'web')
  assert.equal(hostMappings[0].port.host_ip, '127.0.0.1')
  assert.equal(hostMappings[0].port.target, 8080)
  assert.equal(compose.name, nativeComposeProjectName('compose-test-instance'))
  assert.deepEqual(compose.services.database.networks, ['default'])
  assert.deepEqual(compose.volumes, { 'web-data': {}, 'db-data': {} })
  assert.match(started.endpoint, new RegExp(`:${portSequence}/$`))
  assert.equal((await provider.renew({ lab, instance: { id: 'compose-test-instance', expiresAt: started.expiresAt }, lifetimeMinutes: 5 })).expiresAt > started.expiresAt, true)
  const instance = { id: 'compose-test-instance', labId: lab.id, labTitle: lab.title, provider: 'native-compose', endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }
  await provider.stop({ lab, instance, runtime, dataDir: root })
  await assert.rejects(stat(instanceRoot))
  assert.ok(docker.commands.some(args => args.includes('down') && args.includes('--volumes') && args.includes('--remove-orphans')))

  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { web: { privileged: true } }), 'NATIVE_COMPOSE_POLICY_REJECTED')
  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { web: { network_mode: 'host' } }), 'NATIVE_COMPOSE_POLICY_REJECTED')
  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { web: { volumes: [{ type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock' }] } }), 'NATIVE_COMPOSE_POLICY_REJECTED')
  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { database: { ports: [{ target: 3306, published: '3306', host_ip: '0.0.0.0', protocol: 'tcp' }] } }), 'NATIVE_COMPOSE_POLICY_REJECTED')
  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { model: { networks: { external: { external: true } } } }), 'NATIVE_COMPOSE_POLICY_REJECTED')
  await assertRejectedPolicy(root, projectRoot, fixture(projectRoot, { web: { ports: [{ target: 8081, published: '8081', protocol: 'tcp' }] } }), 'NATIVE_COMPOSE_WEB_PORT_MISMATCH')

  const failingDocker = makeDocker({ model: fixture(projectRoot), upOk: false, downFailures: 1 })
  const failingProvider = new NativeComposeProvider({ runDocker: failingDocker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  const failingLab = await createLab(projectRoot, 'failed-start')
  await assert.rejects(failingProvider.start(startInput('compose-failed-start', failingLab, root)), /资源回收将重试/)
  const failedRoot = paths.runtimeInstance('compose-failed-start')
  assert.equal(JSON.parse(await readFile(join(failedRoot, 'native-compose.json'), 'utf8')).cleanupPending, true)
  const restartProvider = new NativeComposeProvider({ runDocker: failingDocker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  assert.deepEqual(await restartProvider.recoverPending(root, new Set()), [])
  await assert.rejects(stat(failedRoot))

  const orphanDocker = makeDocker({ model: fixture(projectRoot) })
  const firstProvider = new NativeComposeProvider({ runDocker: orphanDocker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  const orphanLab = await createLab(projectRoot, 'orphan')
  await firstProvider.start(startInput('compose-orphan-instance', orphanLab, root))
  const restartedProvider = new NativeComposeProvider({ runDocker: orphanDocker.run, allocatePort: async () => ++portSequence, waitUntilReady: async () => {} })
  assert.deepEqual(await restartedProvider.recoverPending(root, new Set()), [])
  await assert.rejects(stat(paths.runtimeInstance('compose-orphan-instance')))

  console.log('VulnLab native Compose tests passed: normalized multi-service config, local-only ingress, policy rejection, cleanup retry, stop and restart recovery.')
} finally {
  await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 150 })
}
