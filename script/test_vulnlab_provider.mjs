import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { NativePhpProvider, ProviderError, ProviderRegistry, QemuVmProvider, SimulatedProvider } from '../src/VulnLab/dist/providers.js'

const lab = {
  id: 'lab-dvwa',
  slug: 'dvwa',
  title: 'DVWA',
  category: 'Web',
  difficulty: '入门',
  sourceType: 'git',
  sourceUrl: 'https://github.com/digininja/DVWA',
  sourceRef: 'digininja/DVWA@master',
  license: 'GPL-3.0',
  runtimeKind: 'container',
  status: 'cataloged',
  summary: 'fixture',
  tags: ['Web'],
  localPath: null,
  importedAt: null,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
}

const provider = new SimulatedProvider()
const native = new NativePhpProvider()
const qemuRegistryProvider = new QemuVmProvider()
const registry = new ProviderRegistry([native, qemuRegistryProvider, provider])
assert.equal(registry.get('simulated'), provider)
assert.throws(() => registry.resolve('simulated', 'container'), error => error instanceof ProviderError && error.code === 'PROVIDER_RUNTIME_UNSUPPORTED')
assert.throws(() => registry.resolve('simulated', 'vm'), error => error instanceof ProviderError && error.code === 'PROVIDER_RUNTIME_UNSUPPORTED')
assert.equal(registry.resolveForLab('simulated', 'native-php'), native)
assert.equal(registry.resolveForLab('native-php', 'simulated'), provider)
assert.equal(registry.resolveForLab('qemu-vm', 'vm').id, 'qemu-vm')
assert.throws(() => registry.resolveForLab('native-php', 'container'), error => error instanceof ProviderError && error.code === 'PROVIDER_RUNTIME_UNSUPPORTED')
assert.throws(() => registry.resolveForLab('simulated', 'container'), error => error instanceof ProviderError && error.code === 'PROVIDER_RUNTIME_UNSUPPORTED')
assert.throws(() => registry.resolve('missing', 'container'), error => error instanceof ProviderError && error.code === 'PROVIDER_NOT_FOUND')
assert.throws(() => new ProviderRegistry([provider, provider]), /Provider ID 重复/)

const started = await provider.start({
  instanceId: 'instance-1',
  lab,
  publicOrigin: 'https://lab.example.com/',
  lifetimeMinutes: 60,
})
assert.equal(started.endpoint, 'https://lab.example.com/lab-preview/dvwa')
assert.equal(started.logs.length, 3)
assert.ok(Date.parse(started.expiresAt) > Date.parse(started.createdAt))

const instance = { id: 'instance-1', labId: lab.id, labTitle: lab.title, provider: provider.id, endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }
const renewed = await provider.renew({ lab, instance, lifetimeMinutes: 60 })
assert.ok(Date.parse(renewed.expiresAt) > Date.now())
assert.match(renewed.log, /运行实例续期/)

const stopped = await provider.stop({ lab, instance })
assert.match(stopped.log, /运行实例结束/)

const vmDataDir = await mkdtemp(join(tmpdir(), 'vulnlab-qemu-provider-'))
try {
  const tarEntry = (name, contents) => {
    const value = Buffer.from(contents)
    const header = Buffer.alloc(512)
    header.write(name, 0, 100, 'utf8')
    header.write(`${value.byteLength.toString(8).padStart(11, '0')}\0`, 124, 12, 'ascii')
    header[156] = 0x30
    header.write('ustar\0', 257, 6, 'ascii')
    const padding = Buffer.alloc((512 - (value.byteLength % 512)) % 512)
    return Buffer.concat([header, value, padding])
  }
  const imagePath = join(vmDataDir, 'fixture.ova')
  const descriptor = '# Disk DescriptorFile\nversion=1\nRW 1 SPARSE "disk-flat.vmdk"\n'
  await writeFile(imagePath, Buffer.concat([
    tarEntry('machine/disk.vmdk', descriptor),
    tarEntry('machine/disk-flat.vmdk', Buffer.alloc(2048, 7)),
    Buffer.alloc(1024),
  ]))
  const spawnCalls = []
  const fakeChildren = []
  const fakeSpawn = (binary, args) => {
    spawnCalls.push({ binary, args })
    const child = new EventEmitter()
    child.exitCode = null
    child.pid = 4242
    child.kill = () => {
      if (child.exitCode === null) {
        child.exitCode = 0
        child.emit('exit', 0, null)
      }
      return true
    }
    fakeChildren.push(child)
    queueMicrotask(() => child.emit('spawn'))
    return child
  }
  const providerVm = new QemuVmProvider({
    qemuBinary: 'qemu-system-x86_64',
    spawnImpl: fakeSpawn,
    allocatePort: async () => 6910,
    probePort: async () => undefined,
  })
  const vmLab = { ...lab, id: 'lab-vulnhub', slug: 'vulnhub-fixture', title: 'VulnHub Fixture', sourceType: 'catalog', runtimeKind: 'vm' }
  const vmStarted = await providerVm.start({
    instanceId: 'vm-instance-1',
    lab: vmLab,
    publicOrigin: 'http://127.0.0.1:6710',
    proxyEndpoint: 'http://127.0.0.1:6710/lab-runtime/vm-instance-1/',
    lifetimeMinutes: 60,
    dataDir: vmDataDir,
    runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php' },
    vm: { portStart: 6900, portEnd: 6999, qemuBinary: 'qemu-system-x86_64', guestPort: 80, memoryMb: 512, cpus: 1, bootTimeoutMs: 1_000 },
    artifactPath: imagePath,
  })
  assert.equal(vmStarted.endpoint, 'http://127.0.0.1:6710/lab-runtime/vm-instance-1/')
  assert.match(vmStarted.logs.join('\n'), /宿主端口=6910/)
  assert.equal(providerVm.getProxyTarget('vm-instance-1'), 'http://127.0.0.1:6910')
  assert.equal(spawnCalls[0].binary, 'qemu-system-x86_64')
  assert.ok(spawnCalls[0].args.includes('-nic'))
  assert.ok(spawnCalls[0].args.includes('-snapshot'))
  assert.ok(spawnCalls[0].args.some(value => value.includes('hostfwd=tcp:127.0.0.1:6910-:80')))
  assert.ok(spawnCalls[0].args.some(value => value.includes('format=vmdk')))
  assert.ok(spawnCalls[0].args.some(value => /vm-runtime[\\/]vm-instance-1[\\/]ova[\\/]machine[\\/]disk\.vmdk/.test(value)))
  const vmInstance = { id: 'vm-instance-1', labId: vmLab.id, labTitle: vmLab.title, provider: providerVm.id, endpoint: vmStarted.endpoint, status: 'running', createdAt: vmStarted.createdAt, expiresAt: vmStarted.expiresAt, logs: vmStarted.logs }
  const vmRenewed = await providerVm.renew({ lab: vmLab, instance: vmInstance, lifetimeMinutes: 60 })
  assert.ok(Date.parse(vmRenewed.expiresAt) > Date.now())
  await providerVm.stop({ lab: vmLab, instance: vmInstance, dataDir: vmDataDir })
  assert.equal(providerVm.getProxyTarget('vm-instance-1'), null)
  await assert.rejects(readFile(join(vmDataDir, 'vm-runtime', 'vm-instance-1', 'state.json')))
  assert.equal(fakeChildren.length, 1)
  const unsafeImagePath = join(vmDataDir, 'unsafe.ova')
  await writeFile(unsafeImagePath, Buffer.concat([tarEntry('../outside.vmdk', 'unsafe'), Buffer.alloc(1024)]))
  await assert.rejects(
    providerVm.start({
      instanceId: 'vm-instance-unsafe',
      lab: vmLab,
      publicOrigin: 'http://127.0.0.1:6710',
      lifetimeMinutes: 60,
      dataDir: vmDataDir,
      runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php' },
      vm: { portStart: 6900, portEnd: 6999, qemuBinary: 'qemu-system-x86_64', guestPort: 80, memoryMb: 512, cpus: 1, bootTimeoutMs: 1_000 },
      artifactPath: unsafeImagePath,
    }),
    error => error instanceof ProviderError && error.code === 'QEMU_OVA_PATH_INVALID',
  )
  assert.equal(spawnCalls.length, 1)
  await assert.rejects(readFile(join(vmDataDir, 'vm-runtime', 'vm-instance-unsafe', 'state.json')))
} finally {
  await rm(vmDataDir, { recursive: true, force: true })
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
await managedNative.recover({ lab, instance: { ...instance, provider: 'native-php' }, runtime: { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', mysql: mysqlConfig } })
assert.equal(recoveries.length, 1)
assert.equal(recoveries[0].labSlug, 'dvwa')
assert.equal(recoveries[0].instanceId, instance.id)

await assert.rejects(
  provider.start({ instanceId: 'instance-invalid', lab, publicOrigin: 'https://lab.example.com', lifetimeMinutes: 0 }),
  error => error instanceof ProviderError && error.code === 'PROVIDER_LIFETIME_INVALID',
)

console.log('VulnLab provider test passed: registry resolution, simulated lifecycle and QEMU command/lifecycle contract.')
