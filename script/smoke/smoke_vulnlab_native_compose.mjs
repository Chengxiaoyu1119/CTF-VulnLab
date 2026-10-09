import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { NativeComposeProvider, nativeComposeProjectName } from '../../src/dist/runtime/providers.js'
import { dataPaths } from '../../src/dist/paths.js'

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-compose-smoke-'))
const runtime = {
  bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899,
  phpBinary: 'php', nodeBinary: process.execPath, javaBinary: 'java', pythonBinary: 'python',
}
const instanceId = `compose-smoke-${process.pid}`
const projectName = nativeComposeProjectName(instanceId)
const provider = new NativeComposeProvider()

const runDocker = async args => {
  const { runDockerCommand } = await import('../../src/dist/labs/oa-vuln-labs/docker-runtime.js')
  const result = await runDockerCommand(args)
  assert.equal(result.ok, true, `docker ${args.join(' ')} failed: ${result.stderr}`)
  return result.stdout.trim()
}

try {
  const projectRoot = join(dataPaths(dataDir).labs, 'compose-smoke')
  await mkdir(projectRoot, { recursive: true })
  await writeFile(join(projectRoot, 'compose.yaml'), [
    'services:',
    '  web:',
    '    image: nginx:1.27-alpine',
    '    ports:',
    '      - "80"',
    '    depends_on:',
    '      - cache',
    '  cache:',
    '    image: redis:8-alpine',
    '',
  ].join('\n'))
  const lab = {
    id: 'lab-compose-smoke', slug: 'compose-smoke', title: 'Compose smoke', category: 'Web', difficulty: '中等',
    sourceType: 'archive', sourceUrl: 'fixture://compose-smoke', sourceRef: 'fixture', license: 'MIT',
    runtimeKind: 'native-compose', providerId: 'native-compose',
    runtimeConfig: { profile: 'compose-project', composeFile: 'compose.yaml', webService: 'web', webPort: 80 },
    builtin: false, version: 'fixture', status: 'ready', summary: '', tags: [], localPath: projectRoot,
    importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }
  const started = await provider.start({
    instanceId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir, runtime,
  })
  const response = await fetch(started.endpoint)
  assert.equal(response.status, 200)
  assert.match(await response.text(), /Welcome to nginx!/)
  const images = await runDocker(['ps', '--filter', `label=com.docker.compose.project=${projectName}`, '--format', '{{.Image}}'])
  assert.match(images, /nginx:1\.27-alpine/)
  assert.match(images, /redis:8-alpine/)
  await provider.stop({
    lab,
    instance: { id: instanceId, labId: lab.id, labTitle: lab.title, provider: 'native-compose', endpoint: started.endpoint, status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs },
    dataDir,
  })
  assert.equal(await runDocker(['ps', '--quiet', '--filter', `label=com.docker.compose.project=${projectName}`]), '')
  assert.equal(await runDocker(['network', 'ls', '--quiet', '--filter', `label=com.docker.compose.project=${projectName}`]), '')
  console.log('VulnLab native Compose smoke passed: Nginx + Redis, local HTTP ingress and resource cleanup.')
} finally {
  await provider.shutdown()
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
