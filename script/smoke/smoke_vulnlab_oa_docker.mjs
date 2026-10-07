import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { DockerOaProvider } from '../../src/dist/runtime/providers.js'
import { inspectOaDockerRuntime } from '../../src/dist/labs/oa-vuln-labs/docker-runtime.js'

const dockerStatus = await inspectOaDockerRuntime()
if (!dockerStatus.available) throw new Error(`Docker smoke prerequisite failed: ${dockerStatus.missing.join(', ')}; ${dockerStatus.engine.detail}`)

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-oa-docker-smoke-'))
const instanceId = `oa-docker-smoke-${randomUUID().replaceAll('-', '')}`
const labRoot = join(dataDir, 'labs', 'oa-vuln-labs', 'smoke')
await mkdir(labRoot, { recursive: true })
const lab = {
  id: 'oa-docker-smoke-lab', slug: 'oa-vuln-labs', title: '中盛达 OA Docker 冒烟测试', category: 'Web', difficulty: '中等',
  sourceType: 'archive', sourceUrl: 'bundle://oa-vuln-labs/source.zip', sourceRef: '1.0.0-beta', license: 'unknown',
  runtimeKind: 'native-oa', providerId: 'oa-docker', runtimeConfig: { profile: 'oa-project' }, builtin: true,
  version: '1.0.0-beta', status: 'ready', summary: '', tags: [], localPath: labRoot,
  importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
}
const provider = new DockerOaProvider()
const runtime = { bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899, phpBinary: 'php', nodeBinary: 'node', javaBinary: 'java', pythonBinary: 'python' }
let started
let instance

const post = async (endpoint, path, token, body) => {
  const response = await fetch(new URL(path, endpoint), {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  })
  return { status: response.status, body: await response.json().catch(() => ({})) }
}

try {
  started = await provider.start({
    instanceId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir, runtime,
  })
  instance = {
    id: instanceId, labId: lab.id, labTitle: lab.title, provider: 'oa-docker', endpoint: started.endpoint,
    status: 'running', createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs,
  }
  const page = await fetch(started.endpoint, { signal: AbortSignal.timeout(10_000) })
  assert.equal(page.status, 200)
  const html = await page.text()
  assert.match(html, /<div id="root"><\/div>/)
  assert.match(html, /index-D6NZ84om\.js/)

  const login = await post(started.endpoint, '/api/auth/login', '', { username: 'admin', password: 'ZSD@admin2025!' })
  assert.equal(login.status, 200, JSON.stringify(login.body))
  const token = login.body?.data?.token
  assert.equal(typeof token, 'string')

  const execution = await post(started.endpoint, '/api/notification/template/preview', token, { content: '{{exec "id"}}' })
  assert.equal(execution.status, 200, JSON.stringify(execution.body))
  const executionOutput = String(execution.body?.data?.rendered ?? '')
  assert.match(executionOutput, /uid=65532\(\d+\)|uid=65532\b/, `Expected non-root container identity, got: ${executionOutput}`)

  const rootWrite = await post(started.endpoint, '/api/notification/template/preview', token, { content: '{{exec "touch /app/backend/oa-host-write-check && echo ROOT_FS_WRITE_OK"}}' })
  assert.equal(rootWrite.status, 200, JSON.stringify(rootWrite.body))
  assert.doesNotMatch(String(rootWrite.body?.data?.rendered ?? ''), /ROOT_FS_WRITE_OK/)

  const ssrf = await post(started.endpoint, '/api/system/check-url', token, { url: 'http://example.com/' })
  assert.equal(ssrf.status, 200, JSON.stringify(ssrf.body))
  assert.doesNotMatch(JSON.stringify(ssrf.body), /Example Domain/)

  await provider.stop({ lab, instance, runtime, dataDir })
  started = null
  console.log(`OA Docker smoke passed: original frontend/API, login, SSTI exec under UID 65532, read-only container root, isolated-network external SSRF check, and instance-scoped volume cleanup (${new URL(instance.endpoint).port}).`)
} finally {
  let cleanupError = null
  if (started && instance) {
    try { await provider.stop({ lab, instance, runtime, dataDir }) } catch (error) { cleanupError = error }
  }
  await provider.shutdown().catch(error => { cleanupError = error })
  try {
    await provider.recoverPending(dataDir, new Set())
    cleanupError = null
  } catch (error) {
    cleanupError = error
  }
  if (cleanupError) {
    console.error(`OA Docker smoke cleanup remains pending; recovery state retained at ${dataDir}: ${cleanupError.message}`)
  } else {
    await rm(dataDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 })
  }
}
