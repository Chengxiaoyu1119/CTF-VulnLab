import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify'
import cookie from '@fastify/cookie'
import helmet from '@fastify/helmet'
import fastifyStatic from '@fastify/static'
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto'
import { cp, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { request as httpRequest } from 'node:http'
import { isIP } from 'node:net'
import { fileURLToPath } from 'node:url'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { VulnLabDatabase } from './db.js'
import { hasBuiltinAsset, installBuiltinAsset } from './builtin-assets.js'
import { importGitHubRepository, importGitLabRepository, ImporterError } from './importer.js'
import { adapterFor } from './importers.js'
import { mysqlRuntimeConfigFromEnv } from './mysql.js'
import { ProviderError, providerRegistry, type NativeRuntimeConfig } from './providers.js'
import { projectEnvironmentOptionsFromEnv } from './project-environment.js'
import { prepareInstalledLab } from './runtime-prep.js'
import { inspectRuntimeDependencies, runtimeReadinessByLab } from './runtime-status.js'
import { autoInstallLabs } from './seed.js'
import type { AppSettings, ImportManifest, Lab, LabInstance, SessionView } from './types.js'

const moduleDir = dirname(fileURLToPath(import.meta.url))
const appDir = basename(moduleDir) === 'dist' ? resolve(moduleDir, '..') : moduleDir
const publicDir = join(appDir, 'public')
const dataDir = process.env.VULNLAB_DATA_DIR ? resolve(process.env.VULNLAB_DATA_DIR) : join(appDir, 'data')
const configuredHost = process.env.VULNLAB_HOST ?? '127.0.0.1'
const configuredPort = Number(process.env.VULNLAB_PORT ?? process.env.PORT ?? 6710)
const fallbackPort = Number.isInteger(configuredPort) && configuredPort >= 1024 && configuredPort <= 65535 ? configuredPort : 6710
const hasHostOverride = process.env.VULNLAB_HOST !== undefined
const hasPortOverride = process.env.VULNLAB_PORT !== undefined || process.env.PORT !== undefined
if (configuredHost !== 'localhost' && isIP(configuredHost) === 0) throw new Error('VULNLAB_HOST 必须是 localhost 或有效 IP 地址。')
const configuredLifetime = Number(process.env.VULNLAB_INSTANCE_MINUTES ?? 60)
const instanceLifetimeMinutes = Number.isFinite(configuredLifetime) && configuredLifetime > 0 ? configuredLifetime : 60
const runtimeHost = process.env.VULNLAB_RUNTIME_HOST ?? '127.0.0.1'
const runtimePortStart = Number(process.env.VULNLAB_RUNTIME_PORT_START ?? 6800)
const runtimePortEnd = Number(process.env.VULNLAB_RUNTIME_PORT_END ?? 6899)
const runtimePhpBinary = process.env.VULNLAB_PHP_BIN ?? 'php'
const runtimePhpIni = process.env.VULNLAB_PHP_INI?.trim() || undefined
const runtimePublicOrigin = process.env.VULNLAB_RUNTIME_PUBLIC_ORIGIN?.trim() || undefined
let runtimeMySql = mysqlRuntimeConfigFromEnv()
if (runtimeHost !== 'localhost' && isIP(runtimeHost) === 0) throw new Error('VULNLAB_RUNTIME_HOST 必须是 localhost 或有效 IP 地址。')
if (!Number.isInteger(runtimePortStart) || !Number.isInteger(runtimePortEnd) || runtimePortStart < 1024 || runtimePortEnd > 65535 || runtimePortStart > runtimePortEnd) throw new Error('VULNLAB_RUNTIME_PORT_START/END 必须是有效端口范围。')
const nativeRuntime: NativeRuntimeConfig = {
  bindHost: runtimeHost,
  portStart: runtimePortStart,
  portEnd: runtimePortEnd,
  phpBinary: runtimePhpBinary,
  phpIni: runtimePhpIni,
  nodeBinary: process.env.VULNLAB_NODE_BIN?.trim() || process.execPath,
  javaBinary: process.env.VULNLAB_JAVA_BIN?.trim() || 'java',
  pythonBinary: process.env.VULNLAB_PYTHON_BIN?.trim() || (process.platform === 'win32' ? 'py' : 'python3'),
  publicOriginTemplate: runtimePublicOrigin,
  mysql: runtimeMySql,
}
const projectEnvironment = projectEnvironmentOptionsFromEnv(dataDir, process.env.VULNLAB_PHP_BIN?.trim(), runtimePhpIni, runtimeMySql, process.env.VULNLAB_NODE_BIN?.trim())
const isProduction = process.env.NODE_ENV === 'production'
const secureCookies = isProduction
const configuredPublicUrl = process.env.VULNLAB_PUBLIC_URL?.trim().replace(/\/+$/, '') ?? ''
if (configuredPublicUrl) {
  const publicUrl = new URL(configuredPublicUrl)
  if (!['http:', 'https:'].includes(publicUrl.protocol) || publicUrl.username || publicUrl.password || publicUrl.search || publicUrl.hash) {
    throw new Error('VULNLAB_PUBLIC_URL 必须是没有账号、密码、查询参数和片段的 HTTP(S) 地址。')
  }
}

const defaultAdminUser = 'vulnlab'
const defaultAdminPassword = 'vulnlab'
const cookieSecret = process.env.VULNLAB_COOKIE_SECRET ?? (isProduction ? '' : 'vulnlab-development-cookie-secret')
const adminPassword = process.env.VULNLAB_ADMIN_PASSWORD ?? (isProduction ? '' : defaultAdminPassword)

if (isProduction) {
  if (cookieSecret.length < 32) throw new Error('生产环境必须设置长度至少为 32 的 VULNLAB_COOKIE_SECRET。')
  if (!process.env.VULNLAB_ADMIN_PASSWORD || adminPassword === defaultAdminPassword || adminPassword.length < 12) throw new Error('生产环境必须通过 VULNLAB_ADMIN_PASSWORD 设置至少 12 个字符的管理员密码。')
}

const adminAccount = { userName: defaultAdminUser, password: adminPassword, role: 'admin' as const }

const database = new VulnLabDatabase(dataDir, { bindHost: configuredHost, port: String(fallbackPort), dataDir })
const persistedSettings = database.getSettings()
const persistedHost = persistedSettings.bindHost === 'localhost' || isIP(persistedSettings.bindHost) !== 0 ? persistedSettings.bindHost : configuredHost
const persistedPort = Number(persistedSettings.port)
const host = hasHostOverride ? configuredHost : persistedHost
const port = hasPortOverride || !Number.isInteger(persistedPort) || persistedPort < 1024 || persistedPort > 65535 ? fallbackPort : persistedPort
const recoverProviderInstances = async () => {
  for (const instance of database.listInstances().filter(item => item.status === 'running')) {
    const lab = database.getLab(instance.labId)
    const provider = providerRegistry.get(instance.provider)
    if (!lab || !provider?.recover) continue
    try {
      await provider.recover({ lab, instance, runtime: nativeRuntime, dataDir })
      database.destroyInstance(instance.id, `服务启动时回收遗留 ${instance.provider} 运行资源`)
      database.addAudit('system', 'instance.recovered', instance.labTitle, instance.id)
    } catch (error) {
      // Keep the row running when provider recovery fails so the failure is
      // visible and the next restart can retry resource cleanup.
      console.error(`VulnLab 无法清理遗留实例 ${instance.id} 的运行资源。`, error)
    }
  }
}
const trustProxy = process.env.VULNLAB_TRUST_PROXY === 'true'
const app = Fastify({ logger: process.env.NODE_ENV !== 'test', bodyLimit: 64 * 1024, trustProxy })
const loginWindowMs = 60_000
const loginLimit = isProduction ? 10 : 30
const activeImports = new Map<string, { task: Promise<void>; controller: AbortController }>()
const pendingStarts = new Map<string, Promise<LabInstance | null>>()
const activeStarts = new Map<string, Promise<LabInstance>>()
let reapingExpiredInstances = false
let runtimeStatusCache: { expiresAt: number; value: Awaited<ReturnType<typeof inspectRuntimeDependencies>> } | null = null

const runtimeDependencies = async () => {
  if (runtimeStatusCache && runtimeStatusCache.expiresAt > Date.now()) return runtimeStatusCache.value
  const projectStatus = projectEnvironment.getStatus()
  const value = await inspectRuntimeDependencies({
    phpBinary: nativeRuntime.phpBinary,
    phpIni: nativeRuntime.phpIni,
    nodeBinary: nativeRuntime.nodeBinary,
    javaBinary: nativeRuntime.javaBinary,
    pythonBinary: nativeRuntime.pythonBinary,
    mysql: nativeRuntime.mysql,
    sources: {
      php: { source: projectStatus.php.source },
      'php-mysqli': { source: projectStatus.php.source, action: projectStatus.php.available ? 'ready' : 'configure' },
      mysql: { source: projectStatus.mysql.source, action: projectStatus.mysql.available ? 'ready' : 'configure' },
      node: { source: projectStatus.node.source, action: projectStatus.node.available ? 'ready' : 'prepare' },
      java: { source: projectStatus.java.source, action: projectStatus.java.available ? 'ready' : 'prepare' },
      python: { source: projectStatus.python.source, action: projectStatus.python.available ? 'ready' : 'prepare' },
    },
  })
  runtimeStatusCache = { expiresAt: Date.now() + 15_000, value }
  return value
}

const prepareProjectEnvironment = async (force = false, installMissing = false) => {
  try {
    const prepared = await projectEnvironment.prepare(force, installMissing)
    nativeRuntime.phpBinary = prepared.phpBinary
    nativeRuntime.phpIni = prepared.phpIni
    runtimeMySql = prepared.mysql
    nativeRuntime.mysql = prepared.mysql
    nativeRuntime.nodeBinary = prepared.nodeBinary
    nativeRuntime.javaBinary = prepared.javaBinary
    nativeRuntime.pythonBinary = prepared.pythonBinary
    runtimeStatusCache = null
    app.log.info({ runtimeDir: prepared.status.runtimeDir, php: prepared.status.php.source, mysql: prepared.status.mysql.source, node: prepared.status.node.source }, '项目运行环境已准备。')
  } catch (error) {
    runtimeMySql = mysqlRuntimeConfigFromEnv()
    nativeRuntime.mysql = runtimeMySql
    app.log.error(error, '项目运行环境准备失败，服务仍会启动，并在对应靶场启动时返回具体依赖错误。')
  }
  return projectEnvironment.getStatus()
}

const reapExpiredInstances = async () => {
  if (reapingExpiredInstances) return
  reapingExpiredInstances = true
  try {
    const candidates = database.listExpiredInstances()
    await Promise.all(candidates.map(async instance => {
      const lab = database.getLab(instance.labId)
      const provider = lab ? providerRegistry.get(instance.provider) : null
      if (!lab || !provider) {
        // Keep the row running when a newer/older deployment no longer knows
        // the lab or Provider; expiring the row here could hide leaked resources.
        app.log.error({ instanceId: instance.id, labId: instance.labId, provider: instance.provider }, '过期实例缺少可用的 Provider，等待下一次恢复。')
        return
      }
      try {
        await provider.stop({ lab, instance, runtime: nativeRuntime, dataDir })
      } catch (error) {
        // Keep the row running so the next sweep retries the provider cleanup.
        app.log.error(error, `过期实例 ${instance.id} 的运行资源回收失败。`)
        return
      }
      const expired = database.expireInstance(instance.id, '运行实例已过期，Provider 资源已回收')
      if (expired) database.addAudit('system', 'instance.expired', expired.labTitle, expired.id)
    }))
  } finally {
    reapingExpiredInstances = false
  }
}

const expiredInstanceTimer = setInterval(() => {
  void reapExpiredInstances().catch(error => app.log.error(error, '过期实例回收任务失败。'))
}, 5_000)
expiredInstanceTimer.unref()
app.addHook('onClose', async () => {
  clearInterval(expiredInstanceTimer)
})

const hashPassword = (password: string, salt: Buffer) => scryptSync(password, salt, 32)

const sameSecret = (expected: string, actual: string) => {
  const salt = createHash('sha256').update(expected).digest().subarray(0, 16)
  const expectedHash = hashPassword(expected, salt)
  const actualHash = hashPassword(actual, salt)
  return timingSafeEqual(expectedHash, actualHash)
}

const getSession = (request: FastifyRequest): SessionView | null => {
  const rawSessionId = request.cookies.vulnlab_session
  if (!rawSessionId) return null
  const signedSession = request.unsignCookie(rawSessionId)
  if (!signedSession.valid) return null
  const sessionId = signedSession.value
  database.cleanupSessions()
  const session = database.getSession(sessionId)
  if (!session) return null
  return { userName: session.userName, role: session.role, csrfToken: session.csrfToken }
}

const requireUser = (request: FastifyRequest, reply: FastifyReply): SessionView | null => {
  const session = getSession(request)
  if (!session) {
    reply.code(401).send({ code: 'UNAUTHENTICATED', message: '请先登录。' })
    return null
  }
  return session
}

const requireAdmin = (request: FastifyRequest, reply: FastifyReply): SessionView | null => {
  const session = requireUser(request, reply)
  if (!session) return null
  if (session.role !== 'admin') {
    reply.code(403).send({ code: 'FORBIDDEN', message: '当前账号没有管理权限。' })
    return null
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
    const csrfToken = request.headers['x-csrf-token']
    if (csrfToken !== session.csrfToken) {
      reply.code(403).send({ code: 'CSRF_INVALID', message: '请求校验已过期，请刷新页面后重试。' })
      return null
    }
  }
  return session
}

const requireCsrf = (request: FastifyRequest, reply: FastifyReply, session: SessionView) => {
  const csrfToken = request.headers['x-csrf-token']
  if (csrfToken !== session.csrfToken) {
    reply.code(403).send({ code: 'CSRF_INVALID', message: '请求校验已过期，请刷新页面后重试。' })
    return false
  }
  return true
}

const requestBody = (request: FastifyRequest) => (request.body ?? {}) as Record<string, unknown>

const publicOrigin = (request: FastifyRequest) => {
  if (configuredPublicUrl) return configuredPublicUrl
  if (host !== '0.0.0.0' && host !== '::') return `http://${host}:${port}`
  const protocol = request.protocol
  const requestHost = request.headers.host
  return requestHost ? `${protocol}://${requestHost}` : `http://127.0.0.1:${port}`
}

const promoteBuiltinManifest = async (lab: Lab, jobId: string, manifest: ImportManifest) => {
  if (!lab.builtin || manifest.adapterId === 'builtin-release') return manifest
  const targetRoot = join(dataDir, 'labs', lab.slug, lab.version)
  const targetPath = targetRoot
  if (resolve(manifest.localPath) === resolve(targetPath)) return manifest
  await rm(targetRoot, { recursive: true, force: true })
  await mkdir(dirname(targetRoot), { recursive: true })
  try {
    await rename(manifest.localPath, targetPath)
  } catch {
    await cp(manifest.localPath, targetPath, { recursive: true, force: true })
  }
  const promoted = { ...manifest, localPath: targetPath }
  await writeFile(join(targetRoot, 'vulnlab.manifest.json'), JSON.stringify(promoted, null, 2), 'utf8')
  await rm(join(dataDir, 'imports', jobId), { recursive: true, force: true })
  return promoted
}

const cleanupOutdatedBuiltinVersions = async (lab: Lab) => {
  if (!lab.builtin || !/^[a-z0-9-]+$/.test(lab.slug) || !/^[A-Za-z0-9._-]+$/.test(lab.version)) return
  const root = join(dataDir, 'labs', lab.slug)
  const entries = await readdir(root, { withFileTypes: true }).catch(() => [])
  await Promise.allSettled(entries
    .filter(entry => entry.isDirectory() && entry.name !== lab.version)
    .map(entry => rm(join(root, entry.name), { recursive: true, force: true, maxRetries: 6, retryDelay: 150 })))
}

const runtimeRequest = (url: string) => {
  const parsed = new URL(url, 'http://vulnlab.internal')
  const prefix = '/lab-runtime/'
  if (!parsed.pathname.startsWith(prefix)) return null
  const remainder = parsed.pathname.slice(prefix.length)
  const separator = remainder.indexOf('/')
  const rawId = separator === -1 ? remainder : remainder.slice(0, separator)
  if (!rawId) return null
  return { id: decodeURIComponent(rawId), suffix: separator === -1 ? '/' : remainder.slice(separator), search: parsed.search }
}

const proxyRuntimeRequest = async (request: FastifyRequest, reply: FastifyReply) => {
  const runtime = runtimeRequest(request.url)
  if (!runtime) return false
  const instance = database.getRunningInstance(runtime.id)
  if (!instance) return reply.code(404).send({ code: 'RUNTIME_NOT_FOUND', message: '运行入口不存在或已经结束。' }), true
  const provider = providerRegistry.get(instance.provider)
  if (!provider?.getProxyTarget) return reply.code(404).send({ code: 'RUNTIME_NOT_FOUND', message: '该实例没有可代理的运行入口。' }), true
  const target = provider?.getProxyTarget?.(instance.id)
  if (!target) return reply.code(409).send({ code: 'RUNTIME_PROCESS_MISSING', message: '运行进程已退出，请重新启动实例。' }), true
  const targetUrl = new URL(target)
  targetUrl.pathname = `${targetUrl.pathname.replace(/\/$/, '')}${runtime.suffix.startsWith('/') ? runtime.suffix : `/${runtime.suffix}`}` || '/'
  targetUrl.search = runtime.search
  const headers = { ...request.headers }
  for (const header of ['host', 'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade']) delete headers[header]
  await new Promise<void>(resolveProxy => {
    const upstream = httpRequest({ hostname: targetUrl.hostname, port: Number(targetUrl.port), method: request.method, path: `${targetUrl.pathname}${targetUrl.search}`, headers }, response => {
      const responseHeaders = { ...response.headers }
      for (const header of ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade']) delete responseHeaders[header]
      reply.hijack()
      reply.raw.writeHead(response.statusCode ?? 502, responseHeaders)
      response.once('end', resolveProxy)
      response.once('error', resolveProxy)
      response.pipe(reply.raw)
    })
    upstream.setTimeout(15_000, () => upstream.destroy(new Error('运行入口响应超时。')))
    request.raw.once('aborted', () => upstream.destroy(new Error('客户端已断开运行入口请求。')))
    upstream.once('error', error => {
      if (!reply.sent) reply.code(502).send({ code: 'RUNTIME_PROXY_FAILED', message: error instanceof Error ? error.message : '运行入口连接失败。' })
      resolveProxy()
    })
    request.raw.pipe(upstream)
  })
  return true
}

const runImportJob = (jobId: string, actor: string) => {
  const controller = new AbortController()
  const task = (async () => {
    const job = database.getJob(jobId)
    const lab = job ? database.getLab(job.labId) : null
    if (!job || !lab) return
    if (job.status !== 'importing') return
    try {
      const progress = (value: number, stage: string, message: string) => database.updateJob(jobId, { status: 'importing', progress: value, stage, message })
      const adapter = adapterFor(lab.sourceUrl, lab.sourceType)
      if (!hasBuiltinAsset(lab.slug) && !adapter) throw new ImporterError('当前来源没有可用的 Source Adapter。')
      if (!hasBuiltinAsset(lab.slug) && adapter && !adapter.implemented) throw new ImporterError(`${adapter.label} 已登记，但当前版本还未实现下载与运行适配。`)
      const importedManifest = hasBuiltinAsset(lab.slug)
        ? await installBuiltinAsset({ lab, jobId, dataDir, signal: controller.signal, onProgress: progress })
        : adapter?.id === 'github-git'
        ? await importGitHubRepository({
          sourceUrl: lab.sourceUrl,
          sourceRef: lab.sourceRef,
          jobId,
          dataDir,
          signal: controller.signal,
          // SQLi-Labs contains two case-only duplicate files used by lessons
          // 24/40. Keep the lowercase targets referenced by the application;
          // all other sources retain strict Windows path validation.
          portablePathPolicy: lab.slug === 'sqli-labs' ? 'case-collision-lowercase' : 'strict',
          onProgress: progress,
        })
        : adapter?.id === 'gitlab-git'
          ? await importGitLabRepository({
            sourceUrl: lab.sourceUrl,
            sourceRef: lab.sourceRef,
            jobId,
            dataDir,
            signal: controller.signal,
            portablePathPolicy: lab.slug === 'sqli-labs' ? 'case-collision-lowercase' : 'strict',
            onProgress: progress,
          })
        : (() => { throw new ImporterError(`当前版本尚未实现 ${adapter?.label ?? '该来源'}。`) })()
      const manifest = await promoteBuiltinManifest(lab, jobId, importedManifest)
      await prepareInstalledLab({ ...lab, localPath: manifest.localPath }, progress, nativeRuntime.pythonBinary)
      database.completeJob(jobId, manifest)
      await cleanupOutdatedBuiltinVersions({ ...lab, localPath: manifest.localPath })
      database.addAudit(actor, 'import.completed', lab.title, `${manifest.resolvedRef} · sha256:${manifest.archiveSha256}`)
    } catch (error) {
      if (controller.signal.aborted) {
        database.updateJob(jobId, { status: 'importing', stage: 'stopping', message: '服务关闭，任务将在下次启动后恢复。' })
        return
      }
      const message = error instanceof Error ? error.message : '导入过程出现未知错误。'
      database.failJob(jobId, message)
      database.addAudit(actor, 'import.failed', lab.title, message)
    }
  })()
  activeImports.set(jobId, { task, controller })
  void task.then(
    () => activeImports.delete(jobId),
    error => {
      activeImports.delete(jobId)
      app.log.error(error)
    },
  )
}

const startLabInstall = (lab: Lab, actor: string) => {
  if (lab.status === 'ready') return { lab, job: null, started: false }
  const job = database.createJob(lab.id, lab.sourceUrl, actor)
  if (job.status === 'importing') return { lab: database.getLab(lab.id) as Lab, job, started: false }
  const claimed = database.claimJob(job.id)
  if (!claimed) return { lab: database.getLab(lab.id) as Lab, job: database.getJob(job.id), started: false }
  runImportJob(claimed.id, actor)
  return { lab: database.getLab(lab.id) as Lab, job: claimed, started: true }
}

const startLabInstance = (lab: Lab, actor: string, origin: string): Promise<LabInstance> => {
  const existingStart = activeStarts.get(lab.id)
  if (existingStart) return existingStart
  const task = (async () => {
    const existingInstance = database.listInstances()
      .map(instance => database.getRunningInstance(instance.id))
      .find(instance => instance?.labId === lab.id)
    if (existingInstance) return existingInstance
    if (lab.status !== 'ready') throw new ProviderError('LAB_NOT_READY', '靶场资源正在准备，请稍候。', 409)
    let dependencies = await runtimeDependencies()
    let readiness = await runtimeReadinessByLab([lab], dependencies, dataDir)
    if (!readiness[lab.slug]?.available) {
      await prepareProjectEnvironment(true, true)
      runtimeStatusCache = null
      dependencies = await runtimeDependencies()
      readiness = await runtimeReadinessByLab([lab], dependencies, dataDir)
    }
    if (!readiness[lab.slug]?.available) throw new ProviderError('RUNTIME_DEPENDENCY_MISSING', `本机缺少运行依赖：${readiness[lab.slug]?.missing.join('、') || '未知依赖'}。`, 409)
    const provider = providerRegistry.resolve(lab.providerId, lab.runtimeKind)
    const overview = database.overview()
    const maxInstances = overview.maxInstances
    if (overview.runningInstanceCount >= maxInstances) throw new ProviderError('INSTANCE_CAPACITY_REACHED', '当前运行容量已满，请先结束一个实例。', 409)
    const instanceId = randomUUID()
    const started = await provider.start({
      instanceId,
      lab,
      publicOrigin: origin,
      proxyEndpoint: lab.runtimeKind === 'native-php' ? `${origin}/lab-runtime/${instanceId}/` : undefined,
      lifetimeMinutes: instanceLifetimeMinutes,
      dataDir,
      runtime: nativeRuntime,
    })
    const instance = database.createInstance({ id: instanceId, lab, provider: provider.id, ...started }, maxInstances)
    if (!instance) {
      const candidate = { id: instanceId, labId: lab.id, labTitle: lab.title, provider: provider.id, endpoint: started.endpoint, status: 'running' as const, createdAt: started.createdAt, expiresAt: started.expiresAt, logs: started.logs }
      try { await provider.stop({ lab, instance: candidate, runtime: nativeRuntime, dataDir }) } catch (error) { app.log.error(error, 'Provider 启动后无法回收未持久化实例。') }
      throw new ProviderError('INSTANCE_CAPACITY_REACHED', '当前运行容量已满，请先结束一个实例。', 409)
    }
    database.addAudit(actor, 'instance.start', lab.title, instance.id)
    return instance
  })()
  activeStarts.set(lab.id, task)
  void task.then(() => {
    if (activeStarts.get(lab.id) === task) activeStarts.delete(lab.id)
  }, () => {
    if (activeStarts.get(lab.id) === task) activeStarts.delete(lab.id)
  })
  return task
}

const queueStartAfterImport = (labId: string, jobId: string, actor: string, origin: string) => {
  const existing = pendingStarts.get(labId)
  if (existing) return existing
  const task = (async () => {
    await activeImports.get(jobId)?.task
    const preparedLab = database.getLab(labId)
    if (!preparedLab || preparedLab.status !== 'ready') return null
    try {
      return await startLabInstance(preparedLab, actor, origin)
    } catch (error) {
      const message = error instanceof Error ? error.message : '靶场准备完成，但启动失败。'
      database.updateJob(jobId, { message: `资源已准备，但启动失败：${message}`, error: message })
      database.addAudit(actor, 'instance.start.failed', preparedLab.title, message)
      app.log.error(error, `靶场 ${preparedLab.slug} 自动启动失败。`)
      return null
    }
  })()
  pendingStarts.set(labId, task)
  void task.then(() => {
    if (pendingStarts.get(labId) === task) pendingStarts.delete(labId)
  }, () => {
    if (pendingStarts.get(labId) === task) pendingStarts.delete(labId)
  })
  return task
}

const bootstrapBuiltinLabs = async () => {
  await Promise.allSettled(['vulnhub', 'vulhub', 'crapi'].map(slug => rm(join(dataDir, 'labs', slug), { recursive: true, force: true, maxRetries: 6, retryDelay: 150 })))
  for (const job of database.listJobsParsed().filter(item => item.status === 'queued')) {
    const lab = database.getLab(job.labId)
    if (!lab?.builtin) continue
    const claimed = database.claimJob(job.id)
    if (claimed) runImportJob(claimed.id, 'system')
  }
  for (const lab of database.listLabs().filter(item => item.builtin && item.status === 'ready')) {
    const job = database.listJobsParsed().find(item => item.labId === lab.id && item.status === 'completed' && item.manifest)
    if (job?.manifest) {
      const manifest = await promoteBuiltinManifest(lab, job.id, job.manifest)
      if (manifest.localPath !== job.manifest.localPath) database.completeJob(job.id, manifest)
    }
    try {
      await prepareInstalledLab(database.getLab(lab.id) ?? lab, undefined, nativeRuntime.pythonBinary)
      await cleanupOutdatedBuiltinVersions(database.getLab(lab.id) ?? lab)
    } catch (error) {
      const message = error instanceof Error ? error.message : '运行依赖准备失败。'
      database.updateLabStatus(lab.id, 'error')
      database.addAudit('system', 'runtime.prepare.failed', lab.title, message)
    }
  }
  if (process.env.VULNLAB_AUTO_INSTALL_BUILTINS === '0') return
  for (const definition of autoInstallLabs) {
    const lab = database.getLabBySlug(definition.slug)
    if (!lab || lab.status === 'importing') continue
    if (lab.status === 'ready') continue
    const result = startLabInstall(lab, 'system')
    if (result.job?.id) await activeImports.get(result.job.id)?.task
  }
}

await app.register(cookie, { secret: cookieSecret })
await app.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"],
    },
  },
})
await app.register(fastifyStatic, { root: publicDir, prefix: '/' })

app.addHook('onSend', async (_request, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff')
  reply.header('Referrer-Policy', 'same-origin')
  reply.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
})

app.addHook('onRequest', async (request, reply) => {
  await proxyRuntimeRequest(request, reply)
})

app.get('/healthz', async () => ({ status: 'ok', product: 'VulnLab', runtime: 'node-fastify' }))

app.get('/readyz', async (_request, reply) => {
  try {
    database.overview()
    return { status: 'ready', product: 'VulnLab' }
  } catch {
    return reply.code(503).send({ status: 'not-ready', product: 'VulnLab' })
  }
})

app.get('/api/auth/session', async request => getSession(request))

app.post('/api/auth/login', async (request, reply) => {
  const clientKey = createHash('sha256').update(`${cookieSecret}:${request.ip || 'unknown'}`).digest('hex')
  const attempt = database.consumeLoginAttempt(clientKey, loginLimit, loginWindowMs)
  if (!attempt.allowed) {
    reply.header('Retry-After', String(attempt.retryAfterSeconds))
    return reply.code(429).send({ code: 'LOGIN_RATE_LIMITED', message: '登录尝试过于频繁，请稍后再试。' })
  }
  const body = requestBody(request)
  const userName = typeof body.userName === 'string' ? body.userName.trim() : ''
  const password = typeof body.password === 'string' ? body.password : ''
  const user = adminAccount.userName === userName && sameSecret(adminAccount.password, password) ? adminAccount : null
  if (!user) return reply.code(401).send({ code: 'INVALID_CREDENTIALS', message: '账号或密码不正确。' })
  const sessionId = randomUUID()
  const csrfToken = randomBytes(24).toString('hex')
  database.createSession(sessionId, user.userName, user.role, csrfToken, Date.now() + 8 * 60 * 60 * 1000)
  database.clearLoginAttempts(clientKey)
  reply.setCookie('vulnlab_session', sessionId, { path: '/', httpOnly: true, sameSite: 'lax', secure: secureCookies, signed: true, maxAge: 8 * 60 * 60 })
  database.addAudit(user.userName, 'login', 'session', '登录 VulnLab')
  return { userName: user.userName, role: user.role, csrfToken }
})

app.post('/api/auth/logout', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  if (!requireCsrf(request, reply, session)) return
  const rawSessionId = request.cookies.vulnlab_session
  const sessionId = rawSessionId ? request.unsignCookie(rawSessionId) : null
  if (sessionId?.valid) database.deleteSession(sessionId.value)
  reply.clearCookie('vulnlab_session', { path: '/' })
  database.addAudit(session.userName, 'logout', 'session', '退出 VulnLab')
  return { ok: true }
})

app.get('/api/overview', async (request, reply) => {
  if (!requireUser(request, reply)) return
  await reapExpiredInstances()
  return database.overview()
})

app.get('/api/labs', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  const labs = database.listLabs()
  return labs
})

app.get('/api/labs/:id', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  const { id } = request.params as { id: string }
  const lab = database.getLab(id)
  if (!lab) return reply.code(404).send({ code: 'LAB_NOT_FOUND', message: '靶场不存在。' })
  return lab
})

app.get('/api/import-jobs', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  const jobs = database.listJobsParsed()
  return jobs
})

app.post('/api/labs/:id/install', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  const { id } = request.params as { id: string }
  const lab = database.getLab(id)
  if (!lab) return reply.code(404).send({ code: 'LAB_NOT_FOUND', message: '靶场不存在。' })
  const adapter = adapterFor(lab.sourceUrl, lab.sourceType)
  if (!hasBuiltinAsset(lab.slug) && !adapter?.implemented) return reply.code(409).send({ code: 'LAB_INSTALLER_NOT_READY', message: '该靶场的安装器尚未接通。' })
  const result = startLabInstall(lab, session.userName)
  database.addAudit(session.userName, 'lab.install', lab.title, lab.version)
  return reply.code(result.started ? 202 : 200).send(result)
})

app.get('/api/instances', async (request, reply) => {
  if (!requireUser(request, reply)) return
  await reapExpiredInstances()
  return database.listInstances()
})

app.post('/api/labs/:id/instances', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  await reapExpiredInstances()
  const { id } = request.params as { id: string }
  const lab = database.getLab(id)
  if (!lab) return reply.code(404).send({ code: 'LAB_NOT_FOUND', message: '靶场不存在。' })
  if (lab.status !== 'ready') {
    const adapter = adapterFor(lab.sourceUrl, lab.sourceType)
    if (!hasBuiltinAsset(lab.slug) && !adapter?.implemented) return reply.code(409).send({ code: 'LAB_INSTALLER_NOT_READY', message: '该靶场的内置资源尚未接通。' })
    const preparation = startLabInstall(lab, session.userName)
    if (!preparation.job?.id) return reply.code(409).send({ code: 'LAB_PREPARE_FAILED', message: '靶场准备任务未创建。' })
    queueStartAfterImport(lab.id, preparation.job.id, session.userName, publicOrigin(request))
    database.addAudit(session.userName, 'instance.prepare', lab.title, preparation.job.id)
    return reply.code(202).send({ status: 'preparing', lab: database.getLab(lab.id), job: preparation.job })
  }
  return reply.code(201).send(await startLabInstance(lab, session.userName, publicOrigin(request)))
})

app.post('/api/instances/:id/renew', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  await reapExpiredInstances()
  const { id } = request.params as { id: string }
  const current = database.getRunningInstance(id)
  if (!current) return reply.code(404).send({ code: 'INSTANCE_NOT_FOUND', message: '运行实例不存在或已经结束。' })
  const lab = database.getLab(current.labId)
  if (!lab) return reply.code(404).send({ code: 'LAB_NOT_FOUND', message: '靶场不存在。' })
  const provider = providerRegistry.resolve(current.provider, lab.runtimeKind)
  const renewed = await provider.renew({ lab, instance: current, lifetimeMinutes: instanceLifetimeMinutes })
  const instance = database.renewInstance(id, renewed.expiresAt, renewed.log)
  if (!instance) return reply.code(404).send({ code: 'INSTANCE_NOT_FOUND', message: '运行实例不存在或已经结束。' })
  database.addAudit(session.userName, 'instance.renew', instance.labTitle, id)
  return instance
})

app.delete('/api/instances/:id', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  const { id } = request.params as { id: string }
  const current = database.getInstance(id)
  if (!current) return reply.code(404).send({ code: 'INSTANCE_NOT_FOUND', message: '运行实例不存在。' })
  const lab = database.getLab(current.labId)
  if (!lab) return reply.code(404).send({ code: 'LAB_NOT_FOUND', message: '靶场不存在。' })
  const provider = providerRegistry.resolve(current.provider, lab.runtimeKind)
  const stopped = await provider.stop({ lab, instance: current, runtime: nativeRuntime, dataDir })
  const instance = database.destroyInstance(id, stopped.log)
  if (!instance) return reply.code(404).send({ code: 'INSTANCE_NOT_FOUND', message: '运行实例不存在。' })
  database.addAudit(session.userName, 'instance.destroy', instance.labTitle, id)
  return instance
})

app.get('/api/settings', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  const settings = database.getSettings()
  return settings
})

app.get('/api/runtime-status', async (request, reply) => {
  const session = requireUser(request, reply)
  if (!session) return
  const dependencies = await runtimeDependencies()
  const project = projectEnvironment.getStatus()
  return {
    dependencies,
    labs: await runtimeReadinessByLab(database.listLabs(), dependencies, dataDir),
    project,
  }
})

app.post('/api/runtime/prepare', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  const project = await prepareProjectEnvironment(true, true)
  database.addAudit(session.userName, 'runtime.prepare', 'project', projectEnvironment.getStatus().runtimeDir)
  const failed = project.toolchains.find(item => item.state === 'error')
  return { ok: !failed, message: failed?.detail, project }
})

app.put('/api/settings', async (request, reply) => {
  const session = requireAdmin(request, reply)
  if (!session) return
  const body = requestBody(request)
  const values: Partial<AppSettings> = {}
  for (const key of ['bindHost', 'port', 'maxInstances', 'autoCleanup'] as const) {
    if (typeof body[key] === 'string' && body[key].trim()) values[key] = body[key].trim()
  }
  if (values.bindHost && values.bindHost !== 'localhost' && isIP(values.bindHost) === 0) return reply.code(400).send({ code: 'BIND_HOST_INVALID', message: '监听地址必须是 localhost 或有效 IP 地址。' })
  if (values.port && (!/^\d+$/.test(values.port) || Number(values.port) < 1024 || Number(values.port) > 65535)) return reply.code(400).send({ code: 'PORT_INVALID', message: '端口必须是 1024 到 65535 之间的整数。' })
  if (values.maxInstances && (!/^\d+$/.test(values.maxInstances) || Number(values.maxInstances) < 1 || Number(values.maxInstances) > 99)) return reply.code(400).send({ code: 'MAX_INSTANCES_INVALID', message: '最大并发实例必须是 1 到 99 之间的整数。' })
  if (values.autoCleanup && !['true', 'false'].includes(values.autoCleanup)) return reply.code(400).send({ code: 'AUTO_CLEANUP_INVALID', message: '自动清理设置只能是 true 或 false。' })
  const settings = database.updateSettings(values)
  database.addAudit(session.userName, 'settings.update', 'runtime', JSON.stringify(values))
  return settings
})

app.get('/api/audit', async (request, reply) => {
  if (!requireAdmin(request, reply)) return
  return database.listAudit()
})

app.get('/lab-cover/:slug', async (request, reply) => {
  const { slug } = request.params as { slug: string }
  const lab = database.getLabBySlug(slug)
  if (!lab?.localPath) return reply.code(404).send('Cover not ready')
  const sources: Record<string, { path: string; type: string }> = {
    pygoat: { path: join(lab.localPath, 'introduction', 'static', 'Lab', 'icons', 'pygoat.svg'), type: 'image/svg+xml' },
    mutillidae: { path: join(lab.localPath, 'src', 'images', 'coykillericon-50-38.png'), type: 'image/png' },
  }
  const source = sources[slug]
  if (!source) return reply.code(404).send('Cover not found')
  const coverPath = resolve(source.path)
  const dataRoot = resolve(dataDir)
  const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
  if (coverPath !== dataRoot && !coverPath.startsWith(dataPrefix)) return reply.code(404).send('Cover not found')
  try {
    return reply.type(source.type).send(await readFile(coverPath))
  } catch {
    return reply.code(404).send('Cover not ready')
  }
})

app.setNotFoundHandler((request, reply) => {
  if (request.url.startsWith('/api/')) return reply.code(404).send({ code: 'NOT_FOUND', message: '接口不存在。' })
  return reply.sendFile('index.html')
})

app.setErrorHandler((error, _request, reply) => {
  app.log.error(error)
  if (reply.sent) return
  if (error instanceof ProviderError) return reply.code(error.statusCode).send({ code: error.code, message: error.message })
  const errorRecord = error && typeof error === 'object' ? error as { statusCode?: unknown; code?: unknown; message?: unknown } : null
  const statusCode = typeof errorRecord?.statusCode === 'number' && errorRecord.statusCode >= 400 ? errorRecord.statusCode : 500
  return reply.code(statusCode).send({
    code: statusCode < 500 && typeof errorRecord?.code === 'string' ? errorRecord.code : statusCode < 500 ? 'REQUEST_INVALID' : 'INTERNAL_ERROR',
    message: statusCode < 500 && typeof errorRecord?.message === 'string' ? errorRecord.message : '服务处理出现异常。',
  })
})

const start = async () => {
  await prepareProjectEnvironment()
  await recoverProviderInstances()
  await app.listen({ host, port })
  app.log.info(`VulnLab listening on http://${host}:${port}`)
  void bootstrapBuiltinLabs().catch(error => app.log.error(error, '内置靶场资源整理失败。'))
}

let shuttingDown = false
const shutdown = async (signal: string) => {
  if (shuttingDown) return
  shuttingDown = true
  clearInterval(expiredInstanceTimer)
  app.log.info(`收到 ${signal}，正在关闭 VulnLab。`)
  try {
    for (const { controller } of activeImports.values()) controller.abort()
    await Promise.allSettled([...activeImports.values()].map(({ task }) => task))
    await Promise.allSettled([providerRegistry.shutdown()])
    await projectEnvironment.stop()
    for (const providerId of ['native-php', 'native-node', 'native-java', 'native-python']) {
      database.recoverRunningInstances(providerId, '服务关闭，运行进程已回收')
    }
    await app.close()
  } finally {
    database.close()
  }
}

process.once('SIGINT', () => { void shutdown('SIGINT') })
process.once('SIGTERM', () => { void shutdown('SIGTERM') })

if (process.env.VULNLAB_NO_LISTEN !== '1') start().catch(error => {
  app.log.error(error)
  database.close()
  process.exit(1)
})

export { app, database }
