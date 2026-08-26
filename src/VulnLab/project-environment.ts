import { execFile, spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { createConnection, createServer, type AddressInfo } from 'node:net'
import { randomBytes } from 'node:crypto'
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, extname, join, resolve } from 'node:path'
import type { MySqlRuntimeConfig } from './mysql.js'
import { RuntimeToolchainInstaller, type RuntimeToolchainBinaries, type RuntimeToolchainStatus } from './runtime-toolchains.js'

export type RuntimeSource = 'project' | 'system' | 'external' | 'missing'

export interface ProjectEnvironmentStatus {
  runtimeDir: string
  platform: string
  toolchains: RuntimeToolchainStatus[]
  php: {
    binary: string
    ini?: string
    source: RuntimeSource
    available: boolean
    detail: string
  }
  mysql: {
    source: RuntimeSource
    available: boolean
    managed: boolean
    detail: string
  }
  node: {
    binary: string
    source: RuntimeSource
    available: boolean
    detail: string
  }
  java: {
    binary: string
    source: RuntimeSource
    available: boolean
    detail: string
  }
  python: {
    binary: string
    source: RuntimeSource
    available: boolean
    detail: string
  }
}

export interface PreparedProjectEnvironment {
  phpBinary: string
  phpIni?: string
  mysql?: MySqlRuntimeConfig
  nodeBinary: string
  javaBinary: string
  pythonBinary: string
  status: ProjectEnvironmentStatus
}

interface MysqlState {
  host: string
  port: number
  adminUser: string
  adminPassword: string
  dataDir: string
  pid?: number
  initializedAt: string
}

interface ExecutableCandidate {
  path: string
  source: Exclude<RuntimeSource, 'missing'>
}

export interface ProjectEnvironmentOptions {
  dataDir: string
  phpBinary?: string
  phpIni?: string
  mysqlConfig?: MySqlRuntimeConfig
  mysqlBinary?: string
  mysqlServerBinary?: string
  mysqlPort?: number
  nodeBinary?: string
  javaBinary?: string
  pythonBinary?: string
}

const sleep = (milliseconds: number) => new Promise(resolveSleep => setTimeout(resolveSleep, milliseconds))

const fileExists = async (path: string) => (await stat(path).catch(() => null))?.isFile() === true
const directoryExists = async (path: string) => (await stat(path).catch(() => null))?.isDirectory() === true

const command = (binary: string, args: string[], options: { env?: NodeJS.ProcessEnv; timeout?: number } = {}) => new Promise<{ stdout: string; stderr: string }>((resolveCommand, rejectCommand) => {
  execFile(binary, args, { env: { ...process.env, ...options.env }, timeout: options.timeout ?? 10_000, windowsHide: true, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
    if (error) {
      const detail = String(stderr ?? '').trim()
      rejectCommand(new Error(`${error.message}${detail ? `: ${detail}` : ''}`))
      return
    }
    resolveCommand({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
  })
})

const resolveCommandPath = async (value: string, source: Exclude<RuntimeSource, 'missing'> = 'system'): Promise<ExecutableCandidate | null> => {
  const candidate = value.trim()
  if (!candidate) return null
  if (candidate.includes('\\') || candidate.includes('/') || extname(candidate)) {
    return await fileExists(candidate) ? { path: resolve(candidate), source } : null
  }
  const resolver = process.platform === 'win32' ? 'where.exe' : 'which'
  try {
    const result = await command(resolver, [candidate], { timeout: 3_000 })
    const path = result.stdout.split(/\r?\n/).map(item => item.trim()).find(Boolean)
    return path && await fileExists(path) ? { path: resolve(path), source } : null
  } catch {
    return null
  }
}

const firstExistingExecutable = async (candidates: Array<{ value: string; source: Exclude<RuntimeSource, 'missing'> }>) => {
  for (const candidate of candidates) {
    const found = await resolveCommandPath(candidate.value, candidate.source)
    if (found) return found
  }
  return null
}

const tcpReachable = (host: string, port: number, timeoutMs = 1_000) => new Promise<boolean>(resolveProbe => {
  const socket = createConnection({ host, port })
  let settled = false
  const finish = (value: boolean) => {
    if (settled) return
    settled = true
    socket.destroy()
    resolveProbe(value)
  }
  socket.once('connect', () => finish(true))
  socket.once('error', () => finish(false))
  socket.setTimeout(timeoutMs, () => finish(false))
})

const portAvailable = (port: number) => new Promise<boolean>(resolveProbe => {
  const probe = createServer()
  probe.once('error', () => {
    probe.close(() => resolveProbe(false))
  })
  probe.listen({ host: '127.0.0.1', port }, () => {
    const address = probe.address()
    const available = typeof address === 'object' && address !== null && (address as AddressInfo).port === port
    probe.close(() => resolveProbe(available))
  })
})

const nextAvailablePort = async (start: number) => {
  for (let port = start; port <= Math.min(65_535, start + 99); port += 1) {
    if (await portAvailable(port)) return port
  }
  throw new Error(`项目 MySQL 端口 ${start}-${Math.min(65_535, start + 99)} 均不可用。`)
}

const waitForTcp = async (host: string, port: number, child: ChildProcess | null, timeoutMs = 30_000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) throw new Error(`MySQL 进程启动失败（退出码 ${child.exitCode}）。`)
    if (await tcpReachable(host, port, 800)) return
    await sleep(120)
  }
  throw new Error(`MySQL 未在 ${timeoutMs} ms 内监听 ${host}:${port}。`)
}

const waitForTcpClosed = async (host: string, port: number, timeoutMs = 5_000) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (!await tcpReachable(host, port, 300)) return
    await sleep(100)
  }
}

const waitForChildExit = async (child: ChildProcess | null, timeoutMs = 5_000) => {
  if (!child || (child.exitCode !== null && child.exitCode !== undefined)) return
  await Promise.race([
    new Promise<void>(resolveExit => child.once('exit', () => resolveExit())),
    sleep(timeoutMs),
  ])
}

const terminate = async (child: ChildProcess | null, pid?: number) => {
  const targetPid = pid ?? child?.pid
  if (!targetPid || targetPid <= 0) return
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(targetPid), '/T', '/F'], { windowsHide: true, stdio: 'ignore', timeout: 5_000 })
  } else {
    try { process.kill(targetPid, 'SIGTERM') } catch { return }
  }
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    if (child?.exitCode !== null && child?.exitCode !== undefined) return
    try { process.kill(targetPid, 0) } catch { return }
    await sleep(100)
  }
  if (child?.exitCode === null || child?.exitCode === undefined) {
    try { process.kill(targetPid, 'SIGKILL') } catch { /* process already exited */ }
  }
}

const mysqlString = (value: string) => `'${value.replaceAll('\\', '\\\\').replaceAll("'", "\\'").replaceAll('\0', '')}'`

const mysqlStatePath = (mysqlDir: string) => join(mysqlDir, 'runtime.json')

const jsonState = async (path: string) => {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as MysqlState
  } catch {
    return null
  }
}

const baseDirFor = (binary: string) => {
  const binDir = dirname(binary)
  return basename(binDir).toLowerCase() === 'bin' ? dirname(binDir) : binDir
}

export class ProjectEnvironmentManager {
  private readonly dataDir: string
  private readonly runtimeDir: string
  private readonly phpDir: string
  private readonly mysqlDir: string
  private readonly mysqlDataDir: string
  private readonly mysqlLogDir: string
  private readonly phpBinaryOverride?: string
  private readonly phpIniOverride?: string
  private readonly mysqlConfigOverride?: MySqlRuntimeConfig
  private readonly mysqlBinaryOverride?: string
  private readonly mysqlServerBinaryOverride?: string
  private readonly mysqlPort: number
  private readonly nodeBinaryOverride?: string
  private readonly javaBinaryOverride?: string
  private readonly pythonBinaryOverride?: string
  private readonly toolchains: RuntimeToolchainInstaller
  private toolchainBinaries: RuntimeToolchainBinaries = {}
  private mysqlProcess: ChildProcess | null = null
  private mysqlState: MysqlState | null = null
  private prepared: PreparedProjectEnvironment | null = null
  private preparing: Promise<PreparedProjectEnvironment> | null = null

  constructor(options: ProjectEnvironmentOptions) {
    this.dataDir = resolve(options.dataDir)
    this.runtimeDir = join(this.dataDir, 'runtime')
    this.phpDir = join(this.runtimeDir, 'php')
    this.mysqlDir = join(this.runtimeDir, 'mysql')
    this.mysqlDataDir = join(this.mysqlDir, 'data')
    this.mysqlLogDir = join(this.mysqlDir, 'logs')
    this.phpBinaryOverride = options.phpBinary?.trim() || undefined
    this.phpIniOverride = options.phpIni?.trim() || undefined
    this.mysqlConfigOverride = options.mysqlConfig
    this.mysqlBinaryOverride = options.mysqlBinary?.trim() || undefined
    this.mysqlServerBinaryOverride = options.mysqlServerBinary?.trim() || undefined
    this.mysqlPort = Number.isInteger(options.mysqlPort) && (options.mysqlPort as number) >= 1024 && (options.mysqlPort as number) <= 65535 ? options.mysqlPort as number : 7330
    this.nodeBinaryOverride = options.nodeBinary?.trim() || undefined
    this.javaBinaryOverride = options.javaBinary?.trim() || undefined
    this.pythonBinaryOverride = options.pythonBinary?.trim() || undefined
    this.toolchains = new RuntimeToolchainInstaller(this.runtimeDir)
  }

  private async phpCandidate() {
    if (this.phpBinaryOverride) return await resolveCommandPath(this.phpBinaryOverride, 'external')
    const projectRoot = join(this.runtimeDir, 'bin', 'php')
    return await firstExistingExecutable([
      ...(this.toolchainBinaries.php ? [{ value: this.toolchainBinaries.php, source: 'project' as const }] : []),
      { value: join(projectRoot, process.platform === 'win32' ? 'php.exe' : 'php'), source: 'project' },
      { value: 'php', source: 'system' },
    ])
  }

  private async mysqlCandidates() {
    const projectRoot = join(this.runtimeDir, 'bin', 'mysql')
    const server = this.mysqlServerBinaryOverride
      ? await resolveCommandPath(this.mysqlServerBinaryOverride, 'external')
      : await firstExistingExecutable([
        ...(this.toolchainBinaries.mysqlServer ? [{ value: this.toolchainBinaries.mysqlServer, source: 'project' as const }] : []),
        { value: join(projectRoot, process.platform === 'win32' ? 'mysqld.exe' : 'mysqld'), source: 'project' },
        { value: join(projectRoot, process.platform === 'win32' ? 'mariadbd.exe' : 'mariadbd'), source: 'project' },
        { value: 'mysqld', source: 'system' },
        { value: 'mariadbd', source: 'system' },
      ])
    const client = this.mysqlBinaryOverride
      ? await resolveCommandPath(this.mysqlBinaryOverride, 'external')
      : await firstExistingExecutable([
        ...(this.toolchainBinaries.mysqlClient ? [{ value: this.toolchainBinaries.mysqlClient, source: 'project' as const }] : []),
        { value: join(projectRoot, process.platform === 'win32' ? 'mysql.exe' : 'mysql'), source: 'project' },
        { value: 'mysql', source: 'system' },
        { value: 'mariadb', source: 'system' },
      ])
    return { server, client }
  }

  private async runtimeCandidate(kind: 'node' | 'java' | 'python') {
    const override = kind === 'node' ? this.nodeBinaryOverride : kind === 'java' ? this.javaBinaryOverride : this.pythonBinaryOverride
    if (override) return await resolveCommandPath(override, 'external')
    const projectBinary = kind === 'node' ? this.toolchainBinaries.node : kind === 'java' ? this.toolchainBinaries.java : this.toolchainBinaries.python
    const systemBinary = kind === 'node' ? 'node' : kind === 'java' ? 'java' : process.platform === 'win32' ? 'py' : 'python3'
    return await firstExistingExecutable([
      ...(projectBinary ? [{ value: projectBinary, source: 'project' as const }] : []),
      { value: systemBinary, source: 'system' },
    ])
  }

  private async runtimeVersion(kind: 'node' | 'java' | 'python', binary: ExecutableCandidate | null) {
    if (!binary) return { binary: kind, source: 'missing' as const, available: false, detail: '未检测到' }
    try {
      const launcher = kind === 'python' && process.platform === 'win32' && basename(binary.path).toLowerCase() === 'py.exe' ? ['-3'] : []
      const result = await command(binary.path, [...launcher, kind === 'java' ? '-version' : '--version'], { timeout: 5_000 })
      const detail = `${result.stdout} ${result.stderr}`.replace(/\s+/g, ' ').trim() || '已检测'
      const version = detail.match(/\d+(?:\.\d+){0,3}/)?.[0] ?? ''
      const major = Number(version.split('.')[0])
      const available = kind === 'node' ? major >= 22 : kind === 'java' ? major >= 17 : ['3.10', '3.11'].includes(version.split('.').slice(0, 2).join('.'))
      return { binary: binary.path, source: binary.source, available, detail: available ? detail : `${detail} · ${kind === 'node' ? '需要 22+' : kind === 'java' ? '需要 17+' : '需要 3.10/3.11'}` }
    } catch (error) {
      return { binary: binary.path, source: binary.source, available: false, detail: error instanceof Error ? error.message : '启动失败' }
    }
  }

  private async phpVersion(binary: string, ini?: string) {
    try {
      const result = await command(binary, [...(ini ? ['-c', ini] : []), '-r', 'echo PHP_VERSION;'], { timeout: 5_000 })
      return result.stdout.trim() || '已检测'
    } catch (error) {
      return error instanceof Error ? error.message : 'PHP 不可用'
    }
  }

  private async phpExtensionDir(binary: string) {
    if (process.platform !== 'win32') return undefined
    const sibling = join(dirname(binary), 'ext')
    if (await directoryExists(sibling)) return sibling
    try {
      const result = await command(binary, ['-r', 'echo PHP_BINARY;'], { timeout: 5_000 })
      const reported = result.stdout.trim()
      const reportedExt = join(dirname(reported), 'ext')
      return await directoryExists(reportedExt) ? reportedExt : undefined
    } catch {
      return undefined
    }
  }

  private async preparePhp(binary: ExecutableCandidate | null) {
    if (!binary) {
      return { binary: this.phpBinaryOverride ?? 'php', ini: this.phpIniOverride, source: 'missing' as const, available: false, detail: '未检测到 PHP' }
    }
    if (this.phpIniOverride) {
      return { binary: binary.path, ini: resolve(this.phpIniOverride), source: 'external' as const, available: true, detail: await this.phpVersion(binary.path, this.phpIniOverride) }
    }
    await mkdir(this.phpDir, { recursive: true })
    const ini = join(this.phpDir, 'php.ini')
    const extensionDir = await this.phpExtensionDir(binary.path)
    const extensionNames = ['mysqli', 'pdo_mysql', 'mbstring', 'gd', 'curl', 'openssl']
    const extensionAvailability = await Promise.all(extensionNames.map(name => extensionDir ? fileExists(join(extensionDir, `php_${name}.dll`)) : false))
    const extensions = extensionDir
      ? extensionNames.filter((_, index) => extensionAvailability[index]).map(name => `extension=php_${name}.dll`)
      : []
    const iniContents = [
      '[PHP]',
      'date.timezone=Asia/Shanghai',
      'display_errors=Off',
      'log_errors=On',
      'error_log=""',
      'memory_limit=256M',
      'upload_max_filesize=32M',
      'post_max_size=40M',
      ...(extensionDir ? [`extension_dir="${extensionDir.replaceAll('\\', '/')}"`] : []),
      ...extensions,
      '',
    ].join('\n')
    await writeFile(ini, iniContents, 'utf8')
    const version = await this.phpVersion(binary.path, ini)
    const mysqli = await command(binary.path, ['-c', ini, '-r', 'echo extension_loaded("mysqli") ? "mysqli" : "no-mysqli";'], { timeout: 5_000 }).then(result => result.stdout.trim()).catch(() => 'no-mysqli')
    return { binary: binary.path, ini, source: binary.source, available: version !== '未检测到', detail: `${version}${mysqli === 'mysqli' ? ' · mysqli 已启用' : ' · mysqli 未启用'} · 项目配置` }
  }

  private async executeMysql(binary: string, config: { host: string; port: number; user: string; password: string }, sql: string) {
    return await command(binary, [
      '--no-defaults', '--protocol=tcp', '--host', config.host, '--port', String(config.port), '--user', config.user,
      '--batch', '--skip-column-names', '--execute', sql,
    ], { env: { MYSQL_PWD: config.password }, timeout: 15_000 })
  }

  private async executeMysqlEventually(binary: string, config: { host: string; port: number; user: string; password: string }, sql: string, timeoutMs = 20_000) {
    const deadline = Date.now() + timeoutMs
    let lastError: unknown
    while (Date.now() < deadline) {
      try {
        return await this.executeMysql(binary, config, sql)
      } catch (error) {
        lastError = error
        await sleep(250)
      }
    }
    throw lastError instanceof Error ? lastError : new Error('MySQL 管理账号初始化超时。')
  }

  private async initializeMysql(server: string) {
    await mkdir(this.mysqlDataDir, { recursive: true })
    if (await directoryExists(join(this.mysqlDataDir, 'mysql'))) return
    if (basename(server).toLowerCase().startsWith('mariadbd')) {
      const baseDir = baseDirFor(server)
      const installer = await firstExistingExecutable(process.platform === 'win32'
        ? [
          { value: join(baseDir, 'bin', 'mariadb-install-db.exe'), source: 'project' },
          { value: join(baseDir, 'bin', 'mysql_install_db.exe'), source: 'project' },
        ]
        : [
          { value: join(baseDir, 'scripts', 'mariadb-install-db'), source: 'project' },
          { value: join(baseDir, 'bin', 'mariadb-install-db'), source: 'project' },
          { value: join(baseDir, 'scripts', 'mysql_install_db'), source: 'project' },
        ])
      if (!installer) throw new Error('MariaDB 发行包缺少数据目录初始化工具。')
      const args = process.platform === 'win32'
        ? [`--datadir=${this.mysqlDataDir}`]
        : ['--no-defaults', `--basedir=${baseDir}`, `--datadir=${this.mysqlDataDir}`, '--auth-root-authentication-method=normal', '--skip-test-db']
      await command(installer.path, args, { timeout: 120_000 })
      return
    }
    await command(server, [
      '--no-defaults', '--initialize-insecure', `--datadir=${this.mysqlDataDir}`, `--basedir=${baseDirFor(server)}`,
      '--innodb-log-file-size=64M', '--explicit_defaults_for_timestamp',
    ], { timeout: 120_000 })
  }

  private async startMysql(server: string, port: number, initFile?: string) {
    await mkdir(this.mysqlLogDir, { recursive: true })
    const logPath = join(this.mysqlLogDir, 'mysqld.log')
    const pidPath = join(this.mysqlDir, 'mysqld.pid')
    const args = [
      '--no-defaults', `--datadir=${this.mysqlDataDir}`, `--basedir=${baseDirFor(server)}`, '--bind-address=127.0.0.1',
      `--port=${port}`, `--pid-file=${pidPath}`, `--log-error=${logPath}`, '--max_connections=64',
      ...(initFile ? [`--init-file=${initFile}`] : []),
    ]
    const child = spawn(server, args, { cwd: baseDirFor(server), env: process.env, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, shell: false })
    let stderr = ''
    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', chunk => { stderr = `${stderr}${String(chunk)}`.slice(-2_000) })
    await new Promise<void>((resolveSpawn, rejectSpawn) => {
      child.once('spawn', () => resolveSpawn())
      child.once('error', rejectSpawn)
    }).catch(error => {
      throw new Error(`MySQL 进程启动失败：${error instanceof Error ? error.message : '未知错误'}`)
    })
    try {
      await waitForTcp('127.0.0.1', port, child)
      this.mysqlProcess = child
      return child
    } catch (error) {
      await terminate(child)
      const detail = stderr.replace(/\s+/g, ' ').trim()
      throw new Error(`${error instanceof Error ? error.message : 'MySQL 启动失败'}${detail ? ` ${detail}` : ''}`)
    }
  }

  private async stopMysql() {
    const state = this.mysqlState
    const child = this.mysqlProcess
    this.mysqlProcess = null
    const config = this.prepared?.mysql
    if (state && config && await tcpReachable(state.host, state.port)) {
      await this.executeMysql(config.mysqlBinary, { host: config.host, port: config.port, user: config.adminUser, password: config.adminPassword }, 'SHUTDOWN;').catch(() => undefined)
    }
    await terminate(child, state?.pid)
    if (state) await waitForTcpClosed(state.host, state.port)
    await waitForChildExit(child)
    await sleep(2_000)
    this.mysqlState = state ? { ...state, pid: undefined } : null
  }

  private async configureMysql(server: string, client: string, port: number) {
    const statePath = mysqlStatePath(this.mysqlDir)
    const existing = await jsonState(statePath)
    const password = existing?.adminPassword || Buffer.from(randomBytes(24)).toString('base64url')
    const adminUser = existing?.adminUser || 'vulnlab_admin'
    const configuredPort = existing?.port && Number.isInteger(existing.port) ? existing.port : port
    await this.initializeMysql(server)
    const currentPort = existing && await tcpReachable('127.0.0.1', configuredPort)
      ? configuredPort
      : await nextAvailablePort(configuredPort)
    if (existing && await tcpReachable('127.0.0.1', currentPort)) {
      const config: MySqlRuntimeConfig = { host: '127.0.0.1', port: currentPort, adminUser, adminPassword: password, appHost: '127.0.0.1', mysqlBinary: client }
      await this.executeMysqlEventually(client, { host: config.host, port: config.port, user: config.adminUser, password: config.adminPassword }, 'SELECT 1;')
      this.mysqlState = { host: config.host, port: config.port, adminUser, adminPassword: password, dataDir: this.mysqlDataDir, initializedAt: existing?.initializedAt ?? new Date().toISOString(), pid: existing?.pid }
      return config
    }

    let initFile: string | undefined
    if (!existing) {
      initFile = join(this.mysqlDir, 'init.sql')
      await writeFile(initFile, `CREATE USER IF NOT EXISTS ${mysqlString(adminUser)}@'127.0.0.1' IDENTIFIED BY ${mysqlString(password)};\nCREATE USER IF NOT EXISTS ${mysqlString(adminUser)}@'localhost' IDENTIFIED BY ${mysqlString(password)};\n`, 'utf8')
    }
    await this.startMysql(server, currentPort, initFile)
    const config: MySqlRuntimeConfig = { host: '127.0.0.1', port: currentPort, adminUser, adminPassword: password, appHost: '127.0.0.1', mysqlBinary: client }
    if (!existing) {
      await this.executeMysqlEventually(client, { host: config.host, port: config.port, user: 'root', password: '' }, `GRANT ALL PRIVILEGES ON *.* TO ${mysqlString(adminUser)}@'127.0.0.1' WITH GRANT OPTION; GRANT ALL PRIVILEGES ON *.* TO ${mysqlString(adminUser)}@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;`)
    }
    await this.executeMysqlEventually(client, { host: config.host, port: config.port, user: config.adminUser, password: config.adminPassword }, 'SELECT 1;')
    if (initFile) await rm(initFile, { force: true }).catch(() => undefined)
    this.mysqlState = { host: config.host, port: config.port, adminUser, adminPassword: password, dataDir: this.mysqlDataDir, initializedAt: existing?.initializedAt ?? new Date().toISOString(), pid: this.mysqlProcess?.pid }
    await writeFile(statePath, JSON.stringify(this.mysqlState, null, 2), 'utf8')
    return config
  }

  private async prepareOnce(force = false, installMissing = false): Promise<PreparedProjectEnvironment> {
    if (this.prepared && !force) return this.prepared
    if (force) this.prepared = null
    await mkdir(this.runtimeDir, { recursive: true })
    await this.toolchains.inspect()
    if (installMissing) await this.toolchains.installMissing().catch(() => undefined)
    this.toolchainBinaries = await this.toolchains.binaries()
    const phpCandidate = await this.phpCandidate()
    const php = await this.preparePhp(phpCandidate)
    const [node, java, python] = await Promise.all([
      this.runtimeCandidate('node').then(candidate => this.runtimeVersion('node', candidate)),
      this.runtimeCandidate('java').then(candidate => this.runtimeVersion('java', candidate)),
      this.runtimeCandidate('python').then(candidate => this.runtimeVersion('python', candidate)),
    ])
    let mysql: MySqlRuntimeConfig | undefined
    let mysqlStatus: ProjectEnvironmentStatus['mysql'] = { source: 'missing', available: false, managed: false, detail: '未检测到 MySQL / MariaDB' }
    if (this.mysqlConfigOverride) {
      mysql = this.mysqlConfigOverride
      mysqlStatus = { source: 'external', available: await tcpReachable(mysql.host, mysql.port), managed: false, detail: `${mysql.host}:${mysql.port}` }
    } else {
      const candidates = await this.mysqlCandidates()
      if (candidates.server && candidates.client) {
        try {
          mysql = await this.configureMysql(candidates.server.path, candidates.client.path, this.mysqlPort)
          mysqlStatus = { source: 'project', available: true, managed: true, detail: `${mysql.host}:${mysql.port} · 项目内私有实例` }
        } catch (error) {
          await this.stopMysql().catch(() => undefined)
          await rm(join(this.mysqlDir, 'init.sql'), { force: true }).catch(() => undefined)
          mysqlStatus = { source: 'project', available: false, managed: true, detail: error instanceof Error ? error.message : '项目内 MySQL 准备失败' }
        }
      } else if (candidates.client) {
        mysqlStatus = { source: candidates.client.source, available: false, managed: false, detail: '检测到 MySQL 客户端，但缺少 mysqld / mariadbd' }
      }
    }
    const status: ProjectEnvironmentStatus = {
      runtimeDir: this.runtimeDir,
      platform: this.toolchains.platformLabel(),
      toolchains: this.toolchains.getStatuses(),
      php: { binary: php.binary, ini: php.ini, source: php.source, available: php.available, detail: php.detail },
      mysql: mysqlStatus,
      node,
      java,
      python,
    }
    this.prepared = { phpBinary: php.binary, phpIni: php.ini, mysql, nodeBinary: node.binary, javaBinary: java.binary, pythonBinary: python.binary, status }
    return this.prepared
  }

  async prepare(force = false, installMissing = false): Promise<PreparedProjectEnvironment> {
    if (this.preparing) return this.preparing
    this.preparing = this.prepareOnce(force, installMissing)
    try {
      return await this.preparing
    } finally {
      this.preparing = null
    }
  }

  getStatus() {
    return this.prepared?.status ?? {
      runtimeDir: this.runtimeDir,
      platform: this.toolchains.platformLabel(),
      toolchains: this.toolchains.getStatuses(),
      php: { binary: this.phpBinaryOverride ?? 'php', ini: this.phpIniOverride, source: 'missing' as const, available: false, detail: '尚未准备项目运行环境' },
      mysql: { source: 'missing' as const, available: false, managed: false, detail: '尚未准备项目运行环境' },
      node: { binary: this.nodeBinaryOverride ?? 'node', source: 'missing' as const, available: false, detail: '尚未准备项目运行环境' },
      java: { binary: this.javaBinaryOverride ?? 'java', source: 'missing' as const, available: false, detail: '尚未准备项目运行环境' },
      python: { binary: this.pythonBinaryOverride ?? (process.platform === 'win32' ? 'py' : 'python3'), source: 'missing' as const, available: false, detail: '尚未准备项目运行环境' },
    }
  }

  async stop() {
    if (this.preparing) await this.preparing.catch(() => undefined)
    await this.stopMysql()
    if (this.mysqlState) {
      await writeFile(mysqlStatePath(this.mysqlDir), JSON.stringify(this.mysqlState, null, 2), 'utf8').catch(() => undefined)
    }
  }
}

export const projectEnvironmentOptionsFromEnv = (dataDir: string, phpBinary?: string, phpIni?: string, mysqlConfig?: MySqlRuntimeConfig, nodeBinary?: string) => new ProjectEnvironmentManager({
  dataDir,
  phpBinary: process.env.VULNLAB_PHP_BIN?.trim() || phpBinary,
  phpIni: process.env.VULNLAB_PHP_INI?.trim() || phpIni,
  mysqlConfig: mysqlConfig ?? undefined,
  mysqlBinary: process.env.VULNLAB_MYSQL_BIN?.trim() || undefined,
  mysqlServerBinary: process.env.VULNLAB_MYSQLD_BIN?.trim() || undefined,
  mysqlPort: Number(process.env.VULNLAB_PROJECT_MYSQL_PORT ?? 7330),
  nodeBinary: process.env.VULNLAB_NODE_BIN?.trim() || nodeBinary,
  javaBinary: process.env.VULNLAB_JAVA_BIN?.trim() || undefined,
  pythonBinary: process.env.VULNLAB_PYTHON_BIN?.trim() || undefined,
})
