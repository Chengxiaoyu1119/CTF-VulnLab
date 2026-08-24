import { spawn, type ChildProcess } from 'node:child_process'
import { cp, mkdir, open, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { createConnection, createServer, type AddressInfo } from 'node:net'
import { basename, extname, join, resolve, sep } from 'node:path'
import { CliMySqlManager, mysqlRuntimeConfigFromEnv, type MySqlManager, type MySqlResource, type MySqlRuntimeConfig } from './mysql.js'
import type { Lab, LabInstance, RuntimeKind } from './types.js'

export interface NativeRuntimeConfig {
  bindHost: string
  portStart: number
  portEnd: number
  publicOriginTemplate?: string
  phpBinary: string
  phpIni?: string
  nodeBinary: string
  javaBinary: string
  pythonBinary: string
  mysql?: MySqlRuntimeConfig
}

export interface VmRuntimeConfig {
  portStart: number
  portEnd: number
  qemuBinary: string
  guestPort: number
  memoryMb: number
  cpus: number
  bootTimeoutMs: number
}

export interface ProviderStartInput {
  instanceId: string
  lab: Lab
  publicOrigin: string
  proxyEndpoint?: string
  lifetimeMinutes: number
  dataDir: string
  runtime: NativeRuntimeConfig
  phpAutoPrependFile?: string
  artifactPath?: string
  vm?: VmRuntimeConfig
}

export interface ProviderStartResult {
  endpoint: string
  createdAt: string
  expiresAt: string
  logs: string[]
}

export interface ProviderRenewInput {
  lab: Lab
  instance: LabInstance
  lifetimeMinutes: number
  dataDir?: string
  vm?: VmRuntimeConfig
}

export interface ProviderRenewResult {
  expiresAt: string
  log: string
}

export interface ProviderStopInput {
  lab: Lab
  instance: LabInstance
  runtime?: NativeRuntimeConfig
  dataDir?: string
  vm?: VmRuntimeConfig
}

export interface ProviderStopResult {
  log: string
}

export interface LabProvider {
  readonly id: string
  readonly supportedRuntimeKinds: readonly RuntimeKind[]
  start(input: ProviderStartInput): Promise<ProviderStartResult>
  renew(input: ProviderRenewInput): Promise<ProviderRenewResult>
  stop(input: ProviderStopInput): Promise<ProviderStopResult>
  getProxyTarget?(instanceId: string): string | null
  recover?(input: ProviderRecoverInput): Promise<void>
  shutdown?(): Promise<void>
}

export interface ProviderRecoverInput {
  lab: Lab
  instance: LabInstance
  runtime?: NativeRuntimeConfig
  dataDir?: string
  vm?: VmRuntimeConfig
}

export class ProviderError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly statusCode = 503,
  ) {
    super(message)
    this.name = 'ProviderError'
  }
}

const lease = (lifetimeMinutes: number) => {
  if (!Number.isFinite(lifetimeMinutes) || lifetimeMinutes <= 0) {
    throw new ProviderError('PROVIDER_LIFETIME_INVALID', '运行实例时长必须是正数。', 400)
  }
  const createdAt = new Date()
  return {
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + lifetimeMinutes * 60_000).toISOString(),
  }
}

type SpawnFunction = typeof spawn
type PortAllocator = (host: string, start: number, end: number) => Promise<number>

export interface NativePhpProviderOptions {
  phpBinary?: string
  commandPrefix?: string[]
  spawnImpl?: SpawnFunction
  allocatePort?: PortAllocator
  mysqlManager?: MySqlManager
}

const sleep = (milliseconds: number) => new Promise(resolvePromise => setTimeout(resolvePromise, milliseconds))

const allocatePort: PortAllocator = async (host, start, end) => {
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1024 || end > 65535 || start > end) {
    throw new ProviderError('NATIVE_PHP_PORT_RANGE_INVALID', '原生 PHP 运行端口范围无效。', 500)
  }
  for (let port = start; port <= end; port += 1) {
    const probe = createServer()
    try {
      const selectedPort = await new Promise<number>((resolvePort, reject) => {
        probe.once('error', reject)
        probe.listen({ host, port }, () => {
          const address = probe.address()
          resolvePort(typeof address === 'object' && address ? (address as AddressInfo).port : port)
        })
      })
      await new Promise<void>(resolveClose => probe.close(() => resolveClose()))
      return selectedPort
    } catch (error) {
      await new Promise<void>(resolveClose => probe.close(() => resolveClose())).catch(() => undefined)
      if ((error as NodeJS.ErrnoException)?.code === 'EADDRINUSE') continue
      throw error
    }
  }
  throw new ProviderError('NATIVE_PHP_PORT_EXHAUSTED', '原生 PHP 运行端口已用尽，请扩大端口范围。', 409)
}

const runtimeOrigin = (publicOrigin: string, port: number, template?: string) => {
  const value = template?.trim()
  if (value) {
    if (!value.includes('{port}')) throw new ProviderError('NATIVE_PHP_PUBLIC_ORIGIN_INVALID', 'VULNLAB_RUNTIME_PUBLIC_ORIGIN 必须包含 {port}。', 500)
    const resolved = value.replaceAll('{port}', String(port)).replace(/\/+$/, '')
    const parsed = new URL(resolved)
    if (parsed.protocol !== 'http:') throw new ProviderError('NATIVE_PHP_PUBLIC_ORIGIN_INVALID', '原生 PHP 直连入口必须使用 HTTP。', 500)
    return resolved
  }
  const parsed = new URL(publicOrigin)
  if (parsed.protocol !== 'http:') throw new ProviderError('NATIVE_PHP_PUBLIC_ORIGIN_REQUIRED', 'HTTPS 反向代理需要配置 VULNLAB_RUNTIME_PUBLIC_ORIGIN。', 503)
  parsed.port = String(port)
  parsed.pathname = ''
  parsed.search = ''
  parsed.hash = ''
  return parsed.toString().replace(/\/+$/, '')
}

const waitForHttp = async (host: string, port: number, child: ChildProcess) => {
  const probeHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new ProviderError('NATIVE_PHP_PROCESS_EXITED', 'PHP 进程在启动检查期间退出。', 503)
    try {
      const response = await fetch(`http://${probeHost}:${port}/__vulnlab_startup_probe__`, { redirect: 'manual', signal: AbortSignal.timeout(5_000) })
      await response.body?.cancel().catch(() => undefined)
      return
    } catch {
      await sleep(80)
    }
  }
  throw new ProviderError('NATIVE_PHP_START_TIMEOUT', 'PHP 内置服务器启动超时。', 503)
}

type TcpProbe = (host: string, port: number, child: ChildProcess, timeoutMs: number) => Promise<void>

const waitForTcp: TcpProbe = async (host, port, child, timeoutMs) => {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new ProviderError('QEMU_PROCESS_EXITED', 'QEMU 进程在启动检查期间退出。', 503)
    try {
      await new Promise<void>((resolveProbe, rejectProbe) => {
        const socket = createConnection({ host, port })
        let settled = false
        const finish = (error?: Error) => {
          if (settled) return
          settled = true
          socket.destroy()
          if (error) rejectProbe(error)
          else resolveProbe()
        }
        socket.once('connect', () => finish())
        socket.once('error', error => finish(error))
        socket.setTimeout(Math.min(1_000, Math.max(100, timeoutMs)), () => finish(new Error('TCP probe timeout')))
      })
      return
    } catch {
      await sleep(100)
    }
  }
  throw new ProviderError('QEMU_START_TIMEOUT', `QEMU 虚拟机在 ${timeoutMs} ms 内没有开放端口。`, 503)
}

const waitForExit = async (child: ChildProcess) => {
  if (child.exitCode !== null) return
  await new Promise<void>(resolveExit => {
    let settled = false
    const finish = () => {
      if (settled) return
      settled = true
      resolveExit()
    }
    child.once('exit', finish)
    try { child.kill() } catch { finish() }
    setTimeout(finish, 2_000)
  })
}

const processAlive = (pid: number) => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

type TerminatePid = (pid: number) => Promise<void>

const terminatePid: TerminatePid = async pid => {
  if (!Number.isInteger(pid) || pid <= 0 || !processAlive(pid)) return
  if (process.platform === 'win32') {
    await new Promise<void>(resolveTerminate => {
      const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
      killer.once('error', () => resolveTerminate())
      killer.once('exit', () => resolveTerminate())
    })
  } else {
    try { process.kill(pid, 'SIGTERM') } catch { return }
  }
  const deadline = Date.now() + 3_000
  while (Date.now() < deadline && processAlive(pid)) await sleep(80)
  if (processAlive(pid)) {
    try { process.kill(pid, 'SIGKILL') } catch { /* process exited between probes */ }
  }
}

const removeTree = async (root: string) => {
  await rm(root, { recursive: true, force: true, maxRetries: 6, retryDelay: 150 }).catch(() => undefined)
}

type DatabaseLabProfile = 'dvwa' | 'pikachu' | 'sqli-labs' | 'mutillidae'

const databaseProfile = (lab: Lab): DatabaseLabProfile | null => {
  if (lab.slug === 'dvwa') return 'dvwa'
  if (lab.slug === 'pikachu') return 'pikachu'
  if (lab.slug === 'sqli-labs') return 'sqli-labs'
  if (lab.slug === 'mutillidae') return 'mutillidae'
  return null
}

const sqliLabsMysqlCompat = `<?php
if (!function_exists('mysql_connect')) {
    if (!defined('MYSQL_ASSOC')) define('MYSQL_ASSOC', MYSQLI_ASSOC);
    if (!defined('MYSQL_NUM')) define('MYSQL_NUM', MYSQLI_NUM);
    if (!defined('MYSQL_BOTH')) define('MYSQL_BOTH', MYSQLI_BOTH);

    function vulnlab_mysql_link($link_identifier = null) {
        if ($link_identifier) return $link_identifier;
        return $GLOBALS['__vulnlab_mysql_default_link'] ?? null;
    }

    function mysql_connect($server = null, $username = null, $password = null, $new_link = false, $client_flags = 0) {
        $host = $server ?: (getenv('DB_SERVER') ?: '127.0.0.1');
        $port = (int)(getenv('DB_PORT') ?: 3306);
        $separator = strrpos($host, ':');
        if ($separator !== false && ctype_digit(substr($host, $separator + 1))) {
            $port = (int)substr($host, $separator + 1);
            $host = substr($host, 0, $separator);
        }
        $link = @mysqli_connect($host, $username, $password, null, $port);
        $GLOBALS['__vulnlab_mysql_default_link'] = $link ?: null;
        $GLOBALS['__vulnlab_mysql_last_error'] = $link ? '' : mysqli_connect_error();
        return $link;
    }

    function mysql_select_db($database_name, $link_identifier = null) {
        $link = vulnlab_mysql_link($link_identifier);
        return $link ? @mysqli_select_db($link, $database_name) : false;
    }

    function mysql_query($query, $link_identifier = null) {
        $link = vulnlab_mysql_link($link_identifier);
        if (!$link) return false;
        $result = @mysqli_query($link, $query);
        $GLOBALS['__vulnlab_mysql_last_error'] = mysqli_error($link);
        return $result;
    }

    function mysql_fetch_array($result, $result_type = MYSQL_BOTH) {
        return $result instanceof mysqli_result ? mysqli_fetch_array($result, $result_type) : false;
    }

    function mysql_fetch_assoc($result) {
        return $result instanceof mysqli_result ? mysqli_fetch_assoc($result) : false;
    }

    function mysql_fetch_row($result) {
        return $result instanceof mysqli_result ? mysqli_fetch_row($result) : false;
    }

    function mysql_error($link_identifier = null) {
        $link = vulnlab_mysql_link($link_identifier);
        return $link ? mysqli_error($link) : ($GLOBALS['__vulnlab_mysql_last_error'] ?? '');
    }

    function mysql_real_escape_string($unescaped_string, $link_identifier = null) {
        $link = vulnlab_mysql_link($link_identifier);
        return $link ? mysqli_real_escape_string($link, $unescaped_string) : addslashes($unescaped_string);
    }

    function mysql_escape_string($unescaped_string) {
        return mysql_real_escape_string($unescaped_string);
    }

    function mysql_affected_rows($link_identifier = null) {
        $link = vulnlab_mysql_link($link_identifier);
        return $link ? mysqli_affected_rows($link) : -1;
    }
}
`

const configureSqliLabs = async (root: string) => {
  const connectionsRoot = join(root, 'sql-connections')
  const credentialsPath = join(connectionsRoot, 'db-creds.inc')
  const setupPath = join(connectionsRoot, 'setup-db.php')
  const challengeSetupPath = join(connectionsRoot, 'setup-db-challenge.php')
  const sourceFiles = await Promise.all([credentialsPath, setupPath, challengeSetupPath].map(path => readFile(path, 'utf8').catch(() => null)))
  if (sourceFiles.some(contents => contents === null)) throw new ProviderError('NATIVE_PHP_SQLI_LAYOUT_INVALID', 'SQLi-Labs 缺少数据库初始化文件。', 409)

  const credentials = `<?php
$dbuser = getenv('DB_USER') ?: 'vulnlab';
$dbpass = getenv('DB_PASSWORD') ?: '';
$host = (getenv('DB_SERVER') ?: '127.0.0.1') . ':' . (getenv('DB_PORT') ?: '3306');
$dbname = getenv('DB_DATABASE') ?: 'vulnlab';
$dbname1 = $dbname;
?>\n`
  await writeFile(credentialsPath, credentials, 'utf8')

  let setup = sourceFiles[1] as string
  setup = setup.replaceAll('security', '$dbname')
  setup = setup.replace(/\$sql\s*=\s*"DROP DATABASE IF EXISTS[^;]*;/i, '$sql = "SELECT 1";')
  setup = setup.replace(/\$sql\s*=\s*"CREATE database[^;]*;/i, '$sql = "SELECT 1";')
  if (/DROP DATABASE IF EXISTS|CREATE database/i.test(setup)) throw new ProviderError('NATIVE_PHP_SQLI_SETUP_UNSAFE', 'SQLi-Labs 初始化脚本仍要求管理级数据库权限。', 409)
  await writeFile(setupPath, setup, 'utf8')

  let challengeSetup = sourceFiles[2] as string
  challengeSetup = challengeSetup.replace(/\$sql\s*=\s*"DROP DATABASE IF EXISTS[^;]*;/i, '$sql = "SELECT 1";')
  challengeSetup = challengeSetup.replace(/\$sql\s*=\s*"CREATE database[^;]*;/i, '$sql = "SELECT 1";')
  if (/DROP DATABASE IF EXISTS|CREATE database/i.test(challengeSetup)) throw new ProviderError('NATIVE_PHP_SQLI_SETUP_UNSAFE', 'SQLi-Labs Challenge 初始化仍要求管理级数据库权限。', 409)
  await writeFile(challengeSetupPath, challengeSetup, 'utf8')

  const compatPath = join(connectionsRoot, 'vulnlab-mysql-compat.php')
  await writeFile(compatPath, sqliLabsMysqlCompat, 'utf8')
  return compatPath
}

const replacePikachuDefineExpression = (contents: string, name: string, expression: string) => {
  const pattern = new RegExp(`^\\s*define\\(\\s*['"]${name}['"]\\s*,.*$`, 'mi')
  if (!pattern.test(contents)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', `Pikachu 配置缺少 ${name} 定义。`, 409)
  return contents.replace(pattern, `define('${name}', ${expression});`)
}

const configurePikachu = async (root: string) => {
  const configPath = join(root, 'inc', 'config.inc.php')
  let contents = await readFile(configPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'Pikachu 缺少 inc/config.inc.php 配置文件。', 409)
  })
  const expressions = {
    DBHOST: "getenv('DB_SERVER') ?: '127.0.0.1'",
    DBUSER: "getenv('DB_USER') ?: 'vulnlab'",
    DBPW: "getenv('DB_PASSWORD') ?: ''",
    DBNAME: "getenv('DB_DATABASE') ?: 'vulnlab'",
    DBPORT: "getenv('DB_PORT') ?: '3306'",
  }
  for (const [name, expression] of Object.entries(expressions)) {
    contents = replacePikachuDefineExpression(contents, name, expression)
  }
  await writeFile(configPath, contents, 'utf8')
}

const configurePikachuInstallerPort = async (root: string) => {
  const installPath = join(root, 'install.php')
  let contents = await readFile(installPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'Pikachu 缺少 install.php 初始化入口。', 409)
  })
  const before = contents
  contents = contents.replaceAll('mysqli_connect($dbhost, $dbuser, $dbpw)', 'mysqli_connect($dbhost, $dbuser, $dbpw, DBNAME, DBPORT)')
  contents = contents.replaceAll('mysqli_connect(DBHOST, DBUSER, DBPW)', 'mysqli_connect(DBHOST, DBUSER, DBPW, DBNAME, DBPORT)')
  contents = contents.replace(/\$drop_db\s*=\s*"drop database if exists[^;]*;/i, '$drop_db = "SELECT 1";')
  contents = contents.replace(/\$create_db\s*=\s*"CREATE DATABASE[^;]*;/i, '$create_db = "SELECT 1";')
  if (contents === before) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Pikachu 初始化入口不包含可识别的 MySQL 连接代码。', 409)
  if (/drop database if exists|CREATE DATABASE/i.test(contents)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Pikachu 初始化脚本仍要求管理级数据库权限。', 409)
  await writeFile(installPath, contents, 'utf8')
}

const configureDvwa = async (root: string) => {
  const source = join(root, 'config', 'config.inc.php.dist')
  const target = join(root, 'config', 'config.inc.php')
  if (!await stat(source).then(item => item.isFile()).catch(() => false)) {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'DVWA 缺少 config/config.inc.php.dist 配置文件。', 409)
  }
  await cp(source, target, { force: true })
}

const configureDvwaInstallerCompatibility = async (root: string) => {
  const installerPath = join(root, 'dvwa', 'includes', 'DBMS', 'MySQL.php')
  let contents = await readFile(installerPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'DVWA 缺少 MySQL 初始化脚本。', 409)
  })
  contents = contents.replaceAll('ADD COLUMN IF NOT EXISTS', 'ADD COLUMN')
  await writeFile(installerPath, contents, 'utf8')
}

const configureMutillidae = async (root: string) => {
  const sourceRoot = join(root, 'src')
  const configPath = join(sourceRoot, 'includes', 'database-config.inc')
  const setupPath = join(sourceRoot, 'set-up-database.php')
  if (!(await stat(configPath).catch(() => null))?.isFile() || !(await stat(setupPath).catch(() => null))?.isFile()) {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'Mutillidae 缺少数据库配置或初始化文件。', 409)
  }
  const config = `<?php
define('DB_HOST', getenv('DB_SERVER') ?: '127.0.0.1');
define('DB_USERNAME', getenv('DB_USER') ?: 'vulnlab');
define('DB_PASSWORD', getenv('DB_PASSWORD') ?: '');
define('DB_NAME', getenv('DB_DATABASE') ?: 'vulnlab');
define('DB_PORT', (int)(getenv('DB_PORT') ?: 3306));
?>\n`
  await writeFile(configPath, config, 'utf8')
  let setup = await readFile(setupPath, 'utf8')
  setup = setup.replace(/\$lQueryString\s*=\s*"DROP DATABASE IF EXISTS[^;]*;/i, '$lQueryString = "SELECT 1";')
  setup = setup.replace(/\$lQueryString\s*=\s*"CREATE DATABASE[^;]*;/i, '$lQueryString = "SELECT 1";')
  setup = setup.replaceAll('" with result ".$lQueryResult', '" with result ".($lQueryResult ? "success" : "failure")')
  if (/\$lQueryString\s*=\s*"(?:DROP DATABASE IF EXISTS|CREATE DATABASE)/i.test(setup)) {
    throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Mutillidae 初始化脚本仍要求管理级数据库权限。', 409)
  }
  await writeFile(setupPath, setup, 'utf8')
  return sourceRoot
}

const configureDvwaExistingDatabase = async (root: string) => {
  const installerPath = join(root, 'dvwa', 'includes', 'DBMS', 'MySQL.php')
  let contents = await readFile(installerPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'DVWA 缺少 MySQL 初始化脚本。', 409)
  })
  contents = contents.replace(/\$drop_db\s*=\s*"DROP DATABASE IF EXISTS[^"]*";/, '$drop_db = "SELECT 1";')
  contents = contents.replace(/\$create_db\s*=\s*"CREATE DATABASE[^"]*";/, '$create_db = "SELECT 1";')
  if (/DROP DATABASE IF EXISTS|CREATE DATABASE/.test(contents)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'DVWA 初始化脚本仍要求管理级数据库权限。', 409)
  await writeFile(installerPath, contents, 'utf8')
}

interface NativeRuntime {
  child: ChildProcess
  root: string
  port: number
  bindHost: string
  database: MySqlResource | null
}

export class NativePhpProvider implements LabProvider {
  readonly id = 'native-php'
  readonly supportedRuntimeKinds: readonly RuntimeKind[] = ['native-php']
  private readonly phpBinary: string
  private readonly commandPrefix: string[]
  private readonly spawnImpl: SpawnFunction
  private readonly allocatePortImpl: PortAllocator
  private readonly mysqlManager: MySqlManager
  private readonly runtimes = new Map<string, NativeRuntime>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(options: NativePhpProviderOptions = {}) {
    this.phpBinary = options.phpBinary ?? process.env.VULNLAB_PHP_BIN ?? 'php'
    this.commandPrefix = options.commandPrefix ?? []
    this.spawnImpl = options.spawnImpl ?? spawn
    this.allocatePortImpl = options.allocatePort ?? allocatePort
    this.mysqlManager = options.mysqlManager ?? new CliMySqlManager()
  }

  private async claimPort(config: NativeRuntimeConfig): Promise<number> {
    let release!: () => void
    const turn = new Promise<void>(resolveTurn => { release = resolveTurn })
    const previous = this.portAllocation
    this.portAllocation = previous.then(() => turn)
    await previous
    try {
      for (let attempt = 0; attempt <= config.portEnd - config.portStart; attempt += 1) {
        const port = await this.allocatePortImpl(config.bindHost, config.portStart, config.portEnd)
        if (!this.reservedPorts.has(port)) {
          this.reservedPorts.add(port)
          return port
        }
      }
      throw new ProviderError('NATIVE_PHP_PORT_EXHAUSTED', '原生 PHP 运行端口已用尽，请扩大端口范围。', 409)
    } finally {
      release()
    }
  }

  private async startPhpProcess(root: string, input: ProviderStartInput, environment: Record<string, string> = {}) {
    const port = await this.claimPort(input.runtime)
    const args = [
      ...this.commandPrefix,
      ...(input.runtime.phpIni ? ['-c', input.runtime.phpIni] : []),
      ...(input.phpAutoPrependFile ? ['-d', `auto_prepend_file=${input.phpAutoPrependFile}`] : []),
      '-S', `${input.runtime.bindHost}:${port}`, '-t', root,
    ]
    let child: ChildProcess | null = null
    let stderrTail = ''
    try {
      child = this.spawnImpl(input.runtime.phpBinary || this.phpBinary, args, {
        cwd: root,
        env: { ...process.env, ...environment },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      })
      await new Promise<void>((resolveSpawn, rejectSpawn) => {
        child?.once('spawn', () => resolveSpawn())
        child?.once('error', rejectSpawn)
      })
      child.stdout?.resume()
      child.stderr?.setEncoding('utf8')
      child.stderr?.on('data', chunk => {
        stderrTail = `${stderrTail}${String(chunk)}`.slice(-2_000)
      })
      await waitForHttp(input.runtime.bindHost, port, child)
      return { child, port }
    } catch (error) {
      if (child) await waitForExit(child)
      this.reservedPorts.delete(port)
      if (error instanceof ProviderError) {
        const detail = stderrTail.replace(/\s+/g, ' ').trim()
        throw detail ? new ProviderError(error.code, `${error.message} PHP: ${detail}`, error.statusCode) : error
      }
      throw new ProviderError('NATIVE_PHP_START_FAILED', error instanceof Error ? error.message : '原生 PHP 启动失败。', 503)
    }
  }

  private async stopPhpProcess(processInfo: { child: ChildProcess; port: number }) {
    this.reservedPorts.delete(processInfo.port)
    await waitForExit(processInfo.child)
  }

  private databaseCredentials(resource: MySqlResource) {
    return { host: resource.host, port: resource.port, user: resource.user, password: resource.password, database: resource.database }
  }

  private databaseEnvironment(profile: DatabaseLabProfile, resource: MySqlResource): Record<string, string> {
    const credentials = this.databaseCredentials(resource)
    return {
      DB_SERVER: credentials.host,
      DB_DATABASE: credentials.database,
      DB_USER: credentials.user,
      DB_PASSWORD: credentials.password,
      DB_PORT: String(credentials.port),
      ...(profile === 'dvwa' ? { DBMS: 'MySQL' } : {}),
    }
  }

  private runtimeUrl(input: ProviderStartInput, port: number, path: string) {
    const host = input.runtime.bindHost === '0.0.0.0' || input.runtime.bindHost === '::' ? '127.0.0.1' : input.runtime.bindHost
    return `http://${host}:${port}${path}`
  }

  private responseCookies(response: Response) {
    const headers = response.headers as Headers & { getSetCookie?: () => string[] }
    const values = headers.getSetCookie?.() ?? (response.headers.get('set-cookie') ? [response.headers.get('set-cookie') as string] : [])
    return values.map(value => value.split(';', 1)[0]).filter(Boolean).join('; ')
  }

  private async initializeDatabase(profile: DatabaseLabProfile, input: ProviderStartInput, root: string, resource: MySqlResource) {
    const bootstrapRoot = `${root}-bootstrap`
    let processInfo: { child: ChildProcess; port: number } | null = null
    try {
      await cp(resolve(input.lab.localPath as string), bootstrapRoot, { recursive: true, force: true })
      if (profile === 'dvwa') {
        await configureDvwa(bootstrapRoot)
        await configureDvwaInstallerCompatibility(bootstrapRoot)
        await configureDvwaExistingDatabase(bootstrapRoot)
      }
      if (profile === 'pikachu') {
        await configurePikachu(bootstrapRoot)
        await configurePikachuInstallerPort(bootstrapRoot)
      }
      const mutillidaeRoot = profile === 'mutillidae' ? await configureMutillidae(bootstrapRoot) : null
      const phpInput = profile === 'sqli-labs'
        ? { ...input, phpAutoPrependFile: await configureSqliLabs(bootstrapRoot) }
        : input
      processInfo = await this.startPhpProcess(mutillidaeRoot ?? bootstrapRoot, phpInput, this.databaseEnvironment(profile, resource))
      if (profile === 'dvwa') {
        const setupResponse = await fetch(this.runtimeUrl(input, processInfo.port, '/setup.php'))
        const setupHtml = await setupResponse.text()
        const tokenMatch = setupHtml.match(/name=["']user_token["'][^>]*value=["']([^"']+)["']/i) ?? setupHtml.match(/value=["']([^"']+)["'][^>]*name=["']user_token["']/i)
        if (!setupResponse.ok || !tokenMatch?.[1]) throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', 'DVWA 初始化页没有返回有效校验令牌。', 503)
        const cookie = this.responseCookies(setupResponse)
        const result = await fetch(this.runtimeUrl(input, processInfo.port, '/setup.php'), {
          method: 'POST',
          redirect: 'manual',
          headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
          body: new URLSearchParams({ create_db: 'Create / Reset Database', user_token: tokenMatch[1] }),
        })
        const resultResponseHtml = await result.text()
        const confirmation = await fetch(this.runtimeUrl(input, processInfo.port, '/setup.php'), { headers: cookie ? { cookie } : undefined })
        const resultHtml = await confirmation.text()
        if ((!result.ok && result.status < 300) || !confirmation.ok || !/Setup successful/i.test(resultHtml)) {
          const detail = `${resultResponseHtml} ${resultHtml}`.replace(/\s+/g, ' ').trim().slice(0, 480)
          throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', `DVWA 数据库初始化没有完成（HTTP ${result.status}，${detail || '未返回初始化结果'}）。`, 503)
        }
      } else if (profile === 'pikachu') {
        const result = await fetch(this.runtimeUrl(input, processInfo.port, '/install.php'), {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ submit: '安装/初始化' }),
        })
        const resultHtml = await result.text()
        if (!result.ok || !/好了，可以开搞了|进入首页|数据库连接成功/.test(resultHtml) || /数据连接失败|数据库创建失败/.test(resultHtml)) {
          throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', 'Pikachu 数据库初始化没有完成。', 503)
        }
      } else if (profile === 'sqli-labs') {
        const result = await fetch(this.runtimeUrl(input, processInfo.port, '/sql-connections/setup-db.php'))
        const resultHtml = await result.text()
        if (!result.ok || !/Inserted data correctly|Creating New Table/i.test(resultHtml) || /Could not connect|Failed to connect|Error creating|Unable to connect/i.test(resultHtml)) {
          throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', 'SQLi-Labs 数据库初始化没有完成。', 503)
        }
      } else {
        const result = await fetch(this.runtimeUrl(input, processInfo.port, '/set-up-database.php'))
        const resultHtml = await result.text()
        if (!result.ok || !/Database reset successful/i.test(resultHtml) || /database-failure-message/.test(resultHtml)) {
          const resultText = resultHtml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()
          const detail = resultText.length > 720 ? `${resultText.slice(0, 240)} … ${resultText.slice(-480)}` : resultText
          throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', `Mutillidae 数据库初始化没有完成（${detail || '未返回初始化结果'}）。`, 503)
        }
      }
      await this.mysqlManager.verify(resource)
    } finally {
      if (processInfo) await this.stopPhpProcess(processInfo)
      await removeTree(bootstrapRoot)
    }
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    const sourceRoot = input.lab.localPath
    if (!sourceRoot) throw new ProviderError('NATIVE_PHP_SOURCE_NOT_READY', '该靶场尚未完成导入，暂时没有可运行目录。', 409)
    const sourceStat = await stat(sourceRoot).catch(() => null)
    if (!sourceStat?.isDirectory()) throw new ProviderError('NATIVE_PHP_SOURCE_NOT_FOUND', '靶场导入目录不存在或不是目录。', 409)
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError('NATIVE_PHP_INSTANCE_ID_INVALID', '运行实例 ID 格式无效。', 400)

    const dataRoot = resolve(input.dataDir)
    const sourcePath = resolve(sourceRoot)
    const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
    if (sourcePath !== dataRoot && !sourcePath.startsWith(dataPrefix)) throw new ProviderError('NATIVE_PHP_SOURCE_OUTSIDE_DATA', '靶场目录必须位于 VulnLab 数据目录内。', 409)
    const runtimeRoot = join(dataRoot, 'runtime', input.instanceId)
    const profile = databaseProfile(input.lab)
    let processInfo: { child: ChildProcess; port: number } | null = null
    let database: MySqlResource | null = null
    try {
      await mkdir(resolve(dataRoot, 'runtime'), { recursive: true })
      if (profile) {
        if (!input.runtime.mysql) throw new ProviderError('NATIVE_PHP_MYSQL_NOT_CONFIGURED', 'DVWA/Pikachu 运行需要配置 MySQL 管理账号。', 409)
        database = await this.mysqlManager.provision({ labSlug: input.lab.slug, instanceId: input.instanceId, config: input.runtime.mysql })
        await this.initializeDatabase(profile, input, runtimeRoot, database)
      }
      await cp(sourcePath, runtimeRoot, { recursive: true, force: true })
      if (profile === 'dvwa') await configureDvwa(runtimeRoot)
      if (profile === 'pikachu') await configurePikachu(runtimeRoot)
      const mutillidaeRoot = profile === 'mutillidae' ? await configureMutillidae(runtimeRoot) : null
      const runtimeInput = profile === 'sqli-labs'
        ? { ...input, phpAutoPrependFile: await configureSqliLabs(runtimeRoot) }
        : input
      processInfo = await this.startPhpProcess(mutillidaeRoot ?? runtimeRoot, runtimeInput, profile && database ? this.databaseEnvironment(profile, database) : {})
      const runtime: NativeRuntime = { child: processInfo.child, root: runtimeRoot, port: processInfo.port, bindHost: input.runtime.bindHost, database }
      this.runtimes.set(input.instanceId, runtime)
      if (processInfo.child.pid) await writeFile(join(runtimeRoot, 'vulnlab-runtime.json'), JSON.stringify({ pid: processInfo.child.pid, port: processInfo.port, provider: this.id }), 'utf8')
      processInfo.child.once('exit', () => {
        if (this.runtimes.get(input.instanceId)?.child === processInfo?.child) this.runtimes.delete(input.instanceId)
        this.reservedPorts.delete(processInfo?.port as number)
        const detachedDatabase = runtime.database
        runtime.database = null
        void removeTree(runtimeRoot)
        if (detachedDatabase) void this.mysqlManager.destroy(detachedDatabase).catch(() => undefined)
      })
      const timestamps = lease(input.lifetimeMinutes)
      return {
        ...timestamps,
        endpoint: input.proxyEndpoint ?? `${runtimeOrigin(input.publicOrigin, processInfo.port, input.runtime.publicOriginTemplate)}/`,
        logs: [
          `${timestamps.createdAt} 启动原生 PHP 实例`,
          `${timestamps.createdAt} PHP=${input.runtime.phpBinary || this.phpBinary}`,
          `${timestamps.createdAt} 运行端口=${processInfo.port}`,
          ...(database ? [`${timestamps.createdAt} MySQL 数据库=${database.database}`] : []),
          `${timestamps.createdAt} 入口已准备`,
        ],
      }
    } catch (error) {
      if (processInfo) await this.stopPhpProcess(processInfo)
      this.runtimes.delete(input.instanceId)
      await removeTree(runtimeRoot)
      if (database) await this.mysqlManager.destroy(database).catch(() => undefined)
      if (error instanceof ProviderError) throw error
      throw new ProviderError('NATIVE_PHP_START_FAILED', error instanceof Error ? error.message : '原生 PHP 启动失败。', 503)
    }
  }

  async renew(input: ProviderRenewInput): Promise<ProviderRenewResult> {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError('NATIVE_PHP_PROCESS_MISSING', '原生 PHP 进程已退出，请重新启动实例。', 409)
    const { expiresAt } = lease(input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} 原生 PHP 实例续期` }
  }

  getProxyTarget(instanceId: string): string | null {
    const runtime = this.runtimes.get(instanceId)
    if (!runtime) return null
    const host = runtime.bindHost === '0.0.0.0' || runtime.bindHost === '::' ? '127.0.0.1' : runtime.bindHost
    return `http://${host}:${runtime.port}`
  }

  async stop(input: ProviderStopInput): Promise<ProviderStopResult> {
    const runtime = this.runtimes.get(input.instance.id)
    if (runtime) {
      this.runtimes.delete(input.instance.id)
      const database = runtime.database
      runtime.database = null
      await this.stopPhpProcess({ child: runtime.child, port: runtime.port })
      await removeTree(runtime.root)
      if (database) await this.mysqlManager.destroy(database)
    } else if (databaseProfile(input.lab)) {
      const mysql = input.runtime?.mysql ?? mysqlRuntimeConfigFromEnv()
      if (mysql) await this.mysqlManager.destroyForInstance({ labSlug: input.lab.slug, instanceId: input.instance.id, config: mysql })
    }
    return { log: `${new Date().toISOString()} 原生 PHP 实例结束` }
  }

  async recover(input: ProviderRecoverInput): Promise<void> {
    if (input.dataDir) {
      const root = join(resolve(input.dataDir), 'runtime', input.instance.id)
      const state = await readFile(join(root, 'vulnlab-runtime.json'), 'utf8').then(value => JSON.parse(value) as { pid?: unknown }).catch(() => null)
      if (state && Number.isInteger(state.pid) && Number(state.pid) > 0) await terminatePid(Number(state.pid))
      await removeTree(root)
    }
    if (!databaseProfile(input.lab)) return
    const mysql = input.runtime?.mysql ?? mysqlRuntimeConfigFromEnv()
    if (mysql) await this.mysqlManager.destroyForInstance({ labSlug: input.lab.slug, instanceId: input.instance.id, config: mysql })
  }

  async shutdown(): Promise<void> {
    const runtimes = [...this.runtimes.entries()]
    this.runtimes.clear()
    await Promise.all(runtimes.map(async ([, runtime]) => {
      const database = runtime.database
      runtime.database = null
      await this.stopPhpProcess({ child: runtime.child, port: runtime.port })
      await removeTree(runtime.root)
      if (database) await this.mysqlManager.destroy(database).catch(() => undefined)
    }))
  }
}

interface NativeProcessRuntime {
  child: ChildProcess
  root: string
  port: number
  bindHost: string
  auxiliaryPort?: number
}

type NativeProcessKind = 'native-node' | 'native-java' | 'native-python'

const processLabels: Record<NativeProcessKind, string> = {
  'native-node': 'Node.js',
  'native-java': 'Java',
  'native-python': 'Python',
}

const processErrorPrefix: Record<NativeProcessKind, string> = {
  'native-node': 'NATIVE_NODE',
  'native-java': 'NATIVE_JAVA',
  'native-python': 'NATIVE_PYTHON',
}

const waitForNativeHttp = async (host: string, port: number, child: ChildProcess, kind: NativeProcessKind) => {
  const probeHost = host === '0.0.0.0' || host === '::' ? '127.0.0.1' : host
  const deadline = Date.now() + (kind === 'native-python' ? 45_000 : 120_000)
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new ProviderError(`${processErrorPrefix[kind]}_PROCESS_EXITED`, `${processLabels[kind]} 进程在启动检查期间退出。`, 503)
    try {
      const response = await fetch(`http://${probeHost}:${port}/`, { redirect: 'manual', signal: AbortSignal.timeout(5_000) })
      await response.body?.cancel().catch(() => undefined)
      return
    } catch {
      await sleep(100)
    }
  }
  throw new ProviderError(`${processErrorPrefix[kind]}_START_TIMEOUT`, `${processLabels[kind]} 靶场启动超时。`, 503)
}

const findExistingFile = async (root: string, candidates: readonly string[]) => {
  for (const candidate of candidates) {
    const path = resolve(root, candidate)
    const info = await stat(path).catch(() => null)
    if (info?.isFile()) return path
  }
  return null
}

export interface NativeProcessProviderOptions {
  spawnImpl?: SpawnFunction
  allocatePort?: PortAllocator
}

export class NativeProcessProvider implements LabProvider {
  readonly id: NativeProcessKind
  readonly supportedRuntimeKinds: readonly RuntimeKind[]
  private readonly spawnImpl: SpawnFunction
  private readonly allocatePortImpl: PortAllocator
  private readonly runtimes = new Map<string, NativeProcessRuntime>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(kind: NativeProcessKind, options: NativeProcessProviderOptions = {}) {
    this.id = kind
    this.supportedRuntimeKinds = [kind]
    this.spawnImpl = options.spawnImpl ?? spawn
    this.allocatePortImpl = options.allocatePort ?? allocatePort
  }

  private async claimPort(config: NativeRuntimeConfig): Promise<number> {
    let release!: () => void
    const turn = new Promise<void>(resolveTurn => { release = resolveTurn })
    const previous = this.portAllocation
    this.portAllocation = previous.then(() => turn)
    await previous
    try {
      for (let attempt = 0; attempt <= config.portEnd - config.portStart; attempt += 1) {
        const port = await this.allocatePortImpl(config.bindHost, config.portStart, config.portEnd)
        if (!this.reservedPorts.has(port)) {
          this.reservedPorts.add(port)
          return port
        }
      }
      throw new ProviderError(`${processErrorPrefix[this.id]}_PORT_EXHAUSTED`, `${processLabels[this.id]} 运行端口已用尽。`, 409)
    } finally {
      release()
    }
  }

  private async command(input: ProviderStartInput, root: string, port: number, auxiliaryPort?: number) {
    if (this.id === 'native-node') {
      const entry = await findExistingFile(root, ['build/app.js', 'dist/app.js', 'app.js', 'server.js'])
      if (!entry) throw new ProviderError('NATIVE_NODE_ENTRY_NOT_FOUND', 'Juice Shop 发行包缺少 Node.js 启动入口。', 409)
      return {
        binary: input.runtime.nodeBinary,
        args: [entry],
        cwd: root,
        environment: { PORT: String(port), HOST: input.runtime.bindHost, NODE_ENV: 'production' },
        endpointSuffix: '',
      }
    }
    if (this.id === 'native-java') {
      if (!auxiliaryPort) throw new ProviderError('NATIVE_JAVA_AUX_PORT_REQUIRED', 'WebGoat 缺少 WebWolf 运行端口。', 500)
      const jar = input.lab.localPath && (await stat(input.lab.localPath).catch(() => null))?.isFile()
        ? resolve(input.lab.localPath)
        : await findExistingFile(root, ['webgoat.jar', `webgoat-${input.lab.version}.jar`])
      if (!jar) throw new ProviderError('NATIVE_JAVA_JAR_NOT_FOUND', 'WebGoat 发行包缺少可运行 JAR。', 409)
      return {
        binary: input.runtime.javaBinary,
        args: ['-Dfile.encoding=UTF-8', '-jar', jar, `--server.address=${input.runtime.bindHost}`, `--webgoat.port=${port}`, `--webwolf.port=${auxiliaryPort}`],
        cwd: root,
        environment: { HOME: root, USERPROFILE: root, WEBGOAT_PORT: String(port), WEBWOLF_PORT: String(auxiliaryPort) },
        endpointSuffix: 'WebGoat/',
      }
    }
    const manage = await findExistingFile(root, ['manage.py'])
    if (!manage) throw new ProviderError('NATIVE_PYTHON_ENTRY_NOT_FOUND', 'PyGoat 源码缺少 manage.py。', 409)
    const venvPython = process.platform === 'win32'
      ? await findExistingFile(input.lab.localPath as string, ['.vulnlab-venv/Scripts/python.exe'])
      : await findExistingFile(input.lab.localPath as string, ['.vulnlab-venv/bin/python'])
    const settingsPath = join(root, 'pygoat', 'settings.py')
    let settings = await readFile(settingsPath, 'utf8').catch(() => '')
    if (!settings) throw new ProviderError('NATIVE_PYTHON_SETTINGS_NOT_FOUND', 'PyGoat 缺少 Django 设置文件。', 409)
    settings = settings
      .replace(/^import django_heroku\s*$/m, '')
      .replace(/^django_heroku\.settings\(locals\(\)\)\s*$/m, '')
    const trustedOrigin = new URL(input.publicOrigin).origin
    settings += `\nALLOWED_HOSTS = ['*']\nCSRF_TRUSTED_ORIGINS = [${JSON.stringify(trustedOrigin)}]\n`
    await writeFile(settingsPath, settings, 'utf8')
    const binary = venvPython ?? input.runtime.pythonBinary
    const prefix = !venvPython && process.platform === 'win32' && basename(input.runtime.pythonBinary).toLowerCase() === 'py' ? ['-3'] : []
    await this.runCommand(binary, [...prefix, manage, 'migrate', '--noinput'], root)
    return {
      binary,
      args: [...prefix, manage, 'runserver', `${input.runtime.bindHost}:${port}`, '--noreload'],
      cwd: root,
      environment: { PYTHONUNBUFFERED: '1', DJANGO_SETTINGS_MODULE: 'pygoat.settings' },
      endpointSuffix: '',
    }
  }

  private async runCommand(binary: string, args: string[], cwd: string) {
    await new Promise<void>((resolveRun, rejectRun) => {
      const child = this.spawnImpl(binary, args, { cwd, env: process.env, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, shell: false })
      let tail = ''
      child.stderr?.setEncoding('utf8')
      child.stderr?.on('data', chunk => { tail = `${tail}${String(chunk)}`.slice(-4_000) })
      child.once('error', rejectRun)
      child.once('exit', code => code === 0 ? resolveRun() : rejectRun(new ProviderError(`${processErrorPrefix[this.id]}_PREPARE_FAILED`, `${processLabels[this.id]} 运行副本准备失败：${tail.replace(/\s+/g, ' ').trim()}`, 503)))
    })
  }

  private async copyRuntimeSource(sourcePath: string, runtimeRoot: string) {
    if (this.id === 'native-python') {
      const venvRoot = resolve(sourcePath, '.vulnlab-venv')
      const venvPrefix = `${venvRoot}${sep}`
      await cp(sourcePath, runtimeRoot, { recursive: true, force: true, filter: path => {
        const candidate = resolve(path)
        return candidate !== venvRoot && !candidate.startsWith(venvPrefix)
      } })
      return
    }
    if (this.id !== 'native-node') {
      await cp(sourcePath, runtimeRoot, { recursive: true, force: true })
      return
    }
    const modulesRoot = resolve(sourcePath, 'node_modules')
    const modulesPrefix = `${modulesRoot}${sep}`
    await cp(sourcePath, runtimeRoot, {
      recursive: true,
      force: true,
      filter: path => {
        const candidate = resolve(path)
        return candidate !== modulesRoot && !candidate.startsWith(modulesPrefix)
      },
    })
    if ((await stat(modulesRoot).catch(() => null))?.isDirectory()) {
      await symlink(modulesRoot, join(runtimeRoot, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir')
    }
  }

  private async claimFollowingPort(config: NativeRuntimeConfig, port: number) {
    const ranges: Array<[number, number]> = []
    if (port < config.portEnd) ranges.push([port + 1, config.portEnd])
    if (port > config.portStart) ranges.push([config.portStart, port - 1])
    for (const [start, end] of ranges) {
      try {
        const candidate = await this.allocatePortImpl(config.bindHost, start, end)
        if (!this.reservedPorts.has(candidate)) {
          this.reservedPorts.add(candidate)
          return candidate
        }
      } catch { /* try wrapped range */ }
    }
    throw new ProviderError('NATIVE_JAVA_AUX_PORT_EXHAUSTED', 'WebGoat 的 WebWolf 端口已用尽。', 409)
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    const sourceRoot = input.lab.localPath
    if (!sourceRoot) throw new ProviderError(`${processErrorPrefix[this.id]}_SOURCE_NOT_READY`, '靶场资源尚未安装。', 409)
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError(`${processErrorPrefix[this.id]}_INSTANCE_ID_INVALID`, '运行实例 ID 格式无效。', 400)
    const dataRoot = resolve(input.dataDir)
    const sourcePath = resolve(sourceRoot)
    const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
    if (sourcePath !== dataRoot && !sourcePath.startsWith(dataPrefix)) throw new ProviderError(`${processErrorPrefix[this.id]}_SOURCE_OUTSIDE_DATA`, '靶场资源必须位于 VulnLab 数据目录内。', 409)
    const runtimeRoot = join(dataRoot, 'runtime', input.instanceId)
    const port = await this.claimPort(input.runtime)
    const auxiliaryPort = this.id === 'native-java' ? await this.claimFollowingPort(input.runtime, port) : undefined
    let child: ChildProcess | null = null
    let stderrTail = ''
    try {
      await mkdir(resolve(dataRoot, 'runtime'), { recursive: true })
      await rm(runtimeRoot, { recursive: true, force: true })
      await mkdir(runtimeRoot, { recursive: true })
      const sourceInfo = await stat(sourcePath)
      if (sourceInfo.isDirectory()) await this.copyRuntimeSource(sourcePath, runtimeRoot)
      const command = await this.command(input, runtimeRoot, port, auxiliaryPort)
      child = this.spawnImpl(command.binary, command.args, {
        cwd: command.cwd,
        env: { ...process.env, ...command.environment },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      })
      await new Promise<void>((resolveSpawn, rejectSpawn) => {
        child?.once('spawn', resolveSpawn)
        child?.once('error', rejectSpawn)
      })
      child.stdout?.resume()
      child.stderr?.setEncoding('utf8')
      child.stderr?.on('data', chunk => { stderrTail = `${stderrTail}${String(chunk)}`.slice(-4_000) })
      await waitForNativeHttp(input.runtime.bindHost, port, child, this.id)
      const runtime: NativeProcessRuntime = { child, root: runtimeRoot, port, bindHost: input.runtime.bindHost, auxiliaryPort }
      this.runtimes.set(input.instanceId, runtime)
      if (child.pid) await writeFile(join(runtimeRoot, 'vulnlab-runtime.json'), JSON.stringify({ pid: child.pid, port, auxiliaryPort, provider: this.id }), 'utf8')
      child.once('exit', () => {
        if (this.runtimes.get(input.instanceId)?.child === child) this.runtimes.delete(input.instanceId)
        this.reservedPorts.delete(port)
        if (auxiliaryPort) this.reservedPorts.delete(auxiliaryPort)
        void removeTree(runtimeRoot)
      })
      const timestamps = lease(input.lifetimeMinutes)
      return {
        ...timestamps,
        endpoint: `${input.proxyEndpoint ?? `${runtimeOrigin(input.publicOrigin, port, input.runtime.publicOriginTemplate)}/`}${command.endpointSuffix}`,
        logs: [
          `${timestamps.createdAt} 启动原生 ${processLabels[this.id]} 实例`,
          `${timestamps.createdAt} 运行端口=${port}`,
          ...(auxiliaryPort ? [`${timestamps.createdAt} WebWolf 端口=${auxiliaryPort}`] : []),
          `${timestamps.createdAt} 入口已准备`,
        ],
      }
    } catch (error) {
      this.reservedPorts.delete(port)
      if (auxiliaryPort) this.reservedPorts.delete(auxiliaryPort)
      if (child) await waitForExit(child)
      await removeTree(runtimeRoot)
      if (error instanceof ProviderError) {
        const detail = stderrTail.replace(/\s+/g, ' ').trim()
        throw detail ? new ProviderError(error.code, `${error.message} ${detail}`, error.statusCode) : error
      }
      const code = (error as NodeJS.ErrnoException)?.code === 'ENOENT' ? `${processErrorPrefix[this.id]}_BINARY_NOT_FOUND` : `${processErrorPrefix[this.id]}_START_FAILED`
      throw new ProviderError(code, error instanceof Error ? error.message : `${processLabels[this.id]} 靶场启动失败。`, 503)
    }
  }

  async renew(input: ProviderRenewInput): Promise<ProviderRenewResult> {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError(`${processErrorPrefix[this.id]}_PROCESS_MISSING`, `${processLabels[this.id]} 进程已退出。`, 409)
    const { expiresAt } = lease(input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} 原生 ${processLabels[this.id]} 实例续期` }
  }

  getProxyTarget(instanceId: string): string | null {
    const runtime = this.runtimes.get(instanceId)
    if (!runtime) return null
    const host = runtime.bindHost === '0.0.0.0' || runtime.bindHost === '::' ? '127.0.0.1' : runtime.bindHost
    return `http://${host}:${runtime.port}`
  }

  async stop(input: ProviderStopInput): Promise<ProviderStopResult> {
    const runtime = this.runtimes.get(input.instance.id)
    if (runtime) {
      this.runtimes.delete(input.instance.id)
      this.reservedPorts.delete(runtime.port)
      if (runtime.auxiliaryPort) this.reservedPorts.delete(runtime.auxiliaryPort)
      await waitForExit(runtime.child)
      await removeTree(runtime.root)
    }
    return { log: `${new Date().toISOString()} 原生 ${processLabels[this.id]} 实例结束` }
  }

  async recover(input: ProviderRecoverInput): Promise<void> {
    if (!input.dataDir) return
    const root = join(resolve(input.dataDir), 'runtime', input.instance.id)
    const state = await readFile(join(root, 'vulnlab-runtime.json'), 'utf8').then(value => JSON.parse(value) as { pid?: unknown }).catch(() => null)
    if (state && Number.isInteger(state.pid) && Number(state.pid) > 0) await terminatePid(Number(state.pid))
    await removeTree(root)
  }

  async shutdown(): Promise<void> {
    const runtimes = [...this.runtimes.values()]
    this.runtimes.clear()
    await Promise.all(runtimes.map(async runtime => {
      this.reservedPorts.delete(runtime.port)
      if (runtime.auxiliaryPort) this.reservedPorts.delete(runtime.auxiliaryPort)
      await waitForExit(runtime.child)
      await removeTree(runtime.root)
    }))
  }
}

interface QemuRuntime {
  child: ChildProcess
  root: string
  port: number
}

interface QemuState {
  pid: number
  port: number
  createdAt: string
}

export interface QemuVmProviderOptions {
  qemuBinary?: string
  spawnImpl?: SpawnFunction
  allocatePort?: PortAllocator
  probePort?: TcpProbe
  terminatePid?: TerminatePid
}

const qemuImageFormat = (imagePath: string) => {
  const extension = extname(imagePath).toLowerCase()
  const formats: Record<string, string> = {
    '.qcow': 'qcow',
    '.qcow2': 'qcow2',
    '.raw': 'raw',
    '.img': 'raw',
    '.vdi': 'vdi',
    '.vmdk': 'vmdk',
  }
  const format = formats[extension]
  if (!format) {
    if (extension === '.ova' || extension === '.ovf') {
      throw new ProviderError('QEMU_IMAGE_ARCHIVE_UNSUPPORTED', '当前 QEMU Provider 只把 OVA 作为整体归档处理；单独的 OVF 文件仍需要配套磁盘。', 409)
    }
    throw new ProviderError('QEMU_IMAGE_FORMAT_UNSUPPORTED', '当前 QEMU Provider 只支持 qcow2、raw、vdi 和 vmdk 磁盘镜像。', 409)
  }
  if (imagePath.includes(',')) throw new ProviderError('QEMU_IMAGE_PATH_INVALID', '虚拟机镜像路径不能包含逗号。', 409)
  return format
}

interface OvaMember {
  path: string
  bytes: number
  descriptor: boolean
}

const TAR_BLOCK_BYTES = 512
const OVA_MAX_MEMBERS = 256
const OVA_MAX_EXTRACTED_BYTES = 100 * 1024 ** 3

const tarText = (block: Buffer, start: number, length: number) => {
  const end = block.indexOf(0, start)
  return block.subarray(start, end === -1 ? start + length : end).toString('utf8').trim()
}

const tarSize = (block: Buffer) => {
  const raw = tarText(block, 124, 12).replace(/\0/g, '').trim()
  if (!raw) return 0
  if (!/^[0-7]+$/.test(raw)) throw new ProviderError('QEMU_OVA_HEADER_INVALID', 'OVA 文件包含无效的 TAR 文件大小。', 409)
  const size = Number.parseInt(raw, 8)
  if (!Number.isSafeInteger(size) || size < 0) throw new ProviderError('QEMU_OVA_MEMBER_TOO_LARGE', 'OVA 文件成员大小无效。', 409)
  return size
}

const safeArchivePath = (value: string) => {
  const normalized = value.replaceAll('\\', '/')
  const segments = normalized.split('/')
  if (!normalized || normalized.startsWith('/') || segments.some(segment => !segment || segment === '.' || segment === '..')) {
    throw new ProviderError('QEMU_OVA_PATH_INVALID', `OVA 文件包含不安全路径：${value}。`, 409)
  }
  return segments.join('/')
}

const descriptorHeader = (value: Buffer) => value.toString('utf8').replace(/^\uFEFF/, '').trimStart().startsWith('# Disk DescriptorFile')

const skipArchiveBytes = async (archive: Awaited<ReturnType<typeof open>>, bytes: number) => {
  let remaining = bytes
  const chunk = Buffer.alloc(1024 * 1024)
  while (remaining > 0) {
    const readSize = Math.min(remaining, chunk.byteLength)
    const result = await archive.read(chunk, 0, readSize, null)
    if (result.bytesRead !== readSize) throw new ProviderError('QEMU_OVA_TRUNCATED', 'OVA 文件成员不完整。', 409)
    remaining -= readSize
  }
}

const extractOva = async (sourcePath: string, destinationRoot: string): Promise<string> => {
  const archive = await open(sourcePath, 'r')
  const members: OvaMember[] = []
  const seenPaths = new Set<string>()
  let extractedBytes = 0
  let ended = false
  try {
    await mkdir(destinationRoot, { recursive: true })
    const header = Buffer.alloc(TAR_BLOCK_BYTES)
    for (let memberIndex = 0; memberIndex < OVA_MAX_MEMBERS; memberIndex += 1) {
      const read = await archive.read(header, 0, TAR_BLOCK_BYTES, null)
      if (read.bytesRead !== TAR_BLOCK_BYTES) throw new ProviderError('QEMU_OVA_TRUNCATED', 'OVA 文件的 TAR 头不完整。', 409)
      if (header.every(byte => byte === 0)) {
        ended = true
        break
      }
      const name = tarText(header, 0, 100)
      const prefix = tarText(header, 345, 155)
      const rawMemberPath = prefix ? `${prefix}/${name}` : name
      const memberPath = safeArchivePath(rawMemberPath.replace(/\/+$/, ''))
      if (seenPaths.has(memberPath)) throw new ProviderError('QEMU_OVA_PATH_DUPLICATE', `OVA 文件包含重复成员：${memberPath}。`, 409)
      seenPaths.add(memberPath)
      const size = tarSize(header)
      const type = String.fromCharCode(header[156] || 0)
      const isDirectory = type === '5' || memberPath.endsWith('/')
      const isRegular = type === '\0' || type === '0'
      if (!isDirectory && !isRegular) throw new ProviderError('QEMU_OVA_MEMBER_UNSUPPORTED', `OVA 文件包含不支持的成员类型：${memberPath}。`, 409)
      if (size > OVA_MAX_EXTRACTED_BYTES || extractedBytes > OVA_MAX_EXTRACTED_BYTES - size) throw new ProviderError('QEMU_OVA_SIZE_LIMIT', 'OVA 解包后的磁盘总大小超过限制。', 409)
      extractedBytes += size
      const padding = (TAR_BLOCK_BYTES - (size % TAR_BLOCK_BYTES)) % TAR_BLOCK_BYTES
      if (isDirectory) {
        await mkdir(join(destinationRoot, memberPath), { recursive: true })
        await skipArchiveBytes(archive, size)
      } else if (/\.vmdk$/i.test(memberPath)) {
        const outputPath = join(destinationRoot, memberPath)
        await mkdir(resolve(outputPath, '..'), { recursive: true })
        const output = await open(outputPath, 'w')
        const firstBytes = Buffer.alloc(Math.min(1_024, size))
        let remaining = size
        let firstRead = 0
        try {
          const chunk = Buffer.alloc(1024 * 1024)
          while (remaining > 0) {
            const readSize = Math.min(remaining, chunk.byteLength)
            const result = await archive.read(chunk, 0, readSize, null)
            if (result.bytesRead !== readSize) throw new ProviderError('QEMU_OVA_TRUNCATED', `OVA 文件成员不完整：${memberPath}。`, 409)
            await output.write(chunk.subarray(0, readSize))
            if (firstRead < firstBytes.byteLength) {
              const copySize = Math.min(firstBytes.byteLength - firstRead, readSize)
              chunk.copy(firstBytes, firstRead, 0, copySize)
              firstRead += copySize
            }
            remaining -= readSize
          }
        } finally {
          await output.close()
        }
        members.push({ path: memberPath, bytes: size, descriptor: descriptorHeader(firstBytes) })
      } else {
        let remaining = size
        const chunk = Buffer.alloc(1024 * 1024)
        while (remaining > 0) {
          const readSize = Math.min(remaining, chunk.byteLength)
          const result = await archive.read(chunk, 0, readSize, null)
          if (result.bytesRead !== readSize) throw new ProviderError('QEMU_OVA_TRUNCATED', `OVA 文件成员不完整：${memberPath}。`, 409)
          remaining -= readSize
        }
      }
      if (padding) {
        await skipArchiveBytes(archive, padding)
      }
    }
    if (!ended) throw new ProviderError('QEMU_OVA_MEMBER_LIMIT', 'OVA 文件成员数量超过限制或缺少结束标记。', 409)
    if (!members.length) throw new ProviderError('QEMU_OVA_NO_DISK', 'OVA 文件中没有 VMDK 磁盘成员。', 409)
    const selected = members.find(member => member.descriptor) ?? [...members].sort((left, right) => right.bytes - left.bytes)[0]
    return join(destinationRoot, selected.path)
  } finally {
    await archive.close()
  }
}

const validateQemuRuntime = (config: VmRuntimeConfig | undefined) => {
  if (!config) throw new ProviderError('QEMU_RUNTIME_NOT_CONFIGURED', '尚未配置 QEMU 运行参数。', 409)
  if (!config.qemuBinary?.trim()) throw new ProviderError('QEMU_BINARY_INVALID', 'QEMU 可执行文件配置为空。', 500)
  if (!Number.isInteger(config.portStart) || !Number.isInteger(config.portEnd) || config.portStart < 1024 || config.portEnd > 65535 || config.portStart > config.portEnd) {
    throw new ProviderError('QEMU_PORT_RANGE_INVALID', 'QEMU 运行端口范围无效。', 500)
  }
  if (!Number.isInteger(config.guestPort) || config.guestPort < 1 || config.guestPort > 65535) throw new ProviderError('QEMU_GUEST_PORT_INVALID', 'QEMU 虚拟机服务端口无效。', 500)
  if (!Number.isInteger(config.memoryMb) || config.memoryMb < 128 || config.memoryMb > 65_536) throw new ProviderError('QEMU_MEMORY_INVALID', 'QEMU 内存必须是 128 到 65536 MiB 之间的整数。', 500)
  if (!Number.isInteger(config.cpus) || config.cpus < 1 || config.cpus > 64) throw new ProviderError('QEMU_CPUS_INVALID', 'QEMU CPU 数量必须是 1 到 64 之间的整数。', 500)
  if (!Number.isInteger(config.bootTimeoutMs) || config.bootTimeoutMs < 1_000 || config.bootTimeoutMs > 600_000) throw new ProviderError('QEMU_BOOT_TIMEOUT_INVALID', 'QEMU 启动超时必须是 1000 到 600000 毫秒之间的整数。', 500)
  return config
}

export class QemuVmProvider implements LabProvider {
  readonly id = 'qemu-vm'
  readonly supportedRuntimeKinds: readonly RuntimeKind[] = ['vm']
  private readonly qemuBinary: string
  private readonly spawnImpl: SpawnFunction
  private readonly allocatePortImpl: PortAllocator
  private readonly probePortImpl: TcpProbe
  private readonly terminatePidImpl: TerminatePid
  private readonly runtimes = new Map<string, QemuRuntime>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(options: QemuVmProviderOptions = {}) {
    this.qemuBinary = options.qemuBinary ?? process.env.VULNLAB_QEMU_BIN ?? 'qemu-system-x86_64'
    this.spawnImpl = options.spawnImpl ?? spawn
    this.allocatePortImpl = options.allocatePort ?? allocatePort
    this.probePortImpl = options.probePort ?? waitForTcp
    this.terminatePidImpl = options.terminatePid ?? terminatePid
  }

  private async claimPort(config: VmRuntimeConfig): Promise<number> {
    let release!: () => void
    const turn = new Promise<void>(resolveTurn => { release = resolveTurn })
    const previous = this.portAllocation
    this.portAllocation = previous.then(() => turn)
    await previous
    try {
      for (let attempt = 0; attempt <= config.portEnd - config.portStart; attempt += 1) {
        const port = await this.allocatePortImpl('127.0.0.1', config.portStart, config.portEnd)
        if (!this.reservedPorts.has(port)) {
          this.reservedPorts.add(port)
          return port
        }
      }
      throw new ProviderError('QEMU_PORT_EXHAUSTED', 'QEMU 运行端口已用尽，请扩大端口范围。', 409)
    } finally {
      release()
    }
  }

  private async artifact(input: ProviderStartInput) {
    if (!input.artifactPath) throw new ProviderError('QEMU_IMAGE_NOT_READY', '尚未选择已完成下载的虚拟机镜像。', 409)
    const dataRoot = resolve(input.dataDir)
    const imagePath = resolve(input.artifactPath)
    const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
    if (imagePath !== dataRoot && !imagePath.startsWith(dataPrefix)) throw new ProviderError('QEMU_IMAGE_OUTSIDE_DATA', '虚拟机镜像必须位于 VulnLab 数据目录内。', 409)
    if (imagePath.includes(',')) throw new ProviderError('QEMU_IMAGE_PATH_INVALID', '虚拟机镜像路径不能包含逗号。', 409)
    const imageStat = await stat(imagePath).catch(() => null)
    if (!imageStat?.isFile() || imageStat.size <= 0) throw new ProviderError('QEMU_IMAGE_NOT_FOUND', '虚拟机镜像不存在或为空。', 409)
    return { imagePath, format: extname(imagePath).toLowerCase() === '.ova' ? 'ova' : qemuImageFormat(imagePath) }
  }

  private async launch(input: ProviderStartInput, config: VmRuntimeConfig, imagePath: string, format: string, port: number, root: string) {
    const args = [
      '-m', String(config.memoryMb),
      '-smp', String(config.cpus),
      '-drive', `file=${imagePath},if=ide,format=${format}`,
      '-nic', `user,model=e1000,hostfwd=tcp:127.0.0.1:${port}-:${config.guestPort}`,
      '-display', 'none',
      '-serial', 'none',
      '-monitor', 'none',
      '-snapshot',
      '-no-reboot',
    ]
    let child: ChildProcess | null = null
    let stderrTail = ''
    try {
      child = this.spawnImpl(config.qemuBinary || this.qemuBinary, args, {
        cwd: resolve(input.dataDir),
        env: { ...process.env },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      })
      await new Promise<void>((resolveSpawn, rejectSpawn) => {
        child?.once('spawn', () => resolveSpawn())
        child?.once('error', rejectSpawn)
      })
      child.stdout?.resume()
      child.stderr?.setEncoding('utf8')
      child.stderr?.on('data', chunk => {
        stderrTail = `${stderrTail}${String(chunk)}`.slice(-2_000)
      })
      if (!child.pid) throw new ProviderError('QEMU_PID_MISSING', 'QEMU 进程没有返回有效 PID。', 503)
      await writeFile(join(root, 'state.json'), JSON.stringify({ pid: child.pid, port, createdAt: new Date().toISOString() }, null, 2), 'utf8')
      await this.probePortImpl('127.0.0.1', port, child, config.bootTimeoutMs)
      return child
    } catch (error) {
      if (child) await waitForExit(child)
      if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') throw new ProviderError('QEMU_NOT_FOUND', `找不到 QEMU 可执行文件：${config.qemuBinary || this.qemuBinary}。`, 503)
      if (error instanceof ProviderError) {
        const detail = stderrTail.replace(/\s+/g, ' ').trim()
        throw detail ? new ProviderError(error.code, `${error.message} QEMU: ${detail}`, error.statusCode) : error
      }
      throw new ProviderError('QEMU_START_FAILED', error instanceof Error ? error.message : 'QEMU 虚拟机启动失败。', 503)
    }
  }

  private statePath(dataDir: string, instanceId: string) {
    return join(resolve(dataDir), 'vm-runtime', instanceId, 'state.json')
  }

  private async readState(dataDir: string, instanceId: string): Promise<Partial<QemuState> | null> {
    try {
      return JSON.parse(await readFile(this.statePath(dataDir, instanceId), 'utf8')) as Partial<QemuState>
    } catch {
      return null
    }
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    const config = validateQemuRuntime(input.vm)
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError('QEMU_INSTANCE_ID_INVALID', 'QEMU 运行实例 ID 格式无效。', 400)
    const artifact = await this.artifact(input)
    const root = join(resolve(input.dataDir), 'vm-runtime', input.instanceId)
    let port = 0
    let child: ChildProcess | null = null
    try {
      await mkdir(root, { recursive: true })
      port = await this.claimPort(config)
      const preparedArtifact = extname(artifact.imagePath).toLowerCase() === '.ova'
        ? { imagePath: await extractOva(artifact.imagePath, join(root, 'ova')), format: 'vmdk' }
        : artifact
      child = await this.launch(input, config, preparedArtifact.imagePath, preparedArtifact.format, port, root)
      const runtime: QemuRuntime = { child, root, port }
      this.runtimes.set(input.instanceId, runtime)
      child.once('exit', () => {
        if (this.runtimes.get(input.instanceId)?.child === child) this.runtimes.delete(input.instanceId)
        this.reservedPorts.delete(port)
        void removeTree(root)
      })
      const timestamps = lease(input.lifetimeMinutes)
      const origin = input.publicOrigin.replace(/\/+$/, '')
      return {
        ...timestamps,
        endpoint: input.proxyEndpoint ?? `${origin}/lab-runtime/${encodeURIComponent(input.instanceId)}/`,
        logs: [
          `${timestamps.createdAt} 启动 QEMU 虚拟机`,
          `${timestamps.createdAt} 镜像格式=${artifact.format}`,
          `${timestamps.createdAt} 宿主端口=${port} → 虚拟机端口=${config.guestPort}`,
          `${timestamps.createdAt} 入口已准备`,
        ],
      }
    } catch (error) {
      this.reservedPorts.delete(port)
      if (child) await waitForExit(child)
      await removeTree(root)
      if (error instanceof ProviderError) throw error
      throw new ProviderError('QEMU_START_FAILED', error instanceof Error ? error.message : 'QEMU 虚拟机启动失败。', 503)
    }
  }

  async renew(input: ProviderRenewInput): Promise<ProviderRenewResult> {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError('QEMU_PROCESS_MISSING', 'QEMU 虚拟机进程已退出，请重新启动实例。', 409)
    const { expiresAt } = lease(input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} QEMU 虚拟机实例续期` }
  }

  getProxyTarget(instanceId: string): string | null {
    const runtime = this.runtimes.get(instanceId)
    return runtime ? `http://127.0.0.1:${runtime.port}` : null
  }

  async stop(input: ProviderStopInput): Promise<ProviderStopResult> {
    const runtime = this.runtimes.get(input.instance.id)
    if (runtime) {
      this.runtimes.delete(input.instance.id)
      this.reservedPorts.delete(runtime.port)
      await waitForExit(runtime.child)
      await removeTree(runtime.root)
    } else if (input.dataDir) {
      const state = await this.readState(input.dataDir, input.instance.id)
      if (Number.isInteger(state?.pid) && (state?.pid as number) > 0) await this.terminatePidImpl(state?.pid as number)
      await removeTree(join(resolve(input.dataDir), 'vm-runtime', input.instance.id))
    }
    return { log: `${new Date().toISOString()} QEMU 虚拟机实例结束` }
  }

  async recover(input: ProviderRecoverInput): Promise<void> {
    if (!input.dataDir) return
    const state = await this.readState(input.dataDir, input.instance.id)
    if (Number.isInteger(state?.pid) && (state?.pid as number) > 0) await this.terminatePidImpl(state?.pid as number)
    await removeTree(join(resolve(input.dataDir), 'vm-runtime', input.instance.id))
  }

  async shutdown(): Promise<void> {
    const runtimes = [...this.runtimes.values()]
    this.runtimes.clear()
    await Promise.all(runtimes.map(async runtime => {
      this.reservedPorts.delete(runtime.port)
      await waitForExit(runtime.child)
      await removeTree(runtime.root)
    }))
  }
}

export class ProviderRegistry {
  private readonly providers = new Map<string, LabProvider>()

  constructor(providers: readonly LabProvider[]) {
    for (const provider of providers) {
      if (this.providers.has(provider.id)) throw new Error(`Provider ID 重复：${provider.id}`)
      this.providers.set(provider.id, provider)
    }
  }

  get(id: string): LabProvider | null {
    return this.providers.get(id) ?? null
  }

  resolve(id: string, runtimeKind: RuntimeKind): LabProvider {
    const provider = this.get(id)
    if (!provider) throw new ProviderError('PROVIDER_NOT_FOUND', `运行环境 Provider 不存在：${id}。`)
    if (!provider.supportedRuntimeKinds.includes(runtimeKind)) {
      throw new ProviderError('PROVIDER_RUNTIME_UNSUPPORTED', `Provider ${id} 不支持 ${runtimeKind} 运行类型。`, 409)
    }
    return provider
  }

  async shutdown(): Promise<void> {
    await Promise.allSettled([...this.providers.values()].map(provider => provider.shutdown?.()))
  }
}

export const providerRegistry = new ProviderRegistry([
  new NativePhpProvider(),
  new NativeProcessProvider('native-node'),
  new NativeProcessProvider('native-java'),
  new NativeProcessProvider('native-python'),
  new QemuVmProvider(),
])
