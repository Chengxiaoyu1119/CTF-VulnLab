import { spawn, type ChildProcess } from 'node:child_process'
import { cp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { createServer, type AddressInfo } from 'node:net'
import { basename, join, resolve, sep } from 'node:path'
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

export interface ProviderStartInput {
  instanceId: string
  lab: Lab
  publicOrigin: string
  proxyEndpoint?: string
  lifetimeMinutes: number
  dataDir: string
  runtime: NativeRuntimeConfig
  phpAutoPrependFile?: string
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

type DatabaseLabProfile = 'dvwa' | 'pikachu' | 'sqli-labs' | 'mutillidae' | 'xvwa'

const databaseProfile = (lab: Lab): DatabaseLabProfile | null => {
  if (lab.slug === 'dvwa') return 'dvwa'
  if (lab.slug === 'pikachu') return 'pikachu'
  if (lab.slug === 'sqli-labs') return 'sqli-labs'
  if (lab.slug === 'mutillidae') return 'mutillidae'
  if (lab.slug === 'xvwa') return 'xvwa'
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

const configureXvwa = async (root: string) => {
  const configPath = join(root, 'config.php')
  const setupPath = join(root, 'setup', 'home.php')
  const uploadRoot = join(root, 'img', 'uploads')
  if (!(await stat(configPath).catch(() => null))?.isFile() || !(await stat(setupPath).catch(() => null))?.isFile()) {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'XVWA 缺少 config.php 或数据库初始化文件。', 409)
  }
  const config = [
    '<?php',
    "$XVWA_WEBROOT = '';",
    "$host = getenv('DB_SERVER') ?: '127.0.0.1';",
    "$port = (int)(getenv('DB_PORT') ?: 3306);",
    "$dbname = getenv('DB_DATABASE') ?: 'vulnlab';",
    "$user = getenv('DB_USER') ?: 'vulnlab';",
    "$pass = getenv('DB_PASSWORD') ?: '';",
    '$conn = new mysqli($host, $user, $pass, $dbname, $port);',
    '$conn1 = new PDO("mysql:host=" . $host . ";port=" . $port . ";dbname=" . $dbname, $user, $pass);',
    '$conn1->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);',
    '?>',
    '',
  ].join('\n')
  await writeFile(configPath, config, 'utf8')

  let setup = await readFile(setupPath, 'utf8')
  setup = setup.replace("$sql = 'DROP TABLE '. $tables[$i].';';", "$sql = 'DROP TABLE IF EXISTS '. $tables[$i].';';")
  setup = setup.replaceAll('mysql_error()', 'mysqli_error($conn)')
  if (/DROP TABLE(?! IF EXISTS)/i.test(setup) || /mysql_error\s*\(/i.test(setup)) {
    throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'XVWA 初始化脚本仍包含不兼容的数据库语句。', 409)
  }
  await writeFile(setupPath, setup, 'utf8')
  await mkdir(uploadRoot, { recursive: true })
}

const configureUploadLabs = async (root: string, appUrlRoot: string) => {
  const configPath = join(root, 'config.php')
  let contents = await readFile(configPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'Upload-Labs 缺少 config.php 配置文件。', 409)
  })
  const pattern = /^\s*define\(\s*["']APP_URL_ROOT["']\s*,.*$/mi
  if (!pattern.test(contents)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Upload-Labs 配置缺少 APP_URL_ROOT 定义。', 409)
  if (!/^\/?(?:lab-runtime\/[A-Za-z0-9-]+)?$/.test(appUrlRoot)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Upload-Labs 运行入口路径无效。', 409)
  contents = contents.replace(pattern, `define("APP_URL_ROOT",${JSON.stringify(appUrlRoot)});`)
  await writeFile(configPath, contents, 'utf8')
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
      const sourceRoot = profile === 'xvwa' ? join(bootstrapRoot, 'xvwa') : bootstrapRoot
      await cp(resolve(input.lab.localPath as string), sourceRoot, { recursive: true, force: true })
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
      if (profile === 'xvwa') await configureXvwa(sourceRoot)
      const phpInput = profile === 'sqli-labs'
        ? { ...input, phpAutoPrependFile: await configureSqliLabs(bootstrapRoot) }
        : input
      const documentRoot = profile === 'xvwa' ? bootstrapRoot : mutillidaeRoot ?? bootstrapRoot
      processInfo = await this.startPhpProcess(documentRoot, phpInput, this.databaseEnvironment(profile, resource))
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
      } else if (profile === 'xvwa') {
        const result = await fetch(this.runtimeUrl(input, processInfo.port, '/xvwa/setup/?action=do'))
        const resultHtml = await result.text()
        if (!result.ok || !/Setup finished/i.test(resultHtml) || /Connection Failed|Failed to use\/select database/i.test(resultHtml)) {
          throw new ProviderError('NATIVE_PHP_DB_INIT_FAILED', 'XVWA 数据库初始化没有完成。', 503)
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
    const sourceTarget = profile === 'xvwa' ? join(runtimeRoot, 'xvwa') : runtimeRoot
    let processInfo: { child: ChildProcess; port: number } | null = null
    let database: MySqlResource | null = null
    try {
      await mkdir(resolve(dataRoot, 'runtime'), { recursive: true })
      if (profile) {
        if (!input.runtime.mysql) throw new ProviderError('NATIVE_PHP_MYSQL_NOT_CONFIGURED', 'PHP 数据库靶场运行需要配置 MySQL 管理账号。', 409)
        database = await this.mysqlManager.provision({ labSlug: input.lab.slug, instanceId: input.instanceId, config: input.runtime.mysql })
        await this.initializeDatabase(profile, input, runtimeRoot, database)
      }
      await cp(sourcePath, sourceTarget, { recursive: true, force: true })
      if (profile === 'dvwa') await configureDvwa(sourceTarget)
      if (profile === 'pikachu') await configurePikachu(sourceTarget)
      const mutillidaeRoot = profile === 'mutillidae' ? await configureMutillidae(runtimeRoot) : null
      if (profile === 'xvwa') await configureXvwa(sourceTarget)
      if (input.lab.slug === 'upload-labs') {
        const appUrlRoot = input.proxyEndpoint ? new URL(input.proxyEndpoint).pathname.replace(/\/$/, '') : ''
        await configureUploadLabs(sourceTarget, appUrlRoot)
      }
      const runtimeInput = profile === 'sqli-labs'
        ? { ...input, phpAutoPrependFile: await configureSqliLabs(sourceTarget) }
        : input
      const documentRoot = profile === 'xvwa' ? runtimeRoot : mutillidaeRoot ?? runtimeRoot
      processInfo = await this.startPhpProcess(documentRoot, runtimeInput, profile && database ? this.databaseEnvironment(profile, database) : {})
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
      const endpointSuffix = profile === 'xvwa' ? 'xvwa/' : ''
      return {
        ...timestamps,
        endpoint: `${input.proxyEndpoint ?? `${runtimeOrigin(input.publicOrigin, processInfo.port, input.runtime.publicOriginTemplate)}/`}${endpointSuffix}`,
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
])
