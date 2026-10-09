import { spawn, type ChildProcess } from 'node:child_process'
import { copyFile, cp, lstat, mkdir, readFile, readdir, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { createHash, randomBytes } from 'node:crypto'
import { createConnection, createServer, type AddressInfo, isIP } from 'node:net'
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http'
import { basename, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { dirname, parse as parseUrlPath } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createPool, type Pool } from 'mysql2/promise'
import { CliMySqlManager, mysqlRuntimeConfigFromEnv, type MySqlManager, type MySqlResource, type MySqlRuntimeConfig } from './mysql.js'
import { RpcPeer } from '../labs/oa-vuln-labs/ipc.js'
import { adaptOaSeed } from '../labs/oa-vuln-labs/seed.js'
import { OA_LAUNCHER_SHA256, probeOaAppContainer } from '../labs/oa-vuln-labs/sandbox.js'
import { inspectOaDockerAsset, oaDockerAssetPath, unpackOaDockerAsset } from '../labs/oa-vuln-labs/docker-assets.js'
import { inspectOaDockerRuntime, localDockerEnvironment, runDockerCommand, type DockerCommandResult } from '../labs/oa-vuln-labs/docker-runtime.js'
import { dataPaths } from '../paths.js'
import type { Lab, LabInstance, RuntimeKind } from '../types.js'

const moduleDir = dirname(fileURLToPath(import.meta.url))
const rootCandidate = resolve(moduleDir, '..')
const appDir = basename(rootCandidate) === 'dist' ? resolve(rootCandidate, '..') : rootCandidate

export interface NativeRuntimeConfig {
  bindHost: string
  portStart: number
  portEnd: number
  publicOriginTemplate?: string
  phpBinary: string
  phpIni?: string
  nodeBinary: string
  oaNodeBinary?: string
  javaBinary: string
  pythonBinary: string
  mysql?: MySqlRuntimeConfig
  mysqlManaged?: boolean
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
  recoverPending?(dataDir: string, activeInstanceIds: ReadonlySet<string>): Promise<string[]>
  shutdown?(): Promise<void>
}

export interface ProviderRecoverInput {
  lab: Lab
  instance: LabInstance
  runtime?: NativeRuntimeConfig
  dataDir?: string
}

export const oaDockerProjectName = (instanceId: string) => `vulnlab-oa-${createHash('sha256').update(instanceId).digest('hex').slice(0, 24)}`

const oaDockerIngressDockerfile = [
  'FROM alpine:3.20',
  'RUN apk add --no-cache ca-certificates curl socat tzdata',
  'USER 65532:65532',
  'EXPOSE 9090',
  'ENTRYPOINT ["socat", "TCP-LISTEN:9090,fork,reuseaddr", "TCP:web:9090"]',
  '',
].join('\n')

const oaDockerMysqlDockerfile = [
  'FROM mysql:8.0',
  'COPY init.sql /docker-entrypoint-initdb.d/01-init.sql',
  '',
].join('\n')

export const createOaDockerComposeConfig = (input: {
  projectName: string
  buildContext: string
  mysqlContext: string
  ingressContext: string
  port: number
  databasePassword: string
  redisPassword: string
  jwtSecret: string
  instanceId: string
}) => ({
  name: input.projectName,
  services: {
    ingress: {
      build: { context: input.ingressContext, dockerfile: 'Dockerfile' },
      image: 'vulnlab/oa-ingress:1.0.0-beta',
      restart: 'no',
      security_opt: ['no-new-privileges:true'],
      cap_drop: ['ALL'],
      pids_limit: 64,
      read_only: true,
      user: '65532:65532',
      tmpfs: ['/tmp:rw,noexec,nosuid,size=8m'],
      ports: [{ target: 9090, published: String(input.port), host_ip: '127.0.0.1', protocol: 'tcp' }],
      depends_on: { web: { condition: 'service_healthy' } },
      networks: ['oa-internal', 'oa-ingress'],
      labels: { 'com.vulnlab.instance': input.instanceId },
    },
    mysql: {
      build: { context: input.mysqlContext, dockerfile: 'Dockerfile' },
      image: 'vulnlab/oa-mysql:1.0.0-beta',
      restart: 'no',
      security_opt: ['no-new-privileges:true'],
      pids_limit: 256,
      environment: {
        TZ: 'Asia/Shanghai',
        MYSQL_ROOT_PASSWORD: input.databasePassword,
        MYSQL_DATABASE: 'oa_system',
        MYSQL_ROOT_HOST: '%',
      },
      command: [
        '--character-set-server=utf8mb4',
        '--collation-server=utf8mb4_unicode_ci',
        '--skip-character-set-client-handshake',
        '--default-authentication-plugin=mysql_native_password',
      ],
      volumes: [{ type: 'volume', source: 'mysql-data', target: '/var/lib/mysql' }],
      healthcheck: {
        test: ['CMD-SHELL', 'mysqladmin ping -h 127.0.0.1 -uroot -p"$${MYSQL_ROOT_PASSWORD}" --silent'],
        interval: '5s', timeout: '5s', retries: 30, start_period: '40s',
      },
      networks: ['oa-internal'],
      labels: { 'com.vulnlab.instance': input.instanceId },
    },
    redis: {
      image: 'redis:7-alpine',
      restart: 'no',
      security_opt: ['no-new-privileges:true'],
      pids_limit: 128,
      command: ['redis-server', '--requirepass', input.redisPassword, '--appendonly', 'yes'],
      environment: { TZ: 'Asia/Shanghai', REDIS_PASSWORD: input.redisPassword },
      volumes: [{ type: 'volume', source: 'redis-data', target: '/data' }],
      healthcheck: {
        test: ['CMD-SHELL', 'redis-cli --no-auth-warning -a "$${REDIS_PASSWORD}" ping | grep -q PONG'],
        interval: '5s', timeout: '3s', retries: 20, start_period: '10s',
      },
      networks: ['oa-internal'],
      labels: { 'com.vulnlab.instance': input.instanceId },
    },
    web: {
      platform: 'linux/amd64',
      build: { context: input.buildContext, dockerfile: 'Dockerfile' },
      image: 'vulnlab/oa-system:1.0.0-beta',
      restart: 'no',
      security_opt: ['no-new-privileges:true'],
      cap_drop: ['ALL'],
      pids_limit: 128,
      read_only: true,
      environment: {
        TZ: 'Asia/Shanghai',
        DB_HOST: 'mysql', DB_PORT: '3306', DB_USER: 'root', DB_PASSWORD: input.databasePassword, DB_NAME: 'oa_system',
        REDIS_HOST: 'redis', REDIS_PORT: '6379', REDIS_PASSWORD: input.redisPassword,
        JWT_SECRET: input.jwtSecret, SERVER_PORT: '9090', UPLOAD_PATH: './uploads',
      },
      volumes: [{ type: 'volume', source: 'uploads-data', target: '/app/backend/uploads' }],
      tmpfs: ['/tmp:rw,noexec,nosuid,size=16m'],
      depends_on: {
        mysql: { condition: 'service_healthy' },
        redis: { condition: 'service_healthy' },
      },
      healthcheck: { test: ['CMD', 'curl', '-fsS', 'http://127.0.0.1:9090/'], interval: '10s', timeout: '5s', retries: 12, start_period: '20s' },
      networks: ['oa-internal'],
      labels: { 'com.vulnlab.instance': input.instanceId },
    },
  },
  networks: { 'oa-internal': { driver: 'bridge', internal: true }, 'oa-ingress': { driver: 'bridge' } },
  volumes: { 'mysql-data': {}, 'redis-data': {}, 'uploads-data': {} },
})

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

const lease = (lifetimeMinutes: number, baseTime = Date.now()) => {
  if (!Number.isFinite(lifetimeMinutes) || lifetimeMinutes <= 0) {
    throw new ProviderError('PROVIDER_LIFETIME_INVALID', '运行实例时长必须是正数。', 400)
  }
  const createdAt = new Date(baseTime)
  return {
    createdAt: createdAt.toISOString(),
    expiresAt: new Date(createdAt.getTime() + lifetimeMinutes * 60_000).toISOString(),
  }
}

const renewalLease = (instance: LabInstance, lifetimeMinutes: number) => {
  const now = Date.now()
  const currentExpiry = Date.parse(instance.expiresAt)
  const baseTime = Number.isFinite(currentExpiry) ? Math.max(now, currentExpiry) : now
  return lease(lifetimeMinutes, baseTime)
}

type SpawnFunction = typeof spawn
type PortAllocator = (host: string, start: number, end: number) => Promise<number>

const runtimeEnvironment = (cwd: string, overrides: Record<string, string | undefined> = {}) => {
  const environment: Record<string, string> = {}
  for (const key of ['Path', 'PATH', 'PATHEXT', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'ComSpec', 'COMSPEC']) {
    const value = process.env[key]
    if (value) environment[key] = value
  }
  environment.TEMP = cwd
  environment.TMP = cwd
  environment.HOME = cwd
  environment.USERPROFILE = cwd
  for (const [key, value] of Object.entries(overrides)) if (value !== undefined) environment[key] = value
  return environment
}

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

const stopChildGracefully = async (child: ChildProcess, timeoutMs = 5_000) => {
  if (child.exitCode !== null && child.exitCode !== undefined) return
  const exited = new Promise<void>(resolveExit => child.once('exit', () => resolveExit()))
  child.stdin?.end()
  const graceful = await Promise.race([exited.then(() => true), sleep(timeoutMs).then(() => false)])
  if (graceful) return
  try { child.kill() } catch { return }
  await Promise.race([exited, sleep(2_000)])
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
  const killProcessTree = () => new Promise<void>(resolveTerminate => {
    const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true })
    killer.once('error', () => resolveTerminate())
    killer.once('exit', () => resolveTerminate())
  })
  await killProcessTree()
  const deadline = Date.now() + 3_000
  while (Date.now() < deadline && processAlive(pid)) await sleep(80)
  if (processAlive(pid)) await killProcessTree()
}

const removeTree = async (root: string) => {
  await rm(root, { recursive: true, force: true, maxRetries: 6, retryDelay: 150 }).catch(() => undefined)
}

type DatabaseLabProfile = 'dvwa' | 'pikachu' | 'sqli-labs' | 'mutillidae' | 'xvwa' | 'custom-mysql'

const databaseProfile = (lab: Lab): DatabaseLabProfile | null => {
  if (lab.runtimeConfig?.profile === 'mysql-php') return 'custom-mysql'
  if (lab.slug === 'dvwa') return 'dvwa'
  if (lab.slug === 'pikachu') return 'pikachu'
  if (lab.slug === 'sqli-labs') return 'sqli-labs'
  if (lab.slug === 'mutillidae') return 'mutillidae'
  if (lab.slug === 'xvwa') return 'xvwa'
  return null
}

const projectPath = (root: string, relativePath: string, label: string) => {
  const normalized = relativePath.replaceAll('\\', '/')
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized) || normalized.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new ProviderError('NATIVE_PHP_RUNTIME_CONFIG_INVALID', `${label} 必须是项目内的相对路径。`, 409)
  }
  const target = resolve(root, normalized)
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`
  if (!target.startsWith(prefix)) throw new ProviderError('NATIVE_PHP_RUNTIME_CONFIG_INVALID', `${label} 超出靶场目录。`, 409)
  return target
}

const entryUrlPath = (relativePath: string) => relativePath
  .replaceAll('\\', '/')
  .split('/')
  .map(segment => encodeURIComponent(segment))
  .join('/')

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
  const configuredConnection = /mysqli_connect\(\s*(?:\$dbhost|DBHOST)\s*,\s*(?:\$dbuser|DBUSER)\s*,\s*(?:\$dbpw|DBPW)\s*,\s*DBNAME\s*,\s*DBPORT\s*\)/i.test(contents)
  if (contents === before && !configuredConnection) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'Pikachu 初始化入口不包含可识别的 MySQL 连接代码。', 409)
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
  const handlerPath = join(sourceRoot, 'classes', 'MySQLHandler.php')
  const setupPath = join(sourceRoot, 'set-up-database.php')
  if (!(await stat(configPath).catch(() => null))?.isFile() || !(await stat(handlerPath).catch(() => null))?.isFile() || !(await stat(setupPath).catch(() => null))?.isFile()) {
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
  let handler = await readFile(handlerPath, 'utf8')
  handler = handler.replace(/new mysqli\((\$HOSTNAME|self::\$MUTILLIDAE_DOCKER_HOSTNAME), \$USERNAME, ([^,)]+)\)/g, 'new mysqli($1, $USERNAME, $2, NULL, self::$mMySQLDatabasePort)')
  await writeFile(handlerPath, handler, 'utf8')
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

const configureXvwa = async (root: string, appUrlRoot = '') => {
  const configPath = join(root, 'config.php')
  const setupPath = join(root, 'setup', 'home.php')
  const uploadRoot = join(root, 'img', 'uploads')
  if (appUrlRoot && !/^\/lab-runtime\/[A-Za-z0-9-]+$/.test(appUrlRoot)) {
    throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'XVWA 运行入口路径无效。', 409)
  }
  if (!(await stat(configPath).catch(() => null))?.isFile() || !(await stat(setupPath).catch(() => null))?.isFile()) {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'XVWA 缺少 config.php 或数据库初始化文件。', 409)
  }
  const config = [
    '<?php',
    `$XVWA_WEBROOT = ${JSON.stringify(appUrlRoot)};`,
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
  setup = setup.replaceAll('/xvwa/', `${appUrlRoot}/xvwa/`)
  if (/DROP TABLE(?! IF EXISTS)/i.test(setup) || /mysql_error\s*\(/i.test(setup)) {
    throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'XVWA 初始化脚本仍包含不兼容的数据库语句。', 409)
  }
  await writeFile(setupPath, setup, 'utf8')

  for (const relativePath of ['header.php', 'sidepanel.php', 'login.php', 'logout.php', join('vulnerabilities', 'index.php')]) {
    const path = join(root, relativePath)
    const contents = await readFile(path, 'utf8').catch(() => null)
    if (contents === null) continue
    const rewritten = contents.split('\n').map(line => line.includes('$XVWA_WEBROOT') ? line : line.replaceAll('/xvwa/', `${appUrlRoot}/xvwa/`)).join('\n')
    await writeFile(path, rewritten, 'utf8')
  }

  const uploadPath = join(root, 'vulnerabilities', 'fileupload', 'home.php')
  const upload = await readFile(uploadPath, 'utf8').catch(() => null)
  if (upload !== null) {
    await writeFile(uploadPath, upload.replaceAll("$rpath = '/xvwa/", `$rpath = '${appUrlRoot}/xvwa/`), 'utf8')
  }
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

const configureXssLabs = async (root: string) => {
  const levelPath = join(root, 'level14.php')
  let contents = await readFile(levelPath, 'utf8').catch(() => {
    throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', 'XSS-Labs 缺少 level14.php 关卡文件。', 409)
  })
  if (!contents.includes('http://www.exifviewer.org/') || !contents.includes('/xss/level15.php')) {
    throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', 'XSS-Labs 第 14 关入口与固定版本不匹配。', 409)
  }
  contents = contents.replace('http://www.exifviewer.org/', 'about:blank').replace('/xss/level15.php', 'level15.php')
  await writeFile(levelPath, contents, 'utf8')

  for (const [level, swf] of [[17, 'xsf01.swf'], [18, 'xsf02.swf'], [19, 'xsf03.swf'], [20, 'xsf04.swf']] as const) {
    const path = join(root, `level${level}.php`)
    let html = await readFile(path, 'utf8').catch(() => {
      throw new ProviderError('NATIVE_PHP_CONFIG_NOT_FOUND', `XSS-Labs 缺少 level${level}.php 关卡文件。`, 409)
    })
    if (!html.includes(swf) || !/<embed\b/i.test(html)) {
      throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', `XSS-Labs 第 ${level} 关与固定版本不匹配。`, 409)
    }
    if (!html.includes('ruffle/ruffle.js')) {
      if (!/<\/head>/i.test(html)) throw new ProviderError('NATIVE_PHP_CONFIG_INVALID', `XSS-Labs 第 ${level} 关缺少 head 节点。`, 409)
      html = html.replace(/<\/head>/i, '  <script src="ruffle/ruffle.js"></script>\n</head>')
      await writeFile(path, html, 'utf8')
    }
  }
  await cp(join(appDir, 'public', 'ruffle'), join(root, 'ruffle'), { recursive: true, force: true })
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
        env: runtimeEnvironment(root, environment),
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

  private async initializeDatabase(profile: DatabaseLabProfile, input: ProviderStartInput, root: string, resource: MySqlResource, appUrlRoot: string) {
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
      if (profile === 'xvwa') await configureXvwa(sourceRoot, appUrlRoot)
      if (profile === 'custom-mysql') {
        const initPath = projectPath(bootstrapRoot, input.lab.runtimeConfig?.initSqlPath || 'init.sql', 'MySQL 初始化 SQL')
        const sql = await readFile(initPath, 'utf8').catch(() => {
          throw new ProviderError('NATIVE_PHP_DB_INIT_SQL_NOT_FOUND', '自定义 PHP+MySQL 初始化 SQL 不存在。', 409)
        })
        if (!this.mysqlManager.initializeSql) throw new ProviderError('NATIVE_PHP_DB_INIT_UNSUPPORTED', '当前 MySQL Provider 不支持初始化 SQL。', 503)
        await this.mysqlManager.initializeSql(resource, sql)
        await this.mysqlManager.verify(resource)
        return
      }
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

    const paths = dataPaths(input.dataDir)
    const dataRoot = paths.root
    const sourcePath = resolve(sourceRoot)
    const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
    if (sourcePath !== dataRoot && !sourcePath.startsWith(dataPrefix)) throw new ProviderError('NATIVE_PHP_SOURCE_OUTSIDE_DATA', '靶场目录必须位于 VulnLab 数据目录内。', 409)
    const runtimeRoot = paths.runtimeInstance(input.instanceId)
    const profile = databaseProfile(input.lab)
    const sourceTarget = profile === 'xvwa' ? join(runtimeRoot, 'xvwa') : runtimeRoot
    const appUrlRoot = input.proxyEndpoint ? new URL(input.proxyEndpoint).pathname.replace(/\/$/, '') : ''
    let processInfo: { child: ChildProcess; port: number } | null = null
    let database: MySqlResource | null = null
    try {
      await mkdir(paths.runtime, { recursive: true })
      if (profile) {
        if (!input.runtime.mysql) throw new ProviderError('NATIVE_PHP_MYSQL_NOT_CONFIGURED', 'PHP 数据库靶场运行需要配置 MySQL 管理账号。', 409)
        database = await this.mysqlManager.provision({ labSlug: input.lab.slug, instanceId: input.instanceId, config: input.runtime.mysql })
        await this.initializeDatabase(profile, input, runtimeRoot, database, appUrlRoot)
      }
      await cp(sourcePath, sourceTarget, { recursive: true, force: true })
      if (profile === 'dvwa') await configureDvwa(sourceTarget)
      if (profile === 'pikachu') await configurePikachu(sourceTarget)
      const mutillidaeRoot = profile === 'mutillidae' ? await configureMutillidae(runtimeRoot) : null
      if (profile === 'xvwa') await configureXvwa(sourceTarget, appUrlRoot)
      if (input.lab.slug === 'upload-labs') {
        await configureUploadLabs(sourceTarget, appUrlRoot)
      }
      if (input.lab.slug === 'xss-labs') await configureXssLabs(sourceTarget)
      const runtimeInput = profile === 'sqli-labs'
        ? { ...input, phpAutoPrependFile: await configureSqliLabs(sourceTarget) }
        : input
      const customRoot = ['static-php', 'mysql-php'].includes(input.lab.runtimeConfig?.profile ?? '') && input.lab.runtimeConfig?.documentRoot
        ? projectPath(runtimeRoot, input.lab.runtimeConfig.documentRoot, 'PHP 文档根目录')
        : null
      const customPhp = ['static-php', 'mysql-php'].includes(input.lab.runtimeConfig?.profile ?? '')
      const configuredEntry = input.lab.runtimeConfig?.entryPath
      // 内置 PHP 靶场保留 Provider 专属入口；自定义靶场使用声明的入口文件。
      const customEntry = customPhp && (configuredEntry || !input.lab.builtin) ? configuredEntry || 'index.php' : ''
      if (customEntry) {
        const entryRoot = customRoot ?? runtimeRoot
        const entryFile = projectPath(entryRoot, customEntry, 'PHP 入口文件')
        if (!(await stat(entryFile).catch(() => null))?.isFile()) throw new ProviderError('NATIVE_PHP_ENTRY_NOT_FOUND', 'PHP 入口文件不存在。', 409)
      }
      const documentRoot = customRoot ?? (profile === 'xvwa' ? runtimeRoot : mutillidaeRoot ?? runtimeRoot)
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
      const endpointSuffix = profile === 'xvwa'
        ? 'xvwa/'
        : customEntry && customEntry !== 'index.php' ? entryUrlPath(customEntry) : ''
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
    const { expiresAt } = renewalLease(input.instance, input.lifetimeMinutes)
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
      const root = dataPaths(input.dataDir).runtimeInstance(input.instance.id)
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

interface NativeOaRuntime {
  child: ChildProcess
  peer: RpcPeer
  root: string
  port: number
  server: HttpServer
  pool: Pool
  database: MySqlResource
  cache: Map<string, { value: string; expiresAt: number }>
  instanceId: string
  sandbox: OaSandboxState
  cleanup?: Promise<void>
}

interface OaSandboxState {
  profile: string
  launcherPath: string
  runtimeRoot: string
  uploadRoot: string
  nodePath: string
  entryPath: string
  moduleRoot: string
}

export interface NativeOaProviderOptions {
  spawnImpl?: SpawnFunction
  allocatePort?: PortAllocator
  mysqlManager?: MySqlManager
}

const closeHttpServer = (server: HttpServer) => new Promise<void>(resolveClose => {
  if (!server.listening) return resolveClose()
  server.close(() => resolveClose())
})

const collectHttpBody = async (request: import('node:http').IncomingMessage, limit: number) => {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += bytes.byteLength
    if (size > limit) throw new ProviderError('NATIVE_OA_REQUEST_TOO_LARGE', 'OA 请求超过 32 MiB 上限。', 413)
    chunks.push(bytes)
  }
  return Buffer.concat(chunks, size)
}

const isLoopbackHost = (host: string) => {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, '')
  return normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1'
}

const configureOaFrontendSecrets = async (root: string, jwtSecret: string, inviteCode: string) => {
  const entries = await readdir(root, { withFileTypes: true })
  for (const entry of entries) {
    const path = join(root, entry.name)
    if (entry.isDirectory()) await configureOaFrontendSecrets(path, jwtSecret, inviteCode)
    else if (entry.isFile() && entry.name.endsWith('.js')) {
      const source = await readFile(path, 'utf8')
      const configured = source.replaceAll('oa2025-secret', jwtSecret).replaceAll('oa-admin-2025', inviteCode)
      if (configured !== source) await writeFile(path, configured, 'utf8')
    }
  }
}

export class NativeOaProvider implements LabProvider {
  readonly id = 'oa-local'
  readonly supportedRuntimeKinds: readonly RuntimeKind[] = ['native-oa']
  private readonly spawnImpl: SpawnFunction
  private readonly allocatePortImpl: PortAllocator
  private readonly mysqlManager: MySqlManager
  private readonly runtimes = new Map<string, NativeOaRuntime>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(options: NativeOaProviderOptions = {}) {
    this.spawnImpl = options.spawnImpl ?? spawn
    this.allocatePortImpl = options.allocatePort ?? allocatePort
    this.mysqlManager = options.mysqlManager ?? new CliMySqlManager()
  }

  private sandboxProfile(instanceId: string) {
    return `VulnLab.OA.${createHash('sha256').update(instanceId).digest('hex').slice(0, 32)}`
  }

  private async projectLauncherPath() {
    if (process.platform !== 'win32') throw new ProviderError('NATIVE_OA_SANDBOX_UNAVAILABLE', 'OA 靶场需要 Windows AppContainer 操作系统隔离。', 409)
    const launcherRoot = resolve(appDir, 'assets', 'labs', 'oa-vuln-labs', 'native')
    const launcherPath = await realpath(join(launcherRoot, 'appcontainer-launcher-sandbox.exe')).catch(() => '')
    const relativeLauncher = launcherPath ? relative(launcherRoot.toLowerCase(), launcherPath.toLowerCase()) : ''
    if (!launcherPath || relativeLauncher === '..' || relativeLauncher.startsWith(`..${sep}`) || isAbsolute(relativeLauncher)) {
      throw new ProviderError('NATIVE_OA_LAUNCHER_NOT_PROJECT_MANAGED', '项目内 OA AppContainer 启动器未准备。', 409)
    }
    const launcherHash = createHash('sha256').update(await readFile(launcherPath)).digest('hex')
    if (launcherHash !== OA_LAUNCHER_SHA256) throw new ProviderError('NATIVE_OA_LAUNCHER_HASH_MISMATCH', '项目内 OA AppContainer 启动器校验失败。', 409)
    return { appDir, launcherPath }
  }

  private async verifyOaInstallPaths(dataDir: string, instancePaths: string[], appPaths: string[], nodePath: string) {
    const dataRoot = await realpath(dataDir)
    const appRoot = await realpath(appDir)
    const nodeRoot = await realpath(resolve(dataDir, 'runtime', 'toolchains', 'node'))
    const groups: Array<{ paths: string[]; root: string }> = [
      { paths: instancePaths, root: dataRoot },
      { paths: appPaths, root: appRoot },
      { paths: [nodePath], root: nodeRoot },
    ]
    for (const { paths, root } of groups) {
      for (const path of paths) {
        const normalized = await realpath(path)
        const relativePath = relative(root.toLowerCase(), normalized.toLowerCase())
        if (relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
          throw new ProviderError('NATIVE_OA_SANDBOX_PATH_UNTRUSTED', `OA AppContainer 路径越出受信任目录：${path}`, 409)
        }
        let current = resolve(path)
        while (true) {
          if ((await lstat(current)).isSymbolicLink()) throw new ProviderError('NATIVE_OA_SANDBOX_REPARSE_PATH', `OA AppContainer 路径包含符号链接：${current}`, 409)
          const parent = dirname(current)
          if (parent === current) break
          current = parent
        }
      }
    }
  }

  private async sandboxForInstance(input: ProviderStartInput, root: string, nodePath: string): Promise<OaSandboxState> {
    const uploadRoot = join(root, 'uploads')
    const sandbox: OaSandboxState = {
      profile: this.sandboxProfile(input.instanceId),
      launcherPath: '',
      runtimeRoot: root,
      uploadRoot,
      nodePath,
      entryPath: join(appDir, 'dist', 'labs', 'oa-vuln-labs', 'api-child.js'),
      moduleRoot: join(appDir, 'node_modules'),
    }
    await mkdir(uploadRoot, { recursive: true })
    await this.verifyOaInstallPaths(input.dataDir, [root, uploadRoot], [sandbox.entryPath, sandbox.moduleRoot], nodePath)
    return sandbox
  }

  private async sandboxForRecovery(dataDir: string, instanceId: string, root: string, saved: unknown): Promise<OaSandboxState | null> {
    if (!saved || typeof saved !== 'object') return null
    const stored = saved as Partial<OaSandboxState>
    const profile = this.sandboxProfile(instanceId)
    if (stored.profile !== profile || typeof stored.nodePath !== 'string') return null
    const nodePath = await this.validateProjectNodePath(dataDir, stored.nodePath)
    const { appDir, launcherPath } = await this.projectLauncherPath()
    const sandbox: OaSandboxState = {
      profile,
      launcherPath,
      runtimeRoot: root,
      uploadRoot: join(root, 'uploads'),
      nodePath,
      entryPath: join(appDir, 'dist', 'labs', 'oa-vuln-labs', 'api-child.js'),
      moduleRoot: join(appDir, 'node_modules'),
    }
    await this.verifyOaInstallPaths(dataDir, [sandbox.runtimeRoot, sandbox.uploadRoot], [sandbox.entryPath, sandbox.moduleRoot], nodePath)
    return sandbox
  }

  private async runSandboxCleanup(sandbox: OaSandboxState) {
    const cwd = await stat(sandbox.runtimeRoot).then(() => sandbox.runtimeRoot, () => dirname(sandbox.launcherPath))
    const args = ['cleanup', sandbox.profile, sandbox.runtimeRoot, sandbox.uploadRoot, sandbox.nodePath, sandbox.entryPath, sandbox.moduleRoot]
    const child = this.spawnImpl(sandbox.launcherPath, args, {
      cwd,
      env: runtimeEnvironment(cwd),
      stdio: 'ignore',
      windowsHide: true,
      shell: false,
    })
    const result = await new Promise<{ code: number | null }>((resolveExit, rejectExit) => {
      const timer = setTimeout(() => {
        try { child.kill() } catch { /* the launcher may already have exited */ }
        rejectExit(new ProviderError('NATIVE_OA_SANDBOX_CLEANUP_TIMEOUT', 'OA AppContainer 清理超时。', 503))
      }, 120_000)
      child.once('error', error => { clearTimeout(timer); rejectExit(error) })
      child.once('exit', code => { clearTimeout(timer); resolveExit({ code }) })
    })
    if (result.code !== 0) throw new ProviderError('NATIVE_OA_SANDBOX_CLEANUP_FAILED', `OA AppContainer 清理失败（${result.code}）。`, 503)
  }

  private async claimPort(config: NativeRuntimeConfig, host = config.bindHost) {
    let release!: () => void
    const turn = new Promise<void>(resolveTurn => { release = resolveTurn })
    const previous = this.portAllocation
    this.portAllocation = previous.then(() => turn)
    await previous
    try {
      for (let attempt = 0; attempt <= config.portEnd - config.portStart; attempt += 1) {
        const port = await this.allocatePortImpl(host, config.portStart, config.portEnd)
        if (!this.reservedPorts.has(port)) {
          this.reservedPorts.add(port)
          return port
        }
      }
      throw new ProviderError('NATIVE_OA_PORT_EXHAUSTED', 'OA 靶场运行端口已用尽。', 409)
    } finally {
      release()
    }
  }

  private async mysqlQuery(pool: Pool, payload: unknown) {
    const input = payload as { statement?: unknown; values?: unknown }
    if (typeof input?.statement !== 'string' || input.statement.length > 2 * 1024 * 1024 || !Array.isArray(input.values) || input.values.length > 500 || Buffer.byteLength(JSON.stringify(input.values)) > 4 * 1024 * 1024) {
      throw new Error('MySQL 请求格式无效。')
    }
    const [result] = await pool.query({ sql: input.statement, timeout: 10_000 }, input.values as any[])
    if (Array.isArray(result)) return { rows: result, affectedRows: 0, insertId: 0 }
    const header = result as { affectedRows?: number; insertId?: number }
    return { rows: [], affectedRows: header.affectedRows ?? 0, insertId: header.insertId ?? 0 }
  }

  private redisCommand(cache: Map<string, { value: string; expiresAt: number }>, payload: unknown) {
    const input = payload as { args?: unknown }
    if (!Array.isArray(input?.args) || input.args.length < 2 || input.args.length > 5 || !input.args.every(value => typeof value === 'string')) throw new Error('Redis 请求格式无效。')
    const args = input.args as string[]
    const command = args[0]?.toUpperCase()
    if ((args[1] as string).length > 256) throw new Error('OA 项目内缓存键超过 256 个字符。')
    if (command === 'GET' && args.length === 2) {
      const value = cache.get(args[1] as string)
      if (!value) return null
      if (value.expiresAt <= Date.now()) {
        cache.delete(args[1] as string)
        return null
      }
      return value.value
    } else if (command === 'SET' && args.length === 5 && args[3]?.toUpperCase() === 'EX' && /^\d+$/.test(args[4] ?? '')) {
      if (Buffer.byteLength(args[2] as string) > 4 * 1024) throw new Error('OA 项目内缓存值超过 4 KiB。')
      const ttlSeconds = Math.min(86_400, Number(args[4]))
      for (const [key, value] of cache) if (value.expiresAt <= Date.now()) cache.delete(key)
      if (!cache.has(args[1] as string) && cache.size >= 1_024) throw new Error('OA 项目内缓存实例达到 1,024 个键的上限。')
      cache.set(args[1] as string, { value: args[2] as string, expiresAt: Date.now() + ttlSeconds * 1000 })
      return 'OK'
    } else {
      throw new Error('OA 项目内缓存仅支持 GET 与 SET EX 命令。')
    }
  }

  private async ssrfRequest(payload: unknown, allowedPorts: ReadonlySet<number>) {
    const input = payload as { url?: unknown; method?: unknown; body?: unknown }
    if (typeof input?.url !== 'string' || input.url.length > 2_048) throw new Error('SSRF URL 无效。')
    const method = typeof input.method === 'string' ? input.method.toUpperCase() : 'GET'
    if (!['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method)) throw new Error('SSRF HTTP 方法无效。')
    const body = input.body === undefined ? undefined : typeof input.body === 'string' ? input.body : JSON.stringify(input.body)
    if (body && Buffer.byteLength(body) > 256 * 1024) throw new Error('SSRF 请求体超过 256 KiB。')
    const validateTarget = (value: string, base?: URL) => {
      const url = new URL(value, base)
      const port = Number(url.port || (url.protocol === 'https:' ? '443' : '80'))
      if (url.protocol !== 'http:' || url.username || url.password || !isLoopbackHost(url.hostname) || !allowedPorts.has(port)) {
        throw new Error('SSRF 目标仅允许本实例 Web、数据库和缓存端口。')
      }
      url.hostname = '127.0.0.1'
      url.hash = ''
      return url
    }
    let target = validateTarget(input.url)
    let requestMethod = method
    let requestBody = body
    for (let redirects = 0; redirects <= 5; redirects += 1) {
      const response = await fetch(target, {
        method: requestMethod,
        ...(requestBody !== undefined && !['GET', 'HEAD'].includes(requestMethod) ? { body: requestBody } : {}),
        ...(requestBody !== undefined ? { headers: { 'content-type': 'application/json' } } : {}),
        redirect: 'manual',
        signal: AbortSignal.timeout(8_000),
      })
      const location = response.headers.get('location')
      if (location && [301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel().catch(() => undefined)
        if (redirects === 5) throw new Error('SSRF 重定向次数超过 5 次。')
        target = validateTarget(location, target)
        if ([301, 302, 303].includes(response.status) && requestMethod !== 'HEAD') {
          requestMethod = 'GET'
          requestBody = undefined
        }
        continue
      }
      const reader = response.body?.getReader()
      const chunks: Uint8Array[] = []
      let bytes = 0
      if (reader) {
        while (true) {
          const next = await reader.read()
          if (next.done) break
          bytes += next.value.byteLength
          if (bytes > 1024 * 1024) {
            await reader.cancel()
            break
          }
          chunks.push(next.value)
        }
      }
      return { status: response.status, body: Buffer.concat(chunks).toString('utf8'), headers: Object.fromEntries(response.headers.entries()) }
    }
    throw new Error('SSRF 请求未完成。')
  }

  private async seedDatabase(input: ProviderStartInput, root: string, resource: MySqlResource) {
    if (!this.mysqlManager.initializeSql) throw new ProviderError('NATIVE_OA_DB_INIT_UNSUPPORTED', '当前 MySQL Provider 不支持 OA 初始化 SQL。', 503)
    const sourceSeed = await readFile(join(input.lab.localPath as string, 'database', 'init.sql'), 'utf8')
    const nativeSeedPath = join(input.lab.localPath as string, 'database', 'init.native.sql')
    const sql = await readFile(nativeSeedPath, 'utf8').catch(() => adaptOaSeed(sourceSeed))
    await mkdir(join(root, 'database'), { recursive: true })
    await writeFile(join(root, 'database', 'init.native.sql'), sql, 'utf8')
    await this.mysqlManager.initializeSql(resource, sql)
    await this.mysqlManager.verify(resource)
    const pool = createPool({
      host: resource.host,
      port: resource.port,
      user: resource.user,
      password: resource.password,
      database: resource.database,
      charset: 'utf8mb4',
      waitForConnections: true,
      connectionLimit: 4,
      queueLimit: 32,
      connectTimeout: 10_000,
    })
    try {
      const [users] = await pool.query('SELECT username FROM users ORDER BY id')
      const usernames = (users as Array<{ username: string }>).map(user => user.username)
      const expected = ['admin', 'manager', 'user', 'zhangsan', 'lisi', 'test']
      if (JSON.stringify(usernames) !== JSON.stringify(expected)) throw new ProviderError('NATIVE_OA_DB_SEED_INVALID', 'OA 数据库种子账号校验失败。', 503)
      const [counts] = await pool.query(`SELECT
        (SELECT COUNT(*) FROM departments) AS departments,
        (SELECT COUNT(*) FROM announcements) AS announcements,
        (SELECT COUNT(*) FROM tickets) AS tickets,
        (SELECT COUNT(*) FROM approvals) AS approvals,
        (SELECT COUNT(*) FROM notification_templates) AS templates`)
      const count = (counts as Array<Record<string, unknown>>)[0] ?? {}
      if (['departments', 'announcements', 'tickets', 'approvals', 'templates'].some(key => Number(count[key]) < 1)) {
        throw new ProviderError('NATIVE_OA_DB_SEED_INVALID', 'OA 数据库种子业务数据不完整。', 503)
      }
      return pool
    } catch (error) {
      await pool.end().catch(() => undefined)
      throw error
    }
  }

  private async projectNodeBinary(input: ProviderStartInput) {
    return this.validateProjectNodePath(input.dataDir, input.runtime.oaNodeBinary)
  }

  private async validateProjectNodePath(dataDir: string, binary?: string) {
    const root = await realpath(resolve(dataDir, 'runtime', 'toolchains', 'node')).catch(() => '')
    const candidate = await realpath(binary ?? '').catch(() => '')
    const relativePath = root && candidate ? relative(root.toLowerCase(), candidate.toLowerCase()) : ''
    if (!root || !candidate || basename(candidate).toLowerCase() !== 'node.exe' || relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
      throw new ProviderError('NATIVE_OA_NODE_NOT_PROJECT_MANAGED', 'OA 靶场仅允许使用 VulnLab 项目准备的 Node.js 运行时。', 409)
    }
    return candidate
  }

  private async verifyProjectRuntime(input: ProviderStartInput) {
    const mysql = input.runtime.mysql
    if (!mysql) throw new ProviderError('NATIVE_OA_MYSQL_NOT_CONFIGURED', 'OA 靶场需要项目托管的 MariaDB。', 409)
    if (input.runtime.mysqlManaged !== true) throw new ProviderError('NATIVE_OA_MYSQL_NOT_PROJECT_MANAGED', 'OA 靶场仅允许使用 VulnLab 项目托管的 MariaDB。', 409)
    if (mysql.host !== '127.0.0.1' || mysql.appHost !== '127.0.0.1' || !Number.isInteger(mysql.port) || mysql.port < 1024 || mysql.port > 65535) {
      throw new ProviderError('NATIVE_OA_MYSQL_LOOPBACK_ONLY', 'OA 靶场 MariaDB 必须由项目托管并仅监听 127.0.0.1。', 409)
    }
    const mariaRoot = await realpath(resolve(input.dataDir, 'runtime', 'toolchains', 'mariadb')).catch(() => '')
    const mysqlBinary = await realpath(mysql.mysqlBinary).catch(() => '')
    const relativeMysql = mariaRoot && mysqlBinary ? relative(mariaRoot.toLowerCase(), mysqlBinary.toLowerCase()) : ''
    if (!mariaRoot || !mysqlBinary || !['mariadb.exe', 'mysql.exe'].includes(basename(mysqlBinary).toLowerCase()) || relativeMysql === '..' || relativeMysql.startsWith(`..${sep}`) || isAbsolute(relativeMysql)) {
      throw new ProviderError('NATIVE_OA_MYSQL_BINARY_NOT_PROJECT_MANAGED', 'OA 靶场仅允许使用 VulnLab 项目目录内的 MariaDB 客户端。', 409)
    }
    const nodePath = await this.projectNodeBinary(input)
    return nodePath
  }

  private async launch(input: ProviderStartInput, root: string, port: number, resource: MySqlResource, pool: Pool, projectNodePath: string) {
    const frontendRoot = join(root, 'backend', 'dist')
    const uploadRoot = join(root, 'uploads')
    const tempRoot = join(root, '.tmp')
    const jwtSecret = randomBytes(32).toString('base64url')
    const inviteCode = randomBytes(18).toString('base64url')
    await cp(join(input.lab.localPath as string, 'backend', 'dist'), frontendRoot, { recursive: true, force: true })
    await configureOaFrontendSecrets(frontendRoot, jwtSecret, inviteCode)
    await mkdir(uploadRoot, { recursive: true })
    await mkdir(tempRoot, { recursive: true })
    const cache = new Map<string, { value: string; expiresAt: number }>()
    const state = {
      database_host: '127.0.0.1', database_port: resource.port, database_name: resource.database,
      database_user: resource.user, database_password: resource.password,
      redis_host: 'instance-memory-cache', redis_port: 0, redis_password: '', server_host: '127.0.0.1', server_port: port,
    }
    const sandbox = await this.sandboxForInstance(input, root, projectNodePath)
    const { entryPath, moduleRoot } = sandbox
    await writeFile(join(root, 'vulnlab-runtime.json'), JSON.stringify({ port, provider: this.id, instanceId: input.instanceId, sandbox }), 'utf8')
    const nodeArguments = [
      '--permission', '--max-old-space-size=256', `--import=${pathToFileURL(join(appDir, 'dist', 'labs', 'oa-vuln-labs', 'network-guard.js')).href}`,
      `--allow-fs-read=${root}`, `--allow-fs-read=${dirname(entryPath)}`,
      `--allow-fs-read=${moduleRoot}`, `--allow-fs-write=${uploadRoot}`, `--allow-fs-write=${tempRoot}`,
      entryPath,
    ]
    const child = this.spawnImpl(projectNodePath, nodeArguments, {
      cwd: root,
      env: runtimeEnvironment(root, {
        NODE_ENV: 'production',
        TEMP: tempRoot,
        TMP: tempRoot,
        VULNLAB_OA_FRONTEND_ROOT: frontendRoot,
        VULNLAB_OA_INVITE_CODE: inviteCode,
        VULNLAB_OA_JWT_SECRET: jwtSecret,
        VULNLAB_OA_RUNTIME_ROOT: root,
        VULNLAB_OA_UPLOAD_ROOT: uploadRoot,
      }),
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false,
    })
    try {
      await new Promise<void>((resolveSpawn, rejectSpawn) => {
        child.once('spawn', resolveSpawn)
        child.once('error', rejectSpawn)
        child.once('exit', code => rejectSpawn(new ProviderError('NATIVE_OA_PROCESS_EXITED', `OA 项目 API 子进程提前退出（${code}）。`, 503)))
      })
      await writeFile(join(root, 'vulnlab-runtime.json'), JSON.stringify({ port, provider: this.id, instanceId: input.instanceId, pid: child.pid }), 'utf8')
    } catch (error) {
      await stopChildGracefully(child)
      throw error
    }
    await writeFile(join(root, 'vulnlab-runtime.json'), JSON.stringify({ port, provider: this.id, instanceId: input.instanceId, pid: child.pid, sandbox }), 'utf8')
    if (!child.stdin || !child.stdout) {
      await stopChildGracefully(child)
      throw new ProviderError('NATIVE_OA_IPC_UNAVAILABLE', 'OA 项目 API IPC 流未建立。', 503)
    }
    let stderrTail = ''
    child.stderr?.setEncoding('utf8')
    child.stderr?.on('data', chunk => { stderrTail = `${stderrTail}${String(chunk)}`.slice(-4_000) })
    let signalReady!: () => void
    let rejectReady!: (error: Error) => void
    const ready = new Promise<void>((resolveReady, reject) => { signalReady = resolveReady; rejectReady = reject })
    const peer = new RpcPeer(child.stdout, child.stdin, async (method, payload) => {
      if (method === 'ready') {
        signalReady()
        return { ready: true }
      }
      if (method === 'mysql.query') return this.mysqlQuery(pool, payload)
      if (method === 'redis.command') return this.redisCommand(cache, payload)
      if (method === 'instance.config') return state
      if (method === 'ssrf.request') return this.ssrfRequest(payload, new Set([port]))
      throw new Error(`OA 项目内接口不支持此操作：${method}`)
    })
    child.once('exit', code => rejectReady(new ProviderError('NATIVE_OA_PROCESS_EXITED', `OA 项目 API 子进程退出（${code}）。${stderrTail.replace(/\s+/g, ' ').trim()}`, 503)))
    let readyTimer: NodeJS.Timeout | undefined
    try {
      await Promise.race([
        ready,
        new Promise<never>((_, reject) => { readyTimer = setTimeout(() => reject(new ProviderError('NATIVE_OA_READY_TIMEOUT', 'OA 项目 API 子进程就绪超时。', 503)), 120_000) }),
      ])
    } catch (error) {
      peer.close()
      await stopChildGracefully(child)
      throw error
    } finally {
      if (readyTimer) clearTimeout(readyTimer)
    }
    const server = createHttpServer((request, response) => {
      void (async () => {
        const body = await collectHttpBody(request, 32 * 1024 * 1024)
        const result = await peer.call('http', {
          methodName: request.method ?? 'GET',
          url: request.url ?? '/',
          headers: request.headers,
          ...(body.length ? { bodyBase64: body.toString('base64') } : {}),
        }) as { statusCode: number; headers: Record<string, string | string[]>; bodyBase64: string }
        const headers = { ...result.headers }
        for (const name of Object.keys(headers)) {
          if (['connection', 'transfer-encoding', 'content-length'].includes(name.toLowerCase())) delete headers[name]
        }
        response.writeHead(result.statusCode, headers)
        response.end(Buffer.from(result.bodyBase64, 'base64'))
      })().catch(error => {
        if (response.headersSent) return response.destroy(error instanceof Error ? error : undefined)
        const statusCode = error instanceof ProviderError ? error.statusCode : 502
        response.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' })
        response.end(JSON.stringify({ code: 'OA_BRIDGE_ERROR', message: error instanceof Error ? error.message : 'OA 请求转发失败。' }))
      })
    })
    server.maxConnections = 8
    server.headersTimeout = 10_000
    server.requestTimeout = 20_000
    server.keepAliveTimeout = 5_000
    server.maxHeadersCount = 100
    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        server.once('error', rejectListen)
        server.listen(port, '127.0.0.1', () => {
          server.off('error', rejectListen)
          resolveListen()
        })
      })
    } catch (error) {
      peer.close()
      await stopChildGracefully(child)
      throw error
    }
    return { child, peer, server, cache, sandbox }
  }

  private async cleanupRuntime(runtime: NativeOaRuntime, destroyDatabase = true) {
    if (runtime.cleanup) return runtime.cleanup
    runtime.cleanup = (async () => {
      for (const [instanceId, active] of this.runtimes) if (active === runtime) this.runtimes.delete(instanceId)
      this.reservedPorts.delete(runtime.port)
      await closeHttpServer(runtime.server).catch(() => undefined)
      runtime.peer.close()
      await stopChildGracefully(runtime.child)
      runtime.cache.clear()
      await runtime.pool.end().catch(() => undefined)
      let databaseError: unknown
      if (destroyDatabase) await this.mysqlManager.destroy(runtime.database).catch(error => { databaseError = error })
      await removeTree(runtime.root)
      if (databaseError) throw new ProviderError('NATIVE_OA_DB_CLEANUP_FAILED', `OA 数据库资源回收失败：${databaseError instanceof Error ? databaseError.message : String(databaseError)}`, 503)
    })()
    return runtime.cleanup
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    if (!input.lab.localPath) throw new ProviderError('NATIVE_OA_SOURCE_NOT_READY', 'OA 靶场资源尚未准备。', 409)
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError('NATIVE_OA_INSTANCE_ID_INVALID', 'OA 实例 ID 格式无效。', 400)
    const mysqlConfig = input.runtime.mysql
    if (!mysqlConfig) throw new ProviderError('NATIVE_OA_MYSQL_NOT_CONFIGURED', 'OA 靶场需要项目托管的 MariaDB。', 409)
    const projectNodePath = await this.verifyProjectRuntime(input)
    const paths = dataPaths(input.dataDir)
    const [dataRoot, sourcePath] = await Promise.all([realpath(paths.root), realpath(input.lab.localPath)])
    const sourceRelative = relative(dataRoot.toLowerCase(), sourcePath.toLowerCase())
    if (sourceRelative === '..' || sourceRelative.startsWith(`..${sep}`) || isAbsolute(sourceRelative)) {
      throw new ProviderError('NATIVE_OA_SOURCE_OUTSIDE_DATA', 'OA 靶场资源必须位于 VulnLab 数据目录内。', 409)
    }
    const safeInput = { ...input, lab: { ...input.lab, localPath: sourcePath } }
    const root = paths.runtimeInstance(input.instanceId)
    const port = await this.claimPort(input.runtime, '127.0.0.1')
    let database: MySqlResource | null = null
    let pool: Pool | null = null
    let child: ChildProcess | null = null
    let peer: RpcPeer | null = null
    let server: HttpServer | null = null
    let sandbox: OaSandboxState | null = null
    try {
      await removeTree(root)
      await mkdir(root, { recursive: true })
      database = await this.mysqlManager.provision({ labSlug: input.lab.slug, instanceId: input.instanceId, config: mysqlConfig })
      pool = await this.seedDatabase(safeInput, root, database)
      const launched = await this.launch(safeInput, root, port, database, pool, projectNodePath)
      child = launched.child
      peer = launched.peer
      server = launched.server
      sandbox = launched.sandbox
      const runtime: NativeOaRuntime = { child, peer, root, port, server, pool, database, cache: launched.cache, instanceId: input.instanceId, sandbox: { ...launched.sandbox } }
      this.runtimes.set(input.instanceId, runtime)
      await writeFile(join(root, 'vulnlab-runtime.json'), JSON.stringify({ port, provider: this.id, instanceId: input.instanceId, sandbox }), 'utf8')
      child.once('exit', () => { void this.cleanupRuntime(runtime).catch(() => undefined) })
      const timestamps = lease(input.lifetimeMinutes)
      return {
        ...timestamps,
        endpoint: `${runtimeOrigin(input.publicOrigin, port, input.runtime.publicOriginTemplate)}/`,
        logs: [
          `${timestamps.createdAt} 启动 OA 本地安全模式（仅绑定 127.0.0.1）`,
          `${timestamps.createdAt} HTTP 端口=${port} · 实例缓存为进程内隔离`,
          `${timestamps.createdAt} API 子进程使用 Node.js 权限模型；读写范围限定在项目运行代码和本实例目录，不启用操作系统沙盒`,
          `${timestamps.createdAt} SSTI exec 返回模拟结果，不调用系统命令`,
          `${timestamps.createdAt} MariaDB 数据库=${database.database}`,
          `${timestamps.createdAt} 6 个默认账号与业务数据已校验`,
        ],
      }
    } catch (error) {
      if (server) await closeHttpServer(server).catch(() => undefined)
      peer?.close()
      if (child) await stopChildGracefully(child)
      if (pool) await pool.end().catch(() => undefined)
      if (database) await this.mysqlManager.destroy(database).catch(() => undefined)
      this.reservedPorts.delete(port)
      await removeTree(root)
      if (error instanceof ProviderError) throw error
      const code = (error as NodeJS.ErrnoException)?.code === 'ENOENT' ? 'NATIVE_OA_BINARY_NOT_FOUND' : 'NATIVE_OA_START_FAILED'
      throw new ProviderError(code, error instanceof Error ? error.message : 'OA 靶场启动失败。', 503)
    }
  }

  async renew(input: ProviderRenewInput) {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError('NATIVE_OA_PROCESS_MISSING', 'OA 实例进程已退出。', 409)
    const { expiresAt } = renewalLease(input.instance, input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} OA 项目托管实例续期` }
  }

  getProxyTarget(instanceId: string) {
    const runtime = this.runtimes.get(instanceId)
    if (!runtime) return null
    return `http://127.0.0.1:${runtime.port}`
  }

  async stop(input: ProviderStopInput) {
    const runtime = this.runtimes.get(input.instance.id)
    if (runtime) {
      await this.cleanupRuntime(runtime)
    } else if (input.dataDir) {
      await this.recover({ lab: input.lab, instance: input.instance, runtime: input.runtime, dataDir: input.dataDir })
    } else {
      const mysql = input.runtime?.mysql ?? mysqlRuntimeConfigFromEnv()
      if (mysql && input.runtime?.mysqlManaged === true) await this.mysqlManager.destroyForInstance({ labSlug: input.lab.slug, instanceId: input.instance.id, config: mysql })
    }
    return { log: `${new Date().toISOString()} OA 本地安全模式实例结束并清理独立资源` }
  }

  async recover(input: ProviderRecoverInput) {
    if (!input.dataDir) return
    const root = dataPaths(input.dataDir).runtimeInstance(input.instance.id)
    const state = await readFile(join(root, 'vulnlab-runtime.json'), 'utf8')
      .then(value => JSON.parse(value) as { pid?: unknown; provider?: unknown; instanceId?: unknown; nodePath?: unknown; sandbox?: unknown })
      .catch(() => null)
    if (state?.instanceId !== undefined && state.instanceId !== input.instance.id) throw new ProviderError('NATIVE_OA_RUNTIME_STATE_INVALID', 'OA 本地实例运行记录与实例 ID 不匹配，未执行进程回收。', 409)
    if (state?.pid && Number.isInteger(state.pid) && Number(state.pid) > 0) {
      if (!['oa-local', 'oa-project', 'oa-appcontainer'].includes(String(state.provider))) throw new ProviderError('NATIVE_OA_RUNTIME_STATE_INVALID', 'OA 本地实例 Provider 记录无效，未执行进程回收。', 409)
      const nodePath = typeof state.nodePath === 'string' ? state.nodePath : (state.sandbox as { nodePath?: unknown } | undefined)?.nodePath
      if (typeof nodePath !== 'string') throw new ProviderError('NATIVE_OA_RUNTIME_STATE_INVALID', 'OA 本地实例 Node.js 路径缺失，未执行进程回收。', 409)
      await this.validateProjectNodePath(input.dataDir, nodePath)
      await terminatePid(Number(state.pid))
    }
    if (state?.sandbox && typeof (state.sandbox as { launcherPath?: unknown }).launcherPath === 'string' && (state.sandbox as { launcherPath: string }).launcherPath) {
      const expected = await this.sandboxForRecovery(input.dataDir, input.instance.id, root, state.sandbox)
      if (expected) await this.runSandboxCleanup(expected)
    }
    await removeTree(root)
    const mysql = input.runtime?.mysql ?? mysqlRuntimeConfigFromEnv()
    if (mysql && input.runtime?.mysqlManaged === true) await this.mysqlManager.destroyForInstance({ labSlug: input.lab.slug, instanceId: input.instance.id, config: mysql })
  }

  async shutdown() {
    await Promise.allSettled([...this.runtimes.values()].map(runtime => this.cleanupRuntime(runtime)))
    this.runtimes.clear()
  }
}

interface OaDockerState {
  provider: 'oa-docker'
  instanceId: string
  projectName: string
  port: number
  cleanupPending: boolean
  updatedAt: string
}

interface OaDockerRuntime {
  root: string
  projectName: string
  port: number
  instanceId: string
  cleanup?: Promise<void>
}

export interface OaDockerProviderOptions {
  runDocker?: (args: string[], timeoutMs?: number) => Promise<DockerCommandResult>
  allocatePort?: PortAllocator
}

const dockerComposePath = (root: string) => join(root, 'compose.json')
const dockerStatePath = (root: string) => join(root, 'oa-docker.json')

export class DockerOaProvider implements LabProvider {
  readonly id = 'oa-docker'
  readonly supportedRuntimeKinds: readonly RuntimeKind[] = ['native-oa']
  private readonly runDocker: (args: string[], timeoutMs?: number) => Promise<DockerCommandResult>
  private readonly allocatePortImpl: PortAllocator
  private readonly runtimes = new Map<string, OaDockerRuntime>()
  private readonly starting = new Set<string>()
  private readonly cleanups = new Map<string, Promise<void>>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(options: OaDockerProviderOptions = {}) {
    this.runDocker = options.runDocker ?? runDockerCommand
    this.allocatePortImpl = options.allocatePort ?? allocatePort
  }

  private composeArgs(root: string, projectName: string, args: string[]) {
    return ['compose', '--project-name', projectName, '--file', dockerComposePath(root), '--project-directory', root, ...args]
  }

  private async writeCompose(root: string, state: Pick<OaDockerState, 'instanceId' | 'projectName' | 'port'>, recovery = false) {
    const context = join(root, 'build-context')
    const sqlPath = join(context, 'database', 'init.sql')
    const mysqlContext = join(root, 'mysql-context')
    const ingressContext = join(root, 'ingress-context')
    const ingressDockerfile = join(ingressContext, 'Dockerfile')
    await mkdir(ingressContext, { recursive: true })
    await writeFile(ingressDockerfile, oaDockerIngressDockerfile, 'utf8')
    await mkdir(mysqlContext, { recursive: true })
    await writeFile(join(mysqlContext, 'Dockerfile'), oaDockerMysqlDockerfile, 'utf8')
    if (!recovery) {
      const sqlInfo = await stat(sqlPath).catch(() => null)
      if (!sqlInfo?.isFile()) throw new ProviderError('OA_DOCKER_SEED_MISSING', 'OA Docker 资源中的 MySQL 初始化 SQL 文件缺失。', 409)
      await copyFile(sqlPath, join(mysqlContext, 'init.sql'))
    }
    const config = createOaDockerComposeConfig({
      projectName: state.projectName,
      buildContext: context,
      mysqlContext,
      ingressContext,
      port: state.port,
      databasePassword: recovery ? 'cleanup-only-db' : randomBytes(24).toString('base64url'),
      redisPassword: recovery ? 'cleanup-only-cache' : randomBytes(24).toString('base64url'),
      jwtSecret: recovery ? 'cleanup-only-jwt' : randomBytes(32).toString('base64url'),
      instanceId: state.instanceId,
    })
    await writeFile(dockerComposePath(root), JSON.stringify(config), 'utf8')
  }

  private async claimPort(config: NativeRuntimeConfig) {
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
      throw new ProviderError('OA_DOCKER_PORT_EXHAUSTED', 'OA Docker 模式的回环端口已用尽。', 409)
    } finally {
      release()
    }
  }

  private async assertReady() {
    const [runtime, asset] = await Promise.all([inspectOaDockerRuntime(this.runDocker), inspectOaDockerAsset(oaDockerAssetPath())])
    const missing = [...runtime.missing]
    if (!asset.available) missing.push(asset.detail)
    if (missing.length) {
      const details = [runtime.cli.detail, runtime.compose.detail, runtime.engine.detail, ...(asset.available ? [] : [asset.detail])]
        .filter((value, index, values) => value && values.indexOf(value) === index)
      throw new ProviderError('OA_DOCKER_DEPENDENCY_MISSING', `Docker 模式不可用：${details.join('；')}`, 409)
    }
  }

  private async runCompose(root: string, projectName: string, args: string[], timeoutMs = 30_000) {
    return this.runDocker(this.composeArgs(root, projectName, args), timeoutMs)
  }

  private async waitUntilReady(port: number) {
    const deadline = Date.now() + 180_000
    let lastError = 'Web 容器尚未响应。'
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual', signal: AbortSignal.timeout(2_000) })
        if (response.status >= 200 && response.status < 400) {
          await response.body?.cancel().catch(() => undefined)
          return
        }
        lastError = `OA Web 入口返回 HTTP ${response.status}。`
      } catch (error) {
        lastError = error instanceof Error ? error.message : lastError
      }
      await sleep(1_000)
    }
    throw new ProviderError('OA_DOCKER_WEB_NOT_READY', `Docker 模式启动超时：${lastError}`, 503)
  }

  private async writeState(root: string, state: OaDockerState) {
    await writeFile(dockerStatePath(root), JSON.stringify({ ...state, updatedAt: new Date().toISOString() }), 'utf8')
  }

  private async cleanup(root: string, instanceId: string, projectName: string, port: number) {
    const existing = this.cleanups.get(instanceId)
    if (existing) return existing
    const cleanup = (async () => {
      const baseState = { provider: 'oa-docker' as const, instanceId, projectName, port, cleanupPending: true, updatedAt: new Date().toISOString() }
      await this.writeState(root, baseState)
      await this.writeCompose(root, baseState, true)
      const result = await this.runCompose(root, projectName, ['down', '--volumes', '--remove-orphans'], 120_000)
      if (!result.ok) {
        const detail = `${result.stdout} ${result.stderr}`.replace(/\s+/g, ' ').trim().slice(-700) || result.errorCode || 'Docker 清理命令失败。'
        throw new ProviderError('OA_DOCKER_CLEANUP_PENDING', `OA Docker 实例 ${instanceId} 的容器和数据卷尚未回收；已保留待重试状态：${detail}`, 503)
      }
      await removeTree(root)
      this.reservedPorts.delete(port)
      this.runtimes.delete(instanceId)
    })()
    this.cleanups.set(instanceId, cleanup)
    try {
      await cleanup
    } finally {
      if (this.cleanups.get(instanceId) === cleanup) this.cleanups.delete(instanceId)
    }
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    if (!input.lab.localPath) throw new ProviderError('NATIVE_OA_SOURCE_NOT_READY', 'OA 靶场资源尚未准备。', 409)
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError('NATIVE_OA_INSTANCE_ID_INVALID', 'OA 实例 ID 格式无效。', 400)
    await this.assertReady()
    const root = dataPaths(input.dataDir).runtimeInstance(input.instanceId)
    const projectName = oaDockerProjectName(input.instanceId)
    const port = await this.claimPort(input.runtime)
    let composeCreated = false
    this.starting.add(input.instanceId)
    try {
      await removeTree(root)
      await mkdir(root, { recursive: true })
      const buildContext = join(root, 'build-context')
      await unpackOaDockerAsset(buildContext)
      const jwtSecret = randomBytes(32).toString('base64url')
      const inviteCode = randomBytes(18).toString('base64url')
      await configureOaFrontendSecrets(join(buildContext, 'dist'), jwtSecret, inviteCode)
      const state: OaDockerState = { provider: 'oa-docker', instanceId: input.instanceId, projectName, port, cleanupPending: false, updatedAt: new Date().toISOString() }
      await this.writeCompose(root, state)
      const composeConfig = JSON.parse(await readFile(dockerComposePath(root), 'utf8')) as { services: { web: { environment: Record<string, string> } } }
      composeConfig.services.web.environment.JWT_SECRET = jwtSecret
      await writeFile(dockerComposePath(root), JSON.stringify(composeConfig), 'utf8')
      await this.writeState(root, state)
      composeCreated = true
      const up = await this.runCompose(root, projectName, ['up', '--detach', '--build'], 30 * 60_000)
      if (!up.ok) {
        const detail = `${up.stdout} ${up.stderr}`.replace(/\s+/g, ' ').trim().slice(-900) || up.errorCode || 'Compose 启动失败。'
        const code = /port is already allocated|address already in use/i.test(detail) ? 'OA_DOCKER_PORT_IN_USE' : 'OA_DOCKER_START_FAILED'
        throw new ProviderError(code, `OA Docker 模式启动失败：${detail}`, 503)
      }
      await this.waitUntilReady(port)
      this.runtimes.set(input.instanceId, { root, projectName, port, instanceId: input.instanceId })
      const timestamps = lease(input.lifetimeMinutes)
      return {
        ...timestamps,
        endpoint: `${runtimeOrigin(input.publicOrigin, port, input.runtime.publicOriginTemplate)}/`,
        logs: [
          `${timestamps.createdAt} 启动 OA Docker 原版模式（Compose 项目=${projectName}）`,
          `${timestamps.createdAt} Web 仅发布到 127.0.0.1:${port}；MySQL/Redis 不发布宿主端口`,
          `${timestamps.createdAt} 容器使用实例专属网络、数据库/缓存/上传卷；网络启用 internal`,
          `${timestamps.createdAt} OA Web 进程以容器内 UID 65532 运行；SSTI exec 在容器内执行`,
        ],
      }
    } catch (error) {
      this.reservedPorts.delete(port)
      if (composeCreated) {
        try {
          await this.cleanup(root, input.instanceId, projectName, port)
        } catch (cleanupError) {
          if (error instanceof ProviderError) throw new ProviderError(error.code, `${error.message}；资源回收还在重试：${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`, error.statusCode)
          throw cleanupError
        }
      } else {
        await removeTree(root)
      }
      if (error instanceof ProviderError) throw error
      throw new ProviderError('OA_DOCKER_START_FAILED', `OA Docker 模式启动失败：${error instanceof Error ? error.message : String(error)}`, 503)
    } finally {
      this.starting.delete(input.instanceId)
    }
  }

  async renew(input: ProviderRenewInput) {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError('OA_DOCKER_INSTANCE_MISSING', 'OA Docker 实例没有可续期的 Compose 运行状态。', 409)
    const { expiresAt } = renewalLease(input.instance, input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} OA Docker 原版实例续期` }
  }

  async stop(input: ProviderStopInput) {
    const active = this.runtimes.get(input.instance.id)
    if (active) {
      await this.cleanup(active.root, active.instanceId, active.projectName, active.port)
    } else if (input.dataDir) {
      await this.recover({ lab: input.lab, instance: input.instance, runtime: input.runtime, dataDir: input.dataDir })
    }
    return { log: `${new Date().toISOString()} OA Docker 实例与专属数据卷已回收` }
  }

  async recover(input: ProviderRecoverInput) {
    if (!input.dataDir) return
    const root = dataPaths(input.dataDir).runtimeInstance(input.instance.id)
    const marker = await readFile(dockerStatePath(root), 'utf8').then(value => JSON.parse(value) as Partial<OaDockerState>).catch(() => null)
    const projectName = oaDockerProjectName(input.instance.id)
    if (marker && (marker.provider !== 'oa-docker' || marker.instanceId !== input.instance.id || marker.projectName !== projectName)) {
      throw new ProviderError('OA_DOCKER_STATE_INVALID', 'OA Docker 实例清单与运行记录不匹配，未执行清理。', 409)
    }
    const port = Number.isInteger(marker?.port) && Number(marker?.port) >= 1024 && Number(marker?.port) <= 65535 ? Number(marker?.port) : 6800
    await mkdir(root, { recursive: true })
    await this.cleanup(root, input.instance.id, projectName, port)
  }

  async recoverPending(dataDir: string, activeInstanceIds: ReadonlySet<string>) {
    const runtimeRoot = dataPaths(dataDir).runtime
    const entries = await readdir(runtimeRoot, { withFileTypes: true }).catch(() => [])
    const cleaned: string[] = []
    for (const entry of entries) {
      if (!entry.isDirectory() || !/^[A-Za-z0-9-]+$/.test(entry.name)) continue
      const root = join(runtimeRoot, entry.name)
      const marker = await readFile(dockerStatePath(root), 'utf8').then(value => JSON.parse(value) as Partial<OaDockerState>).catch(() => null)
      if (!marker) continue
      const projectName = oaDockerProjectName(entry.name)
      if (marker.provider !== 'oa-docker' || marker.instanceId !== entry.name || marker.projectName !== projectName) continue
      if (this.starting.has(entry.name)) continue
      if (activeInstanceIds.has(entry.name) && marker.cleanupPending !== true) continue
      const port = Number.isInteger(marker.port) && Number(marker.port) >= 1024 && Number(marker.port) <= 65535 ? Number(marker.port) : 6800
      try {
        await this.cleanup(root, entry.name, projectName, port)
        if (activeInstanceIds.has(entry.name)) cleaned.push(entry.name)
      } catch (error) {
        throw error
      }
    }
    return cleaned
  }

  async shutdown() {
    const runtimes = [...this.runtimes.values()]
    await Promise.allSettled(runtimes.map(runtime => this.cleanup(runtime.root, runtime.instanceId, runtime.projectName, runtime.port)))
  }
}

interface NativeComposeRuntimeState {
  provider: 'native-compose'
  instanceId: string
  projectName: string
  port: number
  cleanupPending: boolean
  updatedAt: string
}

interface NativeComposeRuntime {
  root: string
  projectName: string
  port: number
  instanceId: string
}

type ComposeModel = {
  name?: string
  services?: Record<string, Record<string, unknown>>
  networks?: Record<string, Record<string, unknown>>
  volumes?: Record<string, Record<string, unknown>>
  configs?: Record<string, Record<string, unknown>>
  secrets?: Record<string, Record<string, unknown>>
}

const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value && typeof value === 'object' && !Array.isArray(value))
const composeStatePath = (root: string) => join(root, 'native-compose.json')
const composeFilePath = (root: string) => join(root, 'compose.json')
export const nativeComposeProjectName = (instanceId: string) => `vulnlab-${createHash('sha256').update(instanceId).digest('hex').slice(0, 24)}`

const containedPath = (root: string, target: string) => {
  const relativePath = relative(resolve(root), resolve(target))
  return relativePath === '' || (relativePath !== '..' && !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath))
}

export interface NativeComposeProviderOptions {
  runDocker?: (args: string[], timeoutMs?: number) => Promise<DockerCommandResult>
  allocatePort?: PortAllocator
  waitUntilReady?: (port: number) => Promise<void>
}

export class NativeComposeProvider implements LabProvider {
  readonly id = 'native-compose'
  readonly supportedRuntimeKinds: readonly RuntimeKind[] = ['native-compose']
  private readonly runDocker: (args: string[], timeoutMs?: number) => Promise<DockerCommandResult>
  private readonly allocatePortImpl: PortAllocator
  private readonly waitUntilReadyImpl: (port: number) => Promise<void>
  private readonly runtimes = new Map<string, NativeComposeRuntime>()
  private readonly starting = new Set<string>()
  private readonly cleanups = new Map<string, Promise<void>>()
  private readonly reservedPorts = new Set<number>()
  private portAllocation = Promise.resolve()

  constructor(options: NativeComposeProviderOptions = {}) {
    this.runDocker = options.runDocker ?? ((args, timeoutMs) => runDockerCommand(args, timeoutMs, localDockerEnvironment()))
    this.allocatePortImpl = options.allocatePort ?? allocatePort
    this.waitUntilReadyImpl = options.waitUntilReady ?? (port => this.waitUntilReady(port))
  }

  private composeArgs(root: string, projectName: string, args: string[]) {
    return ['compose', '--project-name', projectName, '--file', composeFilePath(root), '--project-directory', root, ...args]
  }

  private async claimPort(config: NativeRuntimeConfig) {
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
      throw new ProviderError('NATIVE_COMPOSE_PORT_EXHAUSTED', 'Compose 运行端口已用尽。', 409)
    } finally {
      release()
    }
  }

  private async assertReady() {
    const status = await inspectOaDockerRuntime(this.runDocker)
    if (!status.available) throw new ProviderError('NATIVE_COMPOSE_DOCKER_UNAVAILABLE', `Docker Compose 不可用：${[status.cli.detail, status.compose.detail, status.engine.detail].join('；')}`, 409)
  }

  private async projectPath(projectRoot: string, value: unknown, label: string, required = true) {
    if (typeof value !== 'string' || !value) throw new ProviderError('NATIVE_COMPOSE_PATH_INVALID', `${label} 路径无效。`, 409)
    const resolved = resolve(projectRoot, value)
    try {
      const actual = await realpath(resolved)
      if (!containedPath(projectRoot, actual)) throw new ProviderError('NATIVE_COMPOSE_PATH_OUTSIDE_PROJECT', `${label} 必须位于已导入项目目录内。`, 409)
      return actual
    } catch (error) {
      if (!required && (error as NodeJS.ErrnoException)?.code === 'ENOENT') return null
      if (error instanceof ProviderError) throw error
      throw new ProviderError('NATIVE_COMPOSE_PATH_INVALID', `${label} 文件不存在或不可读取。`, 409)
    }
  }

  private async validateComposeModel(model: ComposeModel, projectRoot: string, webService: string, webPort: number) {
    if (!isRecord(model.services) || Object.keys(model.services).length === 0) throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', 'Compose 配置没有服务。', 409)
    if (!isRecord(model.services[webService])) throw new ProviderError('NATIVE_COMPOSE_WEB_SERVICE_MISSING', `Compose 配置中找不到 Web 服务“${webService}”。`, 409)

    for (const [name, rawService] of Object.entries(model.services)) {
      if (!isRecord(rawService)) throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', `Compose 服务“${name}”配置无效。`, 409)
      const service = rawService
      if (service.privileged === true || service.network_mode || service.pid === 'host' || service.ipc === 'host' || service.uts === 'host' || service.userns_mode === 'host') {
        throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 服务“${name}”请求了受限的容器权限或宿主网络命名空间。`, 409)
      }
      if ((Array.isArray(service.devices) && service.devices.length) || (Array.isArray(service.cap_add) && service.cap_add.length) || service.use_api_socket === true || service.credential_spec) {
        throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 服务“${name}”请求了宿主设备、额外权限或宿主凭据接口。`, 409)
      }
      if (Array.isArray(service.volumes) && service.volumes.some(mount => isRecord(mount) && mount.type === 'bind')) {
        throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 服务“${name}”包含宿主目录挂载。`, 409)
      }
      if (service.volumes_from) throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 服务“${name}”不能复用外部容器挂载。`, 409)

      if (service.ports !== undefined) {
        if (!Array.isArray(service.ports)) throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', `Compose 服务“${name}”的端口配置无效。`, 409)
        if (name !== webService && service.ports.length) throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `只有指定的 Web 服务可以映射本机端口。`, 409)
        if (name === webService && service.ports.some(port => !isRecord(port) || Number(port.target) !== webPort)) {
          throw new ProviderError('NATIVE_COMPOSE_WEB_PORT_MISMATCH', `Web 服务“${webService}”只能使用配置的容器入口端口 ${webPort}。`, 409)
        }
      }

      const envFiles = Array.isArray(service.env_file) ? service.env_file : service.env_file === undefined ? [] : [service.env_file]
      for (const item of envFiles) {
        const value = isRecord(item) ? item.path : item
        const required = !isRecord(item) || item.required !== false
        const file = await this.projectPath(projectRoot, value, 'env_file', required)
        if (file && !(await stat(file)).isFile()) throw new ProviderError('NATIVE_COMPOSE_PATH_INVALID', 'env_file 必须指向项目内的普通文件。', 409)
      }

      if (service.build !== undefined) {
        if (!isRecord(service.build)) throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', `Compose 服务“${name}”的 build 配置无效。`, 409)
        if (service.build.network === 'host' || service.build.ssh || service.build.additional_contexts) throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 服务“${name}”的构建配置包含宿主网络或额外宿主资源。`, 409)
        const context = await this.projectPath(projectRoot, service.build.context, 'build.context')
        if (!(await stat(context as string)).isDirectory()) throw new ProviderError('NATIVE_COMPOSE_PATH_INVALID', 'build.context 必须指向项目内的目录。', 409)
        if (typeof service.build.dockerfile === 'string' && !service.build.dockerfile.startsWith('inline:')) {
          const dockerfile = resolve(context as string, service.build.dockerfile)
          const actualDockerfile = await this.projectPath(context as string, dockerfile, 'build.dockerfile')
          if (!(await stat(actualDockerfile as string)).isFile()) throw new ProviderError('NATIVE_COMPOSE_PATH_INVALID', 'build.dockerfile 必须指向项目内的普通文件。', 409)
        }
      }
    }

    for (const [name, network] of Object.entries(model.networks ?? {})) {
      if (network.external === true || network.driver === 'host' || (network.driver && network.driver !== 'bridge') || network.driver_opts) {
        throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 网络“${name}”需要外部或宿主网络配置。`, 409)
      }
    }
    for (const [name, volume] of Object.entries(model.volumes ?? {})) {
      if (volume.external === true || volume.driver_opts) throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose 数据卷“${name}”需要外部或宿主目录配置。`, 409)
    }
    for (const [kind, resources] of [['configs', model.configs], ['secrets', model.secrets]] as const) {
      for (const [name, resource] of Object.entries(resources ?? {})) {
        if (resource.external === true) throw new ProviderError('NATIVE_COMPOSE_POLICY_REJECTED', `Compose ${kind}“${name}”不能引用外部资源。`, 409)
        if (resource.file !== undefined) await this.projectPath(projectRoot, resource.file, `Compose ${kind} 文件`)
      }
    }
  }

  private async waitUntilReady(port: number) {
    const deadline = Date.now() + 180_000
    let lastError = 'Compose Web 入口尚未响应。'
    while (Date.now() < deadline) {
      try {
        const response = await fetch(`http://127.0.0.1:${port}/`, { redirect: 'manual', signal: AbortSignal.timeout(2_000) })
        if (response.status >= 200 && response.status < 500) {
          await response.body?.cancel().catch(() => undefined)
          return
        }
        lastError = `Compose Web 入口返回 HTTP ${response.status}。`
      } catch (error) {
        lastError = error instanceof Error ? error.message : lastError
      }
      await sleep(1_000)
    }
    throw new ProviderError('NATIVE_COMPOSE_WEB_NOT_READY', `Compose Web 入口启动超时：${lastError}`, 503)
  }

  private async writeState(root: string, state: NativeComposeRuntimeState) {
    await writeFile(composeStatePath(root), JSON.stringify({ ...state, updatedAt: new Date().toISOString() }), 'utf8')
  }

  private async cleanup(root: string, instanceId: string, projectName: string, port: number) {
    const existing = this.cleanups.get(instanceId)
    if (existing) return existing
    const cleanup = (async () => {
      await this.writeState(root, { provider: 'native-compose', instanceId, projectName, port, cleanupPending: true, updatedAt: new Date().toISOString() })
      const result = await this.runDocker(this.composeArgs(root, projectName, ['down', '--volumes', '--remove-orphans']), 120_000)
      if (!result.ok) {
        const detail = `${result.stdout} ${result.stderr}`.replace(/\s+/g, ' ').trim().slice(-500) || result.errorCode || 'Docker Compose 清理失败。'
        throw new ProviderError('NATIVE_COMPOSE_CLEANUP_PENDING', `Compose 容器、网络或数据卷尚未回收：${detail}`, 503)
      }
      await rm(root, { recursive: true, force: true, maxRetries: 6, retryDelay: 150 })
      this.reservedPorts.delete(port)
      this.runtimes.delete(instanceId)
    })()
    this.cleanups.set(instanceId, cleanup)
    try { await cleanup } finally { if (this.cleanups.get(instanceId) === cleanup) this.cleanups.delete(instanceId) }
  }

  async start(input: ProviderStartInput): Promise<ProviderStartResult> {
    const sourceRoot = input.lab.localPath
    const config = input.lab.runtimeConfig
    if (!sourceRoot || !config?.composeFile || !config.webService || !Number.isInteger(config.webPort)) {
      throw new ProviderError('NATIVE_COMPOSE_CONFIG_REQUIRED', 'Compose 项目缺少运行目录、Web 服务名或入口端口。', 409)
    }
    const webPort = config.webPort as number
    if (!/^[A-Za-z0-9-]+$/.test(input.instanceId)) throw new ProviderError('NATIVE_COMPOSE_INSTANCE_ID_INVALID', '运行实例 ID 格式无效。', 400)
    await this.assertReady()

    const paths = dataPaths(input.dataDir)
    const realDataRoot = await realpath(paths.root)
    const projectRoot = await realpath(resolve(sourceRoot))
    if (!containedPath(realDataRoot, projectRoot) || !(await stat(projectRoot)).isDirectory()) {
      throw new ProviderError('NATIVE_COMPOSE_SOURCE_OUTSIDE_DATA', 'Compose 项目必须位于 VulnLab 数据目录内。', 409)
    }
    const composeFile = config.composeFile.replaceAll('\\', '/')
    if (!composeFile || composeFile.startsWith('/') || /^[A-Za-z]:/.test(composeFile) || composeFile.split('/').some(part => !part || part === '.' || part === '..')) {
      throw new ProviderError('NATIVE_COMPOSE_FILE_INVALID', 'Compose 文件必须是项目内的相对路径。', 409)
    }
    const composePath = await this.projectPath(projectRoot, resolve(projectRoot, composeFile), 'Compose 文件')
    if (!(await stat(composePath as string)).isFile()) throw new ProviderError('NATIVE_COMPOSE_FILE_INVALID', 'Compose 文件必须指向项目内的普通文件。', 409)

    const projectName = nativeComposeProjectName(input.instanceId)
    const normalized = await this.runDocker([
      'compose', '--project-name', projectName, '--file', composePath as string, '--project-directory', projectRoot,
      'config', '--format', 'json',
    ], 120_000)
    if (!normalized.ok) throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', 'Docker Compose 无法解析所选项目配置。', 409)
    let model: ComposeModel
    try { model = JSON.parse(normalized.stdout) as ComposeModel } catch {
      throw new ProviderError('NATIVE_COMPOSE_CONFIG_INVALID', 'Docker Compose 未返回有效的规范化 JSON 配置。', 409)
    }
    await this.validateComposeModel(model, projectRoot, config.webService, webPort)

    const runtimeRoot = paths.runtimeInstance(input.instanceId)
    if (await stat(runtimeRoot).catch(() => null)) throw new ProviderError('NATIVE_COMPOSE_INSTANCE_EXISTS', '该运行实例目录已存在，未覆盖现有状态。', 409)
    const port = await this.claimPort(input.runtime)
    this.starting.add(input.instanceId)
    let stateCreated = false
    try {
      await mkdir(runtimeRoot, { recursive: true })
      model.name = projectName
      const services = model.services as Record<string, Record<string, unknown>>
      for (const [name, service] of Object.entries(services)) {
        delete service.ports
        if (name === config.webService) service.ports = [{ target: webPort, published: String(port), host_ip: '127.0.0.1', protocol: 'tcp' }]
      }
      await writeFile(composeFilePath(runtimeRoot), JSON.stringify(model), 'utf8')
      const state: NativeComposeRuntimeState = { provider: 'native-compose', instanceId: input.instanceId, projectName, port, cleanupPending: false, updatedAt: new Date().toISOString() }
      await this.writeState(runtimeRoot, state)
      stateCreated = true
      const up = await this.runDocker(this.composeArgs(runtimeRoot, projectName, ['up', '--detach', '--build']), 30 * 60_000)
      if (!up.ok) throw new ProviderError('NATIVE_COMPOSE_START_FAILED', 'Docker Compose 启动失败。', 503)
      await this.waitUntilReadyImpl(port)
      this.runtimes.set(input.instanceId, { root: runtimeRoot, projectName, port, instanceId: input.instanceId })
      const timestamps = lease(input.lifetimeMinutes)
      return {
        ...timestamps,
        endpoint: `${runtimeOrigin(input.publicOrigin, port, input.runtime.publicOriginTemplate)}/`,
        logs: [
          `${timestamps.createdAt} 启动多服务 Docker Compose 项目（${projectName}）`,
          `${timestamps.createdAt} Web 服务 ${config.webService}:${webPort} 仅映射到 127.0.0.1:${port}`,
          `${timestamps.createdAt} Compose 服务使用实例专属网络与数据卷`,
        ],
      }
    } catch (error) {
      this.reservedPorts.delete(port)
      if (stateCreated) {
        try { await this.cleanup(runtimeRoot, input.instanceId, projectName, port) } catch (cleanupError) {
          if (error instanceof ProviderError) throw new ProviderError(error.code, `${error.message} 资源回收将重试。`, error.statusCode)
          throw cleanupError
        }
      } else {
        await rm(runtimeRoot, { recursive: true, force: true }).catch(() => undefined)
      }
      if (error instanceof ProviderError) throw error
      throw new ProviderError('NATIVE_COMPOSE_START_FAILED', 'Docker Compose 项目启动失败。', 503)
    } finally {
      this.starting.delete(input.instanceId)
    }
  }

  async renew(input: ProviderRenewInput) {
    if (!this.runtimes.has(input.instance.id)) throw new ProviderError('NATIVE_COMPOSE_INSTANCE_MISSING', 'Compose 实例没有可续期的运行状态。', 409)
    const { expiresAt } = renewalLease(input.instance, input.lifetimeMinutes)
    return { expiresAt, log: `${new Date().toISOString()} Docker Compose 实例续期` }
  }

  async stop(input: ProviderStopInput) {
    const active = this.runtimes.get(input.instance.id)
    if (active) await this.cleanup(active.root, active.instanceId, active.projectName, active.port)
    else if (input.dataDir) await this.recover({ lab: input.lab, instance: input.instance, runtime: input.runtime, dataDir: input.dataDir })
    return { log: `${new Date().toISOString()} Docker Compose 实例、网络与数据卷已回收` }
  }

  async recover(input: ProviderRecoverInput) {
    if (!input.dataDir) return
    const root = dataPaths(input.dataDir).runtimeInstance(input.instance.id)
    const marker = await readFile(composeStatePath(root), 'utf8').then(value => JSON.parse(value) as Partial<NativeComposeRuntimeState>).catch(() => null)
    if (!marker) {
      await rm(root, { recursive: true, force: true }).catch(() => undefined)
      return
    }
    const projectName = nativeComposeProjectName(input.instance.id)
    if (marker.provider !== 'native-compose' || marker.instanceId !== input.instance.id || marker.projectName !== projectName) {
      throw new ProviderError('NATIVE_COMPOSE_STATE_INVALID', 'Compose 实例清单与运行记录不匹配，未执行清理。', 409)
    }
    const port = Number.isInteger(marker.port) && Number(marker.port) >= 1024 && Number(marker.port) <= 65535 ? Number(marker.port) : 6800
    await this.cleanup(root, input.instance.id, projectName, port)
  }

  async recoverPending(dataDir: string, activeInstanceIds: ReadonlySet<string>) {
    const runtimeRoot = dataPaths(dataDir).runtime
    const entries = await readdir(runtimeRoot, { withFileTypes: true }).catch(() => [])
    const recovered: string[] = []
    for (const entry of entries) {
      if (!entry.isDirectory() || !/^[A-Za-z0-9-]+$/.test(entry.name) || this.starting.has(entry.name)) continue
      const root = join(runtimeRoot, entry.name)
      const marker = await readFile(composeStatePath(root), 'utf8').then(value => JSON.parse(value) as Partial<NativeComposeRuntimeState>).catch(() => null)
      const projectName = nativeComposeProjectName(entry.name)
      if (marker?.provider !== 'native-compose' || marker.instanceId !== entry.name || marker.projectName !== projectName) continue
      if (activeInstanceIds.has(entry.name) && marker.cleanupPending !== true) continue
      const port = Number.isInteger(marker.port) && Number(marker.port) >= 1024 && Number(marker.port) <= 65535 ? Number(marker.port) : 6800
      await this.cleanup(root, entry.name, projectName, port)
      if (activeInstanceIds.has(entry.name)) recovered.push(entry.name)
    }
    return recovered
  }

  async shutdown() {
    await Promise.allSettled([...this.runtimes.values()].map(runtime => this.cleanup(runtime.root, runtime.instanceId, runtime.projectName, runtime.port)))
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
    const normalized = candidate.replaceAll('\\', '/')
    if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized) || normalized.split('/').some(part => !part || part === '.' || part === '..')) continue
    const path = resolve(root, normalized)
    const prefix = root.endsWith(sep) ? root : `${root}${sep}`
    if (!path.startsWith(prefix)) continue
    const info = await stat(path).catch(() => null)
    if (info?.isFile()) return path
  }
  return null
}

const renderProcessArgs = (args: readonly string[] | undefined, portArg: string | undefined, port: number, host: string) => [...(args ?? []), ...(portArg ? [portArg] : [])]
  .map(value => value.replaceAll('{port}', String(port)).replaceAll('{host}', host))

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
      const configuredEntry = input.lab.runtimeConfig?.entryPath
      const candidates = [configuredEntry, 'build/app.js', 'dist/app.js', 'app.js', 'server.js'].filter((value): value is string => Boolean(value))
      const entry = await findExistingFile(root, candidates)
      if (!entry) throw new ProviderError('NATIVE_NODE_ENTRY_NOT_FOUND', 'Node.js 项目缺少可运行启动入口。', 409)
      return {
        binary: input.runtime.nodeBinary,
        args: [entry, ...(input.lab.runtimeConfig?.nodeArgs ?? [])],
        cwd: root,
        environment: { PORT: String(port), HOST: input.runtime.bindHost, NODE_ENV: 'production' },
        endpointSuffix: '',
      }
    }
    if (this.id === 'native-java') {
      const javaProfile = input.lab.runtimeConfig?.profile ?? 'webgoat'
      const configuredEntry = input.lab.runtimeConfig?.entryPath
      const jar = configuredEntry
        ? await findExistingFile(root, [configuredEntry])
        : input.lab.localPath && (await stat(input.lab.localPath).catch(() => null))?.isFile()
        ? resolve(input.lab.localPath)
        : await findExistingFile(root, ['webgoat.jar', `webgoat-${input.lab.version}.jar`])
      if (!jar) throw new ProviderError('NATIVE_JAVA_JAR_NOT_FOUND', 'Java 项目缺少可运行 JAR。', 409)
      if (javaProfile !== 'webgoat') {
        return {
          binary: input.runtime.javaBinary,
          args: ['-Dfile.encoding=UTF-8', '-jar', jar, ...renderProcessArgs(input.lab.runtimeConfig?.javaArgs, input.lab.runtimeConfig?.portArg, port, input.runtime.bindHost)],
          cwd: root,
          environment: {
            HOME: root,
            USERPROFILE: root,
            HOST: input.runtime.bindHost,
            PORT: String(port),
            SERVER_PORT: String(port),
          },
          endpointSuffix: '',
        }
      }
      if (!auxiliaryPort) throw new ProviderError('NATIVE_JAVA_AUX_PORT_REQUIRED', 'WebGoat 缺少 WebWolf 运行端口。', 500)
      return {
        binary: input.runtime.javaBinary,
        args: ['-Dfile.encoding=UTF-8', '-jar', jar, `--server.address=${input.runtime.bindHost}`, `--webgoat.port=${port}`, `--webwolf.port=${auxiliaryPort}`],
        cwd: root,
        environment: { HOME: root, USERPROFILE: root, WEBGOAT_PORT: String(port), WEBWOLF_PORT: String(auxiliaryPort) },
        endpointSuffix: 'WebGoat/',
      }
    }
    if (input.lab.runtimeConfig?.profile === 'python-script') {
      const script = await findExistingFile(root, [input.lab.runtimeConfig.entryPath || 'app.py'])
      if (!script) throw new ProviderError('NATIVE_PYTHON_ENTRY_NOT_FOUND', 'Python 项目缺少可运行文件。', 409)
      const venvPython = await findExistingFile(input.lab.localPath as string, ['.vulnlab-venv/Scripts/python.exe'])
      const binary = venvPython ?? input.runtime.pythonBinary
      const prefix = !venvPython && basename(input.runtime.pythonBinary).toLowerCase().replace(/\.exe$/, '') === 'py' ? ['-3'] : []
      return {
        binary,
        args: [...prefix, script, ...renderProcessArgs(input.lab.runtimeConfig.pythonArgs, input.lab.runtimeConfig.portArg, port, input.runtime.bindHost)],
        cwd: root,
        environment: { PYTHONUNBUFFERED: '1', HOST: input.runtime.bindHost, PORT: String(port) },
        endpointSuffix: '',
      }
    }
    const manage = await findExistingFile(root, [input.lab.runtimeConfig?.entryPath || 'manage.py'])
    if (!manage) throw new ProviderError('NATIVE_PYTHON_ENTRY_NOT_FOUND', 'Python 项目缺少可运行入口。', 409)
    const venvPython = await findExistingFile(input.lab.localPath as string, ['.vulnlab-venv/Scripts/python.exe'])
    const settingsPath = join(root, ...(input.lab.runtimeConfig?.settingsPath || 'pygoat/settings.py').split('/'))
    let settings = await readFile(settingsPath, 'utf8').catch(() => '')
    if (!settings) throw new ProviderError('NATIVE_PYTHON_SETTINGS_NOT_FOUND', 'Python 项目缺少 Django 设置文件。', 409)
    settings = settings
      .replace(/^import django_heroku\s*$/m, '')
      .replace(/^django_heroku\.settings\(locals\(\)\)\s*$/m, '')
      .replace(/^([ \t]*)'django\.contrib\.auth\.middleware\.AuthenticationMiddleware',$/m, "$&\n$1'allauth.account.middleware.AccountMiddleware',")
    const trustedOrigin = new URL(input.publicOrigin).origin
    settings += `\nALLOWED_HOSTS = ['*']\nCSRF_TRUSTED_ORIGINS = [${JSON.stringify(trustedOrigin)}]\n`
    await writeFile(settingsPath, settings, 'utf8')
    const binary = venvPython ?? input.runtime.pythonBinary
    const prefix = !venvPython && basename(input.runtime.pythonBinary).toLowerCase().replace(/\.exe$/, '') === 'py' ? ['-3'] : []
    const settingsModule = (input.lab.runtimeConfig?.settingsPath || 'pygoat/settings.py')
      .replaceAll('\\', '/').replace(/\.py$/i, '').split('/').filter(Boolean).join('.')
    await this.runCommand(binary, [...prefix, manage, 'migrate', '--noinput'], root, { PYTHONUNBUFFERED: '1', DJANGO_SETTINGS_MODULE: settingsModule })
    return {
      binary,
      args: [...prefix, manage, 'runserver', `${input.runtime.bindHost}:${port}`, '--noreload'],
      cwd: root,
      environment: { PYTHONUNBUFFERED: '1', DJANGO_SETTINGS_MODULE: settingsModule },
      endpointSuffix: '',
    }
  }

  private async runCommand(binary: string, args: string[], cwd: string, environment: Record<string, string | undefined> = {}) {
    await new Promise<void>((resolveRun, rejectRun) => {
      const child = this.spawnImpl(binary, args, { cwd, env: runtimeEnvironment(cwd, environment), stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, shell: false })
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
      await symlink(modulesRoot, join(runtimeRoot, 'node_modules'), 'junction')
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
    const paths = dataPaths(input.dataDir)
    const dataRoot = paths.root
    const sourcePath = resolve(sourceRoot)
    const dataPrefix = dataRoot.endsWith(sep) ? dataRoot : `${dataRoot}${sep}`
    if (sourcePath !== dataRoot && !sourcePath.startsWith(dataPrefix)) throw new ProviderError(`${processErrorPrefix[this.id]}_SOURCE_OUTSIDE_DATA`, '靶场资源必须位于 VulnLab 数据目录内。', 409)
    const runtimeRoot = paths.runtimeInstance(input.instanceId)
    // WebGoat 需要同时预留主端口和 WebWolf 辅助端口。辅助端口分配失败时，
    // 主端口也必须立即释放，否则每次重试都会留下一个不可见的保留端口，
    // 最终把端口池耗尽。
    const port = await this.claimPort(input.runtime)
    let auxiliaryPort: number | undefined
    try {
      auxiliaryPort = this.id === 'native-java' && (input.lab.runtimeConfig?.profile ?? 'webgoat') === 'webgoat'
        ? await this.claimFollowingPort(input.runtime, port)
        : undefined
    } catch (error) {
      this.reservedPorts.delete(port)
      throw error
    }
    let child: ChildProcess | null = null
    let stderrTail = ''
    try {
      await mkdir(paths.runtime, { recursive: true })
      await rm(runtimeRoot, { recursive: true, force: true })
      await mkdir(runtimeRoot, { recursive: true })
      const sourceInfo = await stat(sourcePath)
      if (sourceInfo.isDirectory()) await this.copyRuntimeSource(sourcePath, runtimeRoot)
      const command = await this.command(input, runtimeRoot, port, auxiliaryPort)
      child = this.spawnImpl(command.binary, command.args, {
        cwd: command.cwd,
        env: runtimeEnvironment(command.cwd, command.environment),
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
    const { expiresAt } = renewalLease(input.instance, input.lifetimeMinutes)
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
    const root = dataPaths(input.dataDir).runtimeInstance(input.instance.id)
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
      if (provider.id === 'oa-local') {
        this.providers.set('oa-project', provider)
        this.providers.set('oa-appcontainer', provider)
      }
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
    await Promise.allSettled([...new Set(this.providers.values())].map(provider => provider.shutdown?.()))
  }

  async recoverPending(dataDir: string, activeInstanceIds: ReadonlySet<string>) {
    const recovered: string[] = []
    for (const provider of new Set(this.providers.values())) {
      if (provider.recoverPending) recovered.push(...await provider.recoverPending(dataDir, activeInstanceIds))
    }
    return recovered
  }
}

export const providerRegistry = new ProviderRegistry([
  new NativePhpProvider(),
  new NativeOaProvider(),
  new DockerOaProvider(),
  new NativeComposeProvider(),
  new NativeProcessProvider('native-node'),
  new NativeProcessProvider('native-java'),
  new NativeProcessProvider('native-python'),
])
