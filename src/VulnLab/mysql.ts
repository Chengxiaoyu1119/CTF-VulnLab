import { execFile, type ExecFileOptions } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'

export interface MySqlRuntimeConfig {
  host: string
  port: number
  adminUser: string
  adminPassword: string
  appHost: string
  mysqlBinary: string
}

export interface MySqlResource {
  host: string
  port: number
  database: string
  user: string
  password: string
  appHost: string
  config: MySqlRuntimeConfig
}

export interface MySqlProvisionInput {
  labSlug: string
  instanceId: string
  config: MySqlRuntimeConfig
}

export interface MySqlCleanupInput {
  labSlug: string
  instanceId: string
  config: MySqlRuntimeConfig
}

export interface MySqlManager {
  provision(input: MySqlProvisionInput): Promise<MySqlResource>
  verify(resource: MySqlResource): Promise<void>
  destroy(resource: MySqlResource): Promise<void>
  destroyForInstance(input: MySqlCleanupInput): Promise<void>
}

interface ExecFileResult {
  stdout: string
  stderr: string
}

export class MySqlManagerError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
    this.name = 'MySqlManagerError'
  }
}

type ExecFileImpl = (file: string, args: string[], options: ExecFileOptions) => Promise<ExecFileResult>

const defaultExecFile: ExecFileImpl = (file, args, options) => new Promise((resolve, reject) => {
  execFile(file, args, options, (error, stdout, stderr) => {
    if (error) {
      const detail = typeof stderr === 'string' && stderr.trim() ? ` ${stderr.trim()}` : ''
      error.message = `${error.message}${detail}`
      reject(error)
      return
    }
    resolve({ stdout: String(stdout), stderr: String(stderr) })
  })
})

export interface CliMySqlManagerOptions {
  execFileImpl?: ExecFileImpl
  passwordBytes?: (size: number) => Uint8Array
}

const mysqlIdentifier = (value: string) => `\`${value.replaceAll('`', '``')}\``
const mysqlString = (value: string) => `'${value.replaceAll('\\', '\\\\').replaceAll("'", "\\'").replaceAll('\0', '')}'`

const normalizedToken = (value: string, fallback: string) => value
  .replace(/[^a-z0-9]+/gi, '_')
  .replace(/^_+|_+$/g, '')
  .toLowerCase()
  .slice(0, 20) || fallback

const resourceNames = (labSlug: string, instanceId: string) => {
  const identity = createHash('sha256').update(`${labSlug}:${instanceId}`).digest('hex').slice(0, 16)
  const labToken = normalizedToken(labSlug, 'lab')
  return {
    database: `vulnlab_${labToken}_${identity}`.slice(0, 64),
    user: `vl_${normalizedToken(labSlug, 'lab').slice(0, 8)}_${identity}`.slice(0, 32),
  }
}

const validateConfig = (config: MySqlRuntimeConfig) => {
  if (!config.host.trim() || !Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new MySqlManagerError('MYSQL_CONFIG_INVALID', 'MySQL 主机或端口配置无效。')
  }
  if (!config.adminUser.trim()) throw new MySqlManagerError('MYSQL_ADMIN_NOT_CONFIGURED', '尚未配置 MySQL 管理账号。')
  if (!config.appHost.trim()) throw new MySqlManagerError('MYSQL_APP_HOST_INVALID', 'MySQL 靶场账号主机配置无效。')
  if (!config.mysqlBinary.trim()) throw new MySqlManagerError('MYSQL_BINARY_INVALID', 'MySQL 客户端路径配置无效。')
}

export const mysqlResourceNames = resourceNames

export class CliMySqlManager implements MySqlManager {
  private readonly execFileImpl: ExecFileImpl
  private readonly passwordBytes: (size: number) => Uint8Array

  constructor(options: CliMySqlManagerOptions = {}) {
    this.execFileImpl = options.execFileImpl ?? defaultExecFile
    this.passwordBytes = options.passwordBytes ?? ((size: number) => randomBytes(size))
  }

  private async execute(config: MySqlRuntimeConfig, user: string, password: string, sql: string) {
    validateConfig(config)
    const args = [
      '--protocol=tcp',
      '--host', config.host,
      '--port', String(config.port),
      '--user', user,
      '--batch',
      '--skip-column-names',
      '--execute', sql,
    ]
    try {
      return await this.execFileImpl(config.mysqlBinary, args, {
        env: { ...process.env, MYSQL_PWD: password },
        timeout: 15_000,
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      })
    } catch (error) {
      throw new MySqlManagerError('MYSQL_COMMAND_FAILED', error instanceof Error ? error.message : 'MySQL 客户端执行失败。')
    }
  }

  private async destroyIdentity(config: MySqlRuntimeConfig, database: string, user: string, appHost: string) {
    await this.execute(
      config,
      config.adminUser,
      config.adminPassword,
      `DROP DATABASE IF EXISTS ${mysqlIdentifier(database)}; DROP USER IF EXISTS ${mysqlString(user)}@${mysqlString(appHost)}; FLUSH PRIVILEGES;`,
    )
  }

  async provision(input: MySqlProvisionInput): Promise<MySqlResource> {
    validateConfig(input.config)
    const names = resourceNames(input.labSlug, input.instanceId)
    const password = Buffer.from(this.passwordBytes(24)).toString('base64url')
    const resource: MySqlResource = {
      host: input.config.host,
      port: input.config.port,
      database: names.database,
      user: names.user,
      password,
      appHost: input.config.appHost,
      config: input.config,
    }
    try {
      await this.execute(
        input.config,
        input.config.adminUser,
        input.config.adminPassword,
        `DROP DATABASE IF EXISTS ${mysqlIdentifier(resource.database)}; DROP USER IF EXISTS ${mysqlString(resource.user)}@${mysqlString(resource.appHost)}; CREATE DATABASE ${mysqlIdentifier(resource.database)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER ${mysqlString(resource.user)}@${mysqlString(resource.appHost)} IDENTIFIED BY ${mysqlString(resource.password)}; GRANT ALL PRIVILEGES ON ${mysqlIdentifier(resource.database)}.* TO ${mysqlString(resource.user)}@${mysqlString(resource.appHost)}; FLUSH PRIVILEGES;`,
      )
      return resource
    } catch (error) {
      await this.destroyIdentity(input.config, resource.database, resource.user, resource.appHost).catch(() => undefined)
      throw error
    }
  }

  async verify(resource: MySqlResource) {
    await this.execute(resource.config, resource.user, resource.password, `USE ${mysqlIdentifier(resource.database)}; SELECT 1;`)
  }

  async destroy(resource: MySqlResource) {
    await this.destroyIdentity(resource.config, resource.database, resource.user, resource.appHost)
  }

  async destroyForInstance(input: MySqlCleanupInput) {
    validateConfig(input.config)
    const names = resourceNames(input.labSlug, input.instanceId)
    await this.destroyIdentity(input.config, names.database, names.user, input.config.appHost)
  }
}

export const mysqlRuntimeConfigFromEnv = (): MySqlRuntimeConfig | undefined => {
  const adminUser = process.env.VULNLAB_MYSQL_ADMIN_USER?.trim()
  if (!adminUser) return undefined
  const configuredPort = Number(process.env.VULNLAB_MYSQL_PORT ?? 3306)
  return {
    host: process.env.VULNLAB_MYSQL_HOST?.trim() || '127.0.0.1',
    port: Number.isInteger(configuredPort) ? configuredPort : 3306,
    adminUser,
    adminPassword: process.env.VULNLAB_MYSQL_ADMIN_PASSWORD ?? '',
    appHost: process.env.VULNLAB_MYSQL_APP_HOST?.trim() || '127.0.0.1',
    mysqlBinary: process.env.VULNLAB_MYSQL_BIN?.trim() || 'mysql',
  }
}
