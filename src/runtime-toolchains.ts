import { execFile } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { closeSync, createReadStream, mkdirSync, openSync, writeSync } from 'node:fs'
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'
import { Unzip, UnzipInflate } from 'fflate'

export type RuntimeToolchainId = 'php' | 'mariadb' | 'node' | 'java' | 'python'
export type RuntimeToolchainState = 'missing' | 'installing' | 'ready' | 'error'

export interface RuntimeToolchainStatus {
  id: RuntimeToolchainId
  label: string
  version: string
  platform: string
  state: RuntimeToolchainState
  detail: string
  sourceUrl: string
  installedPath?: string
  installedBytes: number
  downloadedBytes: number
  sha256Verified: boolean
}

export interface RuntimeToolchainBinaries {
  php?: string
  mysqlClient?: string
  mysqlServer?: string
  node?: string
  java?: string
  python?: string
}

export interface RuntimeToolchainPackage {
  id: RuntimeToolchainId
  label: string
  version: string
  platform: 'win32'
  arch: 'x64'
  url: string
  sha256: string
  filename: string
  kind: 'zip' | 'tgz'
  stripComponents: number
  maxArchiveBytes: number
  maxExtractedBytes: number
  executables: Partial<Record<'php' | 'mysqlClient' | 'mysqlServer' | 'node' | 'java' | 'python', string>>
}

interface InstalledRuntimeManifest {
  id: RuntimeToolchainId
  version: string
  platform: string
  arch: string
  sourceUrl: string
  archiveSha256: string
  installedPath: string
  installedBytes: number
  fileCount: number
  executables: RuntimeToolchainPackage['executables']
  installedAt: string
}

interface RuntimeToolchainInstallerOptions {
  packages?: RuntimeToolchainPackage[]
  fetchImpl?: typeof fetch
  bundleDir?: string
  offline?: boolean
}

const MAX_FILES = 100_000
const DOWNLOAD_TIMEOUT_MS = 10 * 60_000

const errorDetail = (error: unknown) => {
  if (!(error instanceof Error)) return String(error ?? '未知错误')
  const cause = (error as Error & { cause?: unknown }).cause
  const causeMessage = cause instanceof Error ? cause.message : typeof cause === 'string' ? cause : ''
  return causeMessage && causeMessage !== error.message ? `${error.message}：${causeMessage}` : error.message
}

const defaultPackages: RuntimeToolchainPackage[] = [
  {
    id: 'node',
    label: 'Node.js',
    version: '22.23.1',
    platform: 'win32',
    arch: 'x64',
    url: 'https://nodejs.org/dist/v22.23.1/node-v22.23.1-win-x64.zip',
    sha256: '7df0bc9375723f4a86b3aa1b7cc73342423d9677a8df4538aca31a049e309c29',
    filename: 'node-v22.23.1-win-x64.zip',
    kind: 'zip',
    stripComponents: 1,
    maxArchiveBytes: 64 * 1024 ** 2,
    maxExtractedBytes: 256 * 1024 ** 2,
    executables: { node: 'node.exe' },
  },
  {
    id: 'php',
    label: 'PHP',
    version: '8.3.33',
    platform: 'win32',
    arch: 'x64',
    url: 'https://windows.php.net/downloads/releases/php-8.3.33-nts-Win32-vs16-x64.zip',
    sha256: '534399107056313246f424adbbb7937337e40fbbf6aa7bc26287ba9cfd2e4a2a',
    filename: 'php-8.3.33-nts-Win32-vs16-x64.zip',
    kind: 'zip',
    stripComponents: 0,
    maxArchiveBytes: 64 * 1024 ** 2,
    maxExtractedBytes: 256 * 1024 ** 2,
    executables: { php: 'php.exe' },
  },
  {
    id: 'mariadb',
    label: 'MariaDB',
    version: '11.4.10',
    platform: 'win32',
    arch: 'x64',
    url: 'https://dlm.mariadb.com/4566977/MariaDB/mariadb-11.4.10/winx64-packages/mariadb-11.4.10-winx64.zip',
    sha256: 'fb7c76f0804321ee373daa49145f2056d2d88f321b614130adeb05a1644ea003',
    filename: 'mariadb-11.4.10-winx64.zip',
    kind: 'zip',
    stripComponents: 1,
    maxArchiveBytes: 128 * 1024 ** 2,
    maxExtractedBytes: 1024 * 1024 ** 2,
    executables: { mysqlClient: 'bin/mariadb.exe', mysqlServer: 'bin/mariadbd.exe' },
  },
  {
    id: 'java',
    label: 'Eclipse Temurin JRE',
    version: '21.0.12.1',
    platform: 'win32',
    arch: 'x64',
    url: 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.zip',
    sha256: 'd35f31e712f0fcf6ac5a093edc90204fbff22f720ba3950bd09d331d5e621636',
    filename: 'OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.zip',
    kind: 'zip',
    stripComponents: 1,
    maxArchiveBytes: 96 * 1024 ** 2,
    maxExtractedBytes: 256 * 1024 ** 2,
    executables: { java: 'bin/java.exe' },
  },
  {
    id: 'python',
    label: 'Python',
    version: '3.11.16',
    platform: 'win32',
    arch: 'x64',
    url: 'https://github.com/astral-sh/python-build-standalone/releases/download/20260814/cpython-3.11.16%2B20260814-x86_64-pc-windows-msvc-install_only.tar.gz',
    sha256: 'ffaee1e94c8488f833473e56e1c980ca1a58d91126d21ddf0f6ba052e69cf511',
    filename: 'cpython-3.11.16+20260814-x86_64-pc-windows-msvc-install_only.tar.gz',
    kind: 'tgz',
    stripComponents: 1,
    maxArchiveBytes: 96 * 1024 ** 2,
    maxExtractedBytes: 256 * 1024 ** 2,
    executables: { python: 'python.exe' },
  },
]

export class RuntimeToolchainError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RuntimeToolchainError'
  }
}

const fileExists = async (path: string) => (await stat(path).catch(() => null))?.isFile() === true

const directorySize = async (root: string): Promise<number> => {
  const entries = await readdir(root, { withFileTypes: true }).catch(() => [])
  const sizes = await Promise.all(entries.map(async entry => {
    const path = join(root, entry.name)
    if (entry.isDirectory()) return directorySize(path)
    if (!entry.isFile()) return 0
    return (await stat(path).catch(() => null))?.size ?? 0
  }))
  return sizes.reduce((total, size) => total + size, 0)
}

const safeSegments = (value: string) => {
  const normalized = value.replaceAll('\\', '/')
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || normalized.includes('\0')) throw new RuntimeToolchainError('运行时压缩包包含不安全路径。')
  const segments = normalized.split('/').filter(Boolean)
  if (segments.some(segment => segment === '.' || segment === '..' || segment.includes(':'))) throw new RuntimeToolchainError('运行时压缩包包含路径越界内容。')
  return segments
}

const safeTarget = (root: string, segments: string[]) => {
  const target = resolve(root, ...segments)
  const resolvedRoot = resolve(root)
  const prefix = resolvedRoot.endsWith(sep) ? resolvedRoot : `${resolvedRoot}${sep}`
  if (target !== resolvedRoot && !target.startsWith(prefix)) throw new RuntimeToolchainError('运行时解压路径越出项目目录。')
  return target
}

const command = (binary: string, args: string[], timeout = 10 * 60_000) => new Promise<{ stdout: string; stderr: string }>((resolveCommand, rejectCommand) => {
  execFile(binary, args, { timeout, windowsHide: true, maxBuffer: 32 * 1024 ** 2 }, (error, stdout, stderr) => {
    if (error) {
      const detail = String(stderr ?? '').replace(/\s+/g, ' ').trim()
      rejectCommand(new RuntimeToolchainError(`${error.message}${detail ? `：${detail}` : ''}`))
      return
    }
    resolveCommand({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
  })
})

const extractZip = async (archivePath: string, targetRoot: string, input: RuntimeToolchainPackage) => {
  let fileCount = 0
  let totalBytes = 0
  let activeHandle: number | null = null
  const targets = new Set<string>()
  const unzip = new Unzip(file => {
    const sourceSegments = safeSegments(file.name)
    const segments = sourceSegments.slice(input.stripComponents)
    const directory = file.name.endsWith('/')
    if (!segments.length) {
      file.ondata = error => { if (error) throw error }
      file.start()
      return
    }
    const target = safeTarget(targetRoot, segments)
    const key = target.toLowerCase()
    if (targets.has(key)) throw new RuntimeToolchainError(`运行时压缩包包含重复路径：${segments.join('/')}。`)
    targets.add(key)
    fileCount += 1
    if (fileCount > MAX_FILES) throw new RuntimeToolchainError('运行时压缩包文件数量超过上限。')
    if (directory) mkdirSync(target, { recursive: true })
    else {
      mkdirSync(dirname(target), { recursive: true })
      activeHandle = openSync(target, 'wx')
    }
    file.ondata = (error, chunk, final) => {
      if (error) throw new RuntimeToolchainError(`运行时 ZIP 解压失败：${error.message}`)
      if (!directory && activeHandle !== null && chunk.byteLength) writeSync(activeHandle, chunk)
      totalBytes += chunk.byteLength
      if (totalBytes > input.maxExtractedBytes) throw new RuntimeToolchainError('运行时解压内容超过大小上限。')
      if (final && activeHandle !== null) {
        closeSync(activeHandle)
        activeHandle = null
      }
    }
    file.start()
  })
  unzip.register(UnzipInflate)
  try {
    for await (const chunk of createReadStream(archivePath)) unzip.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk), false)
    unzip.push(new Uint8Array(0), true)
  } catch (error) {
    if (activeHandle !== null) closeSync(activeHandle)
    throw error instanceof RuntimeToolchainError ? error : new RuntimeToolchainError(error instanceof Error ? error.message : '运行时 ZIP 解压失败。')
  }
  if (!fileCount) throw new RuntimeToolchainError('运行时压缩包中没有文件。')
  return { fileCount, totalBytes }
}

const extractTar = async (archivePath: string, targetRoot: string, input: RuntimeToolchainPackage) => {
  const listing = await command('tar', ['-tzf', archivePath])
  const entries = listing.stdout.split(/\r?\n/).filter(Boolean)
  if (!entries.length || entries.length > MAX_FILES) throw new RuntimeToolchainError('运行时 TAR 文件数量异常。')
  for (const entry of entries) safeSegments(entry)
  await command('tar', [
    '-xzf', archivePath,
    '-C', targetRoot,
    `--strip-components=${input.stripComponents}`,
  ])
  const totalBytes = await directorySize(targetRoot)
  if (totalBytes > input.maxExtractedBytes) throw new RuntimeToolchainError('运行时解压内容超过大小上限。')
  return { fileCount: entries.length, totalBytes }
}

const readManifest = async (path: string) => {
  try {
    return JSON.parse((await readFile(path, 'utf8')).replace(/^\uFEFF/, '')) as InstalledRuntimeManifest
  } catch {
    return null
  }
}

export class RuntimeToolchainInstaller {
  private readonly runtimeDir: string
  private readonly packages: RuntimeToolchainPackage[]
  private readonly fetchImpl: typeof fetch
  private readonly bundleDir?: string
  private readonly offline: boolean
  private statuses: RuntimeToolchainStatus[] = []
  private installPromise: Promise<RuntimeToolchainStatus[]> | null = null

  constructor(runtimeDir: string, options: RuntimeToolchainInstallerOptions = {}) {
    this.runtimeDir = resolve(runtimeDir)
    this.packages = options.packages ?? defaultPackages
    this.fetchImpl = options.fetchImpl ?? fetch
    this.bundleDir = options.bundleDir?.trim() ? resolve(options.bundleDir) : undefined
    this.offline = options.offline === true
  }

  private installRoot(input: RuntimeToolchainPackage) {
    return join(this.runtimeDir, 'toolchains', input.id, input.version, `${input.platform}-${input.arch}`)
  }

  private manifestPath(input: RuntimeToolchainPackage) {
    return join(this.runtimeDir, 'manifests', `${input.id}-${input.version}-${input.platform}-${input.arch}.json`)
  }

  private status(input: RuntimeToolchainPackage, values: Partial<RuntimeToolchainStatus> = {}): RuntimeToolchainStatus {
    return {
      id: input.id,
      label: input.label,
      version: input.version,
      platform: `${input.platform}/${input.arch}`,
      state: 'missing',
      detail: '尚未下载到项目目录',
      sourceUrl: input.url,
      installedBytes: 0,
      downloadedBytes: 0,
      sha256Verified: false,
      ...values,
    }
  }

  private async inspectPackage(input: RuntimeToolchainPackage) {
    const root = this.installRoot(input)
    const manifest = await readManifest(this.manifestPath(input))
    const matches = manifest?.id === input.id
      && manifest.version === input.version
      && manifest.platform === input.platform
      && manifest.arch === input.arch
      && manifest.archiveSha256 === input.sha256
    const executablePaths = Object.values(input.executables).filter((value): value is string => Boolean(value)).map(value => join(root, value))
    const ready = Boolean(matches && executablePaths.length && (await Promise.all(executablePaths.map(fileExists))).every(Boolean))
    if (!ready) {
      const previous = this.statuses.find(item => item.id === input.id)
      return previous?.state === 'error' ? previous : this.status(input)
    }
    const installedBytes = manifest?.installedBytes || await directorySize(root)
    return this.status(input, {
      state: 'ready',
      detail: `${input.version} · SHA-256 已校验`,
      installedPath: root,
      installedBytes,
      downloadedBytes: 0,
      sha256Verified: true,
    })
  }

  async inspect() {
    this.statuses = await Promise.all(this.packages.map(input => this.inspectPackage(input)))
    return this.getStatuses()
  }

  private updateStatus(id: RuntimeToolchainId, values: Partial<RuntimeToolchainStatus>) {
    this.statuses = this.statuses.map(item => item.id === id ? { ...item, ...values } : item)
  }

  private async download(input: RuntimeToolchainPackage, destination: string) {
    const response = await this.fetchImpl(input.url, {
      redirect: 'follow',
      signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS),
      headers: { accept: 'application/octet-stream', 'user-agent': 'VulnLab/0.3' },
    })
    if (!response.ok || !response.body) throw new RuntimeToolchainError(`下载 ${input.label} 失败（HTTP ${response.status}）。`)
    const declared = Number(response.headers.get('content-length') ?? 0)
    if (declared > input.maxArchiveBytes) throw new RuntimeToolchainError(`${input.label} 发行包超过下载上限。`)
    const handle = await import('node:fs/promises').then(module => module.open(destination, 'w'))
    const hash = createHash('sha256')
    let downloadedBytes = 0
    try {
      const reader = response.body.getReader()
      while (true) {
        const next = await reader.read()
        if (next.done) break
        downloadedBytes += next.value.byteLength
        if (downloadedBytes > input.maxArchiveBytes) throw new RuntimeToolchainError(`${input.label} 发行包超过下载上限。`)
        hash.update(next.value)
        await handle.write(next.value)
        this.updateStatus(input.id, { downloadedBytes, detail: `正在下载 ${Math.round(downloadedBytes / 1024 / 1024)} MiB` })
      }
    } finally {
      await handle.close()
    }
    if (declared > 0 && downloadedBytes !== declared) throw new RuntimeToolchainError(`${input.label} 发行包下载不完整。`)
    const actual = hash.digest('hex')
    if (actual !== input.sha256) throw new RuntimeToolchainError(`${input.label} SHA-256 校验失败。`)
    return downloadedBytes
  }

  private async copyBundledArchive(input: RuntimeToolchainPackage, destination: string) {
    if (!this.bundleDir) return null
    const bundleRoot = resolve(this.bundleDir)
    const archivePath = resolve(bundleRoot, 'runtime', input.filename)
    const prefix = bundleRoot.endsWith(sep) ? bundleRoot : `${bundleRoot}${sep}`
    if (archivePath !== bundleRoot && !archivePath.startsWith(prefix)) throw new RuntimeToolchainError('离线运行时包路径超出 bundle 目录。')
    if (!await fileExists(archivePath)) return null
    const archive = await readFile(archivePath)
    if (archive.byteLength > input.maxArchiveBytes) throw new RuntimeToolchainError(`${input.label} 离线发行包超过大小限制。`)
    const actual = createHash('sha256').update(archive).digest('hex')
    if (actual !== input.sha256) throw new RuntimeToolchainError(`${input.label} 离线发行包 SHA-256 校验失败。`)
    await mkdir(dirname(destination), { recursive: true })
    await writeFile(destination, archive)
    this.updateStatus(input.id, { detail: '已读取项目离线运行时包', downloadedBytes: archive.byteLength, sha256Verified: true })
    return archive.byteLength
  }

  private async installPackage(input: RuntimeToolchainPackage) {
    const finalRoot = this.installRoot(input)
    const stagingRoot = join(this.runtimeDir, 'toolchains', `.staging-${input.id}-${randomUUID()}`)
    const downloadPath = join(this.runtimeDir, 'downloads', `${input.filename}.part`)
    await mkdir(dirname(downloadPath), { recursive: true })
    await mkdir(dirname(finalRoot), { recursive: true })
    await mkdir(stagingRoot, { recursive: true })
    this.updateStatus(input.id, { state: 'installing', detail: '正在准备运行时包', downloadedBytes: 0 })
    try {
      const bundledBytes = await this.copyBundledArchive(input, downloadPath)
      const downloadedBytes = bundledBytes ?? (this.offline
        ? (() => { throw new RuntimeToolchainError(`${input.label} 离线模式未找到已校验发行包。`) })()
        : await this.download(input, downloadPath))
      this.updateStatus(input.id, { detail: '校验通过，正在安全解压', downloadedBytes, sha256Verified: true })
      const extracted = input.kind === 'zip'
        ? await extractZip(downloadPath, stagingRoot, input)
        : await extractTar(downloadPath, stagingRoot, input)
      for (const relativePath of Object.values(input.executables).filter((value): value is string => Boolean(value))) {
        const executable = join(stagingRoot, relativePath)
        if (!await fileExists(executable)) throw new RuntimeToolchainError(`${input.label} 缺少启动文件 ${relativePath}。`)
      }
      await rm(finalRoot, { recursive: true, force: true })
      await rename(stagingRoot, finalRoot)
      const installedBytes = await directorySize(finalRoot)
      const manifest: InstalledRuntimeManifest = {
        id: input.id,
        version: input.version,
        platform: input.platform,
        arch: input.arch,
        sourceUrl: input.url,
        archiveSha256: input.sha256,
        installedPath: finalRoot,
        installedBytes,
        fileCount: extracted.fileCount,
        executables: input.executables,
        installedAt: new Date().toISOString(),
      }
      await mkdir(dirname(this.manifestPath(input)), { recursive: true })
      await writeFile(this.manifestPath(input), JSON.stringify(manifest, null, 2), 'utf8')
      this.updateStatus(input.id, {
        state: 'ready',
        detail: `${input.version} · SHA-256 已校验`,
        installedPath: finalRoot,
        installedBytes,
        downloadedBytes,
        sha256Verified: true,
      })
    } catch (error) {
      const detail = errorDetail(error) || `${input.label} 安装失败。`
      this.updateStatus(input.id, { state: 'error', detail })
      throw error instanceof RuntimeToolchainError ? error : new RuntimeToolchainError(detail)
    } finally {
      await rm(stagingRoot, { recursive: true, force: true }).catch(() => undefined)
      await rm(downloadPath, { force: true }).catch(() => undefined)
    }
  }

  async installMissing() {
    if (this.installPromise) return this.installPromise
    this.installPromise = (async () => {
      await this.inspect()
      for (const input of this.packages) {
        if (this.statuses.find(item => item.id === input.id)?.state !== 'ready') await this.installPackage(input)
      }
      return this.getStatuses()
    })()
    try {
      return await this.installPromise
    } finally {
      this.installPromise = null
    }
  }

  async binaries(): Promise<RuntimeToolchainBinaries> {
    await this.inspect()
    const result: RuntimeToolchainBinaries = {}
    for (const input of this.packages) {
      const status = this.statuses.find(item => item.id === input.id)
      if (status?.state !== 'ready') continue
      const root = this.installRoot(input)
      if (input.executables.php) result.php = join(root, input.executables.php)
      if (input.executables.mysqlClient) result.mysqlClient = join(root, input.executables.mysqlClient)
      if (input.executables.mysqlServer) result.mysqlServer = join(root, input.executables.mysqlServer)
      if (input.executables.node) result.node = join(root, input.executables.node)
      if (input.executables.java) result.java = join(root, input.executables.java)
      if (input.executables.python) result.python = join(root, input.executables.python)
    }
    return result
  }

  getStatuses() {
    return this.statuses.map(item => ({ ...item }))
  }

  platformLabel() {
    return 'win32/x64'
  }
}

export const runtimeToolchainPackages = () => defaultPackages.map(item => ({ ...item, executables: { ...item.executables } }))
