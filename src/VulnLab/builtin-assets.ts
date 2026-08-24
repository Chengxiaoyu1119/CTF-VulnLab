import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, open, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { createGunzip } from 'node:zlib'
import { unzipSync } from 'fflate'
import type { ImportManifest, Lab } from './types.js'

const MAX_ASSET_BYTES = 512 * 1024 ** 2
const MAX_EXTRACTED_BYTES = 2 * 1024 ** 3
const MAX_FILES = 100_000

export class BuiltinAssetError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BuiltinAssetError'
  }
}

interface BuiltinAsset {
  url: string
  checksumUrl?: string
  sha256?: string
  kind: 'zip' | 'tgz' | 'file'
  filename: string
}

const juiceShopAsset = (): BuiltinAsset => {
  const platform = process.platform
  const arch = process.arch
  const suffix = platform === 'win32' && arch === 'x64'
    ? 'win32_x64.zip'
    : platform === 'linux' && arch === 'x64'
      ? 'linux_x64.tgz'
      : platform === 'linux' && arch === 'arm64'
        ? 'linux_arm64.tgz'
        : platform === 'darwin' && arch === 'arm64'
          ? 'darwin_arm64.zip'
          : ''
  if (!suffix) throw new BuiltinAssetError(`Juice Shop 暂未提供 ${platform}/${arch} 的内置发行包。`)
  const filename = `juice-shop-20.2.0_node22_${suffix}`
  const url = `https://github.com/juice-shop/juice-shop/releases/download/v20.2.0/${filename}`
  return { url, checksumUrl: `${url}.md5`, kind: suffix.endsWith('.tgz') ? 'tgz' : 'zip', filename }
}

const assets: Record<string, () => BuiltinAsset> = {
  'juice-shop': juiceShopAsset,
  webgoat: () => ({
    url: 'https://github.com/WebGoat/WebGoat/releases/download/v2023.8/webgoat-2023.8.jar',
    sha256: '43a76e3e478d7db23c2be91005dc744a5b2fad19902ef6fa4c6af7013b9b50d9',
    kind: 'file',
    filename: 'webgoat-2023.8.jar',
  }),
}

export const hasBuiltinAsset = (slug: string) => Boolean(assets[slug])

const safeSegments = (value: string) => {
  const normalized = value.replaceAll('\\', '/').replace(/^\.\//, '')
  const segments = normalized.split('/').filter(Boolean)
  if (!segments.length || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || segments.some(segment => segment === '..' || segment.includes('\0') || segment.includes(':'))) {
    throw new BuiltinAssetError('发行包包含不可用路径。')
  }
  return segments
}

const safeTarget = (root: string, segments: string[]) => {
  const target = resolve(root, ...segments)
  const resolvedRoot = resolve(root)
  const prefix = resolvedRoot.endsWith(sep) ? resolvedRoot : `${resolvedRoot}${sep}`
  if (target !== resolvedRoot && !target.startsWith(prefix)) throw new BuiltinAssetError('发行包路径越出安装目录。')
  return target
}

const fetchText = async (url: string, signal?: AbortSignal, fetchImpl: typeof fetch = fetch) => {
  const response = await fetchImpl(url, { signal, headers: { accept: 'text/plain', 'user-agent': 'VulnLab/0.3' } })
  if (!response.ok) throw new BuiltinAssetError(`读取官方校验文件失败（HTTP ${response.status}）。`)
  return response.text()
}

const download = async (url: string, destination: string, signal: AbortSignal | undefined, onProgress: (progress: number, stage: string, message: string) => void, fetchImpl: typeof fetch) => {
  const response = await fetchImpl(url, { signal, redirect: 'follow', headers: { accept: 'application/octet-stream', 'user-agent': 'VulnLab/0.3' } })
  if (!response.ok || !response.body) throw new BuiltinAssetError(`下载官方发行包失败（HTTP ${response.status}）。`)
  const declaredLength = Number(response.headers.get('content-length') ?? 0)
  if (declaredLength > MAX_ASSET_BYTES) throw new BuiltinAssetError('官方发行包超过 512 MiB 安装上限。')
  await mkdir(dirname(destination), { recursive: true })
  const handle = await open(destination, 'w')
  const reader = response.body.getReader()
  const sha256 = createHash('sha256')
  const md5 = createHash('md5')
  let received = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      received += value.byteLength
      if (received > MAX_ASSET_BYTES) throw new BuiltinAssetError('官方发行包超过 512 MiB 安装上限。')
      sha256.update(value)
      md5.update(value)
      await handle.write(value)
      const ratio = declaredLength > 0 ? received / declaredLength : 0
      onProgress(15 + Math.min(45, Math.round(ratio * 45)), 'download', `正在下载发行包 ${Math.round(received / 1024 / 1024)} MiB。`)
    }
  } finally {
    await handle.close()
  }
  if (declaredLength > 0 && received !== declaredLength) throw new BuiltinAssetError('官方发行包下载不完整。')
  return { bytes: received, sha256: sha256.digest('hex'), md5: md5.digest('hex') }
}

const extractZip = async (archivePath: string, targetRoot: string, onProgress: (progress: number, stage: string, message: string) => void) => {
  const archive = await readFile(archivePath)
  let files: Record<string, Uint8Array>
  try {
    files = unzipSync(archive)
  } catch {
    throw new BuiltinAssetError('官方 ZIP 发行包解压失败。')
  }
  const entries = Object.entries(files).filter(([name]) => !name.endsWith('/')).map(([name, bytes]) => ({ segments: safeSegments(name), bytes }))
  if (!entries.length || entries.length > MAX_FILES) throw new BuiltinAssetError('官方发行包文件数量异常。')
  const totalBytes = entries.reduce((total, entry) => total + entry.bytes.byteLength, 0)
  if (totalBytes > MAX_EXTRACTED_BYTES) throw new BuiltinAssetError('官方发行包解压内容超过 2 GiB 上限。')
  const commonRoot = entries.every(entry => entry.segments[0] === entries[0]?.segments[0]) ? entries[0]?.segments[0] : null
  for (const [index, entry] of entries.entries()) {
    const segments = commonRoot && entry.segments.length > 1 ? entry.segments.slice(1) : entry.segments
    if (!segments.length) continue
    const target = safeTarget(targetRoot, segments)
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, entry.bytes)
    if (index % Math.max(1, Math.floor(entries.length / 10)) === 0) onProgress(65 + Math.round(index / entries.length * 25), 'extract', `正在解压 ${index + 1}/${entries.length}。`)
  }
  return { fileCount: entries.length, totalBytes }
}

const tarText = (header: Buffer, offset: number, length: number) => header.subarray(offset, offset + length).toString('utf8').replace(/\0.*$/, '').trim()

const extractTarGz = async (archivePath: string, targetRoot: string, onProgress: (progress: number, stage: string, message: string) => void) => {
  const stream = createReadStream(archivePath).pipe(createGunzip())
  let pending = Buffer.alloc(0)
  let remaining = 0
  let padding = 0
  let output: Awaited<ReturnType<typeof open>> | null = null
  let fileCount = 0
  let totalBytes = 0
  let ended = false
  const closeOutput = async () => {
    if (!output) return
    await output.close()
    output = null
  }
  try {
    for await (const rawChunk of stream) {
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk)
      pending = pending.length ? Buffer.concat([pending, chunk]) : chunk
      while (pending.length) {
        if (remaining > 0) {
          const size = Math.min(remaining, pending.length)
          if (output) await output.write(pending.subarray(0, size))
          pending = pending.subarray(size)
          remaining -= size
          if (remaining === 0) await closeOutput()
          continue
        }
        if (padding > 0) {
          const size = Math.min(padding, pending.length)
          pending = pending.subarray(size)
          padding -= size
          continue
        }
        if (ended || pending.length < 512) break
        const header = pending.subarray(0, 512)
        pending = pending.subarray(512)
        if (header.every(byte => byte === 0)) {
          ended = true
          break
        }
        const name = tarText(header, 0, 100)
        const prefix = tarText(header, 345, 155)
        const fullName = prefix ? `${prefix}/${name}` : name
        const segments = safeSegments(fullName)
        const rawSize = tarText(header, 124, 12)
        if (!/^[0-7]*$/.test(rawSize)) throw new BuiltinAssetError('TAR 发行包包含无效文件大小。')
        const size = rawSize ? Number.parseInt(rawSize, 8) : 0
        if (!Number.isSafeInteger(size) || size < 0 || size > MAX_EXTRACTED_BYTES) throw new BuiltinAssetError('TAR 发行包文件大小异常。')
        const type = String.fromCharCode(header[156] ?? 0)
        if (!['\0', '0', '5', 'x', 'g'].includes(type)) throw new BuiltinAssetError('TAR 发行包包含链接或特殊文件。')
        const target = safeTarget(targetRoot, segments)
        if (type === '5') {
          await mkdir(target, { recursive: true })
        } else if (type === '\0' || type === '0') {
          fileCount += 1
          totalBytes += size
          if (fileCount > MAX_FILES || totalBytes > MAX_EXTRACTED_BYTES) throw new BuiltinAssetError('TAR 发行包解压内容超过限制。')
          await mkdir(dirname(target), { recursive: true })
          output = await open(target, 'w')
          if (fileCount % 500 === 0) onProgress(Math.min(90, 65 + Math.round(fileCount / 500)), 'extract', `正在解压 ${fileCount} 个文件。`)
        }
        remaining = size
        padding = (512 - size % 512) % 512
        if (remaining === 0) await closeOutput()
      }
    }
    await closeOutput()
    if (remaining > 0 || !ended || fileCount === 0) throw new BuiltinAssetError('TAR 发行包不完整。')
    const topEntries = await readdir(targetRoot, { withFileTypes: true })
    if (topEntries.length === 1 && topEntries[0]?.isDirectory()) {
      const nestedRoot = join(targetRoot, topEntries[0].name)
      for (const entry of await readdir(nestedRoot)) await rename(join(nestedRoot, entry), join(targetRoot, entry))
      await rm(nestedRoot, { recursive: true, force: true })
    }
    return { fileCount, totalBytes }
  } catch (error) {
    await closeOutput().catch(() => undefined)
    stream.destroy()
    if (error instanceof BuiltinAssetError) throw error
    throw new BuiltinAssetError(error instanceof Error ? error.message : '官方 TAR.GZ 发行包解压失败。')
  }
}

export interface InstallBuiltinAssetInput {
  lab: Lab
  jobId: string
  dataDir: string
  signal?: AbortSignal
  onProgress?: (progress: number, stage: string, message: string) => void
  fetchImpl?: typeof fetch
}

export const installBuiltinAsset = async (input: InstallBuiltinAssetInput): Promise<ImportManifest> => {
  const assetFactory = assets[input.lab.slug]
  if (!assetFactory) throw new BuiltinAssetError('该靶场没有内置发行包安装器。')
  const asset = assetFactory()
  const fetchImpl = input.fetchImpl ?? fetch
  const report = input.onProgress ?? (() => undefined)
  const installRoot = join(resolve(input.dataDir), 'labs', input.lab.slug, input.lab.version)
  const downloadRoot = join(resolve(input.dataDir), 'downloads', input.lab.slug, input.lab.version)
  const archivePath = join(downloadRoot, asset.filename)
  await rm(installRoot, { recursive: true, force: true })
  await mkdir(installRoot, { recursive: true })
  try {
    report(5, 'metadata', '正在读取官方发行信息。')
    const expectedMd5 = asset.checksumUrl
      ? (await fetchText(asset.checksumUrl, input.signal, fetchImpl)).match(/[a-f0-9]{32}/i)?.[0]?.toLowerCase() ?? ''
      : ''
    const downloaded = await download(asset.url, archivePath, input.signal, report, fetchImpl)
    if (expectedMd5 && downloaded.md5 !== expectedMd5) throw new BuiltinAssetError('官方发行包 MD5 校验不一致。')
    if (asset.sha256 && downloaded.sha256 !== asset.sha256) throw new BuiltinAssetError('官方发行包 SHA-256 校验不一致。')
    let localPath = installRoot
    let fileCount = 1
    let totalBytes = downloaded.bytes
    if (asset.kind === 'zip' || asset.kind === 'tgz') {
      report(65, 'extract', '正在解压官方发行包。')
      const extracted = asset.kind === 'zip'
        ? await extractZip(archivePath, installRoot, report)
        : await extractTarGz(archivePath, installRoot, report)
      fileCount = extracted.fileCount
      totalBytes = extracted.totalBytes
    } else {
      localPath = join(installRoot, asset.filename)
      try {
        await rename(archivePath, localPath)
      } catch {
        await writeFile(localPath, await readFile(archivePath))
      }
    }
    const manifest: ImportManifest = {
      adapterId: 'builtin-release',
      sourceUrl: input.lab.sourceUrl,
      sourceRef: input.lab.sourceRef,
      resolvedRef: input.lab.version,
      revision: input.lab.version,
      archiveSha256: downloaded.sha256,
      localPath,
      fileCount,
      totalBytes,
      licenseFiles: [],
      topLevelEntries: [basename(localPath)],
      warnings: expectedMd5 || asset.sha256 ? [] : ['上游未提供独立校验文件，已记录本次下载的 SHA-256。'],
      importedAt: new Date().toISOString(),
    }
    await writeFile(join(installRoot, 'vulnlab.manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
    await rm(downloadRoot, { recursive: true, force: true })
    report(100, 'completed', '官方发行包安装完成。')
    return manifest
  } catch (error) {
    await rm(installRoot, { recursive: true, force: true }).catch(() => undefined)
    await rm(downloadRoot, { recursive: true, force: true }).catch(() => undefined)
    if (error instanceof BuiltinAssetError) throw error
    throw new BuiltinAssetError(error instanceof Error ? error.message : '内置发行包安装失败。')
  }
}
