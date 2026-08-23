import { createHash } from 'node:crypto'
import { mkdir, open, rename, rm, statfs } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import type { VmDownload } from './types.js'
import type { VulnHubCatalogEntry } from './vulnhub.js'

const DOWNLOAD_HOST = 'download.vulnhub.com'
const PROGRESS_BYTES = 512 * 1024
const PROGRESS_INTERVAL_MS = 500
const DISK_CHECK_BYTES = 16 * 1024 * 1024
const MIN_FREE_BYTES = 64 * 1024 * 1024

export class VmDownloadError extends Error {
  constructor(readonly code: string, message: string, readonly statusCode = 409) {
    super(message)
    this.name = 'VmDownloadError'
  }
}

export interface VmDownloadInput {
  download: VmDownload
  entry: VulnHubCatalogEntry
  dataDir: string
  maxBytes: number
  signal?: AbortSignal
  fetchImpl?: typeof fetch
  onProgress?: (value: { progress: number; bytesDownloaded: number; totalBytes: number | null; message: string }) => void
}

export interface VmDownloadResult {
  localPath: string
  filename: string
  bytesDownloaded: number
  totalBytes: number | null
  md5: string
  sha1: string
  sha256: string
  checksumVerified: boolean
}

const safeHash = (value: string | null, length: number, label: string) => {
  const normalized = value?.trim().toLowerCase() ?? ''
  if (!normalized) return null
  if (['n/a', 'na', 'unknown', '-', '—'].includes(normalized)) return null
  if (!new RegExp(`^[a-f0-9]{${length}}$`).test(normalized)) throw new VmDownloadError('VM_CHECKSUM_INVALID', `VulnHub ${label} 校验值格式无效。`)
  return normalized
}

const officialDownloadUrl = (value: string) => {
  let parsed: URL
  try { parsed = new URL(value) } catch { throw new VmDownloadError('VM_DOWNLOAD_URL_INVALID', 'VulnHub 镜像地址无效。') }
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== DOWNLOAD_HOST || parsed.username || parsed.password) {
    throw new VmDownloadError('VM_DOWNLOAD_URL_INVALID', 'VulnHub 镜像地址必须来自官方 HTTPS 下载域名。')
  }
  return parsed.toString()
}

export const vmDownloadFilename = (entry: VulnHubCatalogEntry, downloadUrl: string, entryIndex: number) => {
  const fromEntry = entry.filename?.trim() || new URL(downloadUrl).pathname.split('/').filter(Boolean).pop() || `vulnhub-${entryIndex + 1}.ova`
  const filename = fromEntry.replaceAll('\\', '/').split('/').pop()?.replace(/[<>:"|?*\x00-\x1f]/g, '_').replace(/\.+$/, '').trim() ?? ''
  if (!filename || filename === '.' || filename === '..' || filename.length > 160) throw new VmDownloadError('VM_FILENAME_INVALID', 'VulnHub 镜像文件名无效。')
  return filename
}

const checkFreeSpace = async (root: string, requiredBytes: number) => {
  try {
    const stats = await statfs(root)
    const freeBytes = Number(stats.bavail) * Number(stats.bsize)
    if (!Number.isFinite(freeBytes) || freeBytes < requiredBytes) throw new VmDownloadError('VM_DISK_SPACE_LOW', `磁盘可用空间不足，至少需要 ${Math.ceil(requiredBytes / 1024 / 1024)} MiB。`)
  } catch (error) {
    if (error instanceof VmDownloadError) throw error
    throw new VmDownloadError('VM_DISK_CHECK_FAILED', '无法检查镜像目录所在磁盘的可用空间。', 503)
  }
}

const cancelResponseBody = async (response: Response | null) => {
  if (!response?.body) return
  await response.body.cancel().catch(() => undefined)
}

const fetchWithHeaderTimeout = async (fetchImpl: typeof fetch, url: string, signal?: AbortSignal) => {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 60_000)
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  try {
    const response = await fetchImpl(url, { signal: controller.signal, headers: { accept: 'application/octet-stream', 'user-agent': 'VulnLab/0.2' } })
    clearTimeout(timeout)
    const responseUrl = new URL(response.url || url)
    if (responseUrl.protocol !== 'https:' || responseUrl.hostname.toLowerCase() !== DOWNLOAD_HOST) {
      await cancelResponseBody(response)
      throw new VmDownloadError('VM_REDIRECT_INVALID', '镜像下载被重定向到非官方域名。')
    }
    return { response, cleanup: () => signal?.removeEventListener('abort', abort) }
  } catch (error) {
    clearTimeout(timeout)
    signal?.removeEventListener('abort', abort)
    if (signal?.aborted) throw new VmDownloadError('VM_DOWNLOAD_ABORTED', '镜像下载已中断。', 409)
    if (error instanceof VmDownloadError) throw error
    if ((error as DOMException)?.name === 'AbortError') throw new VmDownloadError('VM_DOWNLOAD_TIMEOUT', '镜像下载连接超时。', 504)
    throw new VmDownloadError('VM_DOWNLOAD_FAILED', error instanceof Error ? error.message : '镜像下载失败。', 502)
  }
}

export const downloadVmImage = async (input: VmDownloadInput): Promise<VmDownloadResult> => {
  if (!Number.isInteger(input.maxBytes) || input.maxBytes <= 0) throw new VmDownloadError('VM_MAX_BYTES_INVALID', '镜像大小上限无效。', 500)
  const downloadUrl = officialDownloadUrl(input.download.downloadUrl)
  if (!/^[A-Za-z0-9-]+$/.test(input.download.labId)) throw new VmDownloadError('VM_LAB_ID_INVALID', '靶场标识格式无效。', 500)
  const filename = vmDownloadFilename(input.entry, downloadUrl, input.download.entryIndex)
  const expectedMd5 = safeHash(input.entry.md5, 32, 'MD5')
  const expectedSha1 = safeHash(input.entry.sha1, 40, 'SHA1')
  const root = join(resolve(input.dataDir), 'vm-images', input.download.labId)
  const finalPath = join(root, `${String(input.download.entryIndex + 1).padStart(3, '0')}-${filename}`)
  const tempPath = `${finalPath}.${input.download.id}.part`
  await mkdir(root, { recursive: true })
  await checkFreeSpace(root, MIN_FREE_BYTES)

  let response: Response | null = null
  let cleanupHeaderRequest: () => void = () => undefined
  try {
    const fetched = await fetchWithHeaderTimeout(input.fetchImpl ?? fetch, downloadUrl, input.signal)
    response = fetched.response
    cleanupHeaderRequest = fetched.cleanup
    if (!response.ok) {
      await cancelResponseBody(response)
      throw new VmDownloadError('VM_DOWNLOAD_HTTP_FAILED', `镜像下载失败（HTTP ${response.status}）。`, 502)
    }
    const rawLength = response.headers.get('content-length')
    const declaredLength = rawLength && /^\d+$/.test(rawLength) ? Number(rawLength) : null
    if (declaredLength !== null && declaredLength > input.maxBytes) {
      await cancelResponseBody(response)
      throw new VmDownloadError('VM_SIZE_LIMIT', `镜像超过大小上限（${Math.ceil(input.maxBytes / 1024 / 1024)} MiB）。`)
    }
    if (declaredLength !== null) await checkFreeSpace(root, declaredLength + MIN_FREE_BYTES)
    if (!response.body) throw new VmDownloadError('VM_DOWNLOAD_EMPTY', '镜像响应没有可读取的数据。', 502)

    const file = await open(tempPath, 'w')
    const reader = response.body.getReader()
    const md5 = createHash('md5')
    const sha1 = createHash('sha1')
    const sha256 = createHash('sha256')
    let bytesDownloaded = 0
    let lastReportBytes = 0
    let lastReportAt = 0
    let lastDiskCheckBytes = 0
    try {
      input.onProgress?.({ progress: 0, bytesDownloaded: 0, totalBytes: declaredLength, message: '正在下载镜像。' })
      while (true) {
        const chunk = await reader.read()
        if (chunk.done) break
        const value = chunk.value
        bytesDownloaded += value.byteLength
        if (bytesDownloaded > input.maxBytes) throw new VmDownloadError('VM_SIZE_LIMIT', `镜像超过大小上限（${Math.ceil(input.maxBytes / 1024 / 1024)} MiB）。`)
        await file.write(value)
        md5.update(value)
        sha1.update(value)
        sha256.update(value)
        if (bytesDownloaded - lastDiskCheckBytes >= DISK_CHECK_BYTES) {
          lastDiskCheckBytes = bytesDownloaded
          await checkFreeSpace(root, MIN_FREE_BYTES)
        }
        const now = Date.now()
        if (bytesDownloaded - lastReportBytes >= PROGRESS_BYTES || now - lastReportAt >= PROGRESS_INTERVAL_MS) {
          lastReportBytes = bytesDownloaded
          lastReportAt = now
          input.onProgress?.({ progress: declaredLength ? Math.min(99, Math.floor(bytesDownloaded / declaredLength * 100)) : 0, bytesDownloaded, totalBytes: declaredLength, message: '正在下载镜像。' })
        }
      }
    } catch (error) {
      await reader.cancel().catch(() => undefined)
      throw error
    } finally {
      await file.close()
      reader.releaseLock()
    }

    const actualMd5 = md5.digest('hex')
    const actualSha1 = sha1.digest('hex')
    const actualSha256 = sha256.digest('hex')
    if (declaredLength !== null && bytesDownloaded !== declaredLength) throw new VmDownloadError('VM_DOWNLOAD_TRUNCATED', '镜像下载长度与服务器声明不一致。', 502)
    if (expectedMd5 && expectedMd5 !== actualMd5) throw new VmDownloadError('VM_MD5_MISMATCH', '镜像 MD5 校验失败。')
    if (expectedSha1 && expectedSha1 !== actualSha1) throw new VmDownloadError('VM_SHA1_MISMATCH', '镜像 SHA1 校验失败。')
    await rm(finalPath, { force: true }).catch(() => undefined)
    await rename(tempPath, finalPath)
    return { localPath: finalPath, filename, bytesDownloaded, totalBytes: declaredLength, md5: actualMd5, sha1: actualSha1, sha256: actualSha256, checksumVerified: Boolean(expectedMd5 || expectedSha1) }
  } catch (error) {
    await rm(tempPath, { force: true }).catch(() => undefined)
    if (error instanceof VmDownloadError) throw error
    if (input.signal?.aborted) throw new VmDownloadError('VM_DOWNLOAD_ABORTED', '镜像下载已中断。', 409)
    throw new VmDownloadError('VM_DOWNLOAD_FAILED', error instanceof Error ? error.message : '镜像下载失败。', 502)
  } finally {
    cleanupHeaderRequest()
  }
}

export const vmDownloadInternals = { officialDownloadUrl, vmDownloadFilename, safeHash, MIN_FREE_BYTES }
