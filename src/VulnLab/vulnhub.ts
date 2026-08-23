import { createHash } from 'node:crypto'
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import type { ImportManifest } from './types.js'

const MAX_PAGE_BYTES = 8 * 1024 * 1024
const MAX_ENTRIES = 100
const FETCH_TIMEOUT_MS = 30_000

export class VulnHubImporterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'VulnHubImporterError'
  }
}

export interface VulnHubImportInput {
  sourceUrl: string
  sourceRef: string
  jobId: string
  dataDir: string
  signal?: AbortSignal
  fetchImpl?: typeof fetch
  onProgress?: (progress: number, stage: string, message: string) => void
}

export interface VulnHubCatalogEntry {
  title: string
  url: string
  author: string | null
  difficulty: string | null
  downloadUrls: string[]
  filename: string | null
  fileSize: string | null
  md5: string | null
  sha1: string | null
}

export interface VulnHubCatalogDocument {
  sourceUrl: string
  entries: VulnHubCatalogEntry[]
}

const report = (input: VulnHubImportInput, progress: number, stage: string, message: string) => input.onProgress?.(progress, stage, message)

const decodeHtml = (value: string) => value.replace(/&(#x?[0-9a-f]+|amp|quot|apos|#39|lt|gt);/gi, (_match, entity: string) => {
  const normalized = entity.toLowerCase()
  if (normalized === 'amp') return '&'
  if (normalized === 'quot') return '"'
  if (normalized === 'apos' || normalized === '#39') return "'"
  if (normalized === 'lt') return '<'
  if (normalized === 'gt') return '>'
  if (normalized.startsWith('#x')) return String.fromCodePoint(Number.parseInt(normalized.slice(2), 16))
  if (normalized.startsWith('#')) return String.fromCodePoint(Number.parseInt(normalized.slice(1), 10))
  return _match
})

const htmlText = (value: string) => decodeHtml(value.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim())

const absoluteUrl = (baseUrl: string, value: string) => new URL(value, baseUrl).toString()

const pageUrl = (sourceUrl: string) => {
  const parsed = new URL(sourceUrl)
  if (parsed.protocol !== 'https:' || !['vulnhub.com', 'www.vulnhub.com'].includes(parsed.hostname.toLowerCase())) {
    throw new VulnHubImporterError('VulnHub 来源必须是 vulnhub.com 的 HTTPS 地址。')
  }
  parsed.hash = ''
  return parsed.toString()
}

const readPage = async (fetchImpl: typeof fetch, url: string, signal?: AbortSignal) => {
  const timeoutSignal = AbortSignal.timeout(FETCH_TIMEOUT_MS)
  const requestSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal
  const response = await fetchImpl(url, { signal: requestSignal, headers: { accept: 'text/html', 'user-agent': 'VulnLab/0.2' } })
  const cancelBody = async () => { await response.body?.cancel().catch(() => undefined) }
  if (!response.ok) {
    await cancelBody()
    throw new VulnHubImporterError(`读取 VulnHub 页面失败（HTTP ${response.status}）。`)
  }
  const declaredLength = Number(response.headers.get('content-length') ?? 0)
  if (declaredLength > MAX_PAGE_BYTES) {
    await cancelBody()
    throw new VulnHubImporterError('VulnHub 页面超过大小限制。')
  }
  if (!response.body) return new TextDecoder().decode(new Uint8Array(await response.arrayBuffer()))
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const next = await reader.read()
      if (next.done) break
      total += next.value.byteLength
      if (total > MAX_PAGE_BYTES) throw new VulnHubImporterError('VulnHub 页面超过大小限制。')
      chunks.push(next.value)
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(bytes)
}

const unique = (values: string[]) => [...new Set(values)]

const parseCatalogLinks = (sourceUrl: string, html: string) => {
  const entries = new Map<string, string>()
  const pattern = /<a\b[^>]*href\s*=\s*["'](\/entry\/[^"'#?]+)["'][^>]*>([\s\S]*?)<\/a>/gi
  for (const match of html.matchAll(pattern)) {
    const url = absoluteUrl(sourceUrl, match[1])
    const title = htmlText(match[2])
    if (title) entries.set(url, title)
  }
  return [...entries.entries()].slice(0, MAX_ENTRIES).map(([url, title]) => ({ url, title }))
}

const parseDetail = (html: string): Omit<VulnHubCatalogEntry, 'title' | 'url'> => {
  const downloadUrls = unique([...html.matchAll(/href\s*=\s*["'](https?:\/\/download\.vulnhub\.com\/[^"']+)["']/gi)].map(match => decodeHtml(match[1])))
  const author = htmlText(html.match(/<li[^>]*>\s*<b>Author<\/b>:\s*([\s\S]*?)<\/li>/i)?.[1] ?? '') || null
  const difficulty = htmlText(html.match(/Difficulty:\s*([^<]+)/i)?.[1] ?? '') || null
  const filename = htmlText(html.match(/<li>\s*<b>Filename<\/b>:\s*([^<]+)<\/li>/i)?.[1] ?? '') || null
  const fileSize = htmlText(html.match(/<li>\s*<b>File size<\/b>:\s*([^<]+)<\/li>/i)?.[1] ?? '') || null
  const md5 = htmlText(html.match(/<li>\s*<b>MD5<\/b>:\s*([^<]+)<\/li>/i)?.[1] ?? '') || null
  const sha1 = htmlText(html.match(/<li>\s*<b>SHA1<\/b>:\s*([^<]+)<\/li>/i)?.[1] ?? '') || null
  return { author, difficulty, downloadUrls, filename, fileSize, md5, sha1 }
}

const catalogText = (value: unknown, label: string, maxLength: number) => {
  if (value === null) return null
  if (typeof value !== 'string' || value.length > maxLength) throw new VulnHubImporterError(`VulnHub catalog.json 的 ${label} 字段无效。`)
  return value
}

const catalogUrl = (value: unknown, label: string) => {
  const url = catalogText(value, label, 2_048)
  if (!url) throw new VulnHubImporterError(`VulnHub catalog.json 的 ${label} 字段为空。`)
  let parsed: URL
  try { parsed = new URL(url) } catch { throw new VulnHubImporterError(`VulnHub catalog.json 的 ${label} 不是有效 URL。`) }
  if (parsed.protocol !== 'https:' || !['vulnhub.com', 'www.vulnhub.com'].includes(parsed.hostname.toLowerCase())) {
    throw new VulnHubImporterError(`VulnHub catalog.json 的 ${label} 不是 VulnHub HTTPS 地址。`)
  }
  return parsed.toString()
}

const catalogDownloadUrl = (value: unknown) => {
  const url = catalogText(value, 'downloadUrls', 2_048)
  if (!url) throw new VulnHubImporterError('VulnHub catalog.json 的下载地址为空。')
  let parsed: URL
  try { parsed = new URL(url) } catch { throw new VulnHubImporterError('VulnHub catalog.json 的下载地址不是有效 URL。') }
  if (parsed.protocol !== 'https:' || parsed.hostname.toLowerCase() !== 'download.vulnhub.com') {
    throw new VulnHubImporterError('VulnHub catalog.json 包含非官方镜像地址。')
  }
  return parsed.toString()
}

const parseCatalogDocument = (value: unknown): VulnHubCatalogDocument => {
  if (!value || typeof value !== 'object') throw new VulnHubImporterError('VulnHub catalog.json 格式无效。')
  const document = value as { sourceUrl?: unknown; entries?: unknown }
  if (!Array.isArray(document.entries) || document.entries.length > MAX_ENTRIES) throw new VulnHubImporterError('VulnHub catalog.json 条目数量无效。')
  const entries = document.entries.map((rawEntry, index) => {
    if (!rawEntry || typeof rawEntry !== 'object') throw new VulnHubImporterError(`VulnHub catalog.json 第 ${index + 1} 条记录无效。`)
    const entry = rawEntry as Record<string, unknown>
    if (entry.downloadUrls !== undefined && (!Array.isArray(entry.downloadUrls) || entry.downloadUrls.length > 8)) throw new VulnHubImporterError(`VulnHub catalog.json 第 ${index + 1} 条记录的下载地址数量无效。`)
    const downloadUrls = Array.isArray(entry.downloadUrls) ? unique(entry.downloadUrls.map(value => catalogDownloadUrl(value))) : []
    const title = catalogText(entry.title, 'title', 240)
    if (!title) throw new VulnHubImporterError(`VulnHub catalog.json 第 ${index + 1} 条记录缺少标题。`)
    return {
      title,
      url: catalogUrl(entry.url, 'url'),
      author: catalogText(entry.author, 'author', 240),
      difficulty: catalogText(entry.difficulty, 'difficulty', 80),
      downloadUrls,
      filename: catalogText(entry.filename, 'filename', 240),
      fileSize: catalogText(entry.fileSize, 'fileSize', 80),
      md5: catalogText(entry.md5, 'md5', 128),
      sha1: catalogText(entry.sha1, 'sha1', 128),
    }
  })
  return { sourceUrl: catalogUrl(document.sourceUrl, 'sourceUrl'), entries }
}

export const readVulnHubCatalog = async (catalogPath: string, expectedSha256?: string): Promise<VulnHubCatalogDocument> => {
  const fileStat = await stat(catalogPath)
  if (!fileStat.isFile() || fileStat.size > MAX_PAGE_BYTES) throw new VulnHubImporterError('VulnHub catalog.json 文件大小无效。')
  const payload = await readFile(catalogPath)
  if (expectedSha256) {
    const actualSha256 = createHash('sha256').update(payload).digest('hex')
    if (actualSha256 !== expectedSha256) throw new VulnHubImporterError('VulnHub catalog.json 校验值不匹配，已拒绝读取。')
  }
  try {
    return parseCatalogDocument(JSON.parse(payload.toString('utf8')))
  } catch (error) {
    if (error instanceof VulnHubImporterError) throw error
    throw new VulnHubImporterError('VulnHub catalog.json 不是有效 JSON。')
  }
}

export const importVulnHubCatalog = async (input: VulnHubImportInput): Promise<ImportManifest> => {
  const sourcePage = pageUrl(input.sourceUrl)
  const fetchImpl = input.fetchImpl ?? fetch
  const root = join(resolve(input.dataDir), 'imports', input.jobId)
  const catalogPath = join(root, 'catalog.json')
  try {
    report(input, 8, 'catalog', '读取 VulnHub 机器目录。')
    const catalogHtml = await readPage(fetchImpl, sourcePage, input.signal)
    const links = parseCatalogLinks(sourcePage, catalogHtml)
    if (!links.length) throw new VulnHubImporterError('VulnHub 页面中没有发现机器详情链接。')

    const warnings: string[] = []
    const entries: VulnHubCatalogEntry[] = []
    for (const [index, link] of links.entries()) {
      report(input, 15 + Math.round(index / links.length * 70), 'details', `读取机器详情 ${index + 1}/${links.length}。`)
      try {
        const detail = await readPage(fetchImpl, link.url, input.signal)
        entries.push({ title: link.title, url: link.url, ...parseDetail(detail) })
      } catch (error) {
        if (input.signal?.aborted) throw error
        warnings.push(`${link.title}：${error instanceof Error ? error.message : '详情读取失败'}。`)
        entries.push({ title: link.title, url: link.url, author: null, difficulty: null, downloadUrls: [], filename: null, fileSize: null, md5: null, sha1: null })
      }
    }

    // Keep the catalog file and its hash deterministic for identical source
    // content. Import time belongs in the manifest, not in the hashed payload.
    const payload = new TextEncoder().encode(JSON.stringify({ sourceUrl: sourcePage, entries }, null, 2))
    const archiveSha256 = createHash('sha256').update(payload).digest('hex')
    await mkdir(root, { recursive: true })
    await writeFile(catalogPath, payload)
    const manifest: ImportManifest = {
      adapterId: 'vulnhub-catalog',
      sourceUrl: input.sourceUrl,
      sourceRef: input.sourceRef,
      resolvedRef: `catalog@${archiveSha256}`,
      revision: `catalog-${archiveSha256}`,
      archiveSha256,
      localPath: catalogPath,
      fileCount: entries.length,
      totalBytes: payload.byteLength,
      licenseFiles: [],
      topLevelEntries: ['catalog.json'],
      warnings,
      importedAt: new Date().toISOString(),
    }
    await writeFile(join(root, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
    report(input, 100, 'completed', `VulnHub 目录导入完成，共 ${entries.length} 台机器。`)
    return manifest
  } catch (error) {
    await rm(root, { recursive: true, force: true }).catch(() => undefined)
    if (error instanceof VulnHubImporterError) throw error
    throw new VulnHubImporterError(error instanceof Error ? error.message : 'VulnHub 目录导入失败。')
  }
}

export const vulnhubInternals = { decodeHtml, htmlText, parseCatalogLinks, parseDetail, parseCatalogDocument, pageUrl, readPage, MAX_PAGE_BYTES, MAX_ENTRIES }
