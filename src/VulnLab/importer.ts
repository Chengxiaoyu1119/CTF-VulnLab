import { createHash } from 'node:crypto'
import { mkdir, rm, writeFile } from 'node:fs/promises'
import { request as httpsRequest } from 'node:https'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { Readable } from 'node:stream'
import { unzipSync } from 'fflate'
import type { ImportManifest } from './types.js'

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
const MAX_FILE_COUNT = 20_000
const MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
const FETCH_TIMEOUT_MS = 30_000
const USER_AGENT = 'VulnLab/0.2'

export class ImporterError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ImporterError'
  }
}

interface GitHubRepository {
  owner: string
  repository: string
}

interface ImportInput {
  sourceUrl: string
  sourceRef: string
  jobId: string
  dataDir: string
  signal?: AbortSignal
  onProgress?: (progress: number, stage: string, message: string) => void
  fetchImpl?: typeof fetch
  portablePathPolicy?: 'strict' | 'case-collision-lowercase'
}

const report = (input: ImportInput, progress: number, stage: string, message: string) => input.onProgress?.(progress, stage, message)

const fetchWithTimeout = async (fetchImpl: typeof fetch, url: string, init: RequestInit, externalSignal?: AbortSignal) => {
  const timeoutSignal = AbortSignal.timeout(FETCH_TIMEOUT_MS)
  const signal = externalSignal ? AbortSignal.any([externalSignal, timeoutSignal]) : timeoutSignal
  return fetchImpl(url, { ...init, signal })
}

const nativeHttpsFetch = (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => new Promise((resolveResponse, reject) => {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input : input.url)
  const request = httpsRequest(url, {
    method: init.method ?? 'GET',
    headers: Object.fromEntries(new Headers(init.headers).entries()),
  }, response => {
    const responseHeaders = new Headers()
    for (const [name, value] of Object.entries(response.headers)) {
      if (value !== undefined) responseHeaders.set(name, Array.isArray(value) ? value.join(', ') : value)
    }
    resolveResponse(new Response(Readable.toWeb(response) as ReadableStream, {
      status: response.statusCode ?? 502,
      statusText: response.statusMessage,
      headers: responseHeaders,
    }))
  })
  const abort = () => request.destroy(new Error('请求已取消。'))
  const cleanup = () => init.signal?.removeEventListener('abort', abort)
  request.once('error', error => { cleanup(); reject(error) })
  init.signal?.addEventListener('abort', abort, { once: true })
  if (init.signal?.aborted) abort()
  request.once('close', cleanup)
  request.end()
})

const parseGitHubRepository = (sourceUrl: string): GitHubRepository => {
  let parsed: URL
  try {
    parsed = new URL(sourceUrl)
  } catch {
    throw new ImporterError('GitHub 来源地址不是有效 URL。')
  }
  if (parsed.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(parsed.hostname.toLowerCase())) {
    throw new ImporterError('当前导入器只接受 github.com 的 HTTPS 仓库地址。')
  }
  const parts = parsed.pathname.split('/').filter(Boolean)
  if (parts.length !== 2 || !parts[0] || !parts[1] || parts[1].endsWith('.git')) {
    throw new ImporterError('GitHub 来源必须是 https://github.com/OWNER/REPOSITORY。')
  }
  return { owner: parts[0], repository: parts[1] }
}

const parseJsonResponse = async (response: Response, description: string) => {
  if (!response.ok) throw new ImporterError(`${description}失败（HTTP ${response.status}）。`)
  try {
    return await response.json() as Record<string, unknown>
  } catch {
    throw new ImporterError(`${description}返回的 JSON 解析失败。`)
  }
}

const isGitHubRateLimited = (response: Response) => response.status === 403 || response.status === 429

const readLimitedResponse = async (response: Response, maxBytes: number, description: string) => {
  if (!response.ok) throw new ImporterError(`${description}失败（HTTP ${response.status}）。`)
  const declaredLength = Number(response.headers.get('content-length') ?? 0)
  if (declaredLength > maxBytes) {
    await response.body?.cancel().catch(() => undefined)
    throw new ImporterError(`${description}超过 ${Math.round(maxBytes / 1024 / 1024)} MiB 限制。`)
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer())
    if (bytes.byteLength > maxBytes) throw new ImporterError(`${description}超过大小限制。`)
    return bytes
  }
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const next = await reader.read()
      if (next.done) break
      total += next.value.byteLength
      if (total > maxBytes) throw new ImporterError(`${description}超过大小限制。`)
      chunks.push(next.value)
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined)
    throw error
  } finally {
    reader.releaseLock()
  }
  const output = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')

const safeRelativePath = (archiveName: string) => {
  const normalized = archiveName.replaceAll('\\', '/')
  if (!normalized || normalized.endsWith('/') || normalized.startsWith('/') || /^[A-Za-z]:[\\/]/.test(normalized)) return null
  const segments = normalized.split('/').filter(Boolean)
  if (segments.some(segment => segment === '.' || segment === '..')) throw new ImporterError(`压缩包包含不安全路径：${archiveName}`)
  const result = segments.join(sep)
  if (!result || result.includes('\0')) return null
  return result
}

const safeTarget = (root: string, relativePath: string) => {
  const target = resolve(root, relativePath)
  const rootWithSeparator = root.endsWith(sep) ? root : `${root}${sep}`
  if (target !== root && !target.startsWith(rootWithSeparator)) throw new ImporterError(`解包路径越界：${relativePath}`)
  return target
}

const windowsPathKey = (relativePath: string) => relativePath
  .replaceAll('\\', '/')
  .split('/')
  .map(segment => segment.replace(/[ .]+$/g, '').toLowerCase())
  .join('/')

const windowsReservedName = /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])(?:\..*)?$/i

const assertPortablePathNames = (paths: string[]) => {
  for (const path of paths) {
    const segments = path.replaceAll('\\', '/').split('/')
    if (segments.some(segment => /[<>:"|?*]/.test(segment) || /[ .]$/.test(segment) || windowsReservedName.test(segment))) {
      throw new ImporterError(`压缩包包含 Windows 不可用文件名：${path}。`)
    }
  }
}

const assertPortablePaths = (paths: string[]) => {
  assertPortablePathNames(paths)
  const seen = new Map<string, string>()
  for (const path of paths) {
    const key = windowsPathKey(path)
    const previous = seen.get(key)
    if (previous) throw new ImporterError(`压缩包包含 Windows 路径冲突：${previous} 与 ${path}。`)
    seen.set(key, path)
  }

  for (const [key, path] of seen) {
    const segments = key.split('/')
    for (let index = 1; index < segments.length; index += 1) {
      const parentKey = segments.slice(0, index).join('/')
      const parentPath = seen.get(parentKey)
      if (parentPath) throw new ImporterError(`压缩包包含 Windows 文件目录冲突：${parentPath} 与 ${path}。`)
    }
  }
}

type ArchiveFileEntry = { name: string; relativePath: string; bytes: Uint8Array }

const portableFiles = (entries: ArchiveFileEntry[], policy: ImportInput['portablePathPolicy'] = 'strict') => {
  assertPortablePathNames(entries.map(item => item.relativePath))
  if (policy !== 'case-collision-lowercase') {
    assertPortablePaths(entries.map(item => item.relativePath))
    return { entries, warnings: [] as string[] }
  }

  const groups = new Map<string, ArchiveFileEntry[]>()
  for (const entry of entries) {
    const key = windowsPathKey(entry.relativePath)
    const group = groups.get(key) ?? []
    group.push(entry)
    groups.set(key, group)
  }

  const selected: ArchiveFileEntry[] = []
  const warnings: string[] = []
  for (const group of groups.values()) {
    if (group.length === 1) {
      selected.push(group[0])
      continue
    }
    const [preferred, ...discarded] = [...group].sort((left, right) => {
      const leftMixedCase = left.relativePath === left.relativePath.toLowerCase() ? 0 : 1
      const rightMixedCase = right.relativePath === right.relativePath.toLowerCase() ? 0 : 1
      return leftMixedCase - rightMixedCase || left.relativePath.localeCompare(right.relativePath)
    })
    selected.push(preferred)
    warnings.push(`Windows 大小写路径冲突：保留 ${preferred.relativePath}，忽略 ${discarded.map(item => item.relativePath).join('、')}。`)
  }
  assertPortablePaths(selected.map(item => item.relativePath))
  return { entries: selected, warnings }
}

const commonRoot = (paths: string[]) => {
  const roots = new Set(paths.map(item => item.split('/')[0]).filter(Boolean))
  return roots.size === 1 ? [...roots][0] : ''
}

const licenseNames = new Set(['license', 'license.md', 'license.txt', 'copying', 'copying.md', 'notice', 'notice.md'])

interface ArchiveImportOptions {
  archive: Uint8Array
  root: string
  archivePath: string
  extractRoot: string
  adapterId: string
  branch: string
  revision: string
  apiFallback: boolean
  sourceLabel: string
}

const importRepositoryArchive = async (input: ImportInput, options: ArchiveImportOptions): Promise<ImportManifest> => {
  const archiveSha256 = sha256(options.archive)
  const revision = options.revision || `archive-${archiveSha256}`
  await mkdir(options.root, { recursive: true })
  await writeFile(options.archivePath, options.archive)

  report(input, 52, 'inspect', `检查 ${options.sourceLabel} 压缩包目录和体积。`)
  let files: Record<string, Uint8Array>
  try {
    files = unzipSync(options.archive)
  } catch {
    throw new ImporterError('下载内容不是可解析的 ZIP 压缩包。')
  }
  const names = Object.keys(files)
  if (names.length > MAX_FILE_COUNT) throw new ImporterError(`压缩包文件数量超过 ${MAX_FILE_COUNT} 限制。`)
  const fileEntries = names.map(name => ({ name, relativePath: safeRelativePath(name), bytes: files[name] })).filter((item): item is ArchiveFileEntry => Boolean(item.relativePath))
  const portable = portableFiles(fileEntries, input.portablePathPolicy)
  const totalBytes = portable.entries.reduce((total, item) => total + item.bytes.byteLength, 0)
  if (totalBytes > MAX_EXTRACTED_BYTES) throw new ImporterError(`解包内容超过 ${Math.round(MAX_EXTRACTED_BYTES / 1024 / 1024)} MiB 限制。`)

  await mkdir(options.extractRoot, { recursive: true })
  report(input, 65, 'extract', `安全解包 ${portable.entries.length} 个文件。`)
  for (const [index, file] of portable.entries.entries()) {
    const target = safeTarget(options.extractRoot, file.relativePath)
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, file.bytes)
    if (index % Math.max(1, Math.floor(portable.entries.length / 10)) === 0) report(input, 65 + Math.round(index / Math.max(1, portable.entries.length) * 25), 'extract', `已解包 ${index + 1}/${portable.entries.length}。`)
  }

  const rootEntry = commonRoot(portable.entries.map(item => item.relativePath.replaceAll(sep, '/')))
  const localPath = rootEntry ? join(options.extractRoot, rootEntry) : options.extractRoot
  const licenseFiles = portable.entries.map(item => item.relativePath).filter(item => licenseNames.has(basename(item).toLowerCase())).slice(0, 20)
  const manifest: ImportManifest = {
    adapterId: options.adapterId,
    sourceUrl: input.sourceUrl,
    sourceRef: input.sourceRef,
    resolvedRef: `${options.branch}@${options.apiFallback ? `archive-sha256:${archiveSha256}` : revision}`,
    revision,
    archiveSha256,
    localPath,
    fileCount: portable.entries.length,
    totalBytes,
    licenseFiles,
    topLevelEntries: [...new Set(portable.entries.map(item => item.relativePath.replaceAll(sep, '/').split('/')[0]))].sort(),
    warnings: portable.warnings,
    importedAt: new Date().toISOString(),
  }
  await writeFile(join(options.root, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8')
  await rm(options.archivePath, { force: true })
  report(input, 100, 'completed', `${options.sourceLabel} 导入完成，共 ${manifest.fileCount} 个文件。`)
  return manifest
}

export const importGitHubRepository = async (input: ImportInput): Promise<ImportManifest> => {
  const repository = parseGitHubRepository(input.sourceUrl)
  const fetchImpl = input.fetchImpl ?? fetch
  const headers = { accept: 'application/vnd.github+json', 'user-agent': USER_AGENT }
  const apiBase = `https://api.github.com/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}`
  const root = join(resolve(input.dataDir), 'imports', input.jobId)
  const archivePath = join(root, 'source.zip')
  const extractRoot = join(root, 'source')
  try {
    report(input, 8, 'repository', '读取 GitHub 仓库信息。')
    const repositoryResponse = await fetchWithTimeout(fetchImpl, apiBase, { headers }, input.signal)
    const requestedRef = input.sourceRef.includes('@') ? input.sourceRef.split('@').slice(1).join('@') : ''
    let branch = requestedRef || 'main'
    let revision = ''
    let apiFallback = false
    if (isGitHubRateLimited(repositoryResponse)) {
      apiFallback = true
      report(input, 18, 'revision', `GitHub API 暂时限流，使用来源指定分支 ${branch}。`)
    } else {
      const metadata = await parseJsonResponse(repositoryResponse, '读取 GitHub 仓库信息')
      const defaultBranch = typeof metadata.default_branch === 'string' && metadata.default_branch ? metadata.default_branch : 'main'
      branch = requestedRef || defaultBranch
      report(input, 18, 'revision', `解析版本 ${branch}。`)
      const commitResponse = await fetchWithTimeout(fetchImpl, `${apiBase}/commits/${encodeURIComponent(branch)}`, { headers }, input.signal)
      if (isGitHubRateLimited(commitResponse)) {
        apiFallback = true
        report(input, 22, 'revision', `GitHub 版本 API 暂时限流，改用分支压缩包哈希固定内容。`)
      } else {
        const commit = await parseJsonResponse(commitResponse, '读取 GitHub 版本')
        revision = typeof commit.sha === 'string' && /^[a-f0-9]{7,64}$/i.test(commit.sha) ? commit.sha : ''
        if (!revision) throw new ImporterError('GitHub 版本响应缺少有效 commit SHA。')
      }
    }

    const archiveBranches = (revision || requestedRef || branch !== 'main') ? [branch] : ['main', 'master']
    let archiveResponse: Response | null = null
    let archiveBranch = branch
    for (const [index, candidate] of archiveBranches.entries()) {
      const archiveRef = revision || `refs/heads/${encodeURIComponent(candidate)}`
      const archiveUrl = `https://codeload.github.com/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.repository)}/zip/${archiveRef}`
      report(input, 28, 'download', apiFallback ? `下载 ${candidate} 分支并用压缩包哈希固定内容。` : `下载固定版本 ${revision.slice(0, 12)}。`)
      const response = await fetchWithTimeout(fetchImpl, archiveUrl, { headers: { accept: 'application/zip', 'user-agent': USER_AGENT } }, input.signal)
      if (response.status === 404 && index < archiveBranches.length - 1) {
        await response.arrayBuffer().catch(() => undefined)
        report(input, 29, 'download', `${candidate} 分支不存在，尝试 ${archiveBranches[index + 1]}。`)
        continue
      }
      archiveResponse = response
      archiveBranch = candidate
      break
    }
    if (!archiveResponse) throw new ImporterError('GitHub 仓库没有可下载的默认分支（已尝试 main 和 master）。')
    branch = archiveBranch
    const archive = await readLimitedResponse(archiveResponse, MAX_ARCHIVE_BYTES, '下载仓库压缩包')
    return await importRepositoryArchive(input, {
      archive,
      root,
      archivePath,
      extractRoot,
      adapterId: 'github-git',
      branch,
      revision,
      apiFallback,
      sourceLabel: 'GitHub',
    })
  } catch (error) {
    await rm(root, { recursive: true, force: true }).catch(() => undefined)
    if (error instanceof ImporterError) throw error
    throw new ImporterError(error instanceof Error ? error.message : '导入过程出现未知错误。')
  }
}

interface GitLabRepository {
  projectPath: string
}

const parseGitLabRepository = (sourceUrl: string): GitLabRepository => {
  let parsed: URL
  try {
    parsed = new URL(sourceUrl)
  } catch {
    throw new ImporterError('GitLab 来源地址不是有效 URL。')
  }
  if (parsed.protocol !== 'https:' || !['gitlab.com', 'www.gitlab.com'].includes(parsed.hostname.toLowerCase()) || parsed.search || parsed.hash) {
    throw new ImporterError('当前导入器只接受 gitlab.com 的 HTTPS 仓库地址。')
  }
  let pathname: string
  try { pathname = decodeURIComponent(parsed.pathname) } catch { throw new ImporterError('GitLab 来源地址编码无效。') }
  const projectPath = pathname.replace(/^\/+|\/+$/g, '')
  const parts = projectPath.split('/')
  if (parts.length < 2 || parts.some(part => !part || part === '.' || part === '..') || parts.at(-1)?.endsWith('.git')) {
    throw new ImporterError('GitLab 来源必须是 https://gitlab.com/NAMESPACE/PROJECT。')
  }
  return { projectPath }
}

const isGitLabRateLimited = (response: Response) => response.status === 403 || response.status === 429

export const importGitLabRepository = async (input: ImportInput): Promise<ImportManifest> => {
  const repository = parseGitLabRepository(input.sourceUrl)
  const fetchImpl = input.fetchImpl ?? fetch
  const headers = { accept: 'application/json', 'user-agent': USER_AGENT }
  const encodedProject = encodeURIComponent(repository.projectPath)
  const apiBase = `https://gitlab.com/api/v4/projects/${encodedProject}`
  const root = join(resolve(input.dataDir), 'imports', input.jobId)
  const archivePath = join(root, 'source.zip')
  const extractRoot = join(root, 'source')
  try {
    report(input, 8, 'repository', '读取 GitLab 仓库信息。')
    const requestedRef = input.sourceRef.includes('@') ? input.sourceRef.split('@').slice(1).join('@') : ''
    let branch = requestedRef || 'main'
    let revision = ''
    let apiFallback = false
    const repositoryResponse = await fetchWithTimeout(fetchImpl, apiBase, { headers }, input.signal)
    if (isGitLabRateLimited(repositoryResponse)) {
      apiFallback = true
      report(input, 18, 'revision', `GitLab API 暂时限流，使用来源指定版本 ${branch}。`)
    } else {
      const metadata = await parseJsonResponse(repositoryResponse, '读取 GitLab 仓库信息')
      const defaultBranch = typeof metadata.default_branch === 'string' && metadata.default_branch ? metadata.default_branch : 'main'
      branch = requestedRef || defaultBranch
      report(input, 18, 'revision', `解析版本 ${branch}。`)
      const commitResponse = await fetchWithTimeout(fetchImpl, `${apiBase}/repository/commits/${encodeURIComponent(branch)}`, { headers }, input.signal)
      if (isGitLabRateLimited(commitResponse)) {
        apiFallback = true
        report(input, 22, 'revision', 'GitLab 版本 API 暂时限流，改用分支压缩包哈希固定内容。')
      } else {
        const commit = await parseJsonResponse(commitResponse, '读取 GitLab 版本')
        revision = typeof commit.id === 'string' && /^[a-f0-9]{7,64}$/i.test(commit.id) ? commit.id : ''
        if (!revision) throw new ImporterError('GitLab 版本响应缺少有效 commit SHA。')
      }
    }

    const archiveBranches = requestedRef || (!apiFallback && branch !== 'main') ? [branch] : [branch, 'master'].filter((value, index, values) => values.indexOf(value) === index)
    let archiveResponse: Response | null = null
    let archiveBranch = branch
    for (const [index, candidate] of archiveBranches.entries()) {
      const archiveRef = revision || candidate
      const archiveUrl = `${apiBase}/repository/archive.zip?sha=${encodeURIComponent(archiveRef)}`
      report(input, 28, 'download', apiFallback ? `下载 ${candidate} 分支并用压缩包哈希固定内容。` : `下载固定版本 ${revision.slice(0, 12)}。`)
      // GitLab's archive CDN can return 406 to Node/undici even when the same
      // public URL succeeds with a normal HTTPS client. Keep the fallback
      // dependency-free and preserve injected fetch implementations in tests.
      const archiveFetch = fetchImpl === fetch ? nativeHttpsFetch as typeof fetch : fetchImpl
      const response = await fetchWithTimeout(archiveFetch, archiveUrl, { headers: { accept: 'application/zip', 'user-agent': USER_AGENT } }, input.signal)
      if (response.status === 404 && index < archiveBranches.length - 1) {
        await response.arrayBuffer().catch(() => undefined)
        report(input, 29, 'download', `${candidate} 分支不存在，尝试 ${archiveBranches[index + 1]}。`)
        continue
      }
      archiveResponse = response
      archiveBranch = candidate
      break
    }
    if (!archiveResponse) throw new ImporterError('GitLab 仓库没有可下载的默认分支（已尝试 main 和 master）。')
    const archive = await readLimitedResponse(archiveResponse, MAX_ARCHIVE_BYTES, '下载 GitLab 仓库压缩包')
    return await importRepositoryArchive(input, {
      archive,
      root,
      archivePath,
      extractRoot,
      adapterId: 'gitlab-git',
      branch: archiveBranch,
      revision,
      apiFallback,
      sourceLabel: 'GitLab',
    })
  } catch (error) {
    await rm(root, { recursive: true, force: true }).catch(() => undefined)
    if (error instanceof ImporterError) throw error
    throw new ImporterError(error instanceof Error ? error.message : 'GitLab 导入过程出现未知错误。')
  }
}

export const importerInternals = { parseGitHubRepository, parseGitLabRepository, safeRelativePath, safeTarget, assertPortablePaths, windowsPathKey, readLimitedResponse, MAX_ARCHIVE_BYTES, MAX_EXTRACTED_BYTES }
