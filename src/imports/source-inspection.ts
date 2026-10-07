import { readZipEntries } from '../zip.js'

const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
const MAX_FILES = 20_000
const MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
const INSPECTION_TIMEOUT_MS = 45_000

export type RuntimeSuggestion = {
  mode: 'php-static' | 'php-mysql' | 'node' | 'java-jar' | 'python' | 'django' | 'webgoat' | null
  confidence: 'high' | 'medium' | 'none'
  signals: string[]
  warnings: string[]
}

export const supportedInspectionModes = ['php-static', 'php-mysql', 'node', 'java-jar', 'webgoat', 'python', 'django'] as const
export type InspectedRuntimeMode = typeof supportedInspectionModes[number]

const selectedModeWarnings = (mode: string | undefined, names: string[]) => {
  if (!mode || !(supportedInspectionModes as readonly string[]).includes(mode)) return []
  const lowered = names.map(name => name.toLowerCase())
  const has = (pattern: RegExp) => lowered.some(name => pattern.test(name))
  const warnings: string[] = []
  if (mode === 'php-static' || mode === 'php-mysql') {
    if (!has(/(^|\/)index\.php$/)) warnings.push('所选 PHP 运行方式需要 index.php；当前文件中未发现该入口。')
    if (mode === 'php-mysql' && !has(/\.sql$/)) warnings.push('PHP + MySQL 需要数据库初始化 SQL 文件；当前未发现 .sql 文件。')
  } else if (mode === 'node') {
    if (!has(/(^|\/)package\.json$/) && !has(/(^|\/)(app|server|index)\.(?:c?js|mjs)$/)) warnings.push('Node.js 需要 package.json 或 app.js / server.js 等入口文件；当前未发现。')
    if (has(/(^|\/)package\.json$/) && !has(/(^|\/)(package-lock\.json|npm-shrinkwrap\.json)$/)) warnings.push('Node.js 项目需使用 package-lock.json 或 npm-shrinkwrap.json 固定依赖。')
  } else if (mode === 'java-jar' || mode === 'webgoat') {
    if (!has(mode === 'webgoat' ? /webgoat.*\.jar$/ : /\.jar$/)) warnings.push(`所选 Java 运行方式需要${mode === 'webgoat' ? ' WebGoat JAR' : '可运行 JAR 文件'}；当前未发现。`)
  } else if (mode === 'python') {
    if (!has(/\.py$/)) warnings.push('Python 脚本需要 .py 入口文件；当前未发现。')
    if (has(/(^|\/)requirements\.txt$/)) warnings.push('检测到 requirements.txt；运行依赖需哈希锁定，并准备本机离线 wheelhouse。')
  } else if (mode === 'django') {
    if (!has(/(^|\/)manage\.py$/)) warnings.push('Django 需要 manage.py；当前未发现。')
    if (!has(/(^|\/)settings\.py$/)) warnings.push('Django 需要 settings.py；当前未发现。')
  }
  return warnings
}

const normalizeFiles = (paths: string[]) => {
  const normalized = paths.map(path => path.replaceAll('\\', '/').replace(/^\.\//, ''))
  if (normalized.some(path => !path || path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.split('/').some(part => !part || part === '.' || part === '..'))) {
    throw new Error('来源中包含不安全的文件路径。')
  }
  const seen = new Set<string>()
  for (const path of normalized) {
    const key = path.replace(/[ .]+$/g, '').toLowerCase()
    if (seen.has(key)) throw new Error('来源中包含 Windows 不兼容的重名路径。')
    seen.add(key)
  }
  const roots = new Set(normalized.map(path => path.split('/')[0]))
  const root = roots.size === 1 && normalized.some(path => path.includes('/')) ? [...roots][0] : ''
  return normalized.map(path => root && path.startsWith(`${root}/`) ? path.slice(root.length + 1) : path)
}

const suggestionForFiles = (files: Array<{ name: string; bytes?: Uint8Array }>): RuntimeSuggestion => {
  const warnings: string[] = []
  const names = normalizeFiles(files.map(file => file.name))
  const lowered = names.map(name => name.toLowerCase())
  const has = (name: string) => lowered.includes(name.toLowerCase())
  const matching = (pattern: RegExp) => names.find(name => pattern.test(name))
  const composeFiles = names.filter(name => /^compose\.ya?ml$/i.test(name) || /(^|\/)docker-compose\.ya?ml$/i.test(name))
  const packagePath = matching(/(^|\/)package\.json$/i)
  const packageEntry = packagePath ? files[names.indexOf(packagePath)] : undefined
  let packageHasDependencies = false
  if (packageEntry?.bytes && packageEntry.bytes.byteLength <= 1024 * 1024) {
    try {
      const manifest = JSON.parse(new TextDecoder().decode(packageEntry.bytes)) as Record<string, unknown>
      packageHasDependencies = ['dependencies', 'optionalDependencies', 'peerDependencies'].some(key => {
        const value = manifest[key]
        return Boolean(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length)
      })
    } catch {
      warnings.push('package.json 无法解析，请检查文件格式。')
    }
  }
  const requirementsPath = matching(/(^|\/)requirements\.txt$/i)
  const requirementsEntry = requirementsPath ? files[names.indexOf(requirementsPath)] : undefined
  const requirementsText = requirementsEntry?.bytes ? new TextDecoder().decode(requirementsEntry.bytes) : ''
  const requirementsHasHashes = requirementsText.split(/\r?\n/).filter(line => line.trim() && !line.trim().startsWith('#') && !line.trim().startsWith('--')).every(line => /--hash=sha256:[a-f0-9]{64}/i.test(line))
  const managePath = matching(/(^|\/)manage\.py$/i)
  const settingsPath = matching(/(^|\/)settings\.py$/i)
  const jarPath = matching(/\.jar$/i)
  const phpEntry = matching(/(^|\/)index\.php$/i)
  const sqlPath = matching(/(^|\/)(init|schema|setup|install)[^/]*\.sql$/i) ?? matching(/\.sql$/i)
  const signals: string[] = []
  let mode: RuntimeSuggestion['mode'] = null
  let confidence: RuntimeSuggestion['confidence'] = 'none'

  if (composeFiles.length) {
    warnings.push('检测到 Docker Compose 配置；当前添加流程不支持 Compose，不会执行该配置。')
  } else if (managePath && settingsPath) {
    mode = 'django'; confidence = 'high'; signals.push('manage.py', 'Django settings.py')
  } else if (jarPath && /webgoat/i.test(jarPath)) {
    mode = 'webgoat'; confidence = 'high'; signals.push('WebGoat JAR')
  } else if (jarPath && !packagePath) {
    mode = 'java-jar'; confidence = 'high'; signals.push('可运行 JAR 文件')
  } else if (packagePath) {
    mode = 'node'; confidence = 'high'; signals.push('package.json')
  } else if (phpEntry) {
    mode = sqlPath ? 'php-mysql' : 'php-static'; confidence = sqlPath ? 'medium' : 'high'; signals.push('index.php')
    if (sqlPath) signals.push('SQL 初始化文件')
  } else if (requirementsPath) {
    mode = 'python'; confidence = 'medium'; signals.push('requirements.txt')
  } else if (matching(/\.py$/i)) {
    mode = 'python'; confidence = 'medium'; signals.push('Python 文件')
  }

  if (mode === 'node' && packageHasDependencies && !has('package-lock.json') && !has('npm-shrinkwrap.json')) {
    warnings.push('package.json 声明了运行依赖，但未发现 package-lock.json 或 npm-shrinkwrap.json。')
  }
  if (mode === 'python' && requirementsPath) {
    if (!requirementsHasHashes) warnings.push('requirements.txt 未能确认每项依赖均含 SHA-256 哈希；离线安装要求哈希锁定文件和本机 wheelhouse。')
    else warnings.push('Python 依赖仅从本机离线 wheelhouse 安装；需提前准备匹配的 wheel 文件。')
  }
  if (mode === 'php-mysql' && sqlPath && sqlPath.toLowerCase() !== 'init.sql') warnings.push(`已发现 ${sqlPath}；请在高级运行参数中确认初始化 SQL 路径。`)
  if (mode && confidence === 'none') confidence = 'medium'
  if (!mode && !composeFiles.length) warnings.push('未识别到明显入口文件；请选择与项目结构匹配的固定运行方式。')
  return { mode, confidence, signals, warnings }
}

const readArchive = async (response: Response) => {
  if (!response.ok) throw new Error(`下载公开仓库压缩包失败（HTTP ${response.status}）。`)
  const declaredLength = Number(response.headers.get('content-length') ?? 0)
  if (declaredLength > MAX_ARCHIVE_BYTES) throw new Error('来源压缩包超过 256 MiB 限制。')
  if (!response.body) throw new Error('来源没有返回可读取的压缩包。')
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > MAX_ARCHIVE_BYTES) throw new Error('来源压缩包超过 256 MiB 限制。')
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const archive = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) { archive.set(chunk, offset); offset += chunk.byteLength }
  return archive
}

const inspectArchiveBytes = async (archive: Uint8Array, selectedMode?: string): Promise<RuntimeSuggestion> => {
  if (!archive.byteLength) throw new Error('请选择有效的 ZIP 压缩包。')
  if (archive.byteLength > MAX_ARCHIVE_BYTES) throw new Error('来源压缩包超过 256 MiB 限制。')
  const entries = await readZipEntries(archive, { maxFiles: MAX_FILES, maxBytes: MAX_EXTRACTED_BYTES })
  const suggestion = suggestionForFiles(entries)
  suggestion.warnings.push(...selectedModeWarnings(selectedMode, entries.map(entry => entry.name)))
  suggestion.warnings = [...new Set(suggestion.warnings)]
  return suggestion
}

const requestedRef = (value: string) => {
  const ref = value.trim()
  if (ref.length > 200 || (ref && !/^[A-Za-z0-9._/-]+$/.test(ref))) throw new Error('分支或版本标识格式无效。')
  return ref
}

export const inspectPublicGitRepository = async (sourceUrl: string, sourceRef = '', fetchImpl: typeof fetch = fetch, selectedMode?: string): Promise<RuntimeSuggestion> => {
  let url: URL
  try { url = new URL(sourceUrl) } catch { throw new Error('仓库地址不是有效 URL。') }
  if (url.protocol !== 'https:' || url.search || url.hash || url.username || url.password) throw new Error('只支持公开 GitHub/GitLab HTTPS 仓库地址。')
  const host = url.hostname.toLowerCase()
  const ref = requestedRef(sourceRef)
  const timeoutSignal = AbortSignal.timeout(INSPECTION_TIMEOUT_MS)
  const fetchJson = async (target: string) => {
    const response = await fetchImpl(target, { headers: { accept: 'application/json', 'user-agent': 'VulnLab/0.2' }, signal: timeoutSignal })
    if (!response.ok) throw new Error(`读取公开仓库信息失败（HTTP ${response.status}）。`)
    return await response.json() as Record<string, unknown>
  }
  let archiveUrl = ''
  let label = ''
  if (host === 'github.com' || host === 'www.github.com') {
    const parts = url.pathname.replace(/^\/+|\/+$/g, '').replace(/\.git$/i, '').split('/')
    if (parts.length !== 2 || parts.some(part => !part)) throw new Error('GitHub 地址应为 https://github.com/组织/项目。')
    const api = `https://api.github.com/repos/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}`
    const repository = await fetchJson(api)
    const branch = ref || (typeof repository.default_branch === 'string' ? repository.default_branch : 'main')
    archiveUrl = `https://codeload.github.com/${encodeURIComponent(parts[0])}/${encodeURIComponent(parts[1])}/zip/${encodeURIComponent(branch)}`
    label = 'GitHub'
  } else if (host === 'gitlab.com' || host === 'www.gitlab.com') {
    let path: string
    try { path = decodeURIComponent(url.pathname.replace(/^\/+|\/+$/g, '')) } catch { throw new Error('GitLab 地址编码无效。') }
    const parts = path.split('/')
    if (parts.length < 2 || parts.some(part => !part || part === '.' || part === '..') || parts.at(-1)?.endsWith('.git')) throw new Error('GitLab 地址应为 https://gitlab.com/命名空间/项目。')
    const project = encodeURIComponent(path)
    const metadata = await fetchJson(`https://gitlab.com/api/v4/projects/${project}`)
    const branch = ref || (typeof metadata.default_branch === 'string' ? metadata.default_branch : 'main')
    archiveUrl = `https://gitlab.com/api/v4/projects/${project}/repository/archive.zip?sha=${encodeURIComponent(branch)}`
    label = 'GitLab'
  } else {
    throw new Error('只支持公开 GitHub/GitLab HTTPS 仓库地址。')
  }
  const response = await fetchImpl(archiveUrl, { headers: { accept: 'application/zip', 'user-agent': 'VulnLab/0.2' }, signal: timeoutSignal })
  const archive = await readArchive(response)
  try { return await inspectArchiveBytes(archive, selectedMode) } catch (error) {
    if (error instanceof Error) throw new Error(`${label} 来源预检失败：${error.message}`)
    throw error
  }
}

export const inspectUploadedArchive = inspectArchiveBytes
export const sourceInspectionInternals = { normalizeFiles, suggestionForFiles, selectedModeWarnings, readArchive, MAX_ARCHIVE_BYTES, MAX_FILES, MAX_EXTRACTED_BYTES }
