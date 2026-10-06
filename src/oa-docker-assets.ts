import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { unzipSync } from 'fflate'

const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
const MAX_UNPACKED_BYTES = 64 * 1024 * 1024

// 更新 Docker 资源包时同步更新此 SHA-256 与 OA 发行版本。
export const OA_DOCKER_ASSET_SHA256 = '6402789609f547668c9c1d41a5aded1ef3dd644a7657ef414b53db2a55e46dcb'

const assetRoot = () => {
  const moduleDir = dirname(fileURLToPath(import.meta.url))
  const appRoot = basename(moduleDir) === 'dist' ? resolve(moduleDir, '..') : moduleDir
  return join(appRoot, 'assets', 'labs', 'oa-vuln-labs', '1.0.0-beta', 'docker.zip')
}

export const oaDockerAssetPath = assetRoot

export const inspectOaDockerAsset = async (path = assetRoot()) => {
  const bytes = await readFile(path).catch(() => null)
  if (!bytes) return { available: false, detail: '项目内 OA Docker 资源包缺失。' }
  if (bytes.byteLength > MAX_ARCHIVE_BYTES) return { available: false, detail: 'OA Docker 资源包超过 64 MiB 上限。' }
  const sha256 = createHash('sha256').update(bytes).digest('hex')
  if (sha256 !== OA_DOCKER_ASSET_SHA256) {
    return { available: false, detail: '项目内 OA Docker 资源包 SHA-256 校验失败。' }
  }
  return { available: true, detail: 'OA Docker 资源包 SHA-256 校验通过。', bytes: bytes.byteLength }
}

export const verifyOaDockerAsset = (path = assetRoot()) => inspectOaDockerAsset(path)

const safeSegments = (name: string) => {
  const normalized = name.replaceAll('\\', '/')
  const segments = normalized.split('/')
  if (!normalized || normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized) || segments.some(segment => !segment || segment === '.' || segment === '..' || segment.includes(':') || segment.includes('\0'))) {
    throw new Error('OA Docker 资源包含无效路径。')
  }
  return segments
}

export const unpackOaDockerAsset = async (targetRoot: string, archivePath = assetRoot()) => {
  const archive = await readFile(archivePath).catch(() => null)
  if (!archive) throw new Error('项目内 OA Docker 资源包缺失。')
  if (archive.byteLength > MAX_ARCHIVE_BYTES) throw new Error('OA Docker 资源包超过 64 MiB 上限。')
  if (createHash('sha256').update(archive).digest('hex') !== OA_DOCKER_ASSET_SHA256) {
    throw new Error('项目内 OA Docker 资源包 SHA-256 校验失败。')
  }
  let files: Record<string, Uint8Array>
  try {
    files = unzipSync(archive) as Record<string, Uint8Array>
  } catch {
    throw new Error('OA Docker 资源包 ZIP 格式无效。')
  }
  const expected = new Set(['Dockerfile', 'config.yaml', 'database/init.sql', 'dist/index.html', 'dist/assets/index-D6NZ84om.js', 'oa-system'])
  const entries = Object.entries(files)
  if (entries.length !== expected.size) throw new Error('OA Docker 资源包文件清单不匹配。')
  let totalBytes = 0
  const root = resolve(targetRoot)
  for (const [name, bytes] of entries) {
    const segments = safeSegments(name)
    const normalized = segments.join('/')
    if (!expected.delete(normalized)) throw new Error(`OA Docker 资源包包含未声明文件：${normalized}`)
    totalBytes += bytes.byteLength
    if (totalBytes > MAX_UNPACKED_BYTES) throw new Error('OA Docker 资源包解压内容超过 64 MiB 上限。')
    const target = resolve(root, ...segments)
    const relativePath = target.slice(root.length).replace(/^[/\\]/, '')
    if (target === root || relativePath.startsWith(`..${sep}`) || resolve(root, relativePath) !== target) throw new Error('OA Docker 资源包路径越出实例目录。')
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, bytes)
  }
  if (expected.size) throw new Error(`OA Docker 资源包缺少文件：${[...expected].join('、')}`)
  return { fileCount: entries.length, totalBytes }
}
