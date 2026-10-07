import { createHash } from 'node:crypto'
import { execFile, spawn } from 'node:child_process'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Lab } from '../types.js'

export class RuntimePreparationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RuntimePreparationError'
  }
}

type Progress = (progress: number, stage: string, message: string) => void

const exists = (path: string) => stat(path).then(item => item.isFile()).catch(() => false)
const existingDirectory = (path: string) => stat(path).then(item => item.isDirectory()).catch(() => false)

export const preparationMarkerValue = async (files: string[]) => {
  const hash = createHash('sha256')
  for (const file of files) {
    const content = await readFile(file)
    hash.update(basename(file)).update('\0').update(String(content.byteLength)).update('\0').update(content).update('\0')
  }
  return `v1:sha256:${hash.digest('hex')}\n`
}

export const preparationMarkerIsCurrent = async (markerPath: string, files: string[]) => {
  try {
    return await readFile(markerPath, 'utf8') === await preparationMarkerValue(files)
  } catch {
    return false
  }
}

const writePreparationMarker = async (markerPath: string, files: string[]) => {
  await writeFile(markerPath, await preparationMarkerValue(files), 'utf8')
}

const bundledPyGoatDependencies = () => {
  if (process.platform !== 'win32' || process.arch !== 'x64') return null
  const moduleDir = dirname(fileURLToPath(import.meta.url))
  const appRoot = basename(dirname(moduleDir)) === 'dist' ? resolve(moduleDir, '..', '..') : resolve(moduleDir, '..')
  return join(appRoot, 'assets', 'python', 'pygoat')
}

const run = (binary: string, args: string[], cwd: string, timeoutMs = 10 * 60_000) => new Promise<void>((resolveRun, rejectRun) => {
  const child = spawn(binary, args, { cwd, env: process.env, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true, shell: false })
  let tail = ''
  let settled = false
  const finish = (error?: Error) => {
    if (settled) return
    settled = true
    clearTimeout(timeout)
    if (error) rejectRun(error)
    else resolveRun()
  }
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', chunk => { tail = `${tail}${String(chunk)}`.slice(-4_000) })
  child.once('error', error => finish(error))
  child.once('exit', code => finish(code === 0 ? undefined : new RuntimePreparationError(`${basename(binary)} 依赖安装失败（退出码 ${code ?? 'unknown'}）：${tail.replace(/\s+/g, ' ').trim()}`)))
  const timeout = setTimeout(() => {
    try { child.kill() } catch { /* process already exited */ }
    finish(new RuntimePreparationError('运行依赖安装超过 10 分钟。'))
  }, timeoutMs)
})

export const pythonInstallConfig = async (lab: Lab) => {
  const builtin = lab.builtin || lab.slug === 'pygoat'
  const bundled = lab.slug === 'pygoat' ? bundledPyGoatDependencies() : null
  const requirements = builtin
    ? process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE?.trim() || (bundled ? join(bundled, 'requirements.txt') : undefined)
    : join(lab.localPath as string, 'requirements.txt')
  // 自定义脚本项目可以不带第三方依赖；只有声明 requirements.txt 时才要求离线 wheelhouse。
  if (!requirements) {
    if (builtin) throw new RuntimePreparationError('内置 Python 靶场需要哈希锁定的 requirements.txt 和离线 wheelhouse。')
    return null
  }
  if (!builtin && !(await exists(requirements))) return null
  const wheelhouse = process.env.VULNLAB_PYTHON_WHEELHOUSE?.trim() || (bundled ? join(bundled, 'wheelhouse') : undefined)
  if (!wheelhouse) throw new RuntimePreparationError(builtin
    ? '内置 Python 靶场需要哈希锁定的 requirements.txt 和离线 wheelhouse。'
    : 'Python 靶场需要离线 wheelhouse 目录。')
  const requirementsPath = resolve(requirements)
  const wheelhousePath = resolve(wheelhouse)
  if (!(await exists(requirementsPath))) throw new RuntimePreparationError('Python 靶场哈希锁定依赖文件不存在；可通过 VULNLAB_PYTHON_REQUIREMENTS_FILE 指定。')
  if (!(await existingDirectory(wheelhousePath))) throw new RuntimePreparationError('Python 靶场离线 wheelhouse 目录不存在；可通过 VULNLAB_PYTHON_WHEELHOUSE 指定。')
  return { requirementsPath, wheelhousePath }
}

export const nodePackageConfig = async (root: string) => {
  const packagePath = join(root, 'package.json')
  if (!(await exists(packagePath))) return null
  let packageJson: Record<string, unknown>
  try {
    const value: unknown = JSON.parse(await readFile(packagePath, 'utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('package.json 顶层必须是对象。')
    packageJson = value as Record<string, unknown>
  } catch (error) {
    throw new RuntimePreparationError(`Node.js 项目的 package.json 无法读取：${error instanceof Error ? error.message : 'JSON 格式无效'}。`)
  }
  let resolvedLockPath: string | undefined
  for (const candidate of [join(root, 'package-lock.json'), join(root, 'npm-shrinkwrap.json')]) {
    if (await exists(candidate)) {
      resolvedLockPath = candidate
      break
    }
  }
  if (resolvedLockPath) return { packagePath, lockPath: resolvedLockPath }
  const runtimeDependencies = ['dependencies', 'optionalDependencies', 'peerDependencies']
    .some(name => {
      const value = packageJson[name]
      return Boolean(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length)
    })
  if (runtimeDependencies) throw new RuntimePreparationError('Node.js 项目声明了运行依赖，但缺少 package-lock.json 或 npm-shrinkwrap.json。')
  return null
}

const commandPath = (binary: string) => new Promise<string | undefined>(resolvePath => {
  execFile('where.exe', [binary], { windowsHide: true, timeout: 3_000 }, (error, stdout) => {
    if (error) return resolvePath(undefined)
    resolvePath(String(stdout).split(/\r?\n/).map(item => item.trim()).find(Boolean))
  })
})

const nodeNpmCli = async (nodeBinary: string) => {
  const configured = process.env.VULNLAB_NPM_CLI?.trim()
  const nodePath = nodeBinary.includes('\\') || nodeBinary.includes('/') || /^[A-Za-z]:/.test(nodeBinary) ? resolve(nodeBinary) : ''
  const processNodePath = process.execPath
  const pathNodePath = nodePath || processNodePath
  const configuredPath = configured && (configured.includes('\\') || configured.includes('/') || /^[A-Za-z]:/.test(configured)) ? resolve(configured) : ''
  const candidates = [
    configuredPath && configuredPath.toLowerCase().endsWith('.js') ? configuredPath : undefined,
    configuredPath ? join(dirname(configuredPath), 'node_modules', 'npm', 'bin', 'npm-cli.js') : undefined,
    join(dirname(pathNodePath), 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    join(dirname(pathNodePath), 'npm-cli.js'),
  ].filter((candidate): candidate is string => Boolean(candidate))
  for (const candidate of candidates) if (await exists(candidate)) return { binary: nodeBinary, args: [resolve(candidate)] }
  const npmCommand = await commandPath('npm')
  if (npmCommand) {
    const npmRoot = dirname(npmCommand)
    for (const candidate of [join(npmRoot, 'node_modules', 'npm', 'bin', 'npm-cli.js'), join(npmRoot, 'npm-cli.js')]) {
      if (await exists(candidate)) return { binary: nodeBinary, args: [resolve(candidate)] }
    }
  }
  throw new RuntimePreparationError('Node.js 项目需要可用的 npm CLI，但当前 Node.js 工具链未提供 npm。')
}

const prepareNodeProject = async (lab: Lab, root: string, onProgress: Progress, nodeBinary?: string) => {
  // 内置 Node 靶场使用自身的预构建发行资源，不在导入时安装 npm 依赖。
  if (lab.builtin) return
  const config = await nodePackageConfig(root)
  if (!config) return
  const readyMarker = join(root, '.vulnlab-node-ready')
  const dependencies = [config.packagePath, config.lockPath]
  if (await preparationMarkerIsCurrent(readyMarker, dependencies)) return
  const configured = nodeBinary?.trim() || process.env.VULNLAB_NODE_BIN?.trim() || process.execPath
  const npm = await nodeNpmCli(configured)
  const args = [...npm.args, 'ci', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund']
  if (process.env.VULNLAB_OFFLINE === '1') args.push('--offline')
  onProgress(94, 'runtime', '正在安装 Node.js 运行依赖。')
  await run(npm.binary, args, root)
  await writePreparationMarker(readyMarker, dependencies)
  onProgress(99, 'runtime', 'Node.js 运行依赖已准备。')
}

export const prepareInstalledLab = async (lab: Lab, onProgress: Progress = () => undefined, pythonBinary?: string, nodeBinary?: string) => {
  if (lab.runtimeKind === 'native-node' && lab.localPath) {
    await prepareNodeProject(lab, lab.localPath, onProgress, nodeBinary ?? pythonBinary)
    return
  }
  // 兼容只传 slug/localPath 的既有 PyGoat 测试对象；自定义 Python
  // 项目声明 requirements.txt 时也复用同一套离线依赖准备流程。
  if ((lab.runtimeKind !== 'native-python' && lab.slug !== 'pygoat') || !lab.localPath) return
  const root = lab.localPath
  const readyMarker = join(root, '.vulnlab-python-ready')
  const installConfig = await pythonInstallConfig(lab)
  if (!installConfig) return
  const { requirementsPath, wheelhousePath } = installConfig
  if (await preparationMarkerIsCurrent(readyMarker, [requirementsPath])) return
  const configured = pythonBinary?.trim() || process.env.VULNLAB_PYTHON_BIN?.trim() || 'py'
  const launcherArgs = basename(configured).toLowerCase().replace(/\.exe$/, '') === 'py' ? ['-3'] : []
  onProgress(91, 'runtime', '正在创建 Python 独立环境。')
  await run(configured, [...launcherArgs, '-m', 'venv', '.vulnlab-venv'], root)
  const python = join(root, '.vulnlab-venv', 'Scripts', 'python.exe')
  onProgress(94, 'runtime', '正在安装 Python 运行依赖。')
  await run(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-cache-dir', '--no-index', '--require-hashes', '--find-links', wheelhousePath, '-r', requirementsPath], root)
  await writePreparationMarker(readyMarker, [requirementsPath])
  onProgress(99, 'runtime', 'Python 运行依赖已准备。')
}
