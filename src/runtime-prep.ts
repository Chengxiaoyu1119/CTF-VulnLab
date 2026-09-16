import { spawn } from 'node:child_process'
import { stat, writeFile } from 'node:fs/promises'
import { basename, join, resolve } from 'node:path'
import type { Lab } from './types.js'

export class RuntimePreparationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RuntimePreparationError'
  }
}

type Progress = (progress: number, stage: string, message: string) => void

const exists = (path: string) => stat(path).then(item => item.isFile()).catch(() => false)
const existingDirectory = (path: string) => stat(path).then(item => item.isDirectory()).catch(() => false)

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
    finish(new RuntimePreparationError('Python 依赖安装超过 10 分钟。'))
  }, timeoutMs)
})

const pythonInstallConfig = async () => {
  const requirements = process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE?.trim()
  const wheelhouse = process.env.VULNLAB_PYTHON_WHEELHOUSE?.trim()
  if (!requirements || !wheelhouse) throw new RuntimePreparationError('PyGoat 需要配置哈希锁定的 VULNLAB_PYTHON_REQUIREMENTS_FILE 和离线 VULNLAB_PYTHON_WHEELHOUSE。')
  const requirementsPath = resolve(requirements)
  const wheelhousePath = resolve(wheelhouse)
  if (!(await exists(requirementsPath))) throw new RuntimePreparationError('PyGoat 哈希锁定依赖文件不存在。')
  if (!(await existingDirectory(wheelhousePath))) throw new RuntimePreparationError('PyGoat 离线 wheelhouse 目录不存在。')
  return { requirementsPath, wheelhousePath }
}

export const prepareInstalledLab = async (lab: Lab, onProgress: Progress = () => undefined, pythonBinary?: string) => {
  if (lab.slug !== 'pygoat' || !lab.localPath) return
  const root = lab.localPath
  const readyMarker = join(root, '.vulnlab-python-ready')
  if (await exists(readyMarker)) return
  const { requirementsPath, wheelhousePath } = await pythonInstallConfig()
  const configured = pythonBinary?.trim() || process.env.VULNLAB_PYTHON_BIN?.trim() || 'py'
  const launcherArgs = basename(configured).toLowerCase().replace(/\.exe$/, '') === 'py' ? ['-3'] : []
  onProgress(91, 'runtime', '正在创建 PyGoat 独立 Python 环境。')
  await run(configured, [...launcherArgs, '-m', 'venv', '.vulnlab-venv'], root)
  const python = join(root, '.vulnlab-venv', 'Scripts', 'python.exe')
  onProgress(94, 'runtime', '正在安装 PyGoat 运行依赖。')
  await run(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '--no-cache-dir', '--no-index', '--require-hashes', '--find-links', wheelhousePath, '-r', requirementsPath], root)
  await writeFile(readyMarker, `${new Date().toISOString()}\n`, 'utf8')
  onProgress(99, 'runtime', 'PyGoat 运行依赖已准备。')
}
