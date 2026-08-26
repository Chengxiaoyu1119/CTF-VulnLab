import { spawn } from 'node:child_process'
import { readFile, stat, writeFile } from 'node:fs/promises'
import { basename, join } from 'node:path'
import type { Lab } from './types.js'

export class RuntimePreparationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RuntimePreparationError'
  }
}

type Progress = (progress: number, stage: string, message: string) => void

const exists = (path: string) => stat(path).then(item => item.isFile()).catch(() => false)

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

const pygoatRequirements = async (root: string) => {
  const original = await readFile(join(root, 'requirements.txt'), 'utf8')
  const retained = original.split(/\r?\n/).filter(line => !/^(?:django-heroku|psycopg2|PyYAML)==/i.test(line.trim()))
  retained.push('PyYAML>=6.0,<7')
  const path = join(root, 'vulnlab-requirements.txt')
  await writeFile(path, `${retained.filter(Boolean).join('\n')}\n`, 'utf8')
  return path
}

export const prepareInstalledLab = async (lab: Lab, onProgress: Progress = () => undefined, pythonBinary?: string) => {
  if (lab.slug !== 'pygoat' || !lab.localPath) return
  const root = lab.localPath
  const readyMarker = join(root, '.vulnlab-python-ready')
  if (await exists(readyMarker)) return
  const configured = pythonBinary?.trim() || process.env.VULNLAB_PYTHON_BIN?.trim() || (process.platform === 'win32' ? 'py' : 'python3')
  const launcherArgs = process.platform === 'win32' && basename(configured).toLowerCase() === 'py' ? ['-3'] : []
  onProgress(91, 'runtime', '正在创建 PyGoat 独立 Python 环境。')
  await run(configured, [...launcherArgs, '-m', 'venv', '.vulnlab-venv'], root)
  const python = process.platform === 'win32'
    ? join(root, '.vulnlab-venv', 'Scripts', 'python.exe')
    : join(root, '.vulnlab-venv', 'bin', 'python')
  const requirements = await pygoatRequirements(root)
  onProgress(94, 'runtime', '正在安装 PyGoat 运行依赖。')
  await run(python, ['-m', 'pip', 'install', '--disable-pip-version-check', '-r', requirements], root)
  await writeFile(readyMarker, `${new Date().toISOString()}\n`, 'utf8')
  onProgress(99, 'runtime', 'PyGoat 运行依赖已准备。')
}
