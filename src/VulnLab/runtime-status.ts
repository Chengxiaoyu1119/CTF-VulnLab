import { execFile } from 'node:child_process'
import { createConnection } from 'node:net'
import { join } from 'node:path'
import { stat } from 'node:fs/promises'
import type { MySqlRuntimeConfig } from './mysql.js'
import type { Lab } from './types.js'

export interface RuntimeDependencyStatus {
  id: 'php' | 'php-mysqli' | 'mysql' | 'node' | 'java' | 'python' | 'qemu'
  label: string
  available: boolean
  detail: string
}

const command = (binary: string, args: string[]) => new Promise<{ available: boolean; output: string }>(resolveCommand => {
  execFile(binary, args, { timeout: 5_000, windowsHide: true, maxBuffer: 256 * 1024 }, (error, stdout, stderr) => {
    const output = `${stdout ?? ''} ${stderr ?? ''}`.replace(/\s+/g, ' ').trim()
    resolveCommand({ available: !error, output })
  })
})

const tcp = (host: string, port: number) => new Promise<boolean>(resolveProbe => {
  const socket = createConnection({ host, port })
  let settled = false
  const finish = (available: boolean) => {
    if (settled) return
    settled = true
    socket.destroy()
    resolveProbe(available)
  }
  socket.once('connect', () => finish(true))
  socket.once('error', () => finish(false))
  socket.setTimeout(1_500, () => finish(false))
})

const firstVersion = (output: string) => output.match(/\d+(?:\.\d+){1,3}/)?.[0] ?? '已检测'
const majorVersion = (output: string) => Number(firstVersion(output).split('.')[0])

export const inspectRuntimeDependencies = async (input: {
  phpBinary: string
  phpIni?: string
  nodeBinary: string
  javaBinary: string
  pythonBinary: string
  qemuBinary: string
  mysql?: MySqlRuntimeConfig
}): Promise<RuntimeDependencyStatus[]> => {
  const [php, node, java, python, qemu, mysqlReachable] = await Promise.all([
    command(input.phpBinary, [...(input.phpIni ? ['-c', input.phpIni] : []), '-r', 'echo PHP_VERSION."|".(extension_loaded("mysqli")?"mysqli":"no-mysqli");']),
    command(input.nodeBinary, ['--version']),
    command(input.javaBinary, ['-version']),
    command(input.pythonBinary, [...(process.platform === 'win32' && /(?:^|[\\/])py(?:\.exe)?$/i.test(input.pythonBinary) ? ['-3'] : []), '--version']),
    command(input.qemuBinary, ['--version']),
    input.mysql ? tcp(input.mysql.host, input.mysql.port) : Promise.resolve(false),
  ])
  const phpParts = php.output.split('|')
  const mysqliReady = php.available && phpParts[1] === 'mysqli'
  const nodeReady = node.available && majorVersion(node.output) >= 22
  const javaReady = java.available && majorVersion(java.output) >= 17
  const pythonMajorMinor = firstVersion(python.output).split('.').slice(0, 2).join('.')
  const pythonReady = python.available && ['3.10', '3.11'].includes(pythonMajorMinor)
  return [
    { id: 'php', label: 'PHP', available: php.available, detail: php.available ? (phpParts[0] || firstVersion(php.output)) : '未检测到' },
    { id: 'php-mysqli', label: 'PHP mysqli', available: mysqliReady, detail: mysqliReady ? '扩展已启用' : '扩展未启用' },
    { id: 'mysql', label: 'MySQL / MariaDB', available: Boolean(input.mysql && mysqlReachable), detail: !input.mysql ? '未配置连接' : mysqlReachable ? `${input.mysql.host}:${input.mysql.port}` : `${input.mysql.host}:${input.mysql.port} 未连接` },
    { id: 'node', label: 'Node.js', available: nodeReady, detail: node.available ? `${firstVersion(node.output)}${nodeReady ? '' : ' · 需要 22+'}` : '未检测到' },
    { id: 'java', label: 'Java', available: javaReady, detail: java.available ? `${firstVersion(java.output)}${javaReady ? '' : ' · 需要 17+'}` : '未检测到' },
    { id: 'python', label: 'Python', available: pythonReady, detail: python.available ? `${firstVersion(python.output)}${pythonReady ? '' : ' · 需要 3.10/3.11'}` : '未检测到' },
    { id: 'qemu', label: 'QEMU', available: qemu.available, detail: qemu.available ? firstVersion(qemu.output) : '未检测到' },
  ]
}

const databaseLabs = new Set(['dvwa', 'pikachu', 'sqli-labs', 'mutillidae'])

export const runtimeReadinessByLab = async (labs: Lab[], dependencies: RuntimeDependencyStatus[], dataDir: string) => {
  const status = new Map(dependencies.map(item => [item.id, item]))
  const entries = await Promise.all(labs.map(async lab => {
    const required: RuntimeDependencyStatus['id'][] = lab.runtimeKind === 'native-php'
      ? ['php', ...(databaseLabs.has(lab.slug) ? ['php-mysqli' as const, 'mysql' as const] : [])]
      : lab.runtimeKind === 'native-node' ? ['node']
        : lab.runtimeKind === 'native-java' ? ['java']
          : lab.runtimeKind === 'native-python' ? ['python']
            : lab.runtimeKind === 'vm' ? ['qemu'] : []
    const missing = required.filter(id => !status.get(id)?.available)
    if (lab.slug === 'pygoat' && lab.status === 'ready') {
      const marker = join(dataDir, 'labs', lab.slug, lab.version, '.vulnlab-python-ready')
      if (!(await stat(marker).then(item => item.isFile()).catch(() => false))) missing.push('python')
    }
    return [lab.slug, { available: missing.length === 0, missing: [...new Set(missing)].map(id => status.get(id)?.label ?? id) }]
  }))
  return Object.fromEntries(entries)
}
