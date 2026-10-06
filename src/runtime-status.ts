import { execFile } from 'node:child_process'
import { createConnection } from 'node:net'
import { join } from 'node:path'
import { stat } from 'node:fs/promises'
import type { MySqlRuntimeConfig } from './mysql.js'
import type { Lab } from './types.js'
import { dataPaths } from './paths.js'
import { inspectOaDockerAsset } from './oa-docker-assets.js'
import { inspectOaDockerRuntime } from './oa-docker-runtime.js'

export type RuntimeSource = 'project' | 'system' | 'external' | 'missing'

export interface RuntimeDependencyStatus {
  id: 'php' | 'php-mysqli' | 'php-pdo-mysql' | 'mysql' | 'node' | 'node-permission' | 'java' | 'python'
  label: string
  available: boolean
  detail: string
  source?: RuntimeSource
  action?: 'ready' | 'prepare' | 'configure'
}

const command = (binary: string, args: string[], env?: NodeJS.ProcessEnv) => new Promise<{ available: boolean; output: string }>(resolveCommand => {
  execFile(binary, args, { env: { ...process.env, ...env }, timeout: 5_000, windowsHide: true, maxBuffer: 256 * 1024 }, (error, stdout, stderr) => {
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
  oaNodeBinary?: string
  javaBinary: string
  pythonBinary: string
  mysql?: MySqlRuntimeConfig
  sources?: Partial<Record<RuntimeDependencyStatus['id'], { source?: RuntimeSource; action?: RuntimeDependencyStatus['action'] }>>
}): Promise<RuntimeDependencyStatus[]> => {
  const [php, node, oaNode, java, python, mysqlReachable] = await Promise.all([
    command(input.phpBinary, [...(input.phpIni ? ['-c', input.phpIni] : []), '-r', 'echo PHP_VERSION."|".(extension_loaded("mysqli")?"mysqli":"no-mysqli")."|".(extension_loaded("pdo_mysql")?"pdo_mysql":"no-pdo_mysql");']),
    command(input.nodeBinary, ['--version']),
    input.oaNodeBinary ? command(input.oaNodeBinary, ['--version']) : Promise.resolve({ available: false, output: '' }),
    command(input.javaBinary, ['-version']),
    command(input.pythonBinary, [/(?:^|[\\/])py(?:\.exe)?$/i.test(input.pythonBinary) ? '-3' : '', '--version'].filter(Boolean)),
    input.mysql ? tcp(input.mysql.host, input.mysql.port) : Promise.resolve(false),
  ])
  const phpParts = php.output.split('|')
  const mysqliReady = php.available && phpParts[1] === 'mysqli'
  const pdoMysqlReady = php.available && phpParts[2] === 'pdo_mysql'
  const nodeReady = node.available && majorVersion(node.output) >= 22
  const oaNodeParts = firstVersion(oaNode.output).split('.').map(Number)
  const oaNodePermissionReady = oaNode.available && (oaNodeParts[0] ?? 0) >= 22 && (
    (oaNodeParts[0] ?? 0) > 23
    || ((oaNodeParts[0] ?? 0) === 23 && (oaNodeParts[1] ?? 0) >= 5)
    || ((oaNodeParts[0] ?? 0) === 22 && (oaNodeParts[1] ?? 0) >= 13)
  )
  const javaReady = java.available && majorVersion(java.output) >= 17
  const pythonMajorMinor = firstVersion(python.output).split('.').slice(0, 2).join('.')
  const pythonReady = python.available && ['3.10', '3.11'].includes(pythonMajorMinor)
  const withSource = (id: RuntimeDependencyStatus['id'], item: Omit<RuntimeDependencyStatus, 'id' | 'source' | 'action'>): RuntimeDependencyStatus => ({ id, ...item, ...input.sources?.[id] })
  return [
    withSource('php', { label: 'PHP', available: php.available, detail: php.available ? (phpParts[0] || firstVersion(php.output)) : '未检测到' }),
    withSource('php-mysqli', { label: 'PHP mysqli', available: mysqliReady, detail: mysqliReady ? '扩展已启用' : '扩展未启用' }),
    withSource('php-pdo-mysql', { label: 'PHP PDO MySQL', available: pdoMysqlReady, detail: pdoMysqlReady ? '扩展已启用' : '扩展未启用' }),
    withSource('mysql', { label: 'MySQL / MariaDB', available: Boolean(input.mysql && mysqlReachable), detail: !input.mysql ? '未配置连接' : mysqlReachable ? `${input.mysql.host}:${input.mysql.port}` : `${input.mysql.host}:${input.mysql.port} 未连接` }),
    withSource('node', { label: 'Node.js', available: nodeReady, detail: node.available ? `${firstVersion(node.output)}${nodeReady ? '' : ' · 需要 22+'}` : '未检测到' }),
    withSource('node-permission', { label: 'Node.js 实例权限限制', available: oaNodePermissionReady, detail: oaNodePermissionReady ? `${firstVersion(oaNode.output)} · 文件权限模型可用（不是 OS 容器）` : '需要项目内 Node.js 22.13+ 或 23.5+；该机制不是 OS 容器' }),
    withSource('java', { label: 'Java', available: javaReady, detail: java.available ? `${firstVersion(java.output)}${javaReady ? '' : ' · 需要 17+'}` : '未检测到' }),
    withSource('python', { label: 'Python', available: pythonReady, detail: python.available ? `${firstVersion(python.output)}${pythonReady ? '' : ' · 需要 3.10/3.11'}` : '未检测到' }),
  ]
}

const databaseLabs = new Set(['dvwa', 'pikachu', 'sqli-labs', 'mutillidae', 'xvwa'])

export const runtimeReadinessByLab = async (labs: Lab[], dependencies: RuntimeDependencyStatus[], dataDir: string) => {
  const status = new Map(dependencies.map(item => [item.id, item]))
  const entries = await Promise.all(labs.map(async lab => {
    const customMysql = lab.runtimeConfig?.profile === 'mysql-php'
    const required: RuntimeDependencyStatus['id'][] = lab.runtimeKind === 'native-php'
      ? ['php', ...(databaseLabs.has(lab.slug) || customMysql ? ['php-mysqli' as const, 'php-pdo-mysql' as const, 'mysql' as const] : [])]
      : lab.runtimeKind === 'native-node' ? ['node']
        : lab.runtimeKind === 'native-java' ? ['java']
          : lab.runtimeKind === 'native-python' ? ['python']
          : lab.runtimeKind === 'native-oa' ? ['mysql', 'node-permission'] : []
    const missing = required.filter(id => !status.get(id)?.available)
    if (lab.runtimeKind === 'native-python' && lab.status === 'ready') {
      const requirements = lab.builtin || lab.slug === 'pygoat'
        ? process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE?.trim()
        : lab.localPath ? join(lab.localPath, 'requirements.txt') : undefined
      const needsIsolatedEnv = lab.slug === 'pygoat' || Boolean(requirements && await stat(requirements).then(item => item.isFile()).catch(() => false))
      if (needsIsolatedEnv) {
        const root = lab.localPath ?? dataPaths(dataDir).lab(lab.slug, lab.version)
        const marker = join(root, '.vulnlab-python-ready')
        if (!(await stat(marker).then(item => item.isFile()).catch(() => false))) missing.push('python')
      }
    }
    return [lab.slug, { available: missing.length === 0, missing: [...new Set(missing)].map(id => status.get(id)?.label ?? id) }]
  }))
  return Object.fromEntries(entries)
}

let oaDockerProbeCache: { expiresAt: number; result: Promise<{ docker: Awaited<ReturnType<typeof inspectOaDockerRuntime>>; asset: Awaited<ReturnType<typeof inspectOaDockerAsset>> }> } | null = null

export const inspectOaRuntimeModes = async () => {
  if (!oaDockerProbeCache || oaDockerProbeCache.expiresAt <= Date.now()) {
    const result = Promise.all([inspectOaDockerRuntime(), inspectOaDockerAsset()]).then(([docker, asset]) => ({ docker, asset }))
    oaDockerProbeCache = { expiresAt: Date.now() + 15_000, result }
  }
  const { docker, asset } = await oaDockerProbeCache.result
  const dockerMissing = [...docker.missing, ...(asset.available ? [] : [asset.detail])]
  return {
    local: {
      default: true,
      available: false,
      label: '本地安全模式',
      missing: [],
      detail: '不调用系统命令；SSTI exec 返回模拟结果。运行进程仍使用启动 VulnLab 的 Windows 账号，不是操作系统沙盒。',
    },
    docker: {
      default: false,
      available: dockerMissing.length === 0,
      label: 'Docker 模式',
      missing: dockerMissing,
      dependencies: { ...docker, available: dockerMissing.length === 0 },
      asset: { available: asset.available, detail: asset.detail },
      detail: dockerMissing.length ? dockerMissing.join('；') : 'Linux x86_64 Engine、Compose v2 与内置资源均可用。',
    },
  }
}
