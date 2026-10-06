import { execFile } from 'node:child_process'

export interface DockerCommandResult {
  ok: boolean
  stdout: string
  stderr: string
  code: number | null
  errorCode?: string
}

export const runDockerCommand = (args: string[], timeoutMs = 15_000, env: NodeJS.ProcessEnv = process.env) => new Promise<DockerCommandResult>(resolveCommand => {
  const commandEnv = { ...env }
  delete commandEnv.COMPOSE_FILE
  delete commandEnv.COMPOSE_PROJECT_NAME
  delete commandEnv.COMPOSE_PROFILES
  delete commandEnv.COMPOSE_PATH_SEPARATOR
  execFile('docker', args, { env: commandEnv, timeout: timeoutMs, windowsHide: true, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
    const failure = error as (Error & { code?: string; killed?: boolean }) | null
    resolveCommand({
      ok: !failure,
      stdout: String(stdout ?? ''),
      stderr: String(stderr ?? ''),
      code: failure && typeof failure.code === 'number' ? failure.code : failure ? null : 0,
      ...(failure?.code && typeof failure.code === 'string' ? { errorCode: failure.code } : {}),
    })
  })
})

export interface OaDockerRuntimeStatus {
  available: boolean
  missing: string[]
  cli: { available: boolean; detail: string }
  compose: { available: boolean; detail: string }
  engine: { available: boolean; detail: string; os: string; architecture: string }
}

type DockerRunner = (args: string[], timeoutMs?: number) => Promise<DockerCommandResult>

const detailOf = (result: DockerCommandResult) => `${result.stdout} ${result.stderr}`.replace(/\s+/g, ' ').trim()

export const inspectOaDockerRuntime = async (run: DockerRunner = runDockerCommand): Promise<OaDockerRuntimeStatus> => {
  const cliResult = await run(['--version'])
  const cliDetail = cliResult.ok ? detailOf(cliResult) || 'Docker CLI 可用' : cliResult.errorCode === 'ENOENT' ? '未找到 Docker CLI。' : detailOf(cliResult) || 'Docker CLI 调用失败。'
  const composeResult = cliResult.ok ? await run(['compose', 'version', '--short']) : { ok: false, stdout: '', stderr: '', code: null }
  const composeDetail = composeResult.ok ? `Compose ${detailOf(composeResult) || 'v2'} 可用` : cliResult.ok ? detailOf(composeResult) || 'Docker Compose v2 插件不可用。' : 'Docker CLI 不可用。'
  const contextResult = cliResult.ok ? await run(['context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}']) : { ok: false, stdout: '', stderr: '', code: null }
  const contextHost = contextResult.ok ? detailOf(contextResult).replace(/^"|"$/g, '') : ''
  const localContext = contextResult.ok && (contextHost.startsWith('unix://') || /^npipe:\/\/(?:\/\/\.\/pipe\/|\/\/\?\/pipe\/)/i.test(contextHost))
  const engineResult = cliResult.ok ? await run(['info', '--format', '{{.OSType}}/{{.Architecture}}'], 8_000) : { ok: false, stdout: '', stderr: '', code: null }
  const engineValue = detailOf(engineResult).toLowerCase()
  const [os = '', architecture = ''] = engineValue.split('/')
  const compatibleEngine = engineResult.ok && os === 'linux' && ['x86_64', 'amd64'].includes(architecture)
  const engineDetail = !contextResult.ok
    ? detailOf(contextResult) || '当前 Docker context 不可读取。'
    : !localContext
      ? `当前 Docker context 指向非本机 Engine（${contextHost || '未知 endpoint'}）。`
      : !engineResult.ok
    ? detailOf(engineResult) || 'Docker Engine 未运行或当前用户无法连接。'
    : compatibleEngine ? `Linux ${architecture} Engine 可用` : `不支持 ${engineValue || '未知'}；此靶场需要 Linux x86_64 Engine。`
  const missing = [
    ...(!cliResult.ok ? ['Docker CLI'] : []),
    ...(cliResult.ok && !composeResult.ok ? ['Docker Compose v2'] : []),
    ...(cliResult.ok && !contextResult.ok ? ['可读取的 Docker context'] : []),
    ...(contextResult.ok && !localContext ? ['本机 Docker Engine'] : []),
    ...(cliResult.ok && !engineResult.ok ? ['运行中的 Docker Engine'] : []),
    ...(engineResult.ok && !compatibleEngine ? ['Linux x86_64 Docker Engine'] : []),
  ]
  return {
    available: missing.length === 0,
    missing,
    cli: { available: cliResult.ok, detail: cliDetail },
    compose: { available: composeResult.ok, detail: composeDetail },
    engine: { available: compatibleEngine, detail: engineDetail, os, architecture },
  }
}
