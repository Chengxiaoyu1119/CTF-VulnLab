import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'

export const OA_LAUNCHER_SHA256 = 'e922e049364166286890c3e49e9438cba267b3ef69878e50ae710ba4ade4a9b1'

export const probeOaAppContainer = (launcherPath: string) => new Promise<{ available: boolean; detail: string }>(resolveProbe => {
  const profile = `VulnLab.OA.Probe.${randomUUID()}`
  execFile(launcherPath, ['check', profile], { timeout: 5_000, windowsHide: true, maxBuffer: 64 * 1024 }, (error, stdout, stderr) => {
    const output = `${stdout ?? ''} ${stderr ?? ''}`.replace(/\s+/g, ' ').trim()
    if (!error) return resolveProbe({ available: true, detail: 'Windows AppContainer 配置文件 API 可用' })
    const hresult = output.match(/OA_SANDBOX:profile:(?:create|delete)-failed:(0x[0-9a-f]{8})/i)?.[1]
    resolveProbe({
      available: false,
      detail: hresult ? `Windows AppContainer 配置文件 API 不可用（HRESULT=${hresult}）` : output || 'Windows AppContainer 配置文件 API 不可用',
    })
  })
})
