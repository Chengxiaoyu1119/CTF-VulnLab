import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'

export const OA_LAUNCHER_SHA256 = 'cf81e3fc88edb0d166e0d15057b72f9a5078bae973b5af51e63585e7a3ea929b'

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
