import { randomUUID } from 'node:crypto'
import { execFile } from 'node:child_process'

export const OA_LAUNCHER_SHA256 = '4da61aa9b309aa451b9dc722d8a256adf9038bb19a84e2be0760ac6b3f5e3d14'

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
