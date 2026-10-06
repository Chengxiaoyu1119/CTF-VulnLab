import { RpcPeer } from './oa-ipc.js'
import { createOaApi } from './oa-api.js'

if (!process.stdin.isTTY && process.stdin.readable && process.stdout.writable) {
  const peer = new RpcPeer(process.stdin, process.stdout, async (method, payload) => {
    if (method !== 'http' || !api) throw new Error('OA HTTP 请求尚未就绪。')
    const request = payload as Record<string, any>
    const result = await api.inject({
      method: request.methodName,
      url: request.url,
      headers: request.headers,
      payload: request.bodyBase64 ? Buffer.from(request.bodyBase64, 'base64') : undefined,
    })
    return {
      statusCode: result.statusCode,
      headers: result.headers,
      bodyBase64: result.rawPayload.toString('base64'),
    }
  })

  let api: Awaited<ReturnType<typeof createOaApi>> | null = null
  const runtimeRoot = process.env.VULNLAB_OA_RUNTIME_ROOT ?? process.cwd()
  api = await createOaApi({
    runtimeRoot,
    frontendRoot: process.env.VULNLAB_OA_FRONTEND_ROOT ?? `${process.cwd()}\\backend\\dist`,
    uploadRoot: process.env.VULNLAB_OA_UPLOAD_ROOT ?? `${process.cwd()}\\uploads`,
    jwtSecret: process.env.VULNLAB_OA_JWT_SECRET,
    inviteCode: process.env.VULNLAB_OA_INVITE_CODE,
    rpc: peer,
  })
  await api.ready()
  await peer.call('ready', { pid: process.pid })

  const shutdown = async () => {
    peer.close()
    await api?.close()
    process.exit(0)
  }
  process.once('SIGTERM', () => { void shutdown() })
  process.once('SIGINT', () => { void shutdown() })
  process.stdin.once('end', () => { void shutdown() })
}
