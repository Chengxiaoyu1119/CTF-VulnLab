import dns from 'node:dns'
import dnsPromises from 'node:dns/promises'
import dgram from 'node:dgram'
import http from 'node:http'
import http2 from 'node:http2'
import https from 'node:https'
import inspector from 'node:inspector'
import net from 'node:net'
import tls from 'node:tls'
import { syncBuiltinESMExports } from 'node:module'

const denied = () => {
  const error = new Error('OA API 子进程不允许直接使用网络；请求必须经项目内受限桥接。') as NodeJS.ErrnoException
  error.code = 'ERR_ACCESS_DENIED'
  throw error
}

const deniedAsync = async () => denied()
const patch = (target: object, names: string[]) => {
  for (const name of names) Object.defineProperty(target, name, { configurable: true, value: denied })
}

patch(dns, ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse', 'setServers'])
patch(dnsPromises, ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'])
patch(dgram, ['createSocket'])
patch(dgram.Socket.prototype, ['bind', 'connect', 'send'])
patch(http, ['request', 'get'])
patch(http2, ['connect', 'createServer', 'createSecureServer'])
patch(https, ['request', 'get'])
patch(net, ['connect', 'createConnection'])
patch(net.Server.prototype, ['listen'])
patch(net.Socket.prototype, ['connect'])
patch(tls, ['connect'])
patch(inspector, ['open', 'openUrl'])
const blockedBindings = new Set(['cares_wrap', 'pipe_wrap', 'quic', 'tcp_wrap', 'tls_wrap', 'udp_wrap'])
const originalBinding = (process as NodeJS.Process & { binding(name: string): unknown }).binding.bind(process)
Object.defineProperty(process, 'binding', {
  configurable: false,
  value: (name: string) => blockedBindings.has(name) ? denied() : originalBinding(name),
})
globalThis.fetch = deniedAsync
if ('WebSocket' in globalThis) globalThis.WebSocket = class { constructor() { denied() } } as unknown as typeof WebSocket
syncBuiltinESMExports()
