import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createServer as createHttpServer } from 'node:http'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { NativeOaProvider } from '../../src/dist/providers.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-oa-permission-'))
const instanceRoot = join(root, 'instance')
const uploadRoot = join(instanceRoot, 'uploads')
const outsideFile = join(root, 'outside.txt')
const uploadFile = join(uploadRoot, 'upload.txt')
const networkGuard = join(import.meta.dirname, '..', '..', 'src', 'dist', 'oa', 'network-guard.js')
await mkdir(uploadRoot, { recursive: true })
await writeFile(join(instanceRoot, 'seed.txt'), 'instance-readable')
await writeFile(outsideFile, 'host-readable')

try {
  const target = createHttpServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('same instance')
  })
  const redirect = createHttpServer((_request, response) => {
    const address = target.address()
    response.writeHead(302, { location: `http://127.0.0.1:${address.port}/` })
    response.end()
  })
  const listen = server => new Promise(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen(server.address().port)))
  const targetPort = await listen(target)
  const redirectPort = await listen(redirect)
  try {
    const provider = new NativeOaProvider()
    const allowed = await provider.ssrfRequest({ url: `http://127.0.0.1:${targetPort}/` }, new Set([targetPort]))
    assert.equal(allowed.body, 'same instance')
    await assert.rejects(provider.ssrfRequest({ url: `http://127.0.0.1:${redirectPort}/` }, new Set([targetPort])), /本实例 Web/)
    await assert.rejects(provider.ssrfRequest({ url: `http://127.0.0.1:${targetPort}/` }, new Set([redirectPort])), /本实例 Web/)
    await assert.rejects(provider.ssrfRequest({ url: 'http://example.com/' }, new Set([targetPort])), /本实例 Web/)
    await assert.rejects(provider.ssrfRequest({ url: `https://127.0.0.1:${targetPort}/` }, new Set([targetPort])), /本实例 Web/)
  } finally {
    await Promise.all([target, redirect].map(server => new Promise(resolveClose => server.close(() => resolveClose()))))
  }

  const code = `
    import net from 'node:net';
    import http from 'node:http';
    import http2 from 'node:http2';
    import dns from 'node:dns';
    import dgram from 'node:dgram';
    import inspector from 'node:inspector';
    import { createRequire } from 'node:module';
    const require = createRequire(import.meta.url);
    const { readFileSync, writeFileSync } = require('node:fs');
    const { spawnSync } = require('node:child_process');
    const [instanceFile, outsideFile, uploadFile] = process.argv.slice(1);
    const instance = readFileSync(instanceFile, 'utf8');
    let outside = 'unexpectedly-readable';
    let child = 'unexpectedly-allowed';
    const network = fn => { try { fn(); return 'unexpectedly-allowed'; } catch (error) { return error.code; } };
    try { readFileSync(outsideFile, 'utf8'); } catch (error) { outside = error.code; }
    try { spawnSync(process.execPath, ['--version']); } catch (error) { child = error.code; }
    writeFileSync(uploadFile, 'upload-write-allowed');
    const netConnect = network(() => net.createConnection({ host: '127.0.0.1', port: 1 }));
    const httpRequest = network(() => http.get('http://127.0.0.1:1'));
    const http2Connect = network(() => http2.connect('http://127.0.0.1:1'));
    const dnsLookup = network(() => dns.lookup('example.com', () => {}));
    const udpSocket = network(() => dgram.createSocket('udp4'));
    const lowLevelTcp = network(() => process.binding('tcp_wrap'));
    const inspectorListener = network(() => inspector.open(0, '127.0.0.1'));
    const fetchRequest = await fetch('http://127.0.0.1:1').then(() => 'unexpectedly-allowed', error => error.code);
    const listener = network(() => net.createServer().listen(0, '127.0.0.1'));
    console.log(JSON.stringify({
      instance, outside, child,
      netConnect, httpRequest, http2Connect, dnsLookup, udpSocket, lowLevelTcp, inspectorListener, fetchRequest, listener,
      read: process.permission.has('fs.read', instanceFile),
      write: process.permission.has('fs.write', uploadFile),
    }));
  `
  const result = spawnSync(process.execPath, [
    '--permission', `--import=${pathToFileURL(networkGuard).href}`, `--allow-fs-read=${instanceRoot}`, `--allow-fs-read=${networkGuard}`, `--allow-fs-write=${uploadRoot}`,
    '--input-type=module', '-e', code, join(instanceRoot, 'seed.txt'), outsideFile, uploadFile,
  ], { encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 0, result.stderr)
  const output = JSON.parse(result.stdout.trim())
  assert.deepEqual(output, {
    instance: 'instance-readable',
    outside: 'ERR_ACCESS_DENIED',
    child: 'ERR_ACCESS_DENIED',
    netConnect: 'ERR_ACCESS_DENIED',
    httpRequest: 'ERR_ACCESS_DENIED',
    http2Connect: 'ERR_ACCESS_DENIED',
    dnsLookup: 'ERR_ACCESS_DENIED',
    udpSocket: 'ERR_ACCESS_DENIED',
    lowLevelTcp: 'ERR_ACCESS_DENIED',
    inspectorListener: 'ERR_ACCESS_DENIED',
    fetchRequest: 'ERR_ACCESS_DENIED',
    listener: 'ERR_ACCESS_DENIED',
    read: true,
    write: true,
  })
  assert.equal(await readFile(uploadFile, 'utf8'), 'upload-write-allowed')
  console.log('VulnLab OA process boundary test passed: app files and uploads are scoped; child processes, direct network, DNS and listeners are denied; SSRF bridge accepts only the same-instance Web port and rejects external/redirect targets.')
} finally {
  await rm(root, { recursive: true, force: true })
}
