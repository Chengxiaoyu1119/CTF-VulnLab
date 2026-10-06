import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { createConnection, createServer } from 'node:net'
import { randomUUID } from 'node:crypto'
import { mkdir, rm } from 'node:fs/promises'
import { join, resolve, dirname } from 'node:path'
import { RuntimeToolchainInstaller } from '../src/dist/runtime-toolchains.js'

const appDir = resolve(import.meta.dirname, '..', 'src')
const dataDir = join(appDir, 'data', `.oa-garnet-smoke-${randomUUID()}`)
const runtimeDir = join(dataDir, 'runtime')
const port = await new Promise((resolvePort, reject) => {
  const server = createServer()
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? reject(error) : resolvePort(typeof address === 'object' && address ? address.port : 0))
  })
})
const encode = args => Buffer.from(`*${args.length}\r\n${args.map(value => `$${Buffer.byteLength(value)}\r\n${value}\r\n`).join('')}`)
const parse = (buffer, offset = 0) => {
  const end = buffer.indexOf('\r\n', offset)
  if (end < 0) return null
  const marker = String.fromCharCode(buffer[offset])
  const header = buffer.toString('utf8', offset + 1, end)
  if (marker === '+' || marker === ':') return { value: marker === ':' ? Number(header) : header, end: end + 2 }
  if (marker === '-') throw new Error(header)
  if (marker === '$') {
    const length = Number(header)
    if (length === -1) return { value: null, end: end + 2 }
    if (buffer.length < end + 2 + length + 2) return null
    return { value: buffer.toString('utf8', end + 2, end + 2 + length), end: end + 2 + length + 2 }
  }
  throw new Error(`Unsupported RESP response: ${marker}`)
}
const command = async args => {
  const socket = createConnection({ host: '127.0.0.1', port })
  try {
    await new Promise((resolveConnect, rejectConnect) => {
      socket.once('connect', resolveConnect)
      socket.once('error', rejectConnect)
      socket.setTimeout(5_000, () => socket.destroy(new Error('Garnet connection timeout')))
    })
    const response = async input => {
      socket.write(encode(input))
      let buffered = Buffer.alloc(0)
      while (true) {
        const parsed = parse(buffered)
        if (parsed) return parsed.value
        const chunk = await new Promise((resolveData, rejectData) => {
          socket.once('data', resolveData)
          socket.once('error', rejectData)
          socket.once('end', () => rejectData(new Error('Garnet closed the connection')))
        })
        buffered = Buffer.concat([buffered, chunk])
      }
    }
    assert.equal(await response(['AUTH', '123456']), 'OK')
    return await response(args)
  } finally {
    socket.destroy()
  }
}
const waitForPort = async child => {
  const deadline = Date.now() + 30_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Garnet exited early (${child.exitCode})`)
    try {
      await new Promise((resolveConnect, rejectConnect) => {
        const socket = createConnection({ host: '127.0.0.1', port })
        socket.once('connect', () => { socket.destroy(); resolveConnect() })
        socket.once('error', rejectConnect)
        socket.setTimeout(500, () => { socket.destroy(); rejectConnect(new Error('not ready')) })
      })
      return
    } catch {}
    await new Promise(resolveWait => setTimeout(resolveWait, 150))
  }
  throw new Error('Garnet did not listen within 30 seconds')
}

let garnet
try {
  await mkdir(dataDir, { recursive: true })
  const installer = new RuntimeToolchainInstaller(runtimeDir)
  const statuses = await installer.installMissing(['dotnet', 'garnet'])
  assert.ok(statuses.filter(item => ['dotnet', 'garnet'].includes(item.id)).every(item => item.state === 'ready' && item.sha256Verified))
  const binaries = await installer.binaries()
  assert.ok(binaries.dotnet && binaries.garnet)
  garnet = spawn(binaries.garnet, [
    '--bind', '127.0.0.1', '--port', String(port), '--memory', '64m', '--page', '16m', '--index', '1m',
    '--segment', '64m', '--object-log-segment', '64m', '--auth', 'Password', '--password', '123456', '--disable-console-logger',
  ], {
    cwd: runtimeDir,
    env: { ...process.env, DOTNET_ROOT: dirname(binaries.dotnet), DOTNET_MULTILEVEL_LOOKUP: '0' },
    stdio: 'ignore',
    windowsHide: true,
  })
  await waitForPort(garnet)
  assert.equal(await command(['SET', 'reset_code:123456', '123456', 'EX', '300']), 'OK')
  assert.equal(await command(['GET', 'reset_code:123456']), '123456')
  assert.equal(await command(['GET', 'missing']), null)
  console.log(`VulnLab OA Garnet smoke passed: pinned .NET 10/Garnet 2.1.8 hashes verified; AUTH, SET EX, GET and nil GET passed on ${port}.`)
} finally {
  if (garnet && garnet.exitCode === null) {
    const exited = new Promise(resolveExit => garnet.once('exit', resolveExit))
    garnet.kill()
    await Promise.race([exited, new Promise(resolveWait => setTimeout(resolveWait, 3_000))])
    if (garnet.exitCode === null && garnet.pid) spawnSync('taskkill', ['/PID', String(garnet.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore', timeout: 5_000 })
  }
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
