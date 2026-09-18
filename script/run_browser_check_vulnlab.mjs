import { spawn } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { join, resolve } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', 'src')
const serverPath = resolve(appDir, 'dist', 'server.js')
const browserCheck = resolve(import.meta.dirname, 'browser_check_vulnlab.py')
const wait = milliseconds => new Promise(resolvePromise => setTimeout(resolvePromise, milliseconds))

const freePort = () => new Promise((resolvePromise, reject) => {
  const server = createServer()
  server.once('error', reject)
  server.listen(0, '127.0.0.1', () => {
    const address = server.address()
    server.close(error => error ? reject(error) : resolvePromise(typeof address === 'object' && address ? address.port : 0))
  })
})

const stop = async child => {
  if (child.exitCode !== null) return
  const exited = new Promise(resolvePromise => child.once('exit', resolvePromise))
  child.kill('SIGTERM')
  await Promise.race([exited, wait(5_000)])
  if (child.exitCode === null) {
    child.kill()
    await Promise.race([exited, wait(2_000)])
  }
}

const run = (command, args, options) => new Promise((resolvePromise, reject) => {
  const child = spawn(command, args, options)
  child.once('error', reject)
  child.once('exit', code => code === 0 ? resolvePromise() : reject(new Error(`${command} exited with ${code ?? 'an unknown'} status.`)))
})

const dataRoot = join(appDir, 'data')
await mkdir(dataRoot, { recursive: true })
const dataDir = await mkdtemp(join(dataRoot, 'browser-check-'))
let server
try {
  const port = await freePort()
  const baseUrl = `http://127.0.0.1:${port}`
  server = spawn(process.execPath, [serverPath], {
    cwd: appDir,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      VULNLAB_ADMIN_PASSWORD: 'vulnlab',
      VULNLAB_AUTO_INSTALL_BUILTINS: '0',
      VULNLAB_OFFLINE: '1',
      VULNLAB_BUNDLE_DIR: '',
      VULNLAB_MYSQL_ADMIN_USER: '',
      VULNLAB_MYSQL_ADMIN_PASSWORD: '',
      VULNLAB_MYSQL_BIN: 'vulnlab-browser-check-disabled-mysql',
      VULNLAB_MYSQLD_BIN: 'vulnlab-browser-check-disabled-mysqld',
      VULNLAB_HOST: '127.0.0.1',
      VULNLAB_PORT: String(port),
      VULNLAB_PUBLIC_URL: '',
      VULNLAB_DATA_DIR: dataDir,
      VULNLAB_INSTANCE_MINUTES: '60',
    },
    stdio: 'inherit',
  })
  let startupError
  server.once('error', error => { startupError = error })
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (startupError) throw startupError
    if (server.exitCode !== null) throw new Error(`VulnLab stopped before listening on ${baseUrl}.`)
    try {
      if ((await fetch(`${baseUrl}/healthz`)).ok) break
    } catch {}
    if (attempt === 299) throw new Error(`VulnLab did not start on ${baseUrl}.`)
    await wait(100)
  }
  await run(process.env.PYTHON ?? 'python', [browserCheck], {
    cwd: resolve(appDir, '..'),
    env: {
      ...process.env,
      VULNLAB_BASE_URL: baseUrl,
      VULNLAB_DATA_DIR: dataDir,
      VULNLAB_BROWSER_ISOLATED: '1',
      VULNLAB_PRIMARY_SCREENSHOT: '',
      VULNLAB_SCREENSHOT_DIR: join(dataDir, 'screenshots'),
    },
    stdio: 'inherit',
  })
} finally {
  if (server) await stop(server)
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
