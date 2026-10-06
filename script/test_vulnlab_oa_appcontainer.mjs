import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { spawn } from 'node:child_process'
import { copyFile, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

if (process.platform !== 'win32') {
  console.log('VulnLab OA AppContainer test skipped: Windows is required.')
  process.exit(0)
}

const appDir = resolve(import.meta.dirname, '..', 'src')
const dataRoot = join(appDir, 'data')
const launcher = await realpath(join(appDir, 'assets', 'native-oa', 'appcontainer-launcher-sandbox.exe'))
const testRoot = join(dataRoot, `.oa-appcontainer-test-${randomUUID()}`)
await mkdir(testRoot, { recursive: true })
const tempRoot = await mkdtemp(join(testRoot, 'sandbox-'))
const runtimeRoot = join(tempRoot, 'runtime')
const moduleRoot = join(tempRoot, 'modules')
const nodeBinary = join(runtimeRoot, 'node.exe')
const uploadRoot = join(runtimeRoot, 'uploads')
const scriptPath = join(runtimeRoot, 'probe.mjs')
const outsidePath = join(tempRoot, 'outside-secret.txt')
const outsideWrite = join(tempRoot, 'outside-write.txt')
const uploadPath = join(uploadRoot, 'probe.txt')
const profile = `VulnLab.OA.test.${createHash('sha256').update(randomUUID()).digest('hex').slice(0, 20)}`
const listener = await import('node:http').then(({ createServer }) => createServer((_request, response) => response.end('unexpected network access')))

const listen = server => new Promise((resolveListen, rejectListen) => {
  server.once('error', rejectListen)
  server.listen(0, '127.0.0.1', () => resolveListen(server.address().port))
})

const run = (binary, args, cwd, timeoutMs = 30_000) => new Promise((resolveRun, rejectRun) => {
  const child = spawn(binary, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false })
  let stdout = ''
  let stderr = ''
  const timeout = setTimeout(() => { child.kill(); rejectRun(new Error(`process timed out: ${binary}\n${stderr}\n${stdout}`)) }, timeoutMs)
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; process.stdout.write(chunk) })
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; process.stderr.write(chunk) })
  child.once('error', error => { clearTimeout(timeout); rejectRun(error) })
  child.once('exit', (code, signal) => { clearTimeout(timeout); resolveRun({ code, signal, stdout, stderr }) })
})

try {
  const profileCheck = await run(launcher, ['check', profile], tempRoot)
  if (profileCheck.code !== 0) {
    assert.match(profileCheck.stderr, /OA_SANDBOX:profile:create-failed:0x800706D9/i, `${profileCheck.stderr}\n${profileCheck.stdout}`)
    console.log('VulnLab OA AppContainer test skipped: Windows profile API returned 0x800706D9; no system service was changed.')
  } else {
  await mkdir(uploadRoot, { recursive: true })
  await mkdir(moduleRoot, { recursive: true })
  await copyFile(await realpath(process.execPath), nodeBinary)
  await writeFile(outsidePath, 'host-secret')
  await writeFile(scriptPath, `
    import { readFileSync, writeFileSync } from 'node:fs';
    import { spawnSync } from 'node:child_process';
    import net from 'node:net';
    const [outsidePath, outsideWrite, uploadPath, networkPort, commandPath] = process.argv.slice(2);
    let outsideRead = 'allowed';
    let outsideWriteResult = 'allowed';
    let childProcess = 'allowed';
    let tcp = 'allowed';
    let web = 'allowed';
    let upload = 'failed';
    try { readFileSync(outsidePath, 'utf8'); } catch (error) { outsideRead = error.code || error.name; }
    try { writeFileSync(outsideWrite, 'escaped'); } catch (error) { outsideWriteResult = error.code || error.name; }
    try { const spawned = spawnSync(commandPath, ['/c', 'exit', '0']); childProcess = spawned.error?.code || (spawned.status === 0 ? 'allowed' : String(spawned.status)); } catch (error) { childProcess = error.code || error.name; }
    const socket = net.createConnection({ host: '127.0.0.1', port: Number(networkPort) });
    try { await new Promise((resolve, reject) => { const timeout = setTimeout(() => reject(new Error('timeout')), 1500); socket.once('connect', () => { clearTimeout(timeout); resolve(); }); socket.once('error', error => { clearTimeout(timeout); reject(error); }); }); } catch (error) { tcp = error.code || error.name; } finally { socket.destroy(); }
    try { await fetch('http://127.0.0.1:' + networkPort + '/', { signal: AbortSignal.timeout(3000) }).then(response => response.text()); } catch (error) { web = error.cause?.code || error.code || error.name; }
    try { writeFileSync(uploadPath, 'upload-ok'); upload = readFileSync(uploadPath, 'utf8'); } catch (error) { upload = error.code || error.name; }
    console.log(JSON.stringify({ outsideRead, outsideWriteResult, childProcess, tcp, web, upload }));
  `)
  const port = await listen(listener)
  const commandPath = join(process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows', 'System32', 'cmd.exe')
  const args = ['appcontainer', profile, runtimeRoot, uploadRoot, nodeBinary, scriptPath, moduleRoot,
    '--max-old-space-size=128', scriptPath, outsidePath, outsideWrite, uploadPath, String(port), commandPath]
  console.log(`VulnLab OA AppContainer probe identity: ${profile}`)
  const result = await run(launcher, args, runtimeRoot, 120_000)
  assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`)
  assert.match(result.stderr, /OA_SANDBOX:verified-appcontainer:resumed:/)
  assert.match(result.stderr, /OA_SANDBOX:cleanup:complete/)
  const probe = JSON.parse(result.stdout.trim())
  assert.equal(probe.outsideRead, 'EACCES')
  assert.equal(probe.outsideWriteResult, 'EACCES')
  assert.notEqual(probe.childProcess, 'allowed')
  assert.notEqual(probe.tcp, 'allowed')
  assert.notEqual(probe.web, 'allowed')
  assert.equal(probe.upload, 'upload-ok')
  assert.equal(await readFile(outsidePath, 'utf8'), 'host-secret')
  await assert.rejects(readFile(outsideWrite), error => error.code === 'ENOENT')
  assert.equal(await readFile(uploadPath, 'utf8'), 'upload-ok')
  const repeatedCleanup = await run(launcher, ['cleanup', profile, runtimeRoot, uploadRoot, nodeBinary, scriptPath, moduleRoot], runtimeRoot)
  assert.equal(repeatedCleanup.code, 0, repeatedCleanup.stderr)
  console.log('VulnLab OA AppContainer test passed: OS ACL denied external file read/write; AppContainer denied child process and loopback network; instance upload remained writable; per-instance ACL cleanup completed and is idempotent.')
  }
} finally {
  await new Promise(resolveClose => listener.close(() => resolveClose()))
  await rm(testRoot, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 })
}
