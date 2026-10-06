import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve, sep } from 'node:path'

const appDir = resolve(import.meta.dirname, '..', 'src')
const require = createRequire(join(appDir, 'package.json'))
const Database = require('better-sqlite3')
const { zipSync } = require('fflate')
const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-custom-api-'))
const sleep = ms => new Promise(resolveSleep => setTimeout(resolveSleep, ms))
const freePort = () => new Promise((resolvePort, rejectPort) => {
  const socket = createServer()
  socket.once('error', rejectPort)
  socket.listen(0, '127.0.0.1', () => {
    const port = socket.address().port
    socket.close(error => error ? rejectPort(error) : resolvePort(port))
  })
})
const [port, runtimePort] = await Promise.all([freePort(), freePort()])
const baseUrl = `http://127.0.0.1:${port}`
let server
let serverOutput = ''
let cookie = ''
let csrfToken = ''

const startServer = async () => {
  server = spawn(process.execPath, [join(appDir, 'dist', 'server.js')], {
    cwd: appDir,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      VULNLAB_ADMIN_PASSWORD: 'vulnlab',
      VULNLAB_AUTO_INSTALL_BUILTINS: '0',
      VULNLAB_OFFLINE: '1',
      VULNLAB_BUNDLE_DIR: '',
      VULNLAB_HOST: '127.0.0.1',
      VULNLAB_PORT: String(port),
      VULNLAB_RUNTIME_PORT_START: String(runtimePort),
      VULNLAB_RUNTIME_PORT_END: String(runtimePort),
      VULNLAB_NODE_BIN: process.execPath,
      // 该 API 夹具只验证 Node 靶场；禁用本机 MariaDB 探测，避免每轮测试启动大型数据库数据目录。
      VULNLAB_MYSQLD_BIN: 'vulnlab-test-missing-mariadbd.exe',
      VULNLAB_DATA_DIR: dataDir,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  server.stdout.on('data', chunk => { serverOutput = `${serverOutput}${chunk}`.slice(-4000) })
  server.stderr.on('data', chunk => { serverOutput = `${serverOutput}${chunk}`.slice(-4000) })
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (server.exitCode !== null) throw new Error(`测试服务提前退出：${serverOutput}`)
    try { if ((await fetch(`${baseUrl}/healthz`)).ok) return } catch {}
    await sleep(100)
  }
  throw new Error(`测试服务未启动：${serverOutput}`)
}

const stopServer = async () => {
  if (!server || server.exitCode !== null) return
  const child = server
  const exited = new Promise(resolveExit => child.once('exit', resolveExit))
  child.kill('SIGTERM')
  await Promise.race([exited, sleep(5000)])
  if (child.exitCode === null) { child.kill(); await Promise.race([exited, sleep(2000)]) }
  server = undefined
}

const request = async (path, { method = 'GET', body, contentType = 'application/json', csrf = true, authenticated = true, headers = {} } = {}) => {
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(body !== undefined ? { 'content-type': contentType } : {}),
      ...(authenticated && cookie ? { cookie } : {}),
      ...(csrf && csrfToken && method !== 'GET' ? { 'x-csrf-token': csrfToken } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: contentType === 'application/json' ? JSON.stringify(body) : body } : {}),
  })
  return { status: response.status, body: await response.json().catch(() => ({})), response }
}

const zip = files => zipSync(Object.fromEntries(Object.entries(files).map(([name, contents]) => [name, new TextEncoder().encode(contents)])))
const upload = async (files, filename = 'fixture.zip') => {
  const result = await request('/api/lab-archives', { method: 'POST', body: zip(files), contentType: 'application/zip', headers: { 'x-vulnlab-file-name': filename } })
  assert.equal(result.status, 201, JSON.stringify(result.body))
  assert.match(result.body.sourceUrl, /^upload:\/\/[0-9a-f-]{36}$/)
  return result.body
}
const createLab = async (sourceUrl, title, runtimeKind, runtimeConfig) => request('/api/labs', {
  method: 'POST', body: { title, sourceType: 'archive', sourceUrl, runtimeKind, runtimeConfig, tags: ['fixture'] },
})
const finishJob = async id => {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const jobs = await request('/api/import-jobs')
    assert.equal(jobs.status, 200)
    const job = jobs.body.find(item => item.id === id)
    if (job?.status === 'completed' || job?.status === 'error') return job
    await sleep(100)
  }
  throw new Error(`导入任务未完成：${id} ${serverOutput}`)
}

try {
  await startServer()
  const anonymousArchive = await request('/api/lab-archives', { method: 'POST', body: zip({ 'site/index.php': '<?php echo 1;' }), contentType: 'application/zip', authenticated: false })
  assert.equal(anonymousArchive.status, 401)
  const anonymousCreate = await createLab('upload://00000000-0000-0000-0000-000000000000', '匿名靶场', 'native-php', { profile: 'static-php' })
  assert.equal(anonymousCreate.status, 401)
  const login = await request('/api/auth/login', { method: 'POST', body: { userName: 'vulnlab', password: 'vulnlab' }, authenticated: false })
  assert.equal(login.status, 200)
  csrfToken = login.body.csrfToken
  cookie = login.response.headers.getSetCookie()[0].split(';', 1)[0]
  assert.ok(csrfToken && cookie)
  const seedLabs = await request('/api/labs')
  assert.equal(seedLabs.status, 200)
  const builtinLab = seedLabs.body.find(item => item.builtin)
  assert.ok(builtinLab)
  assert.equal((await request(`/api/labs/${builtinLab.id}`, { method: 'DELETE' })).status, 404)
  const disableBuiltin = await request(`/api/labs/${builtinLab.id}/status`, { method: 'PATCH', body: { disabled: true } })
  assert.equal(disableBuiltin.status, 200, JSON.stringify(disableBuiltin.body))
  assert.equal(disableBuiltin.body.lab.status, 'disabled')
  assert.ok((await request('/api/labs')).body.some(item => item.id === builtinLab.id && item.status === 'disabled'))
  assert.equal((await request('/api/labs/00000000-0000-0000-0000-000000000000', { method: 'DELETE', csrf: false })).status, 403)
  assert.equal((await request('/api/lab-archives', { method: 'POST', body: zip({ 'site/index.php': '<?php echo 1;' }), contentType: 'application/zip', csrf: false })).status, 403)
  assert.equal((await request('/api/labs', { method: 'POST', body: { title: '缺少 CSRF', sourceType: 'git', sourceUrl: 'https://github.com/example/project' }, csrf: false })).status, 403)
  assert.equal((await request('/api/lab-archives', { method: 'POST', body: zip({ 'site/index.php': '<?php echo 1;' }), contentType: 'application/zip', headers: { 'x-vulnlab-file-name': 'fixture.txt' } })).status, 400)

  const inspectionArchive = await upload({ 'site/index.php': '<?php echo 1;', 'site/init.sql': 'CREATE TABLE fixture (id INT);' })
  const inspection = await request('/api/lab-source-inspections', { method: 'POST', body: { sourceType: 'archive', sourceUrl: inspectionArchive.sourceUrl, runtimeMode: 'php-mysql' } })
  assert.equal(inspection.status, 200, JSON.stringify(inspection.body))
  assert.equal(inspection.body.suggestion.mode, 'php-mysql')
  assert.ok(inspection.body.suggestion.signals.includes('index.php'))
  assert.equal(inspection.body.suggestion.warnings.some(item => item.includes('初始化 SQL')), false)
  const composeArchive = await upload({ 'compose/docker-compose.yml': 'services: {}', 'compose/README.md': 'fixture' })
  const composeInspection = await request('/api/lab-source-inspections', { method: 'POST', body: { sourceType: 'archive', sourceUrl: composeArchive.sourceUrl, runtimeMode: 'node' } })
  assert.equal(composeInspection.status, 200, JSON.stringify(composeInspection.body))
  assert.equal(composeInspection.body.suggestion.mode, null)
  assert.ok(composeInspection.body.suggestion.warnings.some(item => item.includes('Compose') && item.includes('不会执行')))
  assert.ok(composeInspection.body.suggestion.warnings.some(item => item.includes('package.json')))
  const unsupportedInspection = await request('/api/lab-source-inspections', { method: 'POST', body: { sourceType: 'git', sourceUrl: 'https://example.com/team/project' } })
  assert.equal(unsupportedInspection.status, 422)
  const invalidInspectionMode = await request('/api/lab-source-inspections', { method: 'POST', body: { sourceType: 'archive', sourceUrl: inspectionArchive.sourceUrl, runtimeMode: 'compose' } })
  assert.equal(invalidInspectionMode.status, 400, JSON.stringify(invalidInspectionMode.body))

  const invalidConfigs = [
    ['native-php', { profile: 'static-php', entryPath: '../outside.php' }],
    ['native-php', { profile: 'mysql-php', initSqlPath: '../outside.sql' }],
    ['native-node', { profile: 'prebuilt-node', entryPath: '/outside.js' }],
    ['native-java', { profile: 'webgoat', entryPath: '../outside.jar' }],
    ['native-java', { profile: 'java-jar', entryPath: '../outside.jar' }],
    ['native-python', { profile: 'pygoat', settingsPath: '../outside.py' }],
    ['native-python', { profile: 'python-script', entryPath: '../outside.py' }],
  ]
  for (const [runtimeKind, runtimeConfig] of invalidConfigs) {
    const result = await createLab('upload://00000000-0000-0000-0000-000000000000', `非法配置 ${runtimeKind}`, runtimeKind, runtimeConfig)
    assert.equal(result.status, 400, JSON.stringify(result.body))
    assert.equal(result.body.code, 'LAB_RUNTIME_CONFIG_INVALID')
  }

  const traversal = await upload({ 'project/../outside.php': '<?php echo 1;', 'project/index.php': '<?php echo 1;' })
  const traversalLab = await createLab(traversal.sourceUrl, 'ZIP 越界夹具', 'native-php', { profile: 'static-php' })
  assert.equal(traversalLab.status, 202, JSON.stringify(traversalLab.body))
  const traversalJob = await finishJob(traversalLab.body.job.id)
  assert.equal(traversalJob.status, 'error')
  assert.match(traversalJob.error ?? '', /路径|超出|穿越|目录/)
  await assert.rejects(stat(join(dataDir, 'outside.php')))

  const cases = [
    { title: '静态 PHP 缺入口', kind: 'native-php', config: { profile: 'static-php', entryPath: 'missing.php' }, files: { 'site/index.php': '<?php echo 1;' }, error: /PHP 入口文件不存在/ },
    { title: 'MySQL 缺 SQL', kind: 'native-php', config: { profile: 'mysql-php', entryPath: 'index.php', initSqlPath: 'missing.sql' }, files: { 'site/index.php': '<?php echo 1;' }, error: /MySQL 初始化 SQL 不存在/ },
    { title: 'Node 缺入口', kind: 'native-node', config: { profile: 'prebuilt-node', entryPath: 'missing.js' }, files: { 'site/README.md': 'fixture' }, error: /Node.js 项目缺少可运行入口/ },
    { title: 'Java 缺 JAR', kind: 'native-java', config: { profile: 'webgoat', entryPath: 'missing.jar' }, files: { 'site/README.md': 'fixture' }, error: /Java 项目缺少可运行 JAR/ },
    { title: '通用 Java 缺 JAR', kind: 'native-java', config: { profile: 'java-jar', entryPath: 'app.jar' }, files: { 'site/README.md': 'fixture' }, error: /Java 项目缺少可运行 JAR/ },
    { title: 'Python 缺设置', kind: 'native-python', config: { profile: 'pygoat' }, files: { 'site/manage.py': 'print(1)' }, error: /Python 项目缺少 Django 设置文件/ },
    { title: '通用 Python 缺运行文件', kind: 'native-python', config: { profile: 'python-script', entryPath: 'app.py' }, files: { 'site/README.md': 'fixture' }, error: /Python 项目缺少可运行文件/ },
  ]
  for (const item of cases) {
    const source = await upload(item.files)
    const created = await createLab(source.sourceUrl, item.title, item.kind, item.config)
    assert.equal(created.status, 202, JSON.stringify(created.body))
    const job = await finishJob(created.body.job.id)
    assert.equal(job.status, 'error', JSON.stringify(job))
    assert.match(job.error ?? '', item.error)
  }

  const javaSource = await upload({ 'site/app.jar': 'fixture-jar' })
  const javaLab = await createLab(javaSource.sourceUrl, '通用 Java 夹具', 'native-java', { profile: 'java-jar', entryPath: 'app.jar', portArg: '--server.port={port}' })
  assert.equal(javaLab.status, 202, JSON.stringify(javaLab.body))
  assert.equal((await finishJob(javaLab.body.job.id)).status, 'completed')

  const pythonSource = await upload({ 'site/app.py': 'print("fixture")\n' })
  const pythonLab = await createLab(pythonSource.sourceUrl, '通用 Python 夹具', 'native-python', { profile: 'python-script', entryPath: 'app.py', portArg: '--port={port}' })
  assert.equal(pythonLab.status, 202, JSON.stringify(pythonLab.body))
  assert.equal((await finishJob(pythonLab.body.job.id)).status, 'completed')

  const pythonModeSource = await upload({ 'project/app.py': 'print("mapped mode")\n' })
  const pythonModeLab = await request('/api/labs', { method: 'POST', body: { title: '映射 Python 运行方式', sourceType: 'archive', sourceUrl: pythonModeSource.sourceUrl, runtimeMode: 'python' } })
  assert.equal(pythonModeLab.status, 202, JSON.stringify(pythonModeLab.body))
  assert.equal(pythonModeLab.body.lab.runtimeKind, 'native-python')
  assert.equal(pythonModeLab.body.lab.runtimeConfig.profile, 'python-script')
  assert.equal((await finishJob(pythonModeLab.body.job.id)).status, 'completed')

  const appSource = `import { createServer } from 'node:http';\ncreateServer((_req, res) => { res.writeHead(200); res.end('custom-lab-ok'); }).listen(Number(process.env.PORT), process.env.HOST);\n`
  const validArchive = await upload({ 'site/app.js': appSource, 'site/server.js': appSource })
  const valid = await createLab(validArchive.sourceUrl, '离线 Node 靶场', 'native-node', { profile: 'prebuilt-node', entryPath: 'app.js' })
  assert.equal(valid.status, 202, JSON.stringify(valid.body))
  assert.equal((await finishJob(valid.body.job.id)).status, 'completed')
  let labs = await request('/api/labs')
  const ready = labs.body.find(item => item.title === '离线 Node 靶场')
  assert.equal(ready.status, 'ready')
  assert.equal(ready.builtin, false)
  assert.equal(ready.runtimeConfig.entryPath, 'app.js')
  assert.ok(ready.localPath.startsWith(`${dataDir}${sep}`))
  assert.equal((await readFile(join(ready.localPath, 'app.js'), 'utf8')), appSource)
  assert.equal((await stat(join(ready.localPath, 'vulnlab.manifest.json'))).isFile(), true)
  const prepareStateDb = new Database(join(dataDir, 'vulnlab.sqlite'))
  prepareStateDb.prepare("UPDATE labs SET status = 'importing' WHERE id = ?").run(ready.id)
  const deleteWhilePreparing = await request(`/api/labs/${ready.id}`, { method: 'DELETE' })
  assert.equal(deleteWhilePreparing.status, 409)
  assert.equal(deleteWhilePreparing.body.code, 'LAB_PREPARING')
  prepareStateDb.prepare("UPDATE labs SET status = 'ready' WHERE id = ?").run(ready.id)
  prepareStateDb.close()
  const firstStart = await request(`/api/labs/${ready.id}/instances`, { method: 'POST' })
  assert.equal(firstStart.status, 201, JSON.stringify(firstStart.body))
  assert.equal(firstStart.body.status, 'running')
  assert.equal(await (await fetch(firstStart.body.endpoint)).text(), 'custom-lab-ok')
  const deleteWhileRunning = await request(`/api/labs/${ready.id}`, { method: 'DELETE' })
  assert.equal(deleteWhileRunning.status, 409)
  assert.equal(deleteWhileRunning.body.code, 'LAB_RUNNING')
  assert.equal((await request(`/api/labs/${ready.id}/status`, { method: 'PATCH', body: { disabled: true } })).status, 409)
  assert.equal((await request(`/api/instances/${firstStart.body.id}`, { method: 'DELETE' })).status, 200)
  const edited = await request(`/api/labs/${ready.id}`, { method: 'PATCH', body: { title: '已编辑 Node 靶场', summary: '管理信息编辑验证' } })
  assert.equal(edited.status, 200, JSON.stringify(edited.body))
  assert.equal(edited.body.lab.title, '已编辑 Node 靶场')
  assert.equal(edited.body.lab.status, 'ready')
  const invalidEdit = await request(`/api/labs/${ready.id}`, { method: 'PATCH', body: { runtimeConfig: { ...ready.runtimeConfig, entryPath: '../outside.js' } } })
  assert.equal(invalidEdit.status, 400)
  assert.equal(invalidEdit.body.code, 'LAB_RUNTIME_CONFIG_INVALID')
  const invalidEntryEdit = await request(`/api/labs/${ready.id}`, { method: 'PATCH', body: { runtimeKind: 'native-php', runtimeConfig: { profile: 'static-php', entryPath: 'missing.php' } } })
  assert.equal(invalidEntryEdit.status, 202, JSON.stringify(invalidEntryEdit.body))
  assert.equal((await finishJob(invalidEntryEdit.body.job.id)).status, 'error')
  const retried = await request(`/api/labs/${ready.id}/install`, { method: 'POST' })
  assert.equal(retried.status, 202, JSON.stringify(retried.body))
  assert.equal((await finishJob(retried.body.job.id)).status, 'error')
  const restoredConfig = await request(`/api/labs/${ready.id}`, { method: 'PATCH', body: { runtimeKind: 'native-node', runtimeConfig: ready.runtimeConfig } })
  assert.equal(restoredConfig.status, 202, JSON.stringify(restoredConfig.body))
  assert.equal((await finishJob(restoredConfig.body.job.id)).status, 'completed')
  assert.equal((await request('/api/labs')).body.find(item => item.id === ready.id)?.status, 'ready')
  const disabled = await request(`/api/labs/${ready.id}/status`, { method: 'PATCH', body: { disabled: true } })
  assert.equal(disabled.status, 200, JSON.stringify(disabled.body))
  assert.equal(disabled.body.lab.status, 'disabled')
  assert.equal((await request(`/api/labs/${ready.id}/instances`, { method: 'POST' })).status, 409)
  assert.equal((await request(`/api/labs/${ready.id}/install`, { method: 'POST' })).status, 409)
  const disabledEdit = await request(`/api/labs/${ready.id}`, { method: 'PATCH', body: { runtimeConfig: { ...ready.runtimeConfig, entryPath: 'server.js' } } })
  assert.equal(disabledEdit.status, 200, JSON.stringify(disabledEdit.body))
  assert.equal(disabledEdit.body.lab.status, 'disabled')
  assert.equal(disabledEdit.body.lab.localPath, null)
  const restored = await request(`/api/labs/${ready.id}/status`, { method: 'PATCH', body: { disabled: false } })
  assert.equal(restored.status, 202, JSON.stringify(restored.body))
  assert.ok(['queued', 'importing'].includes(restored.body.lab.status), JSON.stringify(restored.body.lab))
  assert.equal((await finishJob(restored.body.job.id)).status, 'completed')
  assert.equal((await request('/api/labs')).body.find(item => item.id === ready.id)?.status, 'ready')
  await stopServer()
  await startServer()
  const relogin = await request('/api/auth/login', { method: 'POST', body: { userName: 'vulnlab', password: 'vulnlab' }, authenticated: false })
  assert.equal(relogin.status, 200)
  csrfToken = relogin.body.csrfToken
  cookie = relogin.response.headers.getSetCookie()[0].split(';', 1)[0]
  labs = await request('/api/labs')
  assert.equal(labs.body.find(item => item.id === ready.id)?.status, 'ready')
  assert.equal(labs.body.find(item => item.id === builtinLab.id)?.status, 'disabled')
  const secondStart = await request(`/api/labs/${ready.id}/instances`, { method: 'POST' })
  assert.equal(secondStart.status, 201, JSON.stringify(secondStart.body))
  assert.equal(await (await fetch(secondStart.body.endpoint)).text(), 'custom-lab-ok')
  assert.equal((await request(`/api/instances/${secondStart.body.id}`, { method: 'DELETE' })).status, 200)
  assert.equal((await request('/api/import-jobs')).body.filter(item => item.labId === ready.id).length, 5)
  const sharedSourceLab = await createLab(validArchive.sourceUrl, '共享上传包副本', 'native-node', { profile: 'prebuilt-node', entryPath: 'app.js' })
  assert.equal(sharedSourceLab.status, 202, JSON.stringify(sharedSourceLab.body))
  assert.equal((await finishJob(sharedSourceLab.body.job.id)).status, 'completed')
  const uploadId = /^upload:\/\/([0-9a-f-]{36})$/i.exec(validArchive.sourceUrl)?.[1]
  assert.ok(uploadId)
  const sharedUploadPath = join(dataDir, 'lab-uploads', `${uploadId}.zip`)
  const deletedLab = await request(`/api/labs/${ready.id}`, { method: 'DELETE' })
  assert.equal(deletedLab.status, 200, JSON.stringify(deletedLab.body))
  assert.equal(deletedLab.body.cleanupPending, false)
  assert.equal((await request('/api/labs')).body.some(item => item.id === ready.id), false)
  assert.equal((await request('/api/import-jobs')).body.some(item => item.labId === ready.id), false)
  await assert.rejects(stat(ready.localPath))
  assert.equal((await stat(sharedUploadPath)).isFile(), true)
  const deletedSharedSource = await request(`/api/labs/${sharedSourceLab.body.lab.id}`, { method: 'DELETE' })
  assert.equal(deletedSharedSource.status, 200, JSON.stringify(deletedSharedSource.body))
  await assert.rejects(stat(sharedUploadPath))
  console.log('VulnLab custom-lab API test passed: auth, CSRF, ZIP safety, template entries, persistence and offline restart.')
} finally {
  await stopServer()
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}

// 重启流程结束后 undici 仍会保留空闲连接；断言和清理完成后显式结束夹具进程。
process.exit(0)
