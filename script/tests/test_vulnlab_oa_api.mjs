import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import bcrypt from '../../src/node_modules/bcryptjs/umd/index.js'
import { strFromU8, unzipSync } from '../../src/node_modules/fflate/esm/index.mjs'
import { createOaApi } from '../../src/dist/oa/api.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-oa-api-'))
const previousCwd = process.cwd()
const uploadRoot = join(root, 'uploads')
const frontendRoot = join(root, 'frontend')
const backendRoot = join(root, 'backend')
const jwtSecret = 'fixture-only-oa-secret'
const inviteCode = 'fixture-only-invite-code'
const calls = []
const cache = new Map()
const files = new Map()
const announcements = new Map([[1, { id: 1, title: 'fixture announcement', content: 'fixture' }]])
const tickets = new Map([[1, { id: 1, title: 'another user ticket', content: 'fixture', status: 1 }]])
let nextId = 2

await mkdir(join(uploadRoot, 'files'), { recursive: true })
await mkdir(join(uploadRoot, 'avatars'), { recursive: true })
await mkdir(frontendRoot, { recursive: true })
await mkdir(join(backendRoot, 'dist'), { recursive: true })
await writeFile(join(frontendRoot, 'index.html'), '<html></html>')
await writeFile(join(backendRoot, 'dist', 'index.html'), '<html>instance-readable fixture</html>')
await writeFile(join(root, 'secret.txt'), 'path traversal fixture')
await mkdir(join(root, 'database'), { recursive: true })
await writeFile(join(root, 'database', 'init.native.sql'), 'instance database seed')
await writeFile(join(uploadRoot, 'files', 'fixture.txt'), 'uploaded file is readable')

const passwordHash = await bcrypt.hash('fixture-password', 4)
const users = new Map([
  ['admin', { id: 1, username: 'admin', password: passwordHash, real_name: '管理员', email: 'admin@example.test', phone: '', avatar: '', dept_id: 1, dept_name: '管理部', role_code: 'admin', role_name: '系统管理员', status: 1 }],
  ['user', { id: 2, username: 'user', password: passwordHash, real_name: '测试用户', email: 'user@example.test', phone: '', avatar: '', dept_id: 1, dept_name: '管理部', role_code: 'user', role_name: '普通员工', status: 1 }],
])

const rpc = {
  async call(method, payload) {
    calls.push({ method, payload })
    if (method === 'ssrf.request') {
      if (payload.url === 'http://example.com/') throw new Error('SSRF 目标仅允许本实例 Web 端口。')
      return { status: 200, body: 'instance service response' }
    }
    if (method === 'instance.config') return { server_port: 6001, database_port: 6002, redis_port: 6003 }
    if (method === 'redis.command') {
      assert.ok(Array.isArray(payload.args) && payload.args.every(value => typeof value === 'string'), 'project cache accepts only string RESP arguments')
      const [command, key, value, expiryMode, ttl] = payload.args
      if (command === 'GET' && payload.args.length === 2) return cache.get(key) ?? null
      if (command === 'SET' && expiryMode === 'EX' && /^\d+$/.test(ttl)) {
        cache.set(key, value)
        return 'OK'
      }
      throw new Error('unsupported project cache command')
    }
    assert.equal(method, 'mysql.query')
    const { statement, values = [] } = payload
    if (statement.includes('WHERE u.username = ? AND u.status = 1')) {
      const user = users.get(values[0])
      return { rows: user ? [{ ...user }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('WHERE u.id = ? LIMIT 1')) {
      const user = [...users.values()].find(item => item.id === Number(values[0]))
      return { rows: user ? [{ ...user }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('FROM users u LEFT JOIN departments d ON d.id=u.dept_id WHERE u.id=?')) {
      const user = [...users.values()].find(item => item.id === Number(values[0]))
      return { rows: user ? [{ id: user.id, username: user.username, real_name: user.real_name, email: user.email, phone: user.phone, avatar: user.avatar, dept_id: user.dept_id, dept_name: user.dept_name }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('SELECT id FROM users WHERE email = ?')) {
      const user = [...users.values()].find(item => item.email === values[0])
      return { rows: user ? [{ id: user.id }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('SELECT id FROM users WHERE username = ? AND email = ?')) {
      const user = users.get(values[0])
      return { rows: user?.email === values[1] ? [{ id: user.id }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('SELECT * FROM files WHERE id=?')) return { rows: [{ id: 77, name: 'fixture.txt', path: '/uploads/files/fixture.txt' }], affectedRows: 0, insertId: 0 }
    if (statement.includes('SELECT path FROM files WHERE id=?')) return { rows: [{ path: '/uploads/files/fixture.txt' }], affectedRows: 0, insertId: 0 }
    if (statement.includes('SELECT a.*,u.real_name AS author FROM announcements a') && statement.includes('WHERE a.id=?')) {
      const row = announcements.get(Number(values[0]))
      return { rows: row ? [{ ...row, author: '测试用户' }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('SELECT t.*,c.real_name AS creator,a.real_name AS assignee FROM tickets')) {
      const row = tickets.get(Number(values[0]))
      return { rows: row ? [{ ...row, creator: '其他用户', assignee: '管理员' }] : [], affectedRows: 0, insertId: 0 }
    }
    if (statement.includes('SELECT c.*,u.real_name,u.avatar FROM ticket_comments')) return { rows: [], affectedRows: 0, insertId: 0 }
    if (statement.includes('SELECT a.*,u.real_name AS applicant FROM approvals') && statement.includes('WHERE a.id=?')) return { rows: [{ id: Number(values[0]), applicant_id: 2, status: 1 }], affectedRows: 0, insertId: 0 }
    if (statement.startsWith('SELECT') && statement.includes('FROM announcements') && statement.includes('LIKE')) return { rows: [...announcements.values()], affectedRows: 0, insertId: 0 }
    if (statement.startsWith('SELECT') && statement.includes('FROM tickets') && statement.includes('LIKE')) return { rows: [...tickets.values()], affectedRows: 0, insertId: 0 }
    if (statement.startsWith('SELECT') && statement.includes('COUNT(*) AS total')) return { rows: [{ total: 1 }], affectedRows: 0, insertId: 0 }
    if (statement.startsWith('SELECT')) return { rows: [], affectedRows: 0, insertId: 0 }
    if (statement.startsWith('INSERT INTO announcements')) announcements.set(nextId, { id: nextId, title: values[0], content: values[1] })
    if (statement.startsWith('INSERT INTO tickets')) tickets.set(nextId, { id: nextId, title: values[0], content: values[1], status: 1 })
    if (statement.startsWith('INSERT INTO users')) {
      const user = { id: nextId, username: values[0], password: values[1], real_name: values[2], email: values[3], phone: '', avatar: '', dept_id: 1, dept_name: '管理部', role_code: 'admin', role_name: '系统管理员', status: 1 }
      users.set(user.username, user)
    }
    if (statement.startsWith('INSERT INTO files')) files.set(nextId, { values })
    const insertId = nextId++
    return { rows: [], affectedRows: 1, insertId }
  },
}

const app = await createOaApi({ runtimeRoot: root, frontendRoot, uploadRoot, jwtSecret, inviteCode, rpc })
const tokenFor = (claims, secret = jwtSecret) => {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url')
  const head = encode({ alg: 'HS256', typ: 'JWT' })
  const body = encode(claims)
  const signature = createHmac('sha256', secret).update(`${head}.${body}`).digest('base64url')
  return `${head}.${body}.${signature}`
}

try {
  process.chdir(root)
  await app.ready()
  const request = (method, url, payload, token) => app.inject({ method, url, ...(payload === undefined ? {} : { payload }), ...(token ? { headers: { authorization: `Bearer ${token}` } } : {}) })
  const login = async username => {
    const response = await request('POST', '/api/auth/login', { username, password: 'fixture-password' })
    assert.equal(response.statusCode, 200)
    return JSON.parse(response.body).data.token
  }
  const adminToken = await login('admin')
  const userToken = await login('user')

  for (const url of ['/api/system/config', '/api/debug/routes', '/api/debug/env', '/api/file/all', '/api/admin/announcement/list']) {
    assert.equal((await request('GET', url)).statusCode, 200, `public exposure: ${url}`)
  }
  const profile = await request('GET', '/api/user/profile/1', undefined, userToken)
  assert.match(profile.body, /"username":"admin"/)
  await request('PUT', '/api/user/profile/1', { email: 'changed@example.test' }, userToken)
  await request('GET', '/api/department/1/members', undefined, userToken)

  await request('GET', `/api/announcement/list?keyword=${encodeURIComponent("' OR 1=1 -- ")}`, undefined, userToken)
  await request('GET', `/api/ticket/list?keyword=${encodeURIComponent("' OR 1=1 -- ")}`, undefined, userToken)
  assert.ok(calls.some(call => call.payload?.statement?.includes("OR 1=1 --")), 'search input reaches SQL statement')

  const xss = '<img src=x onerror=alert(1)>'
  const announcement = await request('POST', '/api/announcement/create', { title: 'fixture', content: xss }, adminToken)
  assert.equal(announcement.statusCode, 200)
  assert.ok(calls.some(call => call.payload?.values?.includes(xss)), 'announcement XSS content stored without escaping')
  const ticket = await request('POST', '/api/ticket/create', { title: 'fixture', content: xss }, userToken)
  assert.equal(ticket.statusCode, 200)
  await request('POST', `/api/ticket/${JSON.parse(ticket.body).data.id}/comment`, { content: xss }, userToken)
  const ticketDetail = await request('GET', '/api/ticket/1', undefined, userToken)
  assert.equal(ticketDetail.statusCode, 200)
  assert.equal(JSON.parse(ticketDetail.body).data.ticket.id, 1, 'ticket detail preserves the compiled frontend response shape')
  assert.equal(JSON.parse(ticketDetail.body).data.id, 1, 'ticket detail keeps the flat API fields for compatibility')
  await request('PUT', '/api/ticket/1/close', {}, userToken)
  const bundlePath = join(previousCwd, 'assets', 'labs', 'oa-vuln-labs', '1.0.0-beta', 'source.zip')
  const bundle = unzipSync(await readFile(bundlePath))
  const frontend = Object.entries(bundle).filter(([name]) => name.endsWith('.js')).map(([, bytes]) => strFromU8(bytes)).join('\n')
  assert.match(frontend, /dangerouslySetInnerHTML:\{__html:n\.content\}/)
  assert.match(frontend, /dangerouslySetInnerHTML:\{__html:C\.content\}/)

  const boundary = 'oa-test-boundary'
  const multipartBody = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="payload.html"\r\nContent-Type: text/plain\r\n\r\n${xss}\r\n--${boundary}--\r\n`)
  const upload = await app.inject({ method: 'POST', url: '/api/file/upload', headers: { authorization: `Bearer ${userToken}`, 'content-type': `multipart/form-data; boundary=${boundary}` }, payload: multipartBody })
  assert.equal(upload.statusCode, 200, upload.body)
  assert.ok(calls.some(call => call.payload?.statement?.startsWith('INSERT INTO files')))

  const preview = await request('GET', '/api/file/preview?path=%2Fuploads%2Ffiles%2Ffixture.txt', undefined, adminToken)
  assert.equal(preview.statusCode, 200)
  assert.equal(preview.body, 'uploaded file is readable')
  assert.equal((await request('GET', '/api/file/preview?path=%2F..%2Fdatabase%2Finit.native.sql', undefined, adminToken)).body, 'instance database seed')
  assert.equal((await request('GET', '/api/file/preview?path=%2F..%2F..%2Foutside.txt', undefined, adminToken)).statusCode, 403)
  assert.equal((await request('GET', '/api/file/preview?path=C%3A%2FWindows%2Fwin.ini', undefined, adminToken)).statusCode, 403)
  const uploadTraversal = await request('GET', '/uploads/%2e%2e/secret.txt', undefined, adminToken)
  assert.notEqual(uploadTraversal.body, 'path traversal fixture', 'an encoded upload traversal must not expose an outside file')
  assert.equal((await request('GET', '/api/file/download/77', undefined, adminToken)).body, 'uploaded file is readable')
  await request('POST', '/api/file/sync-avatar', { url: 'http://127.0.0.1:6001/api/system/config' }, userToken)
  await request('POST', '/api/system/check-url', { url: 'http://127.0.0.1:6001/api/system/config' }, adminToken)
  await request('POST', '/api/system/test-webhook', { url: 'http://127.0.0.1:6001/api/system/config', method: 'POST' }, adminToken)
  assert.equal(calls.filter(call => call.method === 'ssrf.request').length, 3)
  const deniedInternalRequest = await request('POST', '/api/system/check-url', { url: 'http://example.com/' }, adminToken)
  assert.equal(deniedInternalRequest.statusCode, 403)

  const exposedConfig = await request('GET', '/api/system/config')
  assert.match(exposedConfig.body, new RegExp(jwtSecret))
  assert.match(exposedConfig.body, new RegExp(inviteCode))
  const resetNotice = await request('POST', '/api/auth/send-reset-code', { email: 'admin@example.test' })
  assert.match(resetNotice.body, /123456/)
  assert.ok(calls.some(call => call.method === 'redis.command' && JSON.stringify(call.payload.args) === JSON.stringify(['SET', 'reset_code:123456', '123456', 'EX', '300'])), 'password reset stores its TTL as the string required by the project cache adapter')
  assert.equal((await request('POST', '/api/auth/reset-password', { username: 'admin', email: 'admin@example.test', code: '123456', password: 'changed' })).statusCode, 200)
  assert.equal((await request('POST', '/api/test/admin-register', { username: 'created-admin', password: 'new-password', invite_code: 'oa-admin-2025' })).statusCode, 200)

  assert.match(frontend, /window\.__APP_CONFIG__=/)
  assert.ok(frontend.includes('oa2025-secret') && frontend.includes('oa-admin-2025'), 'compiled frontend exposes weak secret and invite code')
  assert.match(frontend, /r\.get\("redirect"\);c\?window\.location\.href=c/)
  assert.equal((await request('GET', '/api/approval/1', undefined, userToken)).statusCode, 200)
  await request('PUT', '/api/approval/1/status', { status: 2 }, userToken)

  const forgedToken = tokenFor({ user_id: 1, username: 'admin', role_code: 'admin', iss: 'oa-system', exp: Math.floor(Date.now() / 1000) + 3600, iat: Math.floor(Date.now() / 1000) })
  const rendered = await request('POST', '/api/notification/template/preview', { content: 'hello {{.RealName}} {{upper "oa"}}', variables: { RealName: 'fixture' } }, forgedToken)
  assert.equal(JSON.parse(rendered.body).data.rendered, 'hello fixture OA')
  const fileRead = await request('POST', '/api/notification/template/preview', { content: '{{readFile "../database/init.native.sql"}}' }, forgedToken)
  assert.equal(JSON.parse(fileRead.body).data.rendered, 'instance database seed')
  const hostFileRead = await request('POST', '/api/notification/template/preview', { content: '{{readFile "C:/Windows/win.ini"}}' }, forgedToken)
  assert.equal(JSON.parse(hostFileRead.body).data.rendered, '文件不存在或访问被拒绝。')
  const virtualCommand = await request('POST', '/api/notification/template/preview', { content: '{{exec "whoami"}}' }, forgedToken)
  assert.equal(JSON.parse(virtualCommand.body).data.rendered, 'vulnlab\\oa-instance\r\n')
  const deniedCommand = await request('POST', '/api/notification/template/preview', { content: '{{exec "powershell -Command whoami"}}' }, forgedToken)
  assert.match(JSON.parse(deniedCommand.body).data.rendered, /not available in the OA virtual command environment/)
  assert.doesNotMatch(await readFile(new URL('../../src/oa/api.ts', import.meta.url), 'utf8'), /execFile|cmd\.exe/)

  const otherRoot = join(root, 'other-instance')
  const otherFrontend = join(otherRoot, 'frontend')
  await mkdir(join(otherRoot, 'uploads'), { recursive: true })
  await mkdir(otherFrontend, { recursive: true })
  await writeFile(join(otherFrontend, 'index.html'), '<html>other instance</html>')
  const otherApp = await createOaApi({ runtimeRoot: otherRoot, frontendRoot: otherFrontend, uploadRoot: join(otherRoot, 'uploads'), jwtSecret: 'different-instance-secret', inviteCode: 'other-instance-invite', rpc })
  await otherApp.ready()
  assert.equal((await otherApp.inject({ method: 'GET', url: '/api/auth/userinfo', headers: { authorization: `Bearer ${adminToken}` } })).statusCode, 401)
  await otherApp.close()

  const deniedPreview = await request('POST', '/api/notification/template/preview', { content: 'hello' }, userToken)
  assert.equal(deniedPreview.statusCode, 403)
  const deniedAnnouncement = await request('POST', '/api/announcement/create', { title: 'fixture', content: 'fixture' }, userToken)
  assert.equal(deniedAnnouncement.statusCode, 403)
  console.log('VulnLab OA API regression passed: vulnerable API contracts plus instance-contained file access, cross-instance token rejection and virtual-only command execution.')
} finally {
  process.chdir(previousCwd)
  await app.close()
  await rm(root, { recursive: true, force: true })
}
