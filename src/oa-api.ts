import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify'
import fastifyStatic from '@fastify/static'
import multipart from '@fastify/multipart'
import bcrypt from 'bcryptjs'
import { createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, realpath, stat, writeFile } from 'node:fs/promises'
import { basename, extname, isAbsolute, join, relative, resolve, sep } from 'node:path'

const defaultJwtSecret = 'oa2025-secret'
const defaultInviteCode = 'oa-admin-2025'

interface OaApiOptions {
  runtimeRoot: string
  frontendRoot: string
  uploadRoot: string
  jwtSecret?: string
  inviteCode?: string
  rpc: { call(method: string, payload: unknown): Promise<any> }
}

interface JwtClaims {
  user_id: number
  username: string
  role_code: string
  iss: string
  exp: number
  iat: number
}

type UserRow = {
  id: number
  username: string
  password?: string
  real_name: string
  email: string
  phone: string
  avatar: string
  dept_id: number
  dept_name?: string
  role_code?: string
  role_name?: string
}

const ok = (data?: unknown, message?: string) => ({ code: 0, ...(data === undefined ? {} : { data }), ...(message ? { message } : {}) })
const fail = (message: string) => ({ code: 1, message })
const pageOf = (request: FastifyRequest) => {
  const query = request.query as Record<string, unknown>
  const page = Math.max(1, Math.min(100_000, Number(query.page) || 1))
  const size = Math.max(1, Math.min(100, Number(query.page_size ?? query.pageSize) || 10))
  return { page, size, offset: (page - 1) * size }
}
const jsonBody = (request: FastifyRequest) => (request.body && typeof request.body === 'object' && !Array.isArray(request.body) ? request.body : {}) as Record<string, any>
const idParam = (request: FastifyRequest) => Number((request.params as Record<string, string>).id)
const b64url = (value: Buffer | string) => Buffer.from(value).toString('base64url')
const signToken = (claims: JwtClaims, secret = defaultJwtSecret) => {
  const input = `${b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.${b64url(JSON.stringify(claims))}`
  return `${input}.${createHmac('sha256', secret).update(input).digest('base64url')}`
}
const verifyToken = (token: string, secret = defaultJwtSecret): JwtClaims | null => {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const input = `${parts[0]}.${parts[1]}`
  const expected = createHmac('sha256', secret).update(input).digest()
  let actual: Buffer
  try { actual = Buffer.from(parts[2], 'base64url') } catch { return null }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null
  try {
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as JwtClaims
    if (claims.iss !== 'oa-system' || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000) return null
    return claims
  } catch { return null }
}
const tokenFrom = (request: FastifyRequest) => {
  const authorization = request.headers.authorization ?? ''
  return authorization.startsWith('Bearer ') ? authorization.slice(7) : ''
}
const publicPaths = new Set([
  '/api/auth/login', '/api/auth/send-reset-code', '/api/auth/reset-password', '/api/test/admin-register',
  '/api/debug/routes', '/api/debug/env', '/api/system/config', '/api/file/all', '/api/admin/announcement/list',
])
const contentTypeFor = (path: string) => ({
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8',
})[extname(path).toLowerCase()] ?? 'application/octet-stream'

const normalizeUser = (row: UserRow) => ({
  id: Number(row.id),
  username: row.username,
  real_name: row.real_name,
  email: row.email,
  phone: row.phone,
  avatar: row.avatar,
  dept_id: Number(row.dept_id),
  department: row.dept_name ? { id: Number(row.dept_id), name: row.dept_name } : undefined,
  role_code: row.role_code ?? 'user',
  role_name: row.role_name ?? '普通员工',
})

export const createOaApi = async (options: OaApiOptions): Promise<FastifyInstance> => {
  const app = Fastify({ logger: false, bodyLimit: 32 * 1024 * 1024 })
  const root = resolve(options.runtimeRoot)
  const frontendRoot = resolve(options.frontendRoot)
  const uploadRoot = resolve(options.uploadRoot)
  const jwtSecret = options.jwtSecret ?? defaultJwtSecret
  const inviteCode = options.inviteCode ?? defaultInviteCode
  await mkdir(join(uploadRoot, 'files'), { recursive: true })
  await mkdir(join(uploadRoot, 'avatars'), { recursive: true })
  await app.register(multipart, { limits: { fileSize: 10 * 1024 * 1024, files: 1 } })
  await app.register(fastifyStatic, { root: options.frontendRoot, prefix: '/', decorateReply: false, index: false })
  app.get('/', async (_request, reply) => reply.type('text/html; charset=utf-8').send(await readFile(join(frontendRoot, 'index.html'))))

  const sql = async (statement: string, values: unknown[] = []) => options.rpc.call('mysql.query', { statement, values }) as Promise<{ rows: any[]; affectedRows: number; insertId: number }>
  const rows = async (statement: string, values: unknown[] = []) => (await sql(statement, values)).rows
  const internalRequest = async (payload: { url: string; method?: string; body?: unknown }) => {
    try {
      return await options.rpc.call('ssrf.request', payload)
    } catch (error) {
      const message = error instanceof Error ? error.message : '实例内请求失败。'
      const statusCode = /SSRF (?:URL|HTTP|目标|重定向)/.test(message) ? 403 : /SSRF 请求(?:体|响应)/.test(message) ? 413 : 502
      throw Object.assign(new Error(message), { statusCode })
    }
  }
  const currentUser = async (request: FastifyRequest): Promise<(UserRow & { claims: JwtClaims }) | null> => {
    const claims = verifyToken(tokenFrom(request), jwtSecret)
    if (!claims) return null
    const found = await rows(`
      SELECT u.id, u.username, u.real_name, u.email, u.phone, u.avatar, u.dept_id,
             d.name AS dept_name, r.code AS role_code, r.name AS role_name
      FROM users u LEFT JOIN departments d ON d.id = u.dept_id
      LEFT JOIN user_roles ur ON ur.user_id = u.id LEFT JOIN roles r ON r.id = ur.role_id
      WHERE u.id = ? LIMIT 1
    `, [claims.user_id])
    return found[0] ? { ...found[0], claims } : null
  }
  const requireUser = async (request: FastifyRequest, reply: FastifyReply, admin = false) => {
    const user = await currentUser(request)
    if (!user) {
      reply.code(401).send(fail('请先登录。'))
      return null
    }
    if (admin && !['admin', 'manager'].includes(user.role_code ?? '')) {
      reply.code(403).send(fail('权限不足。'))
      return null
    }
    return user
  }
  const requireAdmin = async (request: FastifyRequest, reply: FastifyReply) => {
    const user = await requireUser(request, reply)
    if (!user) return null
    if (user.role_code !== 'admin') {
      reply.code(403).send(fail('需要管理员权限。'))
      return null
    }
    return user
  }
  const pathInside = (base: string, target: string) => {
    const path = relative(base, target)
    return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  }
  const safeInstanceFile = async (requested: string) => {
    const normalized = requested.replaceAll('\\', '/')
    if (!normalized || normalized.includes('\0') || /^[A-Za-z]:/.test(normalized) || normalized.startsWith('//') || normalized.split('/').some(segment => segment.includes(':'))) {
      throw Object.assign(new Error('文件路径超出 OA 实例目录。'), { statusCode: 403 })
    }
    const base = join(root, 'backend')
    const target = resolve(base, ...normalized.split('/'))
    const canonicalRoot = await realpath(root)
    const canonicalTarget = await realpath(target).catch(() => null)
    const normalizedRoot = process.platform === 'win32' ? canonicalRoot.toLowerCase() : canonicalRoot
    const normalizedTarget = canonicalTarget && process.platform === 'win32' ? canonicalTarget.toLowerCase() : canonicalTarget
    if (!canonicalTarget || !pathInside(root, target) || !pathInside(normalizedRoot, normalizedTarget as string)) {
      throw Object.assign(new Error('文件路径超出 OA 实例目录。'), { statusCode: 403 })
    }
    const metadata = await stat(canonicalTarget)
    if (!metadata.isFile() || metadata.size > 1024 * 1024) throw Object.assign(new Error('文件不存在或超过读取上限。'), { statusCode: 404 })
    return canonicalTarget
  }
  const safeFilePath = async (base: string, requested: string) => {
    const normalized = requested.replaceAll('\\', '/')
    const segments = normalized.split('/')
    if (!normalized || normalized.includes('\0') || /^[A-Za-z]:/.test(normalized) || normalized.startsWith('//') || segments.some(segment => !segment || segment === '.' || segment === '..' || segment.includes(':'))) {
      throw Object.assign(new Error('文件路径超出 OA 实例目录。'), { statusCode: 403 })
    }
    const target = resolve(base, ...segments)
    const canonicalRoot = await realpath(base)
    const canonicalTarget = await realpath(target).catch(() => null)
    const normalizedRoot = process.platform === 'win32' ? canonicalRoot.toLowerCase() : canonicalRoot
    const normalizedTarget = canonicalTarget && process.platform === 'win32' ? canonicalTarget.toLowerCase() : canonicalTarget
    if (!canonicalTarget || !pathInside(base, target) || !pathInside(normalizedRoot, normalizedTarget as string)) {
      throw Object.assign(new Error('文件路径超出 OA 实例目录。'), { statusCode: 403 })
    }
    const metadata = await stat(canonicalTarget)
    if (!metadata.isFile() || metadata.size > 1024 * 1024) throw Object.assign(new Error('文件不存在或超过读取上限。'), { statusCode: 404 })
    return canonicalTarget
  }
  const fileOnDisk = async (requested: string) => {
    const normalized = requested.replaceAll('\\', '/')
    if (normalized.startsWith('/uploads/')) return safeFilePath(uploadRoot, normalized.slice('/uploads/'.length))
    return safeInstanceFile(normalized.replace(/^\/+/, ''))
  }
  const readVirtualFile = async (requested: string) => {
    const normalized = requested.replaceAll('\\', '/')
    if (normalized.startsWith('/uploads/')) {
      return readFile(await safeFilePath(uploadRoot, normalized.slice('/uploads/'.length)), 'utf8')
    }
    if (normalized.startsWith('dist/')) {
      return readFile(await safeFilePath(frontendRoot, normalized.slice('dist/'.length)), 'utf8')
    }
    return readFile(await safeInstanceFile(normalized.replace(/^\/+/, '')), 'utf8')
  }
  const saveUpload = async (request: FastifyRequest, kind: 'files' | 'avatars') => {
    const part = await request.file()
    if (!part) throw new Error('请选择要上传的文件。')
    const bytes = await part.toBuffer()
    const id = randomUUID()
    const originalName = basename(part.filename || 'upload.bin').slice(0, 255)
    const name = `${Date.now()}_${id.slice(0, 8)}_${originalName}`
    const path = join(uploadRoot, kind, name)
    await writeFile(path, bytes, { flag: 'wx' })
    return { id, name: originalName, storedName: name, bytes, path: `/uploads/${kind}/${name}`, type: part.mimetype, diskPath: path }
  }
  const renderTemplate = async (content: string, variables: Record<string, unknown>) => {
    const expression = /{{\s*([^{}]+?)\s*}}/g
    let output = ''
    let cursor = 0
    for (const match of content.matchAll(expression)) {
      const index = match.index ?? 0
      output += content.slice(cursor, index)
      cursor = index + match[0].length
      const words = match[1].trim().match(/(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\.[\w]+|[^\s]+)/g) ?? []
      const unquote = (value: string) => value.length >= 2 && ['"', "'"].includes(value[0]) ? value.slice(1, -1) : value
      const lookup = (value: string) => value.startsWith('.') ? String(variables[value.slice(1)] ?? '') : unquote(value)
      const [fn = '', arg, ...rest] = words
      let rendered = ''
      if (fn === 'exec' && arg) {
        const command = unquote(arg).trim()
        const [name = '', ...commandArgs] = command.split(/\s+/)
        const executable = name.split(/[\\/]/).at(-1)?.toLowerCase() ?? ''
        if (executable === 'whoami') rendered = `vulnlab\\oa-instance\r\n`
        else if (executable === 'hostname') rendered = 'vulnlab-oa-instance\r\n'
        else if (executable === 'ver') rendered = 'Microsoft Windows [Version 10.0.19045.0]\r\n'
        else if (executable === 'ipconfig') rendered = 'Ethernet adapter OA-Lab:\r\n   IPv4 Address. . . . . . . . . . . : 127.0.0.1\r\n'
        else if (executable === 'dir') rendered = ' Directory of C:\\VulnLab\\OA\\instance\r\nbackend  database  uploads\r\n'
        else if (executable === 'cd') rendered = 'C:\\VulnLab\\OA\\instance\r\n'
        else if (['type', 'cat', 'more'].includes(executable) && commandArgs[0]) {
          rendered = await readVirtualFile(commandArgs[0]).catch(() => '文件不存在或访问被拒绝。')
        } else if (executable === 'echo') rendered = `${commandArgs.join(' ')}\r\n`
        else rendered = `'${name}' is not available in the OA virtual command environment.\r\n`
      } else if (fn === 'readFile' && arg) {
        rendered = await readVirtualFile(unquote(arg)).catch(() => '文件不存在或访问被拒绝。')
      } else if (fn === 'upper' && arg) rendered = lookup(arg).toUpperCase()
      else if (fn === 'lower' && arg) rendered = lookup(arg).toLowerCase()
      else if (fn === 'trim' && arg) rendered = lookup(arg).trim()
      else if (fn === 'printf') rendered = words.slice(1).map(lookup).join(' ')
      else if (fn.startsWith('.')) rendered = lookup(fn)
      else if (fn === 'dateFormat') rendered = new Date().toISOString().slice(0, 10)
      else if (!fn) rendered = ''
      else rendered = [lookup(fn), ...rest.map(lookup)].join(' ')
      output += rendered
    }
    return output + content.slice(cursor)
  }

  app.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/') && !publicPaths.has(request.url.split('?')[0])) {
      await requireUser(request, reply)
    }
  })
  app.setErrorHandler((error: unknown, _request, reply) => {
    const statusCode = typeof error === 'object' && error !== null && 'statusCode' in error && typeof error.statusCode === 'number' ? error.statusCode : 500
    const message = error instanceof Error ? error.message : '请求处理失败。'
    reply.code(statusCode >= 400 ? statusCode : 500).send(fail(message))
  })

  app.post('/api/auth/login', async (request, reply) => {
    const body = jsonBody(request)
    const username = String(body.username ?? '')
    const password = String(body.password ?? '')
    const result = await rows(`
      SELECT u.*, r.code AS role_code, r.name AS role_name, d.name AS dept_name
      FROM users u LEFT JOIN user_roles ur ON ur.user_id = u.id
      LEFT JOIN roles r ON r.id = ur.role_id LEFT JOIN departments d ON d.id = u.dept_id
      WHERE u.username = ? AND u.status = 1 LIMIT 1
    `, [username])
    const user = result[0] as UserRow | undefined
    const valid = Boolean(user && await bcrypt.compare(password, user.password ?? ''))
    await sql('INSERT INTO login_logs (user_id, username, ip, user_agent, status) VALUES (?, ?, ?, ?, ?)', [user?.id ?? 0, username, request.ip, String(request.headers['user-agent'] ?? '').slice(0, 500), valid ? 1 : 0])
    if (!valid || !user) return reply.code(401).send(fail('用户名或密码错误。'))
    const now = Math.floor(Date.now() / 1000)
    const token = signToken({ user_id: Number(user.id), username: user.username, role_code: user.role_code ?? 'user', iss: 'oa-system', iat: now, exp: now + 7200 }, jwtSecret)
    return ok({ token, user: normalizeUser(user) }, '登录成功')
  })

  app.get('/api/auth/userinfo', async request => {
    const user = await currentUser(request)
    if (!user) return fail('登录状态已过期。')
    const permissions = await rows(`SELECT p.code FROM permissions p JOIN role_permissions rp ON rp.permission_id = p.id JOIN user_roles ur ON ur.role_id = rp.role_id WHERE ur.user_id = ? AND p.status = 1`, [user.id])
    return ok({ ...normalizeUser(user), permissions: permissions.map((item: any) => item.code) })
  })

  app.post('/api/auth/send-reset-code', async request => {
    const email = String(jsonBody(request).email ?? '')
    const user = (await rows('SELECT id FROM users WHERE email = ? LIMIT 1', [email]))[0]
    if (!user) return fail('邮箱不存在。')
    await options.rpc.call('redis.command', { args: ['SET', 'reset_code:123456', '123456', 'EX', '300'] })
    return ok({ message: '验证码已发送', code: '123456' })
  })

  app.post('/api/auth/reset-password', async request => {
    const body = jsonBody(request)
    const code = await options.rpc.call('redis.command', { args: ['GET', `reset_code:${String(body.code ?? '')}`] })
    if (String(body.code ?? '') !== '123456' || code !== '123456') return fail('验证码错误。')
    const user = (await rows('SELECT id FROM users WHERE username = ? AND email = ? LIMIT 1', [String(body.username ?? ''), String(body.email ?? '')]))[0]
    if (!user) return fail('账号或邮箱不匹配。')
    await sql('UPDATE users SET password = ? WHERE id = ?', [await bcrypt.hash(String(body.password ?? ''), 10), user.id])
    return ok(undefined, '密码重置成功')
  })

  app.get('/api/dashboard/stats', async (request, reply) => {
    const user = await requireUser(request, reply)
    if (!user) return fail('请先登录。')
    const values = await rows(`SELECT (SELECT COUNT(*) FROM users) AS user_count,(SELECT COUNT(*) FROM departments) AS department_count,(SELECT COUNT(*) FROM announcements WHERE status=1) AS announcement_count,(SELECT COUNT(*) FROM tickets WHERE status<3) AS ticket_count`)
    return ok(values[0] ?? {})
  })

  app.get('/api/user/list', async request => {
    const { page, size, offset } = pageOf(request)
    const result = await rows(`SELECT u.id,u.username,u.real_name,u.email,u.phone,u.avatar,u.dept_id,d.name AS department FROM users u LEFT JOIN departments d ON d.id=u.dept_id ORDER BY u.id LIMIT ? OFFSET ?`, [size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM users'))[0]?.total ?? 0)
    return ok({ list: result, total, page, page_size: size })
  })
  app.get('/api/user/profile/:id', async request => {
    const found = (await rows(`SELECT u.id,u.username,u.real_name,u.email,u.phone,u.avatar,u.dept_id,d.name AS dept_name FROM users u LEFT JOIN departments d ON d.id=u.dept_id WHERE u.id=?`, [idParam(request)]))[0]
    return found ? ok(found) : fail('用户不存在。')
  })
  app.put('/api/user/profile/:id', async request => {
    const body = jsonBody(request)
    await sql('UPDATE users SET email=?,phone=?,real_name=? WHERE id=?', [String(body.email ?? ''), String(body.phone ?? ''), String(body.real_name ?? body.realName ?? ''), idParam(request)])
    return ok(undefined, '更新成功')
  })
  app.put('/api/user/change-password', async request => {
    const user = await currentUser(request)
    if (!user) return fail('请先登录。')
    const body = jsonBody(request)
    const password = await bcrypt.hash(String(body.new_password ?? body.newPassword ?? body.password ?? ''), 10)
    await sql('UPDATE users SET password=? WHERE id=?', [password, user.id])
    return ok(undefined, '密码修改成功')
  })
  app.post('/api/user/avatar', async request => {
    const user = await currentUser(request)
    if (!user) return fail('请先登录。')
    const file = await saveUpload(request, 'avatars')
    await sql('UPDATE users SET avatar=? WHERE id=?', [file.path, user.id])
    return ok({ avatar: file.path }, '上传成功')
  })

  app.get('/api/department/list', async () => ok(await rows(`SELECT d.*,u.real_name AS leader_name,(SELECT COUNT(*) FROM users x WHERE x.dept_id=d.id) AS member_count FROM departments d LEFT JOIN users u ON u.id=d.leader_id ORDER BY d.sort,d.id`)))
  app.get('/api/department/:id/members', async request => ok(await rows('SELECT id,username,real_name,email,phone,dept_id FROM users WHERE dept_id=? ORDER BY id', [idParam(request)])))
  app.post('/api/department/create', async request => {
    const body = jsonBody(request)
    const result = await sql('INSERT INTO departments (name,parent_id,leader_id,sort) VALUES (?,?,?,?)', [String(body.name ?? ''), Number(body.parent_id ?? body.parentId) || 0, Number(body.leader_id ?? body.leaderId) || 0, Number(body.sort) || 0])
    return ok({ id: result.insertId }, '创建成功')
  })
  app.put('/api/department/:id', async request => {
    const body = jsonBody(request)
    await sql('UPDATE departments SET name=?,parent_id=?,leader_id=?,sort=? WHERE id=?', [String(body.name ?? ''), Number(body.parent_id ?? body.parentId) || 0, Number(body.leader_id ?? body.leaderId) || 0, Number(body.sort) || 0, idParam(request)])
    return ok(undefined, '更新成功')
  })
  app.get('/api/role/list', async () => ok(await rows('SELECT r.*,COUNT(DISTINCT ur.user_id) AS member_count FROM roles r LEFT JOIN user_roles ur ON ur.role_id=r.id GROUP BY r.id ORDER BY r.id')))
  app.post('/api/role/create', async request => {
    const body = jsonBody(request)
    const result = await sql('INSERT INTO roles (name,code,description) VALUES (?,?,?)', [String(body.name ?? ''), String(body.code ?? ''), String(body.description ?? '')])
    return ok({ id: result.insertId }, '创建成功')
  })
  app.put('/api/role/:id', async request => {
    const body = jsonBody(request)
    await sql('UPDATE roles SET name=?,description=? WHERE id=?', [String(body.name ?? ''), String(body.description ?? ''), idParam(request)])
    return ok(undefined, '更新成功')
  })
  app.delete('/api/role/:id', async request => {
    await sql('DELETE FROM roles WHERE id=?', [idParam(request)])
    return ok(undefined, '删除成功')
  })

  app.get('/api/announcement/list', async request => {
    const { page, size, offset } = pageOf(request)
    const query = request.query as Record<string, string>
    const keyword = String(query.keyword ?? '')
    const items = await rows(`SELECT a.*,u.real_name AS author FROM announcements a LEFT JOIN users u ON u.id=a.author_id WHERE a.status=1 AND (a.title LIKE '%${keyword}%' OR a.content LIKE '%${keyword}%') ORDER BY a.created_at DESC LIMIT ${size} OFFSET ${offset}`)
    const total = Number((await rows(`SELECT COUNT(*) AS total FROM announcements WHERE status=1 AND (title LIKE '%${keyword}%' OR content LIKE '%${keyword}%')`))[0]?.total ?? 0)
    return ok({ list: items, total, page, page_size: size })
  })
  const getAnnouncement = async (request: FastifyRequest) => {
    const item = (await rows('SELECT a.*,u.real_name AS author FROM announcements a LEFT JOIN users u ON u.id=a.author_id WHERE a.id=?', [idParam(request)]))[0]
    return item ? ok(item) : fail('公告不存在。')
  }
  app.get('/api/announcement/:id', getAnnouncement)
  app.get('/api/announcement/detail/:id', getAnnouncement)
  app.post('/api/announcement/create', async (request, reply) => {
    const user = await requireUser(request, reply, true)
    if (!user) return fail('权限不足。')
    const body = jsonBody(request)
    const result = await sql('INSERT INTO announcements (title,content,type,status,author_id) VALUES (?,?,?,?,?)', [String(body.title ?? ''), String(body.content ?? ''), Number(body.type) || 1, Number(body.status ?? 1), user?.id ?? 0])
    return ok({ id: result.insertId }, '创建成功')
  })
  app.put('/api/announcement/:id', async request => {
    const body = jsonBody(request)
    await sql('UPDATE announcements SET title=?,content=?,type=?,status=? WHERE id=?', [String(body.title ?? ''), String(body.content ?? ''), Number(body.type) || 1, Number(body.status ?? 1), idParam(request)])
    return ok(undefined, '更新成功')
  })
  app.delete('/api/announcement/:id', async request => {
    await sql('DELETE FROM announcements WHERE id=?', [idParam(request)])
    return ok(undefined, '删除成功')
  })
  app.get('/api/admin/announcement/list', async request => {
    const { page, size, offset } = pageOf(request)
    const result = await rows('SELECT * FROM announcements ORDER BY id DESC LIMIT ? OFFSET ?', [size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM announcements'))[0]?.total ?? 0)
    return ok({ list: result, total })
  })

  app.get('/api/ticket/list', async request => {
    const user = await currentUser(request)
    const { page, size, offset } = pageOf(request)
    const query = request.query as Record<string, string>
    const keyword = String(query.keyword ?? '')
    const base = `SELECT t.*,c.real_name AS creator,a.real_name AS assignee,d.name AS department FROM tickets t LEFT JOIN users c ON c.id=t.creator_id LEFT JOIN users a ON a.id=t.assignee_id LEFT JOIN departments d ON d.id=t.dept_id WHERE t.creator_id=${Number(user?.id ?? 0)} AND (t.title LIKE '%${keyword}%' OR t.content LIKE '%${keyword}%')`
    const result = await rows(`${base} ORDER BY t.created_at DESC LIMIT ${size} OFFSET ${offset}`)
    const total = Number((await rows(`SELECT COUNT(*) AS total FROM tickets WHERE creator_id=${Number(user?.id ?? 0)} AND (title LIKE '%${keyword}%' OR content LIKE '%${keyword}%')`))[0]?.total ?? 0)
    return ok({ list: result, total, page, page_size: size })
  })
  const getTicket = async (request: FastifyRequest) => {
    const item = (await rows(`SELECT t.*,c.real_name AS creator,a.real_name AS assignee FROM tickets t LEFT JOIN users c ON c.id=t.creator_id LEFT JOIN users a ON a.id=t.assignee_id WHERE t.id=?`, [idParam(request)]))[0]
    if (!item) return fail('工单不存在。')
    item.comments = await rows('SELECT c.*,u.real_name,u.avatar FROM ticket_comments c LEFT JOIN users u ON u.id=c.user_id WHERE c.ticket_id=? ORDER BY c.id', [idParam(request)])
    return ok(item)
  }
  app.get('/api/ticket/:id', getTicket)
  app.get('/api/ticket/detail/:id', getTicket)
  app.post('/api/ticket/create', async request => {
    const user = await currentUser(request)
    const body = jsonBody(request)
    const result = await sql('INSERT INTO tickets (title,content,type,priority,status,creator_id,assignee_id,dept_id) VALUES (?,?,?,?,1,?,?,?)', [String(body.title ?? ''), String(body.content ?? ''), Number(body.type) || 1, Number(body.priority) || 1, user?.id ?? 0, 0, user?.dept_id ?? 0])
    return ok({ id: result.insertId }, '工单创建成功')
  })
  app.post('/api/ticket/:id/comment', async request => {
    const user = await currentUser(request)
    const body = jsonBody(request)
    const result = await sql('INSERT INTO ticket_comments (ticket_id,user_id,content) VALUES (?,?,?)', [idParam(request), user?.id ?? 0, String(body.content ?? '')])
    return ok({ id: result.insertId }, '评论成功')
  })
  app.put('/api/ticket/:id/close', async request => {
    await sql('UPDATE tickets SET status=3 WHERE id=?', [idParam(request)])
    return ok(undefined, '工单已关闭')
  })

  app.post('/api/file/upload', async request => {
    const user = await currentUser(request)
    const file = await saveUpload(request, 'files')
    const result = await sql('INSERT INTO files (name,path,size,type,folder_id,uploader_id,dept_id) VALUES (?,?,?,?,0,?,?)', [file.name, file.path, file.bytes.byteLength, extname(file.name).slice(1), user?.id ?? 0, user?.dept_id ?? 0])
    return ok({ id: result.insertId, name: file.name, path: file.path, size: file.bytes.byteLength, type: extname(file.name).slice(1), created_at: new Date().toISOString() }, '上传成功')
  })
  app.get('/api/file/list', async request => {
    const { page, size, offset } = pageOf(request)
    const result = await rows(`SELECT f.*,JSON_OBJECT('id',u.id,'real_name',u.real_name) AS uploader FROM files f LEFT JOIN users u ON u.id=f.uploader_id ORDER BY f.created_at DESC LIMIT ? OFFSET ?`, [size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM files WHERE status=1'))[0]?.total ?? 0)
    return ok({ list: result, total, page, page_size: size })
  })
  app.get('/api/file/all', async () => ok(await rows('SELECT * FROM files ORDER BY id DESC')))
  app.get('/api/file/preview', async (request, reply) => {
    const requested = String((request.query as Record<string, string>).path ?? '')
    if (!requested) return reply.code(400).send(fail('缺少文件路径。'))
    const path = await fileOnDisk(requested)
    const bytes = await readFile(path)
    return reply.type(contentTypeFor(path)).send(bytes)
  })
  app.get('/api/file/download/:id', async (request, reply) => {
    const file = (await rows('SELECT * FROM files WHERE id=?', [idParam(request)]))[0]
    if (!file) return reply.code(404).send(fail('文件不存在。'))
    const bytes = await readFile(await fileOnDisk(String(file.path)))
    reply.header('content-disposition', `attachment; filename*=UTF-8''${encodeURIComponent(String(file.name))}`)
    return reply.type(contentTypeFor(String(file.path))).send(bytes)
  })
  app.delete('/api/file/:id', async request => {
    const file = (await rows('SELECT path FROM files WHERE id=?', [idParam(request)]))[0]
    if (file) await sql('DELETE FROM files WHERE id=?', [idParam(request)])
    return ok(undefined, '删除成功')
  })
  app.post('/api/file/sync-avatar', async request => {
    const result = await internalRequest({ url: String(jsonBody(request).url ?? ''), method: 'GET' })
    return ok(result, '头像同步完成')
  })

  const listApprovals = async (request: FastifyRequest) => {
    const user = await currentUser(request)
    const { page, size, offset } = pageOf(request)
    const items = await rows(`SELECT a.*,JSON_OBJECT('id',u.id,'real_name',u.real_name) AS applicant FROM approvals a LEFT JOIN users u ON u.id=a.applicant_id WHERE a.applicant_id=? ORDER BY a.created_at DESC LIMIT ? OFFSET ?`, [user?.id ?? 0, size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM approvals WHERE applicant_id=?', [user?.id ?? 0]))[0]?.total ?? 0)
    return ok({ list: items, total, page, page_size: size })
  }
  app.get('/api/approval/list', listApprovals)
  app.get('/api/approval/my', listApprovals)
  app.get('/api/approval/pending', async request => {
    const { page, size, offset } = pageOf(request)
    const items = await rows(`SELECT a.*,JSON_OBJECT('id',u.id,'real_name',u.real_name) AS applicant FROM approvals a LEFT JOIN users u ON u.id=a.applicant_id WHERE a.status=1 ORDER BY a.created_at DESC LIMIT ? OFFSET ?`, [size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM approvals WHERE status=1'))[0]?.total ?? 0)
    return ok({ list: items, total, page, page_size: size })
  })
  const getApproval = async (request: FastifyRequest) => {
    const item = (await rows('SELECT a.*,u.real_name AS applicant FROM approvals a LEFT JOIN users u ON u.id=a.applicant_id WHERE a.id=?', [idParam(request)]))[0]
    return item ? ok(item) : fail('审批不存在。')
  }
  app.get('/api/approval/:id', getApproval)
  app.get('/api/approval/detail/:id', getApproval)
  app.post('/api/approval/create', async request => {
    const user = await currentUser(request)
    const body = jsonBody(request)
    const result = await sql('INSERT INTO approvals (title,type,content,status,applicant_id) VALUES (?,?,?,1,?)', [String(body.title ?? ''), String(body.type ?? 'leave'), String(body.content ?? ''), user?.id ?? 0])
    return ok({ id: result.insertId }, '申请提交成功')
  })
  app.post('/api/approval/:id/approve', async request => {
    const user = await currentUser(request)
    const body = jsonBody(request)
    const status = Number(body.status) || 2
    await sql('UPDATE approvals SET status=? WHERE id=?', [status, idParam(request)])
    await sql('INSERT INTO approval_records (approval_id,approver_id,status,comment) VALUES (?,?,?,?)', [idParam(request), user?.id ?? 0, status, String(body.comment ?? '')])
    return ok(undefined, '审批完成')
  })
  app.put('/api/approval/:id/status', async request => {
    const body = jsonBody(request)
    await sql('UPDATE approvals SET status=? WHERE id=?', [Number(body.status) || 2, idParam(request)])
    return ok(undefined, '审批状态已更新')
  })

  app.get('/api/log/login', async request => {
    const { page, size, offset } = pageOf(request)
    const query = request.query as Record<string, string>
    const result = await rows('SELECT * FROM login_logs WHERE (? = "" OR username LIKE ?) ORDER BY id DESC LIMIT ? OFFSET ?', [String(query.username ?? ''), `%${String(query.username ?? '')}%`, size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM login_logs'))[0]?.total ?? 0)
    return ok({ list: result, total })
  })
  app.get('/api/log/operation', async request => {
    const { page, size, offset } = pageOf(request)
    const query = request.query as Record<string, string>
    const result = await rows('SELECT * FROM operation_logs WHERE (? = "" OR module LIKE ?) ORDER BY id DESC LIMIT ? OFFSET ?', [String(query.module ?? ''), `%${String(query.module ?? '')}%`, size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM operation_logs'))[0]?.total ?? 0)
    return ok({ list: result, total })
  })

  app.get('/api/system/config', async () => {
    const configs = await rows('SELECT `key`,value FROM system_configs ORDER BY id')
    const runtimeConfig = await options.rpc.call('instance.config', {}) as Record<string, string | number>
    return ok([
      ...configs,
      { key: 'jwt_secret', value: jwtSecret }, { key: 'admin_invite_code', value: inviteCode },
      ...Object.entries(runtimeConfig).map(([key, value]) => ({ key, value })),
    ])
  })
  app.post('/api/system/check-url', async request => {
    const body = jsonBody(request)
    return ok(await internalRequest({ url: String(body.url ?? ''), method: 'GET' }))
  })
  app.post('/api/system/test-webhook', async request => {
    const body = jsonBody(request)
    return ok(await internalRequest({ url: String(body.url ?? ''), method: String(body.method ?? 'POST'), body: body.payload ?? '{}' }))
  })

  app.get('/api/debug/routes', async () => ok([
    '/api/auth/login', '/api/auth/send-reset-code', '/api/auth/reset-password', '/api/test/admin-register',
    '/api/system/check-url', '/api/system/test-webhook', '/api/notification/template/preview', '/api/file/preview',
  ]))
  app.get('/api/debug/env', async () => ok({ platform: process.platform, arch: process.arch, cwd: process.cwd(), version: '1.0.0-beta' }))
  app.post('/api/test/admin-register', async request => {
    const body = jsonBody(request)
    if (String(body.invite_code ?? body.inviteCode ?? '') !== inviteCode) return fail('邀请码错误。')
    const username = String(body.username ?? '').slice(0, 50)
    const password = await bcrypt.hash(String(body.password ?? ''), 10)
    const result = await sql('INSERT INTO users (username,password,real_name,email,dept_id) VALUES (?,?,?,?,1)', [username, password, String(body.real_name ?? username), String(body.email ?? '')])
    await sql('INSERT INTO user_roles (user_id,role_id) VALUES (?,1)', [result.insertId])
    return ok({ id: result.insertId }, '管理员账号创建成功')
  })

  app.get('/api/notification/template/list', async (request, reply) => {
    if (!await requireAdmin(request, reply)) return fail('需要管理员权限。')
    const { page, size, offset } = pageOf(request)
    const items = await rows('SELECT t.*,JSON_OBJECT("id",u.id,"real_name",u.real_name) AS creator FROM notification_templates t LEFT JOIN users u ON u.id=t.creator_id ORDER BY t.id DESC LIMIT ? OFFSET ?', [size, offset])
    const total = Number((await rows('SELECT COUNT(*) AS total FROM notification_templates'))[0]?.total ?? 0)
    return ok({ list: items, total })
  })
  app.post('/api/notification/template/create', async (request, reply) => {
    const user = await requireAdmin(request, reply)
    if (!user) return fail('需要管理员权限。')
    const body = jsonBody(request)
    const result = await sql('INSERT INTO notification_templates (name,type,subject,content,variables,status,creator_id) VALUES (?,?,?,?,?,1,?)', [String(body.name ?? ''), String(body.type ?? 'email'), String(body.subject ?? ''), String(body.content ?? ''), String(body.variables ?? ''), user?.id ?? 0])
    return ok({ id: result.insertId }, '创建成功')
  })
  app.put('/api/notification/template/:id', async (request, reply) => {
    if (!await requireAdmin(request, reply)) return fail('需要管理员权限。')
    const body = jsonBody(request)
    await sql('UPDATE notification_templates SET name=?,type=?,subject=?,content=?,variables=? WHERE id=?', [String(body.name ?? ''), String(body.type ?? 'email'), String(body.subject ?? ''), String(body.content ?? ''), String(body.variables ?? ''), idParam(request)])
    return ok(undefined, '更新成功')
  })
  app.delete('/api/notification/template/:id', async (request, reply) => {
    if (!await requireAdmin(request, reply)) return fail('需要管理员权限。')
    await sql('DELETE FROM notification_templates WHERE id=?', [idParam(request)])
    return ok(undefined, '删除成功')
  })
  app.post('/api/notification/template/preview', async (request, reply) => {
    if (!await requireAdmin(request, reply)) return fail('需要管理员权限。')
    const body = jsonBody(request)
    const variables = typeof body.variables === 'object' && body.variables ? body.variables as Record<string, unknown> : {
      RealName: '张三', TypeName: '请假申请', Title: '2025年6月请假申请', ApproverName: '张主管',
      CreatedAt: '2025-06-15', ApprovedAt: '2025-06-16', SiteName: '中盛达信息科技有限公司',
    }
    return ok({ rendered: await renderTemplate(String(body.content ?? ''), variables) })
  })

  app.get('/uploads/*', async (request, reply) => {
    const requested = request.url.slice('/uploads/'.length).split('?')[0]
    const path = await safeFilePath(uploadRoot, requested.replace(/^\/+/, ''))
    const bytes = await readFile(path)
    return reply.type(contentTypeFor(path)).send(bytes)
  })
  app.setNotFoundHandler(async (request, reply) => {
    if (request.method === 'GET' && !request.url.startsWith('/api/')) {
      const index = await readFile(join(options.frontendRoot, 'index.html'))
      return reply.type('text/html; charset=utf-8').send(index)
    }
    return reply.code(404).send(fail('接口不存在。'))
  })
  return app
}
