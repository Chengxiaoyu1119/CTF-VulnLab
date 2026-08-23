import assert from 'node:assert/strict'
import { cp, mkdtemp, rm, stat } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { join, resolve } from 'node:path'
import { NativePhpProvider } from '../src/VulnLab/dist/providers.js'

const required = (name) => {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`请设置 ${name} 后再执行原生 PHP + MySQL 冒烟。`)
  return value
}

const dvwaSource = resolve(required('VULNLAB_DVWA_SOURCE'))
const pikachuSource = resolve(required('VULNLAB_PIKACHU_SOURCE'))
const sqliLabsSource = resolve(required('VULNLAB_SQLI_SOURCE'))
const phpIni = resolve(required('VULNLAB_PHP_INI'))
const mysqlPort = Number(process.env.VULNLAB_MYSQL_PORT ?? 3306)
const config = {
  host: process.env.VULNLAB_MYSQL_HOST?.trim() || '127.0.0.1',
  port: Number.isInteger(mysqlPort) ? mysqlPort : 3306,
  adminUser: required('VULNLAB_MYSQL_ADMIN_USER'),
  adminPassword: process.env.VULNLAB_MYSQL_ADMIN_PASSWORD ?? '',
  appHost: process.env.VULNLAB_MYSQL_APP_HOST?.trim() || '127.0.0.1',
  mysqlBinary: process.env.VULNLAB_MYSQL_BIN?.trim() || 'mysql',
}
const phpBinary = process.env.VULNLAB_PHP_BIN?.trim() || 'php'
const runtime = {
  bindHost: '127.0.0.1',
  portStart: Number(process.env.VULNLAB_RUNTIME_PORT_START ?? 6820),
  portEnd: Number(process.env.VULNLAB_RUNTIME_PORT_END ?? 6899),
  phpBinary,
  phpIni,
  mysql: config,
}
const dataDir = await mkdtemp(join(process.env.TEMP ?? process.env.TMP ?? '.', 'vulnlab-native-php-mysql-'))

const copySource = async (source, slug) => {
  const target = join(dataDir, 'imports', slug)
  await cp(source, target, { recursive: true, force: true })
  return target
}

const runLab = async (provider, lab, path, checkPath, pattern) => {
  const instanceId = `mysql-smoke-${lab.slug}-${randomUUID().replaceAll('-', '').slice(0, 12)}`
  const started = await provider.start({
    instanceId,
    lab: { ...lab, localPath: path },
    publicOrigin: 'http://127.0.0.1:6720',
    lifetimeMinutes: 5,
    dataDir,
    runtime,
  })
  const response = await fetch(`${started.endpoint}${checkPath}`)
  const html = await response.text()
  assert.equal(response.status, 200)
  assert.match(html, pattern)
  const instance = {
    id: instanceId,
    labId: lab.id,
    labTitle: lab.title,
    provider: 'native-php',
    endpoint: started.endpoint,
    status: 'running',
    createdAt: started.createdAt,
    expiresAt: started.expiresAt,
    logs: started.logs,
  }
  await provider.stop({ lab: { ...lab, localPath: path }, instance, runtime })
  await assert.rejects(stat(join(dataDir, 'runtime', instanceId)))
  return { slug: lab.slug, endpoint: started.endpoint }
}

const baseLab = (slug, title, sourceUrl, path) => ({
  id: `lab-${slug}`,
  slug,
  title,
  category: 'Web',
  difficulty: '入门',
  sourceType: 'git',
  sourceUrl,
  sourceRef: `${sourceUrl.replace('https://github.com/', '')}@master`,
  license: 'fixture',
  runtimeKind: 'native-php',
  status: 'ready',
  summary: 'smoke fixture',
  tags: ['PHP', 'MySQL'],
  localPath: path,
  importedAt: null,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
})

const provider = new NativePhpProvider()
try {
  const dvwaPath = await copySource(dvwaSource, 'dvwa')
  const pikachuPath = await copySource(pikachuSource, 'pikachu')
  const sqliLabsPath = await copySource(sqliLabsSource, 'sqli-labs')
  const results = []
  results.push(await runLab(provider, baseLab('dvwa', 'DVWA', 'https://github.com/digininja/DVWA', dvwaPath), dvwaPath, 'login.php', /DVWA/i))
  results.push(await runLab(provider, baseLab('pikachu', 'Pikachu', 'https://github.com/zhuifengshaonianhanlu/pikachu', pikachuPath), pikachuPath, 'index.php', /pikachu|皮卡丘/i))
  results.push(await runLab(provider, baseLab('sqli-labs', 'SQLi-Labs', 'https://github.com/Audi-1/sqli-labs', sqliLabsPath), sqliLabsPath, 'Less-1/index.php?id=1', /Dumb|Login name/i))
  console.log(`VulnLab native PHP + MySQL smoke passed: ${results.map(item => `${item.slug}=${item.endpoint}`).join(', ')}`)
} finally {
  await provider.shutdown()
  await rm(dataDir, { recursive: true, force: true }).catch(() => undefined)
}
