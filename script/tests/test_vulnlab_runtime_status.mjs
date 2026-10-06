import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { runtimeReadinessByLab } from '../../src/dist/runtime-status.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-runtime-status-'))
const lab = (slug, runtimeKind, version = 'fixture') => ({
  id: slug, slug, title: slug, category: 'Web', difficulty: '入门', sourceType: 'git', sourceUrl: '', sourceRef: '', license: '',
  runtimeKind, providerId: runtimeKind, builtin: true, version, status: 'ready', summary: '', tags: [], localPath: join(root, 'labs', slug, version),
  importedAt: null, createdAt: '', updatedAt: '',
})
const dependencies = [
  { id: 'php', label: 'PHP', available: true, detail: '8.3' },
  { id: 'php-mysqli', label: 'PHP mysqli', available: false, detail: '扩展未启用' },
  { id: 'php-pdo-mysql', label: 'PHP PDO MySQL', available: false, detail: '扩展未启用' },
  { id: 'mysql', label: 'MySQL / MariaDB', available: false, detail: '未配置连接' },
  { id: 'node', label: 'Node.js', available: true, detail: '22' },
  { id: 'node-permission', label: 'Node.js 实例文件权限', available: true, detail: '22.23' },
  { id: 'java', label: 'Java', available: true, detail: '21' },
  { id: 'python', label: 'Python', available: true, detail: '3.11' },
]
try {
  const labs = [lab('upload-labs', 'native-php'), lab('dvwa', 'native-php'), lab('xvwa', 'native-php'), lab('juice-shop', 'native-node'), lab('webgoat', 'native-java'), lab('pygoat', 'native-python')]
  await Promise.all(labs.map(item => mkdir(item.localPath, { recursive: true })))
  let readiness = await runtimeReadinessByLab(labs, dependencies, root)
  assert.equal(readiness['upload-labs'].available, true)
  assert.deepEqual(readiness.dvwa.missing, ['PHP mysqli', 'PHP PDO MySQL', 'MySQL / MariaDB'])
  assert.deepEqual(readiness.xvwa.missing, ['PHP mysqli', 'PHP PDO MySQL', 'MySQL / MariaDB'])
  assert.equal(readiness['juice-shop'].available, true)
  assert.equal(readiness.webgoat.available, true)
  assert.deepEqual(readiness.pygoat.missing, ['Python'])
  const catalogedPyGoat = { ...labs.find(item => item.slug === 'pygoat'), status: 'cataloged' }
  readiness = await runtimeReadinessByLab([catalogedPyGoat], dependencies, root)
  assert.deepEqual(readiness.pygoat.missing, ['靶场资源未安装'])
  await rm(catalogedPyGoat.localPath, { recursive: true, force: true })
  readiness = await runtimeReadinessByLab([labs.find(item => item.slug === 'pygoat')], dependencies, root)
  assert.ok(readiness.pygoat.missing.includes('靶场资源未安装'))
  await mkdir(join(root, 'labs', 'pygoat', 'fixture'), { recursive: true })
  await writeFile(join(root, 'labs', 'pygoat', 'fixture', '.vulnlab-python-ready'), 'ready')
  readiness = await runtimeReadinessByLab(labs, dependencies, root)
  assert.equal(readiness.pygoat.available, true)
  const customRoot = join(root, 'custom-python')
  await mkdir(customRoot, { recursive: true })
  const customPython = { ...lab('custom-python', 'native-python'), builtin: false, localPath: customRoot, runtimeConfig: { profile: 'python-script', entryPath: 'app.py' } }
  await writeFile(join(customRoot, 'requirements.txt'), 'fixture==1.0\n')
  readiness = await runtimeReadinessByLab([customPython], dependencies, root)
  assert.deepEqual(readiness['custom-python'].missing, ['Python'])
  await writeFile(join(customRoot, '.vulnlab-python-ready'), 'ready')
  readiness = await runtimeReadinessByLab([customPython], dependencies, root)
  assert.equal(readiness['custom-python'].available, true)
  const oa = lab('oa-vuln-labs', 'native-oa')
  await mkdir(oa.localPath, { recursive: true })
  const oaDependencies = [
    ...dependencies.filter(item => item.id !== 'mysql'),
    { id: 'mysql', label: 'MySQL / MariaDB', available: true, detail: 'connected' },
    { id: 'node-permission', label: 'Node.js 实例文件权限', available: true, detail: '22.23' },
  ]
  readiness = await runtimeReadinessByLab([oa], oaDependencies, root)
  assert.equal(readiness['oa-vuln-labs'].available, true)
  readiness = await runtimeReadinessByLab([oa], oaDependencies.map(item => item.id === 'node-permission' ? { ...item, available: false } : item), root)
  assert.deepEqual(readiness['oa-vuln-labs'].missing, ['Node.js 实例文件权限'])
  assert.equal(oaDependencies.some(item => item.id === 'oa-sandbox'), false, 'local OA readiness must not depend on AppContainer')
  console.log('VulnLab runtime status test passed: per-lab dependency gates, AppContainer-independent local OA, and PyGoat readiness marker.')
} finally {
  await rm(root, { recursive: true, force: true })
}
