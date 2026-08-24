import assert from 'node:assert/strict'
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { runtimeReadinessByLab } from '../src/VulnLab/dist/runtime-status.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-runtime-status-'))
const lab = (slug, runtimeKind, version = 'fixture') => ({
  id: slug, slug, title: slug, category: 'Web', difficulty: '入门', sourceType: 'git', sourceUrl: '', sourceRef: '', license: '',
  runtimeKind, providerId: runtimeKind, builtin: true, version, status: 'ready', summary: '', tags: [], localPath: join(root, 'labs', slug, version),
  importedAt: null, createdAt: '', updatedAt: '',
})
const dependencies = [
  { id: 'php', label: 'PHP', available: true, detail: '8.3' },
  { id: 'php-mysqli', label: 'PHP mysqli', available: false, detail: '扩展未启用' },
  { id: 'mysql', label: 'MySQL / MariaDB', available: false, detail: '未配置连接' },
  { id: 'node', label: 'Node.js', available: true, detail: '22' },
  { id: 'java', label: 'Java', available: true, detail: '21' },
  { id: 'python', label: 'Python', available: true, detail: '3.11' },
  { id: 'qemu', label: 'QEMU', available: false, detail: '未检测到' },
]
try {
  const labs = [lab('upload-labs', 'native-php'), lab('dvwa', 'native-php'), lab('juice-shop', 'native-node'), lab('webgoat', 'native-java'), lab('pygoat', 'native-python'), lab('vulnhub', 'vm')]
  let readiness = await runtimeReadinessByLab(labs, dependencies, root)
  assert.equal(readiness['upload-labs'].available, true)
  assert.deepEqual(readiness.dvwa.missing, ['PHP mysqli', 'MySQL / MariaDB'])
  assert.equal(readiness['juice-shop'].available, true)
  assert.equal(readiness.webgoat.available, true)
  assert.deepEqual(readiness.pygoat.missing, ['Python'])
  assert.deepEqual(readiness.vulnhub.missing, ['QEMU'])
  await mkdir(join(root, 'labs', 'pygoat', 'fixture'), { recursive: true })
  await writeFile(join(root, 'labs', 'pygoat', 'fixture', '.vulnlab-python-ready'), 'ready')
  readiness = await runtimeReadinessByLab(labs, dependencies, root)
  assert.equal(readiness.pygoat.available, true)
  console.log('VulnLab runtime status test passed: per-lab dependency gates and PyGoat readiness marker.')
} finally {
  await rm(root, { recursive: true, force: true })
}
