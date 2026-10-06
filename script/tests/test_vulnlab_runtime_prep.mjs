import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { prepareInstalledLab, pythonInstallConfig } from '../../src/dist/runtime-prep.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-runtime-prep-'))
const savedRequirements = process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
const savedWheelhouse = process.env.VULNLAB_PYTHON_WHEELHOUSE
const savedOffline = process.env.VULNLAB_OFFLINE
try {
  delete process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
  delete process.env.VULNLAB_PYTHON_WHEELHOUSE
  const pygoatConfig = await pythonInstallConfig({ slug: 'pygoat', builtin: true, localPath: root })
  const bundledPyGoat = fileURLToPath(new URL('../../src/assets/python/pygoat/', import.meta.url))
  assert.equal(pygoatConfig.requirementsPath, join(bundledPyGoat, 'requirements.txt'))
  assert.equal(pygoatConfig.wheelhousePath, join(bundledPyGoat, 'wheelhouse'))
  assert.match(await readFile(pygoatConfig.requirementsPath, 'utf8'), /^whitenoise==6\.2\.0 \\/m)
  assert.ok((await readdir(pygoatConfig.wheelhousePath)).includes('whitenoise-6.2.0-py3-none-any.whl'))
  process.env.VULNLAB_PYTHON_WHEELHOUSE = join(root, 'missing-wheelhouse')
  await assert.rejects(pythonInstallConfig({ slug: 'pygoat', builtin: true, localPath: root }), /wheelhouse 目录不存在/)
  delete process.env.VULNLAB_PYTHON_WHEELHOUSE
  await assert.rejects(stat(join(root, '.vulnlab-venv')))

  const pythonRoot = await mkdtemp(join(tmpdir(), 'vulnlab-python-prep-'))
  try {
    await writeFile(join(pythonRoot, 'requirements.txt'), 'fixture==1.0 --hash=sha256:' + '0'.repeat(64) + '\n', 'utf8')
    await assert.rejects(prepareInstalledLab({
      slug: 'custom-python', runtimeKind: 'native-python', localPath: pythonRoot,
      runtimeConfig: { profile: 'python-script', entryPath: 'app.py' }, builtin: false,
    }), /wheelhouse/)
    await assert.rejects(stat(join(pythonRoot, '.vulnlab-venv')))
  } finally {
    await rm(pythonRoot, { recursive: true, force: true })
  }

  const nodeLab = (localPath) => ({
    id: 'custom-node',
    slug: 'custom-node',
    title: 'Custom Node',
    category: 'Web',
    difficulty: '入门',
    sourceType: 'archive',
    sourceUrl: 'upload://fixture',
    sourceRef: 'fixture',
    license: 'MIT',
    runtimeKind: 'native-node',
    providerId: 'native-node',
    runtimeConfig: { profile: 'prebuilt-node', entryPath: 'app.js' },
    builtin: false,
    version: 'custom',
    status: 'importing',
    summary: 'fixture',
    tags: [],
    localPath,
    importedAt: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  })
  const nodeRoot = await mkdtemp(join(tmpdir(), 'vulnlab-node-prep-'))
  try {
    await writeFile(join(nodeRoot, 'app.js'), 'console.log("fixture")\n', 'utf8')
    // 自包含项目不需要 npm，应保持可导入。
    await prepareInstalledLab(nodeLab(nodeRoot))
    await assert.rejects(stat(join(nodeRoot, '.vulnlab-node-ready')))

    await writeFile(join(nodeRoot, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { missing: '^1.0.0' } }), 'utf8')
    await assert.rejects(prepareInstalledLab(nodeLab(nodeRoot)), /缺少 package-lock\.json/)
    await assert.rejects(stat(join(nodeRoot, '.vulnlab-node-ready')))

    await mkdir(join(nodeRoot, 'dep'), { recursive: true })
    await writeFile(join(nodeRoot, 'dep', 'package.json'), JSON.stringify({ name: 'fixture-dep', version: '1.0.0', main: 'index.js' }), 'utf8')
    await writeFile(join(nodeRoot, 'dep', 'index.js'), 'module.exports = 1\n', 'utf8')
    await writeFile(join(nodeRoot, 'package.json'), JSON.stringify({ name: 'fixture', version: '1.0.0', dependencies: { 'fixture-dep': 'file:dep' } }), 'utf8')
    await writeFile(join(nodeRoot, 'package-lock.json'), JSON.stringify({
      name: 'fixture', version: '1.0.0', lockfileVersion: 3, requires: true,
      packages: {
        '': { name: 'fixture', version: '1.0.0', dependencies: { 'fixture-dep': 'file:dep' } },
        dep: { name: 'fixture-dep', version: '1.0.0' },
        'node_modules/fixture-dep': { resolved: 'dep', link: true },
      },
    }), 'utf8')
    process.env.VULNLAB_OFFLINE = '1'
    await prepareInstalledLab(nodeLab(nodeRoot), undefined, undefined, process.execPath)
    assert.match(await readFile(join(nodeRoot, '.vulnlab-node-ready'), 'utf8'), /^\d{4}-\d{2}-\d{2}T/) // 标记文件内容是 ISO 时间戳
    assert.equal(await readFile(join(nodeRoot, 'node_modules', 'fixture-dep', 'index.js'), 'utf8'), 'module.exports = 1\n')
    await prepareInstalledLab(nodeLab(nodeRoot), undefined, undefined, join(nodeRoot, 'missing-node.exe'))
    assert.match(await readFile(join(nodeRoot, '.vulnlab-node-ready'), 'utf8'), /T/)
  } finally {
    await rm(nodeRoot, { recursive: true, force: true })
  }
  console.log('VulnLab runtime preparation test passed: Python wheelhouse and custom Node/npm preparation paths.')
} finally {
  if (savedRequirements === undefined) delete process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
  else process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE = savedRequirements
  if (savedWheelhouse === undefined) delete process.env.VULNLAB_PYTHON_WHEELHOUSE
  else process.env.VULNLAB_PYTHON_WHEELHOUSE = savedWheelhouse
  if (savedOffline === undefined) delete process.env.VULNLAB_OFFLINE
  else process.env.VULNLAB_OFFLINE = savedOffline
  await rm(root, { recursive: true, force: true })
}
