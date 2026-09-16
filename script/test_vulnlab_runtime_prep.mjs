import assert from 'node:assert/strict'
import { mkdtemp, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { prepareInstalledLab } from '../src/dist/runtime-prep.js'

const root = await mkdtemp(join(tmpdir(), 'vulnlab-runtime-prep-'))
const savedRequirements = process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
const savedWheelhouse = process.env.VULNLAB_PYTHON_WHEELHOUSE
try {
  delete process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
  delete process.env.VULNLAB_PYTHON_WHEELHOUSE
  await assert.rejects(
    prepareInstalledLab({ slug: 'pygoat', localPath: root }),
    /VULNLAB_PYTHON_REQUIREMENTS_FILE/,
  )
  await assert.rejects(stat(join(root, '.vulnlab-venv')))
  console.log('VulnLab runtime preparation test passed: PyGoat requires an offline hash-locked wheelhouse.')
} finally {
  if (savedRequirements === undefined) delete process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE
  else process.env.VULNLAB_PYTHON_REQUIREMENTS_FILE = savedRequirements
  if (savedWheelhouse === undefined) delete process.env.VULNLAB_PYTHON_WHEELHOUSE
  else process.env.VULNLAB_PYTHON_WHEELHOUSE = savedWheelhouse
  await rm(root, { recursive: true, force: true })
}
