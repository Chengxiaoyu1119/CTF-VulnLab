import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')
const require = createRequire(resolve(root, 'src/VulnLab/package.json'))
const { zipSync } = require('fflate')
const { importGitHubRepository, importGitLabRepository, importerInternals, ImporterError } = await import(new URL('../src/VulnLab/dist/importer.js', import.meta.url))

const archive = zipSync({
  'DVWA-main/README.md': new TextEncoder().encode('# DVWA fixture'),
  'DVWA-main/LICENSE': new TextEncoder().encode('fixture license'),
  'DVWA-main/config/config.inc.php.dist': new TextEncoder().encode('<?php return [];'),
})
const calls = []
const fakeFetch = async (url) => {
  calls.push(url)
  if (url.endsWith('/repos/digininja/DVWA')) return new Response(JSON.stringify({ default_branch: 'main' }), { status: 200 })
  if (url.endsWith('/commits/main')) return new Response(JSON.stringify({ sha: 'a'.repeat(40) }), { status: 200 })
  if (url.includes('/zip/')) return new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } })
  throw new Error(`unexpected URL: ${url}`)
}

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-test-'))
try {
  const manifest = await importGitHubRepository({
    sourceUrl: 'https://github.com/digininja/DVWA',
    sourceRef: 'digininja/DVWA',
    jobId: 'fixture-job',
    dataDir,
    fetchImpl: fakeFetch,
  })
  assert.equal(manifest.adapterId, 'github-git')
  assert.equal(manifest.revision, 'a'.repeat(40))
  assert.equal(manifest.fileCount, 3)
  assert.equal(manifest.licenseFiles.length, 1)
  assert.equal(await readFile(join(manifest.localPath, 'README.md'), 'utf8'), '# DVWA fixture')
  assert.ok(calls.some(url => url.includes('/zip/' + 'a'.repeat(40))))
  assert.deepEqual(importerInternals.parseGitLabRepository('https://gitlab.com/group/subgroup/project'), { projectPath: 'group/subgroup/project' })
  assert.throws(() => importerInternals.parseGitLabRepository('https://gitlab.com/group/project.git'), ImporterError)

  const gitlabCalls = []
  const gitlabArchiveHeaders = []
  const gitlabFetch = async (url, init = {}) => {
    gitlabCalls.push(url)
    if (url.includes('/repository/archive.zip?sha=')) gitlabArchiveHeaders.push(new Headers(init.headers))
    if (url.endsWith('/projects/group%2Fsubgroup%2Fproject')) return new Response(JSON.stringify({ default_branch: 'main' }), { status: 200 })
    if (url.endsWith('/repository/commits/main')) return new Response(JSON.stringify({ id: 'd'.repeat(40) }), { status: 200 })
    if (url.includes('/repository/archive.zip?sha=')) return new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } })
    throw new Error(`unexpected GitLab URL: ${url}`)
  }
  const gitlabDir = await mkdtemp(join(tmpdir(), 'vulnlab-gitlab-import-'))
  try {
    const gitlabManifest = await importGitLabRepository({
      sourceUrl: 'https://gitlab.com/group/subgroup/project',
      sourceRef: 'gitlab.com/group/subgroup/project',
      jobId: 'gitlab-fixture-job',
      dataDir: gitlabDir,
      fetchImpl: gitlabFetch,
    })
    assert.equal(gitlabManifest.adapterId, 'gitlab-git')
    assert.equal(gitlabManifest.revision, 'd'.repeat(40))
    assert.equal(await readFile(join(gitlabManifest.localPath, 'README.md'), 'utf8'), '# DVWA fixture')
    assert.ok(gitlabCalls.some(url => url.includes('group%2Fsubgroup%2Fproject')))
    assert.ok(gitlabCalls.some(url => url.includes('archive.zip?sha=' + 'd'.repeat(40))))
    assert.equal(gitlabArchiveHeaders[0]?.get('accept'), 'application/zip')
  } finally {
    await rm(gitlabDir, { recursive: true, force: true })
  }
  let importerBodyCancelled = false
  const oversizedResponse = new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(8)) },
    cancel() { importerBodyCancelled = true },
  }), { status: 200 })
  await assert.rejects(importerInternals.readLimitedResponse(oversizedResponse, 4, '导入夹具'), /超过大小限制/)
  assert.equal(importerBodyCancelled, true)
  assert.throws(() => importerInternals.safeRelativePath('../outside.txt'), ImporterError)
  assert.throws(() => importerInternals.safeTarget(resolve(dataDir, 'root'), resolve('..', 'outside.txt')), ImporterError)
  assert.equal(importerInternals.windowsPathKey('Less-24/Logged-in.php'), 'less-24/logged-in.php')
  assert.throws(() => importerInternals.assertPortablePaths(['Less-24/Logged-in.php', 'Less-24/logged-in.php']), /Windows 路径冲突/)
  assert.throws(() => importerInternals.assertPortablePaths(['A', 'a/index.php']), /Windows 文件目录冲突/)
  assert.throws(() => importerInternals.assertPortablePaths(['CON.txt']), /Windows 不可用文件名/)
  assert.throws(() => importerInternals.assertPortablePaths(['report.txt:secret']), /Windows 不可用文件名/)

  const collisionArchive = zipSync({
    'Less-24/Logged-in.php': new TextEncoder().encode('<?php echo "upper";'),
    'Less-24/logged-in.php': new TextEncoder().encode('<?php echo "lower";'),
  })
  const collisionDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-collision-'))
  try {
    await assert.rejects(importGitHubRepository({
      sourceUrl: 'https://github.com/digininja/DVWA',
      sourceRef: 'digininja/DVWA@main',
      jobId: 'collision-job',
      dataDir: collisionDir,
      fetchImpl: async url => {
        if (url.endsWith('/repos/digininja/DVWA')) return new Response(JSON.stringify({ default_branch: 'main' }), { status: 200 })
        if (url.endsWith('/commits/main')) return new Response(JSON.stringify({ sha: 'b'.repeat(40) }), { status: 200 })
        if (url.includes('/zip/')) return new Response(collisionArchive, { status: 200, headers: { 'content-length': String(collisionArchive.byteLength) } })
        throw new Error(`unexpected collision URL: ${url}`)
      },
    }), /Windows 路径冲突/)
  } finally {
    await rm(collisionDir, { recursive: true, force: true })
  }

  const sqliCollisionDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-sqli-collision-'))
  try {
    const sqliManifest = await importGitHubRepository({
      sourceUrl: 'https://github.com/Audi-1/sqli-labs',
      sourceRef: 'Audi-1/sqli-labs@master',
      jobId: 'sqli-collision-job',
      dataDir: sqliCollisionDir,
      portablePathPolicy: 'case-collision-lowercase',
      fetchImpl: async url => {
        if (url.endsWith('/repos/Audi-1/sqli-labs')) return new Response(JSON.stringify({ default_branch: 'master' }), { status: 200 })
        if (url.endsWith('/commits/master')) return new Response(JSON.stringify({ sha: 'c'.repeat(40) }), { status: 200 })
        if (url.includes('/zip/')) return new Response(collisionArchive, { status: 200, headers: { 'content-length': String(collisionArchive.byteLength) } })
        throw new Error(`unexpected SQLi URL: ${url}`)
      },
    })
    assert.equal(sqliManifest.fileCount, 1)
    assert.equal(sqliManifest.warnings.length, 1)
    assert.equal(await readFile(join(sqliManifest.localPath, 'logged-in.php'), 'utf8'), '<?php echo "lower";')
  } finally {
    await rm(sqliCollisionDir, { recursive: true, force: true })
  }

  const fallbackCalls = []
  const fallbackFetch = async (url) => {
    fallbackCalls.push(url)
    if (url.endsWith('/repos/digininja/DVWA')) return new Response('{}', { status: 403 })
    if (url.includes('/zip/')) return new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } })
    throw new Error(`unexpected fallback URL: ${url}`)
  }
  const fallbackDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-fallback-'))
  try {
    const fallbackManifest = await importGitHubRepository({
      sourceUrl: 'https://github.com/digininja/DVWA',
      sourceRef: 'digininja/DVWA@main',
      jobId: 'fallback-job',
      dataDir: fallbackDir,
      fetchImpl: fallbackFetch,
    })
    assert.equal(fallbackManifest.revision, `archive-${fallbackManifest.archiveSha256}`)
    assert.equal(fallbackManifest.resolvedRef, `main@archive-sha256:${fallbackManifest.archiveSha256}`)
    assert.ok(fallbackCalls.some(url => url.includes('/zip/refs/heads/main')))
  } finally {
    await rm(fallbackDir, { recursive: true, force: true })
  }

  const pinnedSha = 'e'.repeat(40)
  const pinnedFallbackCalls = []
  const pinnedFallbackDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-pinned-fallback-'))
  try {
    const pinnedManifest = await importGitHubRepository({
      sourceUrl: 'https://github.com/digininja/DVWA',
      sourceRef: `digininja/DVWA@${pinnedSha}`,
      jobId: 'pinned-fallback-job',
      dataDir: pinnedFallbackDir,
      fetchImpl: async url => {
        pinnedFallbackCalls.push(url)
        if (url.endsWith('/repos/digininja/DVWA')) return new Response('{}', { status: 403 })
        if (url.includes(`/zip/${pinnedSha}`)) return new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } })
        throw new Error(`unexpected pinned fallback URL: ${url}`)
      },
    })
    assert.equal(pinnedManifest.resolvedRef, `${pinnedSha}@archive-sha256:${pinnedManifest.archiveSha256}`)
    assert.ok(pinnedFallbackCalls.some(url => url.endsWith(`/zip/${pinnedSha}`)))
    assert.ok(!pinnedFallbackCalls.some(url => url.includes('/refs/heads/')))
  } finally {
    await rm(pinnedFallbackDir, { recursive: true, force: true })
  }

  const branchFallbackCalls = []
  const branchFallbackFetch = async (url) => {
    branchFallbackCalls.push(url)
    if (url.endsWith('/repos/digininja/DVWA')) return new Response('{}', { status: 403 })
    if (url.includes('/zip/refs/heads/main')) return new Response('missing', { status: 404 })
    if (url.includes('/zip/refs/heads/master')) return new Response(archive, { status: 200, headers: { 'content-length': String(archive.byteLength) } })
    throw new Error(`unexpected branch fallback URL: ${url}`)
  }
  const branchFallbackDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-branch-fallback-'))
  try {
    const branchFallbackManifest = await importGitHubRepository({
      sourceUrl: 'https://github.com/digininja/DVWA',
      sourceRef: 'digininja/DVWA',
      jobId: 'branch-fallback-job',
      dataDir: branchFallbackDir,
      fetchImpl: branchFallbackFetch,
    })
    assert.equal(branchFallbackManifest.resolvedRef, `master@archive-sha256:${branchFallbackManifest.archiveSha256}`)
    assert.ok(branchFallbackCalls.some(url => url.includes('/zip/refs/heads/main')))
    assert.ok(branchFallbackCalls.some(url => url.includes('/zip/refs/heads/master')))
  } finally {
    await rm(branchFallbackDir, { recursive: true, force: true })
  }

  const abortController = new AbortController()
  abortController.abort()
  const abortDir = await mkdtemp(join(tmpdir(), 'vulnlab-import-abort-'))
  try {
    await assert.rejects(importGitHubRepository({
      sourceUrl: 'https://github.com/digininja/DVWA',
      sourceRef: 'digininja/DVWA@main',
      jobId: 'abort-job',
      dataDir: abortDir,
      signal: abortController.signal,
      fetchImpl: async (_url, init) => {
        assert.equal(init.signal.aborted, true)
        throw new Error('aborted fixture')
      },
    }), ImporterError)
  } finally {
    await rm(abortDir, { recursive: true, force: true })
  }

  console.log('VulnLab importer test passed: fixed revision, rate-limit fallback, hash manifest, safe extraction and traversal guard.')
} finally {
  await rm(dataDir, { recursive: true, force: true })
}
