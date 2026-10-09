import assert from 'node:assert/strict'
import { cp, mkdir, mkdtemp, rm, stat } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { NativePhpProvider } from '../../src/dist/runtime/providers.js'
import { dataPaths } from '../../src/dist/paths.js'

const repoRoot = resolve(import.meta.dirname, '..', '..')
const appRoot = join(repoRoot, 'src')
const sourceRoot = join(appRoot, 'data', 'labs', 'xss-labs', 'c97bed6')
const phpCandidates = [
  process.env.VULNLAB_PHP_BIN,
  join(appRoot, 'data', 'runtime', 'toolchains', 'php', '8.3.33', 'win32-x64', 'php.exe'),
  'php',
].filter(Boolean)
const phpBinary = phpCandidates.find(candidate => candidate === 'php' || spawnSync(candidate, ['--version'], { stdio: 'ignore' }).status === 0)
assert.ok(phpBinary, 'PHP runtime is required for the XSS-Labs browser smoke test.')
assert.ok((await stat(sourceRoot).catch(() => null))?.isDirectory(), 'Install the fixed XSS-Labs source before running this smoke test.')

const dataDir = await mkdtemp(join(tmpdir(), 'vulnlab-xss-ruffle-'))
const sourceCopy = join(dataPaths(dataDir).labs, 'xss-labs', 'fixture')
const runtime = {
  bindHost: '127.0.0.1', portStart: 6800, portEnd: 6899,
  phpBinary, nodeBinary: process.execPath, javaBinary: 'java', pythonBinary: 'python',
}
const provider = new NativePhpProvider()
const instanceId = `xss-ruffle-${process.pid}`

try {
  await mkdir(sourceCopy, { recursive: true })
  await cp(sourceRoot, sourceCopy, { recursive: true, force: true })
  const lab = {
    id: 'lab-xss-ruffle', slug: 'xss-labs', title: 'XSS-Labs', category: 'Web', difficulty: '中等',
    sourceType: 'git', sourceUrl: 'https://github.com/do0dl3/xss-labs', sourceRef: 'fixture', license: '上游未声明',
    runtimeKind: 'native-php', providerId: 'native-php', builtin: true, version: 'fixture', status: 'ready',
    summary: '', tags: [], localPath: sourceCopy, importedAt: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
  }
  const started = await provider.start({
    instanceId, lab, publicOrigin: 'http://127.0.0.1:6710', lifetimeMinutes: 5, dataDir, runtime,
  })
  const pythonCode = [
    'import asyncio, sys',
    'from urllib.parse import urlparse',
    'from playwright.async_api import async_playwright',
    'async def main():',
    '  base = sys.argv[1]',
    '  external = []',
    '  async with async_playwright() as p:',
    '    browser = await p.chromium.launch(headless=True)',
    '    page = await browser.new_page()',
    '    page.on("request", lambda request: external.append(request.url) if urlparse(request.url).hostname not in ("127.0.0.1", "localhost") else None)',
    '    for level in range(17, 21):',
    '      await page.goto(f"{base}level{level}.php?arg01=a&arg02=b", wait_until="networkidle")',
    '      await page.locator("ruffle-embed, ruffle-player").first.wait_for(timeout=30000)',
    '      player = page.locator("ruffle-embed, ruffle-player").first',
    '      assert await player.evaluate("el => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 }")',
    '      assert await page.locator("script[src*=ruffle]").count() == 1',
    '    assert not external, external',
    '    await browser.close()',
    'asyncio.run(main())',
  ].join('\n')
  const browser = spawnSync(process.env.PYTHON ?? 'python', ['-c', pythonCode, started.endpoint], { cwd: repoRoot, stdio: 'inherit' })
  assert.equal(browser.status, 0, 'XSS-Labs Ruffle browser checks failed.')
  console.log('VulnLab XSS-Labs browser smoke passed: levels 17-20 use local Ruffle resources.')
} finally {
  await provider.stop({ lab: { ...labForStop(instanceId), localPath: sourceCopy }, instance: { id: instanceId, labId: 'lab-xss-ruffle', labTitle: 'XSS-Labs', provider: 'native-php' }, dataDir }).catch(() => undefined)
  await rm(dataDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}

function labForStop() {
  return { id: 'lab-xss-ruffle', slug: 'xss-labs', title: 'XSS-Labs', runtimeKind: 'native-php', providerId: 'native-php' }
}
