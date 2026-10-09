import { realpath, rm } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path'
import type { VulnLabDatabase } from './db.js'

const assertContained = async (root: string, relativePath: string) => {
  if (!relativePath || isAbsolute(relativePath) || relativePath.split(/[\\/]/).some(part => !part || part === '.' || part === '..')) {
    throw new Error('待清理路径格式无效。')
  }
  const target = resolve(root, relativePath)
  const fromRoot = relative(root, target)
  if (!fromRoot || fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
    throw new Error('待清理路径超出 VulnLab 数据目录。')
  }

  let ancestor = target
  let resolvedAncestor = ''
  while (!resolvedAncestor) {
    try {
      resolvedAncestor = await realpath(ancestor)
    } catch {
      const parent = dirname(ancestor)
      if (parent === ancestor) throw new Error('无法确认待清理路径所在目录。')
      ancestor = parent
    }
  }
  const realRoot = await realpath(root)
  const realRelative = relative(realRoot, resolvedAncestor)
  if (realRelative === '..' || realRelative.startsWith(`..${sep}`) || isAbsolute(realRelative)) {
    throw new Error('待清理路径的实际位置超出 VulnLab 数据目录。')
  }
  return target
}

export const processPendingCleanup = async (
  database: VulnLabDatabase,
  dataDir: string,
  remove: typeof rm = rm,
) => {
  const root = resolve(dataDir)
  let completed = 0
  let failed = 0
  for (const job of database.pendingCleanupJobs()) {
    try {
      const target = await assertContained(root, job.relativePath)
      await remove(target, { recursive: true, force: true, maxRetries: 6, retryDelay: 150 })
      database.completeCleanupJob(job.id)
      completed += 1
    } catch (error) {
      database.retryCleanupJob(job.id, error instanceof Error ? error.message : '资源清理失败。')
      failed += 1
    }
  }
  return { completed, failed }
}
