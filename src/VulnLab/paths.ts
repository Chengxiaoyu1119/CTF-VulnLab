import { join, resolve, sep } from 'node:path'

const segment = (value: string, label: string) => {
  if (!value || value === '.' || value === '..' || /[\\/\0]/.test(value)) throw new Error(`${label} 不是有效的路径片段。`)
  return value
}

export const dataPaths = (dataDir: string) => {
  const root = resolve(dataDir)
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`
  const inside = (target: string) => {
    if (target !== root && !target.startsWith(prefix)) throw new Error('路径必须位于 VulnLab 数据目录内。')
    return target
  }
  const child = (parent: string, value: string, label: string) => inside(join(parent, segment(value, label)))
  const labs = join(root, 'labs')
  const imports = join(root, 'imports')
  const downloads = join(root, 'downloads')
  const runtime = join(root, 'runtime')
  const labRoot = (slug: string) => child(labs, slug, '靶场标识')
  const lab = (slug: string, version: string) => child(labRoot(slug), segment(version, '靶场版本'), '靶场版本')

  return {
    root,
    database: join(root, 'vulnlab.sqlite'),
    labs,
    imports,
    downloads,
    runtime,
    labRoot,
    lab,
    importJob: (jobId: string) => child(imports, jobId, '导入任务标识'),
    labDownload: (slug: string, version: string) => child(child(downloads, slug, '靶场标识'), version, '靶场版本'),
    runtimeInstance: (instanceId: string) => child(runtime, instanceId, '运行实例标识'),
  }
}
