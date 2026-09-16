import { join, resolve, sep } from 'node:path'

const segment = (value: string, label: string) => {
  if (!value || value === '.' || value === '..' || /[\\/\0]/.test(value)) throw new Error(`${label} 不是有效的路径片段。`)
  return value
}

export const runtimePaths = (runtimeDir: string) => {
  const root = resolve(runtimeDir)
  const prefix = root.endsWith(sep) ? root : `${root}${sep}`
  const inside = (target: string) => {
    if (target !== root && !target.startsWith(prefix)) throw new Error('路径必须位于 VulnLab 运行时目录内。')
    return target
  }
  const child = (parent: string, value: string, label: string) => inside(join(parent, segment(value, label)))
  const toolchains = join(root, 'toolchains')
  const manifests = join(root, 'manifests')
  const downloads = join(root, 'downloads')

  return {
    root,
    toolchains,
    manifests,
    downloads,
    php: child(root, 'php', 'PHP 运行目录'),
    mysql: child(root, 'mysql', 'MariaDB 运行目录'),
    toolchain: (id: string, version: string, platform: string, arch: string) => child(child(child(toolchains, id, '运行时标识'), version, '运行时版本'), `${platform}-${arch}`, '运行时平台'),
    manifest: (fileName: string) => child(manifests, fileName, '运行时清单'),
    download: (fileName: string) => child(downloads, fileName, '运行时下载文件'),
  }
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
  const runtimeLayout = runtimePaths(runtime)
  const labRoot = (slug: string) => child(labs, slug, '靶场标识')
  const lab = (slug: string, version: string) => child(labRoot(slug), segment(version, '靶场版本'), '靶场版本')

  return {
    root,
    database: join(root, 'vulnlab.sqlite'),
    labs,
    imports,
    downloads,
    runtime,
    runtimeToolchains: runtimeLayout.toolchains,
    runtimeManifests: runtimeLayout.manifests,
    runtimeDownloads: runtimeLayout.downloads,
    labRoot,
    lab,
    importJob: (jobId: string) => child(imports, jobId, '导入任务标识'),
    labDownload: (slug: string, version: string) => child(child(downloads, slug, '靶场标识'), version, '靶场版本'),
    runtimeInstance: (instanceId: string) => child(runtime, instanceId, '运行实例标识'),
    runtimeToolchain: runtimeLayout.toolchain,
    runtimeManifest: runtimeLayout.manifest,
    runtimeDownload: runtimeLayout.download,
    runtimePhp: runtimeLayout.php,
    runtimeMysql: runtimeLayout.mysql,
  }
}
