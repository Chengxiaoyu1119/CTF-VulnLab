import type { SourceType } from './types.js'

export interface LabSourceAdapter {
  id: string
  label: string
  sourceTypes: SourceType[]
  supportsHost(hostname: string): boolean
  implemented: boolean
  nextStage: string
}

export const sourceAdapters: LabSourceAdapter[] = [
  { id: 'github-git', label: 'GitHub 仓库适配器', sourceTypes: ['git'], supportsHost: hostname => hostname === 'github.com' || hostname === 'www.github.com', implemented: true, nextStage: '已支持固定版本下载与安全解包' },
  { id: 'gitlab-git', label: 'GitLab 仓库适配器', sourceTypes: ['git'], supportsHost: hostname => hostname === 'gitlab.com' || hostname === 'www.gitlab.com', implemented: true, nextStage: '已支持固定 commit、压缩包校验与安全解包' },
  { id: 'vulnhub-catalog', label: 'VulnHub 目录适配器', sourceTypes: ['catalog'], supportsHost: hostname => hostname === 'vulnhub.com' || hostname === 'www.vulnhub.com', implemented: true, nextStage: '已支持机器详情、显式镜像下载和校验信息清单；可选 QEMU Provider 支持已下载磁盘镜像' },
]

export const adapterFor = (sourceUrl: string, sourceType: SourceType) => {
  const hostname = new URL(sourceUrl).hostname.toLowerCase()
  return sourceAdapters.find(adapter => adapter.sourceTypes.includes(sourceType) && adapter.supportsHost(hostname)) ?? null
}
