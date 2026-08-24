export type UserRole = 'admin' | 'learner'

export type LabStatus = 'cataloged' | 'queued' | 'importing' | 'ready' | 'error' | 'disabled'

export type SourceType = 'git' | 'archive' | 'vm' | 'catalog'

export type RuntimeKind = 'native-php' | 'native-node' | 'native-java' | 'native-python' | 'vm'

export type Difficulty = '入门' | '简单' | '中等' | '困难'

export interface Lab {
  id: string
  slug: string
  title: string
  category: string
  difficulty: Difficulty
  sourceType: SourceType
  sourceUrl: string
  sourceRef: string
  license: string
  runtimeKind: RuntimeKind
  providerId: string
  builtin: boolean
  version: string
  status: LabStatus
  summary: string
  tags: string[]
  localPath: string | null
  importedAt: string | null
  createdAt: string
  updatedAt: string
}

export interface ImportJob {
  id: string
  labId: string
  sourceUrl: string
  requestedBy: string
  status: 'queued' | 'importing' | 'completed' | 'error'
  stage: string
  message: string
  progress: number
  error: string | null
  manifest: ImportManifest | null
  createdAt: string
  updatedAt: string
}

export interface ImportManifest {
  adapterId: string
  sourceUrl: string
  sourceRef: string
  resolvedRef: string
  revision: string
  archiveSha256: string
  localPath: string
  fileCount: number
  totalBytes: number
  licenseFiles: string[]
  topLevelEntries: string[]
  warnings: string[]
  importedAt: string
}

export type VmDownloadStatus = 'queued' | 'downloading' | 'completed' | 'error'

export interface VmDownload {
  id: string
  labId: string
  entryIndex: number
  title: string
  sourceUrl: string
  downloadUrl: string
  filename: string
  status: VmDownloadStatus
  message: string
  progress: number
  bytesDownloaded: number
  totalBytes: number | null
  expectedMd5: string | null
  expectedSha1: string | null
  actualMd5: string | null
  actualSha1: string | null
  checksumVerified: boolean
  sha256: string | null
  localPath: string | null
  error: string | null
  createdAt: string
  updatedAt: string
}

export interface LabInstance {
  id: string
  labId: string
  labTitle: string
  provider: string
  endpoint: string
  status: 'running' | 'expired' | 'destroyed'
  createdAt: string
  expiresAt: string
  logs: string[]
}

export interface SessionView {
  userName: string
  role: UserRole
  csrfToken: string
}

export interface AppSettings {
  bindHost: string
  port: string
  maxInstances: string
  dataDir: string
  autoCleanup: string
}

export interface Overview {
  labCount: number
  readyCount: number
  queuedImportCount: number
  runningInstanceCount: number
  maxInstances: number
  auditCount: number
}
