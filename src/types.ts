export type UserRole = 'admin'

export type LabStatus = 'cataloged' | 'queued' | 'importing' | 'ready' | 'error' | 'disabled'

export type SourceType = 'git' | 'archive'

export type RuntimeKind = 'native-php' | 'native-node' | 'native-java' | 'native-python'

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
