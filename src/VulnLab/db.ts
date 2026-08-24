import Database from 'better-sqlite3'
import { mkdirSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'
import { seedLabs, type SeedLab } from './seed.js'
import type { AppSettings, ImportJob, ImportManifest, Lab, LabInstance, LabStatus, Overview, SessionView, UserRole, VmDownload, VmDownloadStatus } from './types.js'

type Row = Record<string, unknown>

export interface PersistInstanceInput {
  id: string
  lab: Lab
  provider: string
  endpoint: string
  createdAt: string
  expiresAt: string
  logs: string[]
}

const now = () => new Date().toISOString()

const asString = (value: unknown, fallback = '') => typeof value === 'string' ? value : fallback

const providerForRuntime = (runtimeKind: Lab['runtimeKind']) => {
  if (runtimeKind === 'native-php') return 'native-php'
  if (runtimeKind === 'native-node') return 'native-node'
  if (runtimeKind === 'native-java') return 'native-java'
  if (runtimeKind === 'native-python') return 'native-python'
  if (runtimeKind === 'vm') return 'qemu-vm'
  return runtimeKind
}

const parseLab = (row: Row): Lab => ({
  id: asString(row.id),
  slug: asString(row.slug),
  title: asString(row.title),
  category: asString(row.category),
  difficulty: asString(row.difficulty) as Lab['difficulty'],
  sourceType: asString(row.source_type) as Lab['sourceType'],
  sourceUrl: asString(row.source_url),
  sourceRef: asString(row.source_ref),
  license: asString(row.license),
  runtimeKind: asString(row.runtime_kind) as Lab['runtimeKind'],
  providerId: asString(row.provider_id) || providerForRuntime(asString(row.runtime_kind) as Lab['runtimeKind']),
  builtin: Number(row.builtin ?? 0) === 1,
  version: asString(row.version, 'unversioned'),
  status: asString(row.status) as LabStatus,
  summary: asString(row.summary),
  tags: JSON.parse(asString(row.tags_json, '[]')) as string[],
  localPath: row.local_path ? asString(row.local_path) : null,
  importedAt: row.imported_at ? asString(row.imported_at) : null,
  createdAt: asString(row.created_at),
  updatedAt: asString(row.updated_at),
})

const parseManifest = (value: string): ImportManifest => {
  const parsed = JSON.parse(value) as Partial<ImportManifest>
  return { ...parsed, warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [] } as ImportManifest
}

const parseJob = (row: Row): ImportJob => ({
  id: asString(row.id),
  labId: asString(row.lab_id),
  sourceUrl: asString(row.source_url),
  requestedBy: asString(row.requested_by, 'system'),
  status: asString(row.status) as ImportJob['status'],
  stage: asString(row.stage),
  message: asString(row.message),
  progress: Number(row.progress ?? 0),
  error: row.error ? asString(row.error) : null,
  manifest: row.manifest_json ? parseManifest(asString(row.manifest_json)) : null,
  createdAt: asString(row.created_at),
  updatedAt: asString(row.updated_at),
})

const parseVmDownload = (row: Row): VmDownload => ({
  id: asString(row.id),
  labId: asString(row.lab_id),
  entryIndex: Number(row.entry_index ?? 0),
  title: asString(row.title),
  sourceUrl: asString(row.source_url),
  downloadUrl: asString(row.download_url),
  filename: asString(row.filename),
  status: asString(row.status) as VmDownloadStatus,
  message: asString(row.message),
  progress: Number(row.progress ?? 0),
  bytesDownloaded: Number(row.bytes_downloaded ?? 0),
  totalBytes: row.total_bytes === null || row.total_bytes === undefined ? null : Number(row.total_bytes),
  expectedMd5: row.expected_md5 ? asString(row.expected_md5) : null,
  expectedSha1: row.expected_sha1 ? asString(row.expected_sha1) : null,
  actualMd5: row.actual_md5 ? asString(row.actual_md5) : null,
  actualSha1: row.actual_sha1 ? asString(row.actual_sha1) : null,
  checksumVerified: Number(row.checksum_verified ?? 0) === 1,
  sha256: row.sha256 ? asString(row.sha256) : null,
  localPath: row.local_path ? asString(row.local_path) : null,
  error: row.error ? asString(row.error) : null,
  createdAt: asString(row.created_at),
  updatedAt: asString(row.updated_at),
})

const parseInstance = (row: Row): LabInstance => ({
  id: asString(row.id),
  labId: asString(row.lab_id),
  labTitle: asString(row.lab_title),
  provider: asString(row.provider),
  endpoint: asString(row.endpoint),
  status: asString(row.status) as LabInstance['status'],
  createdAt: asString(row.created_at),
  expiresAt: asString(row.expires_at),
  logs: JSON.parse(asString(row.logs_json, '[]')) as string[],
})

export class VulnLabDatabase {
  private readonly db: Database.Database
  private readonly runtimeDefaults: AppSettings

  constructor(dataDir: string, runtimeDefaults: Partial<AppSettings> = {}) {
    this.runtimeDefaults = {
      bindHost: '127.0.0.1',
      port: '6710',
      maxInstances: '8',
      dataDir: resolve(dataDir),
      autoCleanup: 'true',
      ...runtimeDefaults,
    }
    mkdirSync(dataDir, { recursive: true })
    this.db = new Database(join(dataDir, 'vulnlab.sqlite'))
    this.db.pragma('busy_timeout = 5000')
    this.db.pragma('journal_mode = WAL')
    this.db.pragma('foreign_keys = ON')
    this.migrate()
    this.recoverInterruptedJobs()
    this.recoverInterruptedVmDownloads()
    this.seed()
  }

  close() {
    this.db.close()
  }

  private migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS labs (
        id TEXT PRIMARY KEY,
        slug TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_url TEXT NOT NULL,
        source_ref TEXT NOT NULL,
        license TEXT NOT NULL,
        runtime_kind TEXT NOT NULL,
        provider_id TEXT NOT NULL DEFAULT '',
        builtin INTEGER NOT NULL DEFAULT 0,
        version TEXT NOT NULL DEFAULT 'unversioned',
        status TEXT NOT NULL,
        summary TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        local_path TEXT,
        imported_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS import_jobs (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        source_url TEXT NOT NULL,
        requested_by TEXT NOT NULL DEFAULT 'system',
        status TEXT NOT NULL,
        stage TEXT NOT NULL,
        message TEXT NOT NULL,
        progress INTEGER NOT NULL DEFAULT 0,
        error TEXT,
        manifest_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS vm_downloads (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        entry_index INTEGER NOT NULL,
        title TEXT NOT NULL,
        source_url TEXT NOT NULL,
        download_url TEXT NOT NULL,
        filename TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        progress INTEGER NOT NULL DEFAULT 0,
        bytes_downloaded INTEGER NOT NULL DEFAULT 0,
        total_bytes INTEGER,
        expected_md5 TEXT,
        expected_sha1 TEXT,
        actual_md5 TEXT,
        actual_sha1 TEXT,
        checksum_verified INTEGER NOT NULL DEFAULT 0,
        sha256 TEXT,
        local_path TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (lab_id, entry_index, download_url)
      );
      CREATE TABLE IF NOT EXISTS instances (
        id TEXT PRIMARY KEY,
        lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
        lab_title TEXT NOT NULL,
        provider TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        logs_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit (
        id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        detail TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_name TEXT NOT NULL,
        role TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS login_attempts (
        client_key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        reset_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_reset_at ON login_attempts(reset_at);
      CREATE INDEX IF NOT EXISTS idx_import_jobs_lab_status ON import_jobs(lab_id, status, created_at);
      CREATE INDEX IF NOT EXISTS idx_import_jobs_created_at ON import_jobs(created_at);
      CREATE INDEX IF NOT EXISTS idx_vm_downloads_lab_status ON vm_downloads(lab_id, status, updated_at);
      CREATE INDEX IF NOT EXISTS idx_vm_downloads_updated_at ON vm_downloads(updated_at);
      CREATE INDEX IF NOT EXISTS idx_instances_status_expires_at ON instances(status, expires_at);
      CREATE INDEX IF NOT EXISTS idx_instances_created_at ON instances(created_at);
      CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit(created_at);
    `)
    this.ensureColumn('import_jobs', 'requested_by', "TEXT NOT NULL DEFAULT 'system'")
    this.ensureColumn('import_jobs', 'manifest_json', 'TEXT')
    this.ensureColumn('labs', 'provider_id', "TEXT NOT NULL DEFAULT ''")
    this.ensureColumn('labs', 'builtin', 'INTEGER NOT NULL DEFAULT 0')
    this.ensureColumn('labs', 'version', "TEXT NOT NULL DEFAULT 'unversioned'")
    this.ensureColumn('vm_downloads', 'actual_md5', 'TEXT')
    this.ensureColumn('vm_downloads', 'actual_sha1', 'TEXT')
    this.ensureColumn('vm_downloads', 'checksum_verified', 'INTEGER NOT NULL DEFAULT 0')
  }

  private ensureColumn(table: string, column: string, definition: string) {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>
    if (!columns.some(item => item.name === column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
  }

  private recoverInterruptedJobs() {
    const timestamp = now()
    const interrupted = this.db.prepare("SELECT lab_id FROM import_jobs WHERE status = 'importing'").all() as Array<{ lab_id: string }>
    this.db.prepare("UPDATE import_jobs SET status = 'queued', stage = 'recovered', message = '服务重启后已重新排队。', progress = 0, updated_at = ? WHERE status = 'importing'").run(timestamp)
    const updateLab = this.db.prepare("UPDATE labs SET status = 'queued', updated_at = ? WHERE id = ? AND status = 'importing'")
    for (const job of interrupted) updateLab.run(timestamp, job.lab_id)
  }

  private recoverInterruptedVmDownloads() {
    this.db.prepare("UPDATE vm_downloads SET status = 'queued', message = '服务重启后已重新排队。', progress = 0, bytes_downloaded = 0, total_bytes = NULL, actual_md5 = NULL, actual_sha1 = NULL, checksum_verified = 0, error = NULL, updated_at = ? WHERE status = 'downloading'").run(now())
  }

  private seed() {
    const insert = this.db.prepare(`
      INSERT OR IGNORE INTO labs
        (id, slug, title, category, difficulty, source_type, source_url, source_ref, license, runtime_kind, provider_id, builtin, version, status, summary, tags_json, created_at, updated_at)
      VALUES (@id, @slug, @title, @category, @difficulty, @sourceType, @sourceUrl, @sourceRef, @license, @runtimeKind, @providerId, 1, @version, 'cataloged', @summary, @tagsJson, @createdAt, @updatedAt)
    `)
    const refreshSeed = this.db.prepare(`
      UPDATE labs SET title = @title, category = @category, difficulty = @difficulty,
        source_type = @sourceType, source_url = @sourceUrl, source_ref = @sourceRef,
        license = @license, runtime_kind = @runtimeKind, provider_id = @providerId,
        builtin = 1,
        status = CASE WHEN version <> @version THEN 'cataloged' ELSE status END,
        local_path = CASE WHEN version <> @version THEN NULL ELSE local_path END,
        imported_at = CASE WHEN version <> @version THEN NULL ELSE imported_at END,
        version = @version, summary = @summary, tags_json = @tagsJson,
        updated_at = @updatedAt
      WHERE slug = @slug
    `)
    const transaction = this.db.transaction((items: SeedLab[]) => {
      for (const item of items) {
        const timestamp = now()
        insert.run({
          id: randomUUID(),
          slug: item.slug,
          title: item.title,
          category: item.category,
          difficulty: item.difficulty,
          sourceType: item.sourceType,
          sourceUrl: item.sourceUrl,
          sourceRef: item.sourceRef,
          license: item.license,
          runtimeKind: item.runtimeKind,
          providerId: item.providerId,
          version: item.version,
          summary: item.summary,
          tagsJson: JSON.stringify(item.tags),
          createdAt: timestamp,
          updatedAt: timestamp,
        })
        refreshSeed.run({
          slug: item.slug,
          title: item.title,
          category: item.category,
          difficulty: item.difficulty,
          sourceType: item.sourceType,
          sourceUrl: item.sourceUrl,
          sourceRef: item.sourceRef,
          license: item.license,
          runtimeKind: item.runtimeKind,
          providerId: item.providerId,
          version: item.version,
          summary: item.summary,
          tagsJson: JSON.stringify(item.tags),
          updatedAt: timestamp,
        })
      }
      const activeSlugs = new Set(items.map(item => item.slug))
      for (const slug of ['vulhub', 'crapi']) {
        if (!activeSlugs.has(slug)) this.db.prepare("UPDATE labs SET status = 'disabled', updated_at = ? WHERE slug = ?").run(now(), slug)
      }
    })
    transaction(seedLabs)
  }

  listLabs(): Lab[] {
    const seedOrder = new Map(seedLabs.map((item, index) => [item.slug, index]))
    return this.db.prepare("SELECT * FROM labs WHERE builtin = 1 AND status != 'disabled'").all()
      .map(row => parseLab(row as Row))
      .sort((left, right) => {
        const leftOrder = seedOrder.get(left.slug) ?? Number.MAX_SAFE_INTEGER
        const rightOrder = seedOrder.get(right.slug) ?? Number.MAX_SAFE_INTEGER
        if (leftOrder !== rightOrder) return leftOrder - rightOrder
        return left.createdAt.localeCompare(right.createdAt) || left.title.localeCompare(right.title)
      })
  }

  getLab(id: string): Lab | null {
    const row = this.db.prepare('SELECT * FROM labs WHERE id = ?').get(id) as Row | undefined
    return row ? parseLab(row) : null
  }

  getLabBySlug(slug: string): Lab | null {
    const row = this.db.prepare('SELECT * FROM labs WHERE slug = ?').get(slug) as Row | undefined
    return row ? parseLab(row) : null
  }

  createLab(input: Omit<Lab, 'id' | 'createdAt' | 'updatedAt' | 'importedAt' | 'localPath' | 'status' | 'providerId' | 'builtin' | 'version'> & { status?: LabStatus; providerId?: string; builtin?: boolean; version?: string }): Lab {
    const timestamp = now()
    const id = randomUUID()
    this.db.prepare(`
      INSERT INTO labs
        (id, slug, title, category, difficulty, source_type, source_url, source_ref, license, runtime_kind, provider_id, builtin, version, status, summary, tags_json, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, input.slug, input.title, input.category, input.difficulty, input.sourceType, input.sourceUrl, input.sourceRef, input.license, input.runtimeKind, input.providerId ?? providerForRuntime(input.runtimeKind), input.builtin ? 1 : 0, input.version ?? 'custom', input.status ?? 'queued', input.summary, JSON.stringify(input.tags), timestamp, timestamp)
    return this.getLab(id) as Lab
  }

  updateLabStatus(id: string, status: LabStatus, localPath: string | null = null) {
    const importedAt = status === 'ready' ? now() : null
    this.db.prepare('UPDATE labs SET status = ?, local_path = COALESCE(?, local_path), imported_at = COALESCE(?, imported_at), updated_at = ? WHERE id = ?').run(status, localPath, importedAt, now(), id)
  }

  listJobs(): ImportJob[] {
    return this.db.prepare('SELECT * FROM import_jobs ORDER BY created_at DESC').all().map(row => parseJob(row as Row))
  }

  createJob(labId: string, sourceUrl: string, requestedBy = 'system'): ImportJob {
    const existing = this.db.prepare("SELECT * FROM import_jobs WHERE lab_id = ? AND status IN ('queued', 'importing') ORDER BY created_at DESC LIMIT 1").get(labId) as Row | undefined
    if (existing) return parseJob(existing)
    const timestamp = now()
    const id = randomUUID()
    this.db.prepare(`
      INSERT INTO import_jobs (id, lab_id, source_url, requested_by, status, stage, message, progress, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'queued', 'source', '来源已登记，等待对应适配器。', 0, ?, ?)
    `).run(id, labId, sourceUrl, requestedBy, timestamp, timestamp)
    this.updateLabStatus(labId, 'queued')
    return parseJob(this.db.prepare('SELECT * FROM import_jobs WHERE id = ?').get(id) as Row)
  }

  claimJob(id: string): ImportJob | null {
    const timestamp = now()
    const claim = this.db.transaction(() => {
      const result = this.db.prepare(`
        UPDATE import_jobs
        SET status = 'importing', stage = 'starting', message = '正在准备导入器。', progress = 1, error = NULL, updated_at = ?
        WHERE id = ? AND status = 'queued'
      `).run(timestamp, id)
      if (result.changes !== 1) return false
      const job = this.getJob(id)
      if (!job) return false
      this.db.prepare("UPDATE labs SET status = 'importing', updated_at = ? WHERE id = ?").run(timestamp, job.labId)
      return true
    })()
    return claim ? this.getJob(id) : null
  }

  getJob(id: string): ImportJob | null {
    const row = this.db.prepare('SELECT * FROM import_jobs WHERE id = ?').get(id) as Row | undefined
    return row ? parseJob(row) : null
  }

  updateJob(id: string, patch: { status?: ImportJob['status']; stage?: string; message?: string; progress?: number; error?: string | null; manifest?: ImportManifest | null }): ImportJob | null {
    const current = this.getJob(id)
    if (!current) return null
    this.db.prepare(`
      UPDATE import_jobs
      SET status = ?, stage = ?, message = ?, progress = ?, error = ?, manifest_json = ?, updated_at = ?
      WHERE id = ?
    `).run(
      patch.status ?? current.status,
      patch.stage ?? current.stage,
      patch.message ?? current.message,
      patch.progress ?? current.progress,
      patch.error === undefined ? current.error : patch.error,
      patch.manifest === undefined ? (current.manifest ? JSON.stringify(current.manifest) : null) : patch.manifest ? JSON.stringify(patch.manifest) : null,
      now(),
      id,
    )
    return this.getJob(id)
  }

  completeJob(id: string, manifest: ImportManifest): ImportJob | null {
    const job = this.getJob(id)
    if (!job) return null
    this.updateLabStatus(job.labId, 'ready', manifest.localPath)
    return this.updateJob(id, { status: 'completed', stage: 'completed', message: `已导入 ${manifest.fileCount} 个文件。`, progress: 100, error: null, manifest })
  }

  failJob(id: string, message: string): ImportJob | null {
    const job = this.getJob(id)
    if (!job) return null
    this.updateLabStatus(job.labId, 'error')
    return this.updateJob(id, { status: 'error', stage: 'failed', message, progress: 0, error: message })
  }

  listJobsParsed(): ImportJob[] {
    return this.db.prepare('SELECT * FROM import_jobs ORDER BY created_at DESC').all().map(row => parseJob(row as Row))
  }

  listVmDownloads(labId?: string): VmDownload[] {
    const rows = labId
      ? this.db.prepare('SELECT * FROM vm_downloads WHERE lab_id = ? ORDER BY updated_at DESC').all(labId)
      : this.db.prepare('SELECT * FROM vm_downloads ORDER BY updated_at DESC').all()
    return rows.map(row => parseVmDownload(row as Row))
  }

  getVmDownload(id: string): VmDownload | null {
    const row = this.db.prepare('SELECT * FROM vm_downloads WHERE id = ?').get(id) as Row | undefined
    return row ? parseVmDownload(row) : null
  }

  createVmDownload(input: Pick<VmDownload, 'labId' | 'entryIndex' | 'title' | 'sourceUrl' | 'downloadUrl' | 'filename' | 'expectedMd5' | 'expectedSha1'>): VmDownload {
    const existing = this.db.prepare('SELECT * FROM vm_downloads WHERE lab_id = ? AND entry_index = ? AND download_url = ?').get(input.labId, input.entryIndex, input.downloadUrl) as Row | undefined
    if (existing) {
      if (asString(existing.status) === 'error') {
        this.db.prepare("UPDATE vm_downloads SET status = 'queued', message = '已重新排队，等待下载。', progress = 0, bytes_downloaded = 0, total_bytes = NULL, actual_md5 = NULL, actual_sha1 = NULL, checksum_verified = 0, sha256 = NULL, local_path = NULL, error = NULL, updated_at = ? WHERE id = ?").run(now(), asString(existing.id))
      }
      return this.getVmDownload(asString(existing.id)) as VmDownload
    }
    const timestamp = now()
    const id = randomUUID()
    this.db.prepare(`
      INSERT INTO vm_downloads
        (id, lab_id, entry_index, title, source_url, download_url, filename, status, message, progress, bytes_downloaded, total_bytes, expected_md5, expected_sha1, actual_md5, actual_sha1, checksum_verified, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', '已登记，等待下载。', 0, 0, NULL, ?, ?, NULL, NULL, 0, ?, ?)
    `).run(id, input.labId, input.entryIndex, input.title, input.sourceUrl, input.downloadUrl, input.filename, input.expectedMd5, input.expectedSha1, timestamp, timestamp)
    return this.getVmDownload(id) as VmDownload
  }

  claimVmDownload(id: string): VmDownload | null {
    const claimed = this.db.prepare("UPDATE vm_downloads SET status = 'downloading', message = '正在准备下载。', progress = 0, bytes_downloaded = 0, total_bytes = NULL, actual_md5 = NULL, actual_sha1 = NULL, checksum_verified = 0, sha256 = NULL, local_path = NULL, error = NULL, updated_at = ? WHERE id = ? AND status = 'queued'").run(now(), id)
    return claimed.changes === 1 ? this.getVmDownload(id) : null
  }

  requeueVmDownload(id: string, message: string): VmDownload | null {
    const current = this.getVmDownload(id)
    if (!current) return null
    this.db.prepare("UPDATE vm_downloads SET status = 'queued', message = ?, progress = 0, bytes_downloaded = 0, total_bytes = NULL, actual_md5 = NULL, actual_sha1 = NULL, checksum_verified = 0, sha256 = NULL, local_path = NULL, error = NULL, updated_at = ? WHERE id = ?").run(message, now(), id)
    return this.getVmDownload(id)
  }

  updateVmDownload(id: string, patch: { message?: string; progress?: number; bytesDownloaded?: number; totalBytes?: number | null; sha256?: string | null; localPath?: string | null; error?: string | null }): VmDownload | null {
    const current = this.getVmDownload(id)
    if (!current) return null
    this.db.prepare(`
      UPDATE vm_downloads
      SET message = ?, progress = ?, bytes_downloaded = ?, total_bytes = ?, sha256 = ?, local_path = ?, error = ?, updated_at = ?
      WHERE id = ?
    `).run(
      patch.message ?? current.message,
      patch.progress ?? current.progress,
      patch.bytesDownloaded ?? current.bytesDownloaded,
      patch.totalBytes === undefined ? current.totalBytes : patch.totalBytes,
      patch.sha256 === undefined ? current.sha256 : patch.sha256,
      patch.localPath === undefined ? current.localPath : patch.localPath,
      patch.error === undefined ? current.error : patch.error,
      now(),
      id,
    )
    return this.getVmDownload(id)
  }

  completeVmDownload(id: string, input: { localPath: string; sha256: string; actualMd5: string; actualSha1: string; checksumVerified: boolean; bytesDownloaded: number; totalBytes: number | null; message: string }): VmDownload | null {
    const current = this.getVmDownload(id)
    if (!current) return null
    this.db.prepare(`
      UPDATE vm_downloads
      SET status = 'completed', message = ?, progress = 100, bytes_downloaded = ?, total_bytes = ?, actual_md5 = ?, actual_sha1 = ?, checksum_verified = ?, sha256 = ?, local_path = ?, error = NULL, updated_at = ?
      WHERE id = ?
    `).run(input.message, input.bytesDownloaded, input.totalBytes, input.actualMd5, input.actualSha1, input.checksumVerified ? 1 : 0, input.sha256, input.localPath, now(), id)
    return this.getVmDownload(id)
  }

  failVmDownload(id: string, message: string): VmDownload | null {
    const current = this.getVmDownload(id)
    if (!current) return null
    this.db.prepare("UPDATE vm_downloads SET status = 'error', message = ?, progress = 0, error = ?, updated_at = ? WHERE id = ?").run(message, message, now(), id)
    return this.getVmDownload(id)
  }

  createInstance(input: PersistInstanceInput, maxInstances = Number.MAX_SAFE_INTEGER): LabInstance | null {
    const insertedId = this.db.transaction(() => {
      const running = Number((this.db.prepare("SELECT COUNT(*) AS count FROM instances WHERE status = 'running'").get() as { count: number }).count)
      if (running >= maxInstances) return null
      this.db.prepare(`
        INSERT INTO instances (id, lab_id, lab_title, provider, endpoint, status, created_at, expires_at, logs_json)
        VALUES (?, ?, ?, ?, ?, 'running', ?, ?, ?)
      `).run(input.id, input.lab.id, input.lab.title, input.provider, input.endpoint, input.createdAt, input.expiresAt, JSON.stringify(input.logs))
      return input.id
    })()
    return insertedId ? this.getInstance(insertedId) : null
  }

  listInstances(): LabInstance[] {
    return this.db.prepare('SELECT * FROM instances ORDER BY created_at DESC').all().map(row => parseInstance(row as Row))
  }

  getInstance(id: string): LabInstance | null {
    const row = this.db.prepare('SELECT * FROM instances WHERE id = ?').get(id) as Row | undefined
    return row ? parseInstance(row) : null
  }

  getRunningInstance(id: string): LabInstance | null {
    const instance = this.getInstance(id)
    return instance?.status === 'running' && Date.parse(instance.expiresAt) > Date.now() ? instance : null
  }

  renewInstance(id: string, expiresAt: string, log: string): LabInstance | null {
    const updatedId = this.db.transaction(() => {
      const row = this.db.prepare('SELECT status, logs_json FROM instances WHERE id = ?').get(id) as Row | undefined
      if (!row || asString(row.status) !== 'running') return null
      const logs = JSON.parse(asString(row.logs_json, '[]')) as string[]
      logs.push(log)
      const result = this.db.prepare("UPDATE instances SET expires_at = ?, logs_json = ? WHERE id = ? AND status = 'running'").run(expiresAt, JSON.stringify(logs), id)
      return result.changes === 1 ? id : null
    })()
    return updatedId ? this.getInstance(updatedId) : null
  }

  destroyInstance(id: string, log: string): LabInstance | null {
    const updatedId = this.db.transaction(() => {
      const row = this.db.prepare('SELECT logs_json FROM instances WHERE id = ?').get(id) as Row | undefined
      if (!row) return null
      const logs = JSON.parse(asString(row.logs_json, '[]')) as string[]
      logs.push(log)
      this.db.prepare("UPDATE instances SET status = 'destroyed', logs_json = ? WHERE id = ?").run(JSON.stringify(logs), id)
      return id
    })()
    return updatedId ? this.getInstance(updatedId) : null
  }

  recoverRunningInstances(provider: string, log: string): number {
    const timestamp = now()
    const update = this.db.prepare("UPDATE instances SET status = 'destroyed', logs_json = ? WHERE id = ? AND provider = ? AND status = 'running'")
    const rows = this.db.prepare("SELECT id, logs_json FROM instances WHERE provider = ? AND status = 'running'").all(provider) as Array<{ id: string; logs_json: string }>
    if (!rows.length) return 0
    const transaction = this.db.transaction((items: Array<{ id: string; logs_json: string }>) => {
      for (const item of items) {
        const logs = JSON.parse(item.logs_json) as string[]
        logs.push(`${timestamp} ${log}`)
        update.run(JSON.stringify(logs), item.id, provider)
      }
    })
    transaction(rows)
    return rows.length
  }

  getSettings(): AppSettings {
    const defaults: AppSettings = { ...this.runtimeDefaults }
    const rows = this.db.prepare('SELECT key, value FROM settings').all() as Row[]
    for (const row of rows) {
      const key = asString(row.key) as keyof AppSettings
      if (key in defaults) defaults[key] = asString(row.value) as never
    }
    return defaults
  }

  createSession(id: string, userName: string, role: UserRole, csrfToken: string, expiresAt: number) {
    const timestamp = now()
    this.db.prepare(`
      INSERT INTO sessions (id, user_name, role, csrf_token, expires_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, userName, role, csrfToken, new Date(expiresAt).toISOString(), timestamp)
  }

  getSession(id: string): (SessionView & { expiresAt: number }) | null {
    const row = this.db.prepare('SELECT user_name AS userName, role, csrf_token AS csrfToken, expires_at AS expiresAt FROM sessions WHERE id = ?').get(id) as { userName: string; role: UserRole; csrfToken: string; expiresAt: string } | undefined
    if (!row) return null
    const expiresAt = Date.parse(row.expiresAt)
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      this.deleteSession(id)
      return null
    }
    return { userName: row.userName, role: row.role, csrfToken: row.csrfToken, expiresAt }
  }

  deleteSession(id: string) {
    this.db.prepare('DELETE FROM sessions WHERE id = ?').run(id)
  }

  cleanupSessions() {
    this.db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString())
  }

  consumeLoginAttempt(clientKey: string, limit: number, windowMs: number): { allowed: boolean; retryAfterSeconds: number } {
    const nowMs = Date.now()
    const timestamp = now()
    const resetAt = new Date(nowMs + windowMs).toISOString()
    const result = this.db.transaction(() => {
      this.db.prepare('DELETE FROM login_attempts WHERE reset_at <= ?').run(timestamp)
      const row = this.db.prepare('SELECT count, reset_at AS resetAt FROM login_attempts WHERE client_key = ?').get(clientKey) as { count: number; resetAt: string } | undefined
      if (!row) {
        this.db.prepare('INSERT INTO login_attempts (client_key, count, reset_at, updated_at) VALUES (?, 1, ?, ?)').run(clientKey, resetAt, timestamp)
        return { allowed: true, retryAfterSeconds: 0 }
      }
      if (row.count >= limit) {
        return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((Date.parse(row.resetAt) - nowMs) / 1000)) }
      }
      this.db.prepare('UPDATE login_attempts SET count = count + 1, updated_at = ? WHERE client_key = ?').run(timestamp, clientKey)
      return { allowed: true, retryAfterSeconds: 0 }
    })()
    return result
  }

  clearLoginAttempts(clientKey: string) {
    this.db.prepare('DELETE FROM login_attempts WHERE client_key = ?').run(clientKey)
  }

  listExpiredInstances(): LabInstance[] {
    if (this.getSettings().autoCleanup !== 'true') return []
    const expiry = new Date().toISOString()
    return this.db.prepare("SELECT * FROM instances WHERE status = 'running' AND expires_at <= ? ORDER BY expires_at ASC").all(expiry).map(row => parseInstance(row as Row))
  }

  expireInstance(id: string, log: string): LabInstance | null {
    const current = this.getInstance(id)
    if (!current || current.status !== 'running' || Date.parse(current.expiresAt) > Date.now()) return null
    const logs = [...current.logs, `${now()} ${log}`]
    const result = this.db.prepare("UPDATE instances SET status = 'expired', logs_json = ? WHERE id = ? AND status = 'running'").run(JSON.stringify(logs), id)
    return result.changes === 1 ? this.getInstance(id) : null
  }

  expireInstances(): LabInstance[] {
    return this.listExpiredInstances()
      .map(instance => this.expireInstance(instance.id, '运行实例已过期，自动标记为已过期'))
      .filter((instance): instance is LabInstance => Boolean(instance))
  }

  updateSettings(values: Partial<AppSettings>): AppSettings {
    const timestamp = now()
    const statement = this.db.prepare('INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at')
    const transaction = this.db.transaction((entries: [string, string][]) => entries.forEach(([key, value]) => statement.run(key, value, timestamp)))
    transaction(Object.entries(values).filter((entry): entry is [string, string] => typeof entry[1] === 'string'))
    return this.getSettings()
  }

  addAudit(actor: string, action: string, target: string, detail: string) {
    this.db.prepare('INSERT INTO audit (id, actor, action, target, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(randomUUID(), actor, action, target, detail, now())
  }

  listAudit() {
    return this.db.prepare('SELECT id, actor, action, target, detail, created_at AS createdAt FROM audit ORDER BY created_at DESC LIMIT 100').all()
  }

  overview(): Overview {
    const count = (sql: string) => Number((this.db.prepare(sql).get() as { count: number }).count)
    const settings = this.getSettings()
    return {
      labCount: count("SELECT COUNT(*) AS count FROM labs WHERE builtin = 1 AND status != 'disabled'"),
      readyCount: count("SELECT COUNT(*) AS count FROM labs WHERE builtin = 1 AND status = 'ready'"),
      queuedImportCount: count("SELECT COUNT(*) AS count FROM import_jobs WHERE status IN ('queued', 'importing')"),
      runningInstanceCount: count("SELECT COUNT(*) AS count FROM instances WHERE status = 'running'"),
      maxInstances: Number(settings.maxInstances),
      auditCount: count('SELECT COUNT(*) AS count FROM audit'),
    }
  }
}
