const consoleBanner = [
  '   ____ _                           _',
  '  / ___| |__   ___ _ __   __ ___  _(_) __ _  ___  _   _ _   _',
  " | |   | '_ \\ / _ \\ '_ \\ / _` \\ \\/ / |/ _` |/ _ \\| | | | | | |",
  ' | |___| | | |  __/ | | | (_| |>  <| | (_| | (_) | |_| | |_| |',
  '  \\____|_| |_|\\___|_| |_|\\__, /_/\\_\\_|\\__,_|\\___/ \\__, |\\__,_|',
  '                         |___/                    |___/',
].join('\n')

console.info(
  '%c何辰风的攻防控制台\n%c%s\n%c版本: 0.1.0\nGithub: https://github.com/Chengxiaoyu1119/CTF-VulnLab',
  'color:#ff8a3d;font-size:18px;font-weight:700;',
  'color:#ff8a3d;line-height:1.35;',
  consoleBanner,
  'color:#55a8ff;font-weight:500;',
)

const app = document.querySelector('#app')
let importPollTimer = null
let detailPollTimer = null
let systemPollTimer = null
let systemRequestVersion = 0
let systemRefreshReturnFocus = false
let modalReturnFocus = null
let confirmReturnFocus = null
let loginSuccessNoticeTimer = null
let toastTimer = null
let loginModeTransitionTimer = null

const LOGIN_NOTICE_DURATION = 4200
const DETAIL_POLL_INTERVAL = 5000
const REQUEST_TIMEOUT_MS = 15000
const START_REQUEST_TIMEOUT_MS = 150000
const START_WAIT_TIMEOUT_MS = 150000
const LAB_ARCHIVE_MAX_BYTES = 256 * 1024 * 1024
const OVERLAY_EXIT_DURATION = 190
const accountPattern = /^[A-Za-z0-9._-]{3,32}$/

const state = {
  session: null,
  csrfToken: '',
  labs: [],
  jobs: [],
  instances: [],
  oaModes: null,
  oaModesLoading: false,
  oaModesError: '',
  oaMode: 'local',
  oaModeMenuOpen: false,
  loading: true,
  busy: false,
  busyActions: [],
  busyAction: null,
  error: '',
  loginErrorFields: [],
  loginFieldErrors: {},
  authMode: 'login',
  authNotice: '',
  loginUserName: '',
  loginPasswordVisible: false,
  registerPasswordVisible: false,
  registerConfirmPasswordVisible: false,
  successNotice: null,
  toast: null,
  confirm: null,
  labDetailId: null,
  adminPanelOpen: false,
  adminView: 'profile',
  adminLabEditorOpen: false,
  adminLabEditId: null,
  adminLabInspection: null,
  adminLabInspectionLoading: false,
  adminLabInspectionError: '',
  adminLabDraft: {
    title: '', sourceType: 'git', sourceUrl: '', sourceUploadUrl: '', sourceRef: '', archiveFileName: '', runtimeMode: 'php-static', runtimeKind: 'native-php', runtimeProfile: 'static-php',
    documentRoot: '', entryPath: '', initSqlPath: '', nodeArgs: '', javaArgs: '', pythonArgs: '', portArg: '', settingsPath: '',
    category: 'Web', difficulty: '入门', license: '', summary: '', tags: '',
  },
  adminLabArchiveFile: null,
  adminRecordsPanel: null,
  adminRecordsReturnFocus: null,
  adminSelectedRecordIds: { invitations: [], audit: [], users: [] },
  adminNextCursors: { invitations: null, audit: null, users: null },
  adminTotals: { invitations: 0, audit: 0, users: 0 },
  adminRecordRequestVersions: { invitations: 0, audit: 0, users: 0 },
  adminAuditDate: '',
  adminAuditAction: '',
  adminAuditExpandedId: null,
  adminAuditReturnToSystem: null,
  invitation: null,
  invitationCodes: new Map(),
  invitations: [],
  audit: [],
  users: [],
  adminLoading: false,
  adminError: '',
  adminOverview: null,
  adminSystemLoading: false,
  adminSystemError: '',
  adminActivityDate: '',
  adminSystemReturnLabId: null,
  adminSystemScrollTop: 0,
}

const esc = value => String(value ?? '').replace(/[&<>'"]/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
}[character]))

const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const leaseDisplay = value => {
  const parsed = value ? new Date(value) : null
  if (!parsed || Number.isNaN(parsed.getTime())) return { remaining: '剩余时间未知', expires: '到期时间未知' }
  const remainingMs = parsed.getTime() - Date.now()
  const remaining = remainingMs <= 0 ? '即将到期' : remainingMs < 60_000 ? '不足 1 分钟' : `剩余 ${Math.ceil(remainingMs / 60_000)} 分钟`
  const pad = part => String(part).padStart(2, '0')
  const expires = `到期 ${parsed.getFullYear()}/${pad(parsed.getMonth() + 1)}/${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`
  return { remaining, expires }
}
const auditTimestamp = value => {
  const parsed = value ? new Date(value) : null
  if (!parsed || Number.isNaN(parsed.getTime())) return { date: '—', time: '' }
  const pad = part => String(part).padStart(2, '0')
  return {
    date: `${parsed.getFullYear()}/${pad(parsed.getMonth() + 1)}/${pad(parsed.getDate())}`,
    time: `${pad(parsed.getHours())}:${pad(parsed.getMinutes())}:${pad(parsed.getSeconds())}`,
  }
}
const busyFor = (action, id = '') => state.busyActions.some(item => item.action === action && (!id || item.id === id))

class ApiError extends Error {
  constructor(message, status, code = '') {
    super(message)
    this.status = status
    this.code = code
  }
}

const authErrorMessage = error => error?.status === 0 ? '网络连接失败，请检查网络后重试' : error.message

async function request(path, options = {}) {
  const { recordPage = false, timeout = REQUEST_TIMEOUT_MS, ...fetchOptions } = options
  const method = (fetchOptions.method ?? 'GET').toUpperCase()
  const headers = { ...(fetchOptions.body ? { 'Content-Type': 'application/json' } : {}), ...(fetchOptions.headers ?? {}) }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !path.endsWith('/auth/login') && state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), timeout)
  let response
  try {
    response = await fetch(path, { ...fetchOptions, credentials: 'same-origin', headers, signal: controller.signal })
    const payload = await response.json().catch(error => {
      if (controller.signal.aborted) throw error
      return {}
    })
    if (!response.ok) throw new ApiError(payload.message ?? `请求失败（${response.status}）`, response.status, payload.code ?? '')
    if (!recordPage) return payload
    const total = Number(response.headers.get('X-VulnLab-Record-Total'))
    return {
      items: Array.isArray(payload) ? payload : [],
      total: Number.isSafeInteger(total) && total >= 0 ? total : Array.isArray(payload) ? payload.length : 0,
      nextCursor: response.headers.get('X-VulnLab-Next-Cursor'),
    }
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error?.name === 'AbortError') throw new ApiError('请求超时，请稍后重试。', 504, 'REQUEST_TIMEOUT')
    throw new ApiError('本地服务连接失败，请确认 VulnLab 服务正在运行。', 0)
  } finally {
    window.clearTimeout(timeoutId)
  }
}

async function uploadLabArchive(file) {
  const controller = new AbortController()
  const timeoutId = window.setTimeout(() => controller.abort(), START_REQUEST_TIMEOUT_MS)
  const fileName = String(file?.name ?? '').replace(/[^\x20-\x7e]/g, '_')
  const headers = {
    'Content-Type': 'application/octet-stream',
    ...(state.csrfToken ? { 'X-CSRF-Token': state.csrfToken } : {}),
    ...(fileName ? { 'X-VulnLab-File-Name': fileName } : {}),
  }
  try {
    const response = await fetch('/api/lab-archives', {
      method: 'POST',
      credentials: 'same-origin',
      headers,
      body: file,
      signal: controller.signal,
    })
    const payload = await response.json().catch(() => ({}))
    if (!response.ok) throw new ApiError(payload.message ?? `请求失败（${response.status}）`, response.status, payload.code ?? '')
    if (!payload || typeof payload.token !== 'string' || typeof payload.sourceUrl !== 'string') {
      throw new ApiError('压缩包上传响应无效。', 502, 'LAB_ARCHIVE_RESPONSE_INVALID')
    }
    return payload
  } catch (error) {
    if (error instanceof ApiError) throw error
    if (error?.name === 'AbortError') throw new ApiError('压缩包上传超时，请稍后重试。', 504, 'REQUEST_TIMEOUT')
    throw new ApiError('本地服务连接失败，请确认 VulnLab 服务正在运行。', 0)
  } finally {
    window.clearTimeout(timeoutId)
  }
}

const adminRecordPath = panel => panel === 'invitations' ? '/api/auth/invitations' : panel === 'users' ? '/api/auth/users' : '/api/audit'
const adminRecordId = (panel, item) => panel === 'users' ? item.userName : item.id
const isAdminRecordSelectable = (panel, item) => !(panel === 'users' && item.kind === 'system') && !(panel === 'invitations' && item.status === 'used')
const invitationCodeStorageKey = () => state.session?.userName ? `vulnlab:invitation-codes:${state.session.userName.toLowerCase()}` : ''

function persistInvitationCodes() {
  const key = invitationCodeStorageKey()
  if (!key) return
  const entries = [...state.invitationCodes].filter(([, item]) => item.expiresAt > Date.now())
  try { sessionStorage.setItem(key, JSON.stringify(entries)) } catch {}
}

function restoreInvitationCodes() {
  state.invitationCodes = new Map()
  const key = invitationCodeStorageKey()
  if (!key) return
  try {
    const entries = JSON.parse(sessionStorage.getItem(key) ?? '[]')
    if (!Array.isArray(entries)) return
    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length !== 2) continue
      const [id, item] = entry
      if (typeof id === 'string' && item && typeof item.code === 'string' && item.code.length <= 128 && Number.isFinite(item.expiresAt) && item.expiresAt > Date.now()) {
        state.invitationCodes.set(id, item)
      }
    }
    const latest = [...state.invitationCodes].at(-1)
    if (latest) state.invitation = { id: latest[0], code: latest[1].code, expiresAt: new Date(latest[1].expiresAt).toISOString() }
    persistInvitationCodes()
  } catch {}
}

function saveInvitationCode(invitation) {
  state.invitationCodes.set(invitation.id, { code: invitation.code, expiresAt: Date.parse(invitation.expiresAt) })
  persistInvitationCodes()
}

function forgetInvitationCode(id) {
  state.invitationCodes.delete(id)
  persistInvitationCodes()
}

function getInvitationCode(id) {
  const item = state.invitationCodes.get(id)
  if (item && item.expiresAt > Date.now()) return item.code
  if (item) forgetInvitationCode(id)
  return ''
}

function clearInvitationCodes() {
  const key = invitationCodeStorageKey()
  state.invitationCodes.clear()
  if (key) {
    try { sessionStorage.removeItem(key) } catch {}
  }
}

function resetAdminRecords() {
  systemRequestVersion += 1
  clearSystemPolling()
  state.adminSelectedRecordIds = { invitations: [], audit: [], users: [] }
  state.adminNextCursors = { invitations: null, audit: null, users: null }
  state.adminTotals = { invitations: 0, audit: 0, users: 0 }
  state.adminRecordRequestVersions = { invitations: 0, audit: 0, users: 0 }
  state.adminAuditDate = ''
  state.adminAuditAction = ''
  state.adminAuditExpandedId = null
  state.adminAuditReturnToSystem = null
  state.invitations = []
  state.audit = []
  state.users = []
  state.adminOverview = null
  state.adminSystemLoading = false
  state.adminSystemError = ''
  state.adminActivityDate = ''
  state.adminSystemReturnLabId = null
  state.adminSystemScrollTop = 0
}

function resetAdminLabDraft() {
  state.adminLabDraft = {
    title: '', sourceType: 'git', sourceUrl: '', sourceUploadUrl: '', sourceRef: '', archiveFileName: '', runtimeMode: 'php-static', runtimeKind: 'native-php', runtimeProfile: 'static-php',
    documentRoot: '', entryPath: '', initSqlPath: '', nodeArgs: '', javaArgs: '', pythonArgs: '', portArg: '', settingsPath: '',
    category: 'Web', difficulty: '入门', license: '', summary: '', tags: '',
  }
  state.adminLabEditorOpen = false
  state.adminLabEditId = null
  state.adminLabInspection = null
  state.adminLabInspectionLoading = false
  state.adminLabInspectionError = ''
  state.adminLabArchiveFile = null
}

function focusAdminLabTitle() {
  window.queueMicrotask(() => {
    const content = app.querySelector('.admin-dialog-content')
    if (content) content.scrollTop = 0
    app.querySelector('#admin-lab-form [name="title"]')?.focus({ preventScroll: true })
  })
}

async function loadAdminRecords(panel, append = false) {
  const cursor = append ? state.adminNextCursors[panel] : null
  const requestVersion = ++state.adminRecordRequestVersions[panel]
  const params = new URLSearchParams()
  if (cursor) params.set('cursor', cursor)
  if (panel === 'audit') {
    if (state.adminAuditDate) params.set('date', state.adminAuditDate)
    if (state.adminAuditAction) params.set('action', state.adminAuditAction)
  }
  const query = params.toString()
  const page = await request(`${adminRecordPath(panel)}${query ? `?${query}` : ''}`, { cache: 'no-store', recordPage: true })
  if (requestVersion !== state.adminRecordRequestVersions[panel]) return false
  const items = Array.isArray(page?.items) ? page.items : []
  state[panel] = append ? [...state[panel], ...items] : items
  state.adminNextCursors[panel] = typeof page?.nextCursor === 'string' ? page.nextCursor : null
  const total = Number(page?.total)
  state.adminTotals[panel] = Number.isSafeInteger(total) && total >= state[panel].length ? total : state[panel].length
  state.adminSelectedRecordIds[panel] = state.adminSelectedRecordIds[panel].filter(id => state[panel].some(item => isAdminRecordSelectable(panel, item) && adminRecordId(panel, item) === id))
  return true
}

async function refreshAdminAudit() {
  const requestVersion = state.adminRecordRequestVersions.audit + 1
  try {
    await loadAdminRecords('audit')
    if (requestVersion === state.adminRecordRequestVersions.audit) state.adminError = ''
  } catch (error) {
    if (requestVersion === state.adminRecordRequestVersions.audit) state.adminError = error.message
  } finally {
    if (requestVersion === state.adminRecordRequestVersions.audit) {
      state.adminLoading = false
      render()
    }
  }
}

async function setAuditFilters(dateValue, actionValue) {
  state.adminAuditDate = dateValue
  state.adminAuditAction = actionValue
  state.adminAuditExpandedId = null
  state.adminSelectedRecordIds.audit = []
  state.adminNextCursors.audit = null
  state.adminTotals.audit = 0
  state.audit = []
  state.adminError = ''
  state.adminLoading = true
  render()
  await refreshAdminAudit()
}

function setSystemRefreshLoading(loading, preserveFocus = false) {
  const button = document.querySelector('.admin-system-refresh')
  const view = document.querySelector('.admin-system-view')
  if (loading) systemRefreshReturnFocus = Boolean(button && (preserveFocus || document.activeElement === button))
  view?.setAttribute('aria-busy', String(loading))
  if (button) {
    button.disabled = loading
    button.classList.toggle('is-loading', loading)
    button.setAttribute('aria-busy', String(loading))
  }
  if (!loading && systemRefreshReturnFocus) {
    button?.focus({ preventScroll: true })
    systemRefreshReturnFocus = false
  }
}

function adminPanelKey() {
  const adminRecordsKey = ['invitations', 'audit', 'users'].map(panel => `${state[panel].length}:${state.adminTotals[panel]}:${state.adminNextCursors[panel] ?? ''}`).join(':')
  const activity = state.adminOverview?.activity
  const adminOverviewKey = activity ? `${activity.rangeEnd}:${activity.launchCount}:${activity.activeDays}:${state.adminOverview.runningInstanceCount}` : ''
  return state.adminPanelOpen ? `${state.adminView}:${state.invitation?.id ?? 'open'}:${state.adminLoading}:${adminRecordsKey}:${adminOverviewKey}:${state.adminError}:${state.adminSystemError}` : ''
}

function patchAdminSystemView() {
  if (!state.adminPanelOpen || state.adminView !== 'system') return false
  const slot = app.querySelector('[data-overlay-slot="admin"]')
  const current = slot?.querySelector('.admin-system-view')
  if (!slot || !current) return false

  const scrollContainer = current.closest('.admin-dialog-content')
  const scrollTop = scrollContainer?.scrollTop ?? 0
  const active = current.contains(document.activeElement) ? {
    action: document.activeElement.dataset.action ?? '',
    id: document.activeElement.dataset.id ?? '',
    activityDate: document.activeElement.dataset.activityDate ?? '',
  } : null
  const template = document.createElement('template')
  template.innerHTML = adminSystemPanel()
  const next = template.content.firstElementChild
  if (!next) return false
  next.style.setProperty('animation', 'none')
  current.replaceWith(next)
  if (scrollContainer) scrollContainer.scrollTop = scrollTop
  if (active) {
    const target = [...next.querySelectorAll('button')].find(button => button.dataset.action === active.action
      && (button.dataset.id ?? '') === active.id
      && (button.dataset.activityDate ?? '') === active.activityDate)
    target?.focus({ preventScroll: true })
  }

  slot.__vulnlabKey = adminPanelKey()
  slot.__vulnlabContent = adminPanel()
  return true
}

async function refreshAdminOverview({ showLoading = true, trigger = null } = {}) {
  if (state.adminSystemLoading || !state.session || !state.adminPanelOpen || state.adminView !== 'system') return
  const version = systemRequestVersion
  state.adminSystemLoading = true
  state.adminSystemError = ''
  if (showLoading) {
    if (state.adminOverview) setSystemRefreshLoading(true, trigger?.classList?.contains('admin-system-refresh'))
    else if (!patchAdminSystemView()) render()
  }
  try {
    const overview = await request('/api/overview', { cache: 'no-store' })
    if (!overview?.activity || overview.activity.daily?.length !== 365) throw new ApiError('系统数据暂时不可用，请重试。', 502)
    if (version === systemRequestVersion) state.adminOverview = overview
  } catch (error) {
    if (version === systemRequestVersion) state.adminSystemError = error.message
  } finally {
    if (version === systemRequestVersion) {
      state.adminSystemLoading = false
      setSystemRefreshLoading(false)
      if (!patchAdminSystemView() && state.adminPanelOpen && state.adminView === 'system') render()
    }
  }
}

async function refresh() {
  const [labs, jobs, instances] = await Promise.all([
    request('/api/labs'), request('/api/import-jobs'), request('/api/instances'),
  ])
  state.labs = labs
  state.jobs = jobs
  state.instances = instances
  state.error = ''
  if (state.adminPanelOpen && state.adminView === 'system') await refreshAdminOverview({ showLoading: false })
}

async function loadOaRuntimeModes(labId) {
  if (state.oaModesLoading) return
  state.oaModesLoading = true
  state.oaModesError = ''
  render()
  try {
    const status = await request('/api/runtime-status', { cache: 'no-store' })
    if (state.labDetailId === labId) state.oaModes = status.oaModes ?? null
  } catch (error) {
    if (state.labDetailId === labId) state.oaModesError = error.message
  } finally {
    state.oaModesLoading = false
    if (state.labDetailId === labId) render()
  }
}

async function bootstrap() {
  try {
    state.session = await request('/api/auth/session')
    state.csrfToken = state.session?.csrfToken ?? ''
    if (state.session) restoreInvitationCodes()
    if (state.session) await refresh()
  } catch (error) {
    state.error = error.message
  } finally {
    state.loading = false
    render()
  }
}

function navigate() {
  state.labDetailId = null
  if (location.hash !== '#labs') location.hash = 'labs'
}

function setToast(message, type = 'success') {
  if (toastTimer) { window.clearTimeout(toastTimer); toastTimer = null }
  state.toast = { message: readableError(message), type }
  render()
  toastTimer = window.setTimeout(() => {
    toastTimer = null
    state.toast = null
    render()
  }, 3600)
}

function clearLoginSuccessNoticeTimer() {
  if (loginSuccessNoticeTimer) { window.clearTimeout(loginSuccessNoticeTimer); loginSuccessNoticeTimer = null }
}

function clearDetailPolling() {
  if (detailPollTimer) { window.clearTimeout(detailPollTimer); detailPollTimer = null }
}

function clearSystemPolling() {
  if (systemPollTimer) window.clearTimeout(systemPollTimer)
  systemPollTimer = null
}

function scheduleSystemPolling() {
  if (!state.session || !state.adminPanelOpen || state.adminView !== 'system' || document.hidden) { clearSystemPolling(); return }
  if (systemPollTimer || state.adminSystemLoading) return
  systemPollTimer = window.setTimeout(() => {
    systemPollTimer = null
    void refreshAdminOverview({ showLoading: false })
  }, 15000)
}

function selectActivityDate(value, restoreFocus = false) {
  const item = state.adminOverview?.activity?.daily.find(item => item.date === value)
  if (!item) return
  state.adminActivityDate = value
  const cells = [...document.querySelectorAll('[data-activity-date]')]
  cells.forEach(cell => { cell.tabIndex = cell.dataset.activityDate === value ? 0 : -1 })
  const output = document.querySelector('.admin-activity-selection')
  if (output) output.textContent = `${item.date} · ${item.count} 次启动`
  if (restoreFocus) cells.find(cell => cell.dataset.activityDate === value)?.focus({ preventScroll: true })
}

function returnToSystemData() {
  const saved = state.adminAuditReturnToSystem
  state.adminAuditReturnToSystem = null
  state.adminRecordsPanel = null
  state.adminView = 'system'
  state.adminLoading = false
  state.adminError = ''
  render()
  window.queueMicrotask(() => {
    const content = document.querySelector('.admin-dialog-content')
    if (content) content.scrollTop = saved?.scrollTop ?? 0
    if (!saved?.date) return
    selectActivityDate(saved.date)
    const cell = [...document.querySelectorAll('[data-activity-date]')].find(item => item.dataset.activityDate === saved.date)
    cell?.focus({ preventScroll: true })
  })
}

function beginBusy(action, id = '') {
  if (state.busyActions.some(item => item.action === action && item.id === id)) return false
  state.busyActions.push({ action, id })
  state.busy = true
  state.busyAction = { action, id }
  render()
  return true
}

function endBusy(action, id = '') {
  const index = state.busyActions.findIndex(item => item.action === action && item.id === id)
  if (index >= 0) state.busyActions.splice(index, 1)
  state.busy = state.busyActions.length > 0
  state.busyAction = state.busyActions.at(-1) ?? null
}

function scheduleLoginSuccessNoticeDismiss() {
  if (!state.successNotice || !state.session) { clearLoginSuccessNoticeTimer(); return }
  if (loginSuccessNoticeTimer) return
  loginSuccessNoticeTimer = window.setTimeout(() => {
    loginSuccessNoticeTimer = null
    if (state.successNotice) {
      state.successNotice = null
      render()
    }
  }, LOGIN_NOTICE_DURATION)
}

function loginNoticeCard({ id, title, message, action, kind = 'error' }) {
  const isSuccess = kind === 'success'
  return `<div class="login-notice${isSuccess ? ' login-notice-success' : ''}" id="${esc(id)}" role="${isSuccess ? 'status' : 'alert'}" aria-live="polite"><span class="login-notice-copy"><strong>${esc(title)}</strong><span>${esc(message)}</span></span><button class="login-notice-close" type="button" data-action="${esc(action)}" aria-label="关闭提示">×</button></div>`
}

function deleteRecordIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 7h14m-9 4v6m4-6v6M9 7V5h6v2m-9 0 1 13h8l1-13"></path></svg>'
}

function recordArrowIcon() {
  return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 5 7 7-7 7"></path></svg>'
}

function labsShell() {
  const centerLabel = state.session?.role === 'admin' ? '管理中心' : '个人中心'
  return `<div class="labs-screen">
    <section class="lab-workspace">
      <div class="workspace-brand">
        <img class="workspace-brand-mark" src="/favicon.png" alt="" />
        <h1 class="workspace-brand-name" aria-label="VulnLab"><button class="workspace-brand-trigger" type="button" data-action="open-admin-panel" aria-label="${centerLabel}" title="打开${centerLabel}">VulnLab</button></h1>
        <p class="workspace-brand-subtitle">攻防控制台</p>
      </div>
      <main class="lab-canvas" tabindex="-1"></main>
    </section>
    <div data-overlay-slot="success"></div>
    <div data-overlay-slot="toast"></div>
    <div data-overlay-slot="admin"></div>
    <div data-overlay-slot="records"></div>
    <div data-overlay-slot="detail"></div>
    <div data-overlay-slot="confirm"></div>
  </div>`
}

const coverAssets = Object.freeze({
  'oa-vuln-labs': '/covers/oa-vuln-labs.svg',
  dvwa: '/covers/dvwa.png',
  pikachu: '/covers/pikachu.png',
  'xss-labs': '/covers/xss-labs.svg',
  'sqli-labs': '/covers/sqli-labs.jpg',
  'upload-labs': '/covers/upload-labs.jpg',
  xvwa: '/covers/xvwa.png',
  'juice-shop': '/covers/juice-shop.png',
  webgoat: '/covers/webgoat.png',
  mutillidae: '/covers/mutillidae.svg',
  pygoat: '/covers/pygoat.svg',
})
const coverVariant = lab => Object.hasOwn(coverAssets, lab.slug) ? lab.slug : 'default'
const coverArt = (lab, imageClass = 'lab-card-cover', lazy = false) => coverAssets[lab.slug]
  ? `<img class="${esc(imageClass)}" data-cover-image="true" src="${coverAssets[lab.slug]}" alt="${esc(lab.title)} 封面"${lazy ? ' loading="lazy"' : ''} decoding="async" />`
  : `<span class="${esc(imageClass)} lab-card-cover-fallback" aria-hidden="true">${esc(Array.from(String(lab.title ?? '靶').trim())[0] ?? '靶')}</span>`
const jobStageLabel = stage => ({
  queued: '排队等待',
  starting: '准备启动',
  downloading: '下载资源',
  extracting: '解压资源',
  verifying: '校验资源',
  reconcile: '整理资源',
  completed: '准备完成',
  failed: '准备失败',
}[String(stage ?? '')] ?? (String(stage ?? '').trim() || '准备资源'))
const jobProgress = job => Math.max(0, Math.min(100, Number(job?.progress ?? 0) || 0))
const readableError = value => String(value ?? '')
  .replace(/[A-Za-z]:[\\/][^\s"'<>]*/g, '本地资源路径')
  .replace(/\/(?:Users|home|tmp|var|opt|workspace)\/[^\s"'<>]*/g, '本地资源路径')

function labCardView(lab) {
  const ready = lab.status === 'ready'
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const starting = busyFor('start-instance', lab.id)
  const cardState = instance ? 'running' : starting ? 'starting' : importing ? 'preparing' : queued ? 'preparing' : failed ? 'error' : ready ? 'ready' : 'idle'
  const statusLabel = instance ? '运行中' : starting ? '启动中' : importing || queued ? '准备中' : failed ? '准备失败' : ready ? '已就绪' : '待启动'
  return { cardState, statusLabel, busy: starting || importing || queued }
}

function labCard(lab, index) {
  const view = labCardView(lab)
  return `<article class="lab-card" data-state="${view.cardState}" data-runtime="${esc(lab.runtimeKind ?? '')}" aria-label="${esc(lab.title)}，${view.statusLabel}"${view.busy ? ' aria-busy="true"' : ''}>
    <button class="lab-card-media" type="button" data-action="open-lab-details" data-id="${esc(lab.id)}" data-cover="${coverVariant(lab)}" aria-label="查看 ${esc(lab.title)} 信息">${coverArt(lab, 'lab-card-cover', index >= 3)}<span class="lab-card-caption" title="${esc(lab.title)}"><span class="lab-card-title">${esc(lab.title)}</span></span></button>
  </article>`
}

function labDetailModal() {
  const lab = state.labs.find(item => item.id === state.labDetailId)
  if (!lab) return ''
  const admin = state.session.role === 'admin'
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const cataloged = lab.status === 'cataloged'
  const activeJob = state.jobs
    .filter(job => job.labId === lab.id && ['queued', 'importing'].includes(job.status))
    .sort((left, right) => String(right.updatedAt ?? '').localeCompare(String(left.updatedAt ?? '')))[0] ?? null
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const starting = busyFor('start-instance', lab.id)
  const preparing = importing || queued
  let primaryAction = ''
  if (instance) {
    primaryAction = `<a class="button button-primary lab-detail-action lab-detail-open" href="${esc(instance.endpoint)}" target="_blank" rel="noreferrer" data-action="open-instance-page">打开页面</a>`
  } else if (starting) {
    primaryAction = '<span class="button button-quiet lab-detail-action" aria-busy="true">启动中…</span>'
  } else if (preparing) {
    primaryAction = '<span class="button button-quiet lab-detail-action" aria-busy="true">准备中…</span>'
  } else if (admin) {
    const oaStart = lab.runtimeKind === 'native-oa'
    primaryAction = `<button class="button ${failed ? 'button-danger' : 'button-primary'} lab-detail-action${oaStart ? ' oa-start-trigger' : ''}" type="button" data-action="${oaStart ? 'toggle-oa-start-menu' : 'start-instance'}" data-id="${esc(lab.id)}"${oaStart ? ` aria-haspopup="true" aria-expanded="${state.oaModeMenuOpen}" aria-controls="oa-mode-menu"` : ''}>${failed ? '重试启动' : '启动环境'}</button>`
  } else {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待准备</span>'
  }
  const detailState = instance ? 'running' : starting ? 'starting' : preparing ? 'preparing' : failed ? 'error' : cataloged ? 'cataloged' : 'ready'
  const oaModeMenu = lab.runtimeKind === 'native-oa' && state.oaModeMenuOpen && !instance && admin && !preparing && !starting
    ? (() => {
      const local = state.oaModes?.local
      const docker = state.oaModes?.docker
      const localStatus = state.oaModesLoading ? '检测中' : local?.available ? '可用' : '需准备'
      const localDetail = state.oaModesLoading ? '检测 Node.js、MariaDB…'
        : local?.available ? 'Node.js、MariaDB · exec 模拟'
          : `${state.oaModesError || `需准备：${(local?.missing ?? []).join('、') || 'Node.js、MariaDB'}`} · exec 模拟`
      const dockerDetail = state.oaModesLoading ? '检测 Docker、Compose、Engine…'
        : state.oaModesError || docker?.detail || '打开靶场详情后检测运行依赖。'
      return `<div class="oa-mode-menu" id="oa-mode-menu" role="group" aria-label="选择 OA 启动模式"><button class="oa-mode-option" type="button" data-action="start-instance" data-id="${esc(lab.id)}" data-mode="local" title="${esc(localDetail)}"><span class="oa-mode-option-heading"><strong>本地安全模式</strong><span class="oa-mode-status${local?.available ? ' is-ready' : ' is-pending'}">${esc(localStatus)}</span></span></button><button class="oa-mode-option" type="button" data-action="start-instance" data-id="${esc(lab.id)}" data-mode="docker" title="${esc(dockerDetail)} 真实命令仅在靶场容器内执行"><span class="oa-mode-option-heading"><strong>Docker 原版模式</strong><span class="oa-mode-status${docker?.available ? ' is-ready' : ' is-unavailable'}">${esc(state.oaModesLoading ? '检测中' : docker?.available ? '可用' : '不可用')}</span></span></button><p class="oa-mode-note">本地非沙盒，exec 模拟；Docker 命令限容器。</p></div>`
    })()
    : ''
  const stateLabel = preparing ? '准备中' : ''
  const facts = [lab.category, lab.difficulty].filter(Boolean).map(esc).join('<span aria-hidden="true">·</span>')
  const sourceInfo = lab.slug === 'xss-labs'
    ? `<details class="lab-detail-notes"><summary>版本与兼容性</summary><p>版本 ${esc(lab.version)} · 许可证${esc(lab.license || '未声明')}</p><p>第 14 关使用本地空白占位；第 17–20 关依赖 Flash，现代浏览器不支持。</p><a href="${esc(lab.sourceUrl)}" target="_blank" rel="noreferrer">上游仓库</a></details>`
    : ''
  const tags = Array.isArray(lab.tags) && lab.tags.length ? `<div class="lab-detail-tags">${lab.tags.slice(0, 4).map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''
  const preparationInfo = preparing ? `<div class="lab-detail-progress" role="status" aria-live="polite"><div class="lab-detail-progress-head"><span>${esc(jobStageLabel(activeJob?.stage))}</span><strong>${jobProgress(activeJob)}%</strong></div><div class="lab-detail-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${jobProgress(activeJob)}"><span class="lab-detail-progress-fill" style="--progress:${jobProgress(activeJob)}%"></span></div><p class="lab-detail-progress-message">${esc(activeJob?.message ?? '正在准备靶场资源，请稍候。')}</p></div>` : ''
  const runningInfo = instance
    ? (() => { const lease = leaseDisplay(instance.expiresAt); const modeLabel = instance.provider === 'oa-docker' ? 'Docker 模式' : '本地安全模式'; return `<section class="lab-detail-runtime" aria-label="运行状态"><div class="lab-detail-runtime-head"><div><span class="lab-detail-running-dot" aria-hidden="true"></span><strong>运行中 · ${lab.runtimeKind === 'native-oa' ? modeLabel : '本地运行'}</strong></div><strong class="lab-detail-remaining">${esc(lease.remaining)}</strong></div><div class="lab-detail-runtime-meta"><time datetime="${esc(instance.expiresAt)}">${esc(lease.expires)}</time><div class="lab-detail-endpoint" aria-label="入口 ${esc(instance.endpoint)}"><code>${esc(instance.endpoint)}</code></div></div></section>` })()
    : ''
  const managementActions = instance && admin
    ? `<button class="button button-quiet lab-detail-stop lab-detail-action" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button><button class="button button-outline lab-detail-action" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button>`
    : ''
  return `<div class="dialog-backdrop workspace-dialog-backdrop lab-detail-backdrop" data-action="close-lab-details"><section class="dialog lab-detail-dialog" data-state="${detailState}" role="dialog" aria-modal="true" aria-labelledby="lab-detail-title"><div class="lab-card-media lab-detail-cover" data-cover="${coverVariant(lab)}">${coverArt(lab)}<button class="dialog-close lab-detail-close" type="button" data-action="close-lab-details" aria-label="关闭靶场信息">×</button></div><div class="lab-detail-body"><div class="lab-detail-heading"><div><h2 id="lab-detail-title">${esc(lab.title)}</h2><div class="lab-detail-facts">${facts}</div></div>${stateLabel ? `<span class="lab-detail-state">${esc(stateLabel)}</span>` : ''}</div>${lab.summary ? `<p class="lab-detail-summary">${esc(lab.summary)}</p>` : ''}${tags}${sourceInfo}${preparationInfo}${runningInfo}<div class="lab-detail-actions">${managementActions}${primaryAction}</div></div>${oaModeMenu}</section></div>`
}

function passwordToggleIcon(visible) {
  return visible
    ? '<svg viewBox="0 0 1024 1024" aria-hidden="true"><path fill="currentColor" d="M876.8 156.8c0-9.6-3.2-16-9.6-22.4s-12.8-9.6-22.4-9.6-16 3.2-22.4 9.6L736 220.8c-64-32-137.6-51.2-224-60.8-160 16-288 73.6-377.6 176S0 496 0 512s48 73.6 134.4 176c22.4 25.6 44.8 48 73.6 67.2l-86.4 89.6c-6.4 6.4-9.6 12.8-9.6 22.4s3.2 16 9.6 22.4 12.8 9.6 22.4 9.6 16-3.2 22.4-9.6l704-710.4c3.2-6.4 9.6-12.8 9.6-22.4m-646.4 528Q115.2 579.2 76.8 512q43.2-72 153.6-172.8C304 272 400 230.4 512 224c64 3.2 124.8 19.2 176 44.8l-54.4 54.4C598.4 300.8 560 288 512 288c-64 0-115.2 22.4-160 64s-64 96-64 160c0 48 12.8 89.6 35.2 124.8L256 707.2c-9.6-6.4-19.2-16-25.6-22.4m140.8-96Q352 555.2 352 512c0-44.8 16-83.2 48-112s67.2-48 112-48c28.8 0 54.4 6.4 73.6 19.2zM889.599 336c-12.8-16-28.8-28.8-41.6-41.6l-48 48c73.6 67.2 124.8 124.8 150.4 169.6q-43.2 72-153.6 172.8c-73.6 67.2-172.8 108.8-284.8 115.2-51.2-3.2-99.2-12.8-140.8-28.8l-48 48c57.6 22.4 118.4 38.4 188.8 44.8 160-16 288-73.6 377.6-176S1024 528 1024 512s-48.001-73.6-134.401-176"/><path fill="currentColor" d="M511.998 672c-12.8 0-25.6-3.2-38.4-6.4l-51.2 51.2c28.8 12.8 57.6 19.2 89.6 19.2 64 0 115.2-22.4 160-64 41.6-41.6 64-96 64-160 0-32-6.4-64-19.2-89.6l-51.2 51.2c3.2 12.8 6.4 25.6 6.4 38.4 0 44.8-16 83.2-48 112s-67.2 48-112 48"/></svg>'
    : '<svg viewBox="0 0 1024 1024" aria-hidden="true"><path fill="currentColor" d="M512 160c320 0 512 352 512 352S832 864 512 864 0 512 0 512s192-352 512-352m0 64c-225.28 0-384.128 208.064-436.8 288 52.608 79.872 211.456 288 436.8 288 225.28 0 384.128-208.064 436.8-288-52.608-79.872-211.456-288-436.8-288m0 64a224 224 0 1 1 0 448 224 224 0 0 1 0-448m0 64a160.19 160.19 0 0 0-160 160c0 88.192 71.744 160 160 160s160-71.808 160-160-71.744-160-160-160"/></svg>'
}

function loginInputIcon(field) {
  const paths = {
    user: '<path fill="currentColor" d="M512 512a192 192 0 1 0 0-384 192 192 0 0 0 0 384m0 64a256 256 0 1 1 0-512 256 256 0 0 1 0 512m320 320v-96a96 96 0 0 0-96-96H288a96 96 0 0 0-96 96v96a32 32 0 1 1-64 0v-96a160 160 0 0 1 160-160h448a160 160 0 0 1 160 160v96a32 32 0 1 1-64 0"/>',
    password: '<path fill="currentColor" d="M224 448a32 32 0 0 0-32 32v384a32 32 0 0 0 32 32h576a32 32 0 0 0 32-32V480a32 32 0 0 0-32-32zm0-64h576a96 96 0 0 1 96 96v384a96 96 0 0 1-96 96H224a96 96 0 0 1-96-96V480a96 96 0 0 1 96-96"/><path fill="currentColor" d="M512 544a32 32 0 0 1 32 32v192a32 32 0 1 1-64 0V576a32 32 0 0 1 32-32m192-160v-64a192 192 0 1 0-384 0v64zM512 64a256 256 0 0 1 256 256v128H256V320A256 256 0 0 1 512 64"/>',
    confirm: '<path fill="currentColor" d="M406.656 706.944 195.84 496.256a32 32 0 1 0-45.248 45.248l256 256 512-512a32 32 0 0 0-45.248-45.248L406.592 706.944z"/>',
    invite: '<path fill="currentColor" d="M448 456.064V96a32 32 0 0 1 32-32.064L672 64a32 32 0 0 1 0 64H512v128h160a32 32 0 0 1 0 64H512v128a256 256 0 1 1-64 8.064M512 896a192 192 0 1 0 0-384 192 192 0 0 0 0 384"/>',
  }
  return `<span class="login-field-icon" aria-hidden="true"><svg viewBox="0 0 1024 1024">${paths[field] ?? paths.user}</svg></span>`
}

function passwordToggleMarkup(visible, fieldName) {
  const label = visible ? '隐藏密码' : '显示密码'
  return `<button class="password-toggle" type="button" data-action="toggle-password" data-password-field="${fieldName}" aria-label="${label}" aria-pressed="${visible}">${passwordToggleIcon(visible)}</button>`
}

function passwordVisibilityKey(fieldName) {
  if (state.authMode === 'register') return fieldName === 'passwordConfirm' ? 'registerConfirmPasswordVisible' : 'registerPasswordVisible'
  return 'loginPasswordVisible'
}

function resetPasswordVisibility() {
  state.loginPasswordVisible = false
  state.registerPasswordVisible = false
  state.registerConfirmPasswordVisible = false
}

function syncPasswordToggles() {
  const fieldNames = state.authMode === 'register' ? ['password', 'passwordConfirm'] : ['password']
  fieldNames.forEach(fieldName => {
    const input = document.querySelector(`#login-form input[name="${fieldName}"]`)
    const wrap = input?.closest('.login-input-wrap')
    if (!input || !wrap) return
    const toggle = wrap.querySelector('.password-toggle')
    const visibilityKey = passwordVisibilityKey(fieldName)
    if (input.value) {
      if (!toggle) wrap.insertAdjacentHTML('beforeend', passwordToggleMarkup(state[visibilityKey], fieldName))
      return
    }
    toggle?.remove()
    if (state[visibilityKey]) {
      state[visibilityKey] = false
      input.type = 'password'
    }
  })
}

function loginErrorMarkup() {
  return `<div class="login-form-error" id="login-error" role="alert" aria-live="polite"><span class="login-error-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9.5"></circle><path d="m8.5 8.5 7 7m0-7-7 7"></path></svg></span><span class="login-error-message">${esc(state.error)}</span><button class="login-error-close" type="button" data-action="dismiss-login-error" aria-label="关闭提示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12m0-12L6 18"></path></svg></button></div>`
}

function loginFieldAttributes(name) {
  const fieldError = state.loginFieldErrors[name]
  const invalid = Boolean(fieldError) || state.loginErrorFields.includes(name)
  const describedBy = fieldError ? `login-error-field-${name}` : invalid && state.error ? 'login-error' : ''
  return `aria-invalid="${invalid}"${describedBy ? ` aria-describedby="${describedBy}"` : ''}`
}

function loginFieldErrorMarkup(name) {
  const message = state.loginFieldErrors[name]
  return message ? `<span class="login-field-error" id="login-error-field-${name}" data-field-error="${name}" role="alert">${esc(message)}</span>` : ''
}

function registrationValidation(values) {
  const userName = typeof values.userName === 'string' ? values.userName.trim() : ''
  const password = typeof values.password === 'string' ? values.password : ''
  const passwordConfirm = typeof values.passwordConfirm === 'string' ? values.passwordConfirm : ''
  const inviteCode = typeof values.inviteCode === 'string' ? values.inviteCode.trim() : ''
  const errors = {}
  if (!userName) errors.userName = '请输入账号'
  else if (!accountPattern.test(userName)) errors.userName = '账号格式不正确。'
  if (!password) errors.password = '请输入密码'
  else if (password.length < 8) errors.password = '密码长度至少为 8 位'
  if (!passwordConfirm) errors.passwordConfirm = '请确认密码'
  else if (password !== passwordConfirm) errors.passwordConfirm = '两次密码不一致'
  if (!inviteCode) errors.inviteCode = '请输入邀请码'
  else if (inviteCode.length > 128) errors.inviteCode = '邀请码无效'
  return Object.keys(errors).length ? errors : null
}

function loginFieldsMarkup(animate = true) {
  const registerMode = state.authMode === 'register'
  const passwordType = state.loginPasswordVisible ? 'text' : 'password'
  const registerPasswordType = state.registerPasswordVisible ? 'text' : 'password'
  const registerConfirmPasswordType = state.registerConfirmPasswordVisible ? 'text' : 'password'
  const fieldClass = animate ? 'login-field' : 'login-field login-field-static'
  return registerMode
    ? `<label class="${fieldClass}" for="login-username"><span class="login-field-label">账号</span><span class="login-input-wrap" data-field="user">${loginInputIcon('user')}<input id="login-username" name="userName" aria-label="账号" autocomplete="username" maxlength="32" placeholder="请设置账号" required ${loginFieldAttributes('userName')}></span>${loginFieldErrorMarkup('userName')}</label><label class="${fieldClass}" for="login-password"><span class="login-field-label">密码</span><span class="login-input-wrap" data-field="password">${loginInputIcon('password')}<input id="login-password" name="password" aria-label="密码" type="${registerPasswordType}" autocomplete="new-password" placeholder="请设置密码" required ${loginFieldAttributes('password')}></span>${loginFieldErrorMarkup('password')}</label><label class="${fieldClass}" for="login-password-confirm"><span class="login-field-label">确认密码</span><span class="login-input-wrap" data-field="confirm">${loginInputIcon('confirm')}<input id="login-password-confirm" name="passwordConfirm" aria-label="确认密码" type="${registerConfirmPasswordType}" autocomplete="new-password" placeholder="请确认密码" required ${loginFieldAttributes('passwordConfirm')}></span>${loginFieldErrorMarkup('passwordConfirm')}</label><label class="${fieldClass}" for="login-invite-code"><span class="login-field-label">邀请码</span><span class="login-input-wrap" data-field="invite">${loginInputIcon('invite')}<input id="login-invite-code" name="inviteCode" aria-label="邀请码" autocomplete="off" maxlength="128" placeholder="请输入邀请码" required ${loginFieldAttributes('inviteCode')}></span>${loginFieldErrorMarkup('inviteCode')}</label>`
    : `<label class="${fieldClass}" for="login-username"><span class="login-field-label">账号</span><span class="login-input-wrap" data-field="user">${loginInputIcon('user')}<input id="login-username" name="userName" aria-label="账号" value="${esc(state.loginUserName)}" autocomplete="username" maxlength="32" placeholder="请输入账号" required ${loginFieldAttributes('userName')}></span>${loginFieldErrorMarkup('userName')}</label><label class="${fieldClass}" for="login-password"><span class="login-field-label">密码</span><span class="login-input-wrap" data-field="password">${loginInputIcon('password')}<input id="login-password" name="password" aria-label="密码" type="${passwordType}" autocomplete="current-password" placeholder="请输入密码" required ${loginFieldAttributes('password')}></span>${loginFieldErrorMarkup('password')}</label>`
}

function loginPage() {
  const registerMode = state.authMode === 'register'
  const fields = loginFieldsMarkup()
  const submit = registerMode
    ? `<button class="button button-primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '注册中…' : '注册账号'}</button>`
    : `<button class="button button-primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '登录中…' : '登录系统'}</button>`
  const authNotice = state.authNotice ? loginNoticeCard({ id: 'auth-success-notice', title: '注册成功', message: state.authNotice, action: 'dismiss-auth-notice', kind: 'success' }) : ''
  return `<div class="login-page"><div data-login-notice-slot>${authNotice}</div><form class="login-form${registerMode ? ' login-form-register' : ''}" id="login-form" novalidate><div class="login-brand"><div class="login-logo"><img src="/favicon.png" alt="攻防控制台Logo"></div><h1>攻防控制台</h1><p>网络攻防靶场管理系统</p></div><div class="login-mode" role="tablist" aria-label="账号操作"><button type="button" role="tab" data-action="switch-auth-mode" data-mode="login" aria-selected="${!registerMode}" ${state.busy ? 'disabled' : ''}>登录</button><button type="button" role="tab" data-action="switch-auth-mode" data-mode="register" aria-selected="${registerMode}" ${state.busy ? 'disabled' : ''}>注册</button></div>${state.error ? loginErrorMarkup() : ''}<div class="login-fields">${fields}</div>${submit}</form></div>`
}

function updateLoginNoticeView() {
  const slot = document.querySelector('[data-login-notice-slot]')
  if (!slot) return
  slot.innerHTML = state.authNotice ? loginNoticeCard({ id: 'auth-success-notice', title: '注册成功', message: state.authNotice, action: 'dismiss-auth-notice', kind: 'success' }) : ''
}

function updateLoginFormView() {
  const form = document.querySelector('#login-form')
  if (!form) return
  const error = form.querySelector('#login-error')
  if (state.error && !error) form.querySelector('.login-mode')?.insertAdjacentHTML('afterend', loginErrorMarkup())
  else if (!state.error) error?.remove()
  syncLoginFieldErrors(form)
  const submit = form.querySelector('button[type="submit"]')
  if (submit) {
    submit.disabled = state.busy
    submit.textContent = state.authMode === 'register' ? (state.busy ? '注册中…' : '注册账号') : state.busy ? '登录中…' : '登录系统'
  }
}

function syncLoginFieldErrors(form) {
  form.querySelectorAll('input[name]').forEach(input => {
    const message = state.loginFieldErrors[input.name]
    const serverInvalid = state.loginErrorFields.includes(input.name)
    const invalid = Boolean(message) || serverInvalid
    input.setAttribute('aria-invalid', String(invalid))
    const describedBy = message ? `login-error-field-${input.name}` : serverInvalid && state.error ? 'login-error' : ''
    if (describedBy) input.setAttribute('aria-describedby', describedBy)
    else input.removeAttribute('aria-describedby')
    const field = input.closest('.login-field')
    const wrap = input.closest('.login-input-wrap')
    const error = field?.querySelector('.login-field-error')
    if (message && !error) wrap?.insertAdjacentHTML('afterend', loginFieldErrorMarkup(input.name))
    else if (message && error) error.textContent = message
    else error?.remove()
  })
}

function updateLoginModeView() {
  const form = document.querySelector('#login-form')
  const fields = form?.querySelector('.login-fields')
  if (!form || !fields) { render(); return }
  if (loginModeTransitionTimer) { window.clearTimeout(loginModeTransitionTimer); loginModeTransitionTimer = null }
  const startHeight = form.getBoundingClientRect().height
  form.style.height = `${startHeight}px`
  void form.offsetHeight
  form.classList.toggle('login-form-register', state.authMode === 'register')
  form.querySelectorAll('[data-action="switch-auth-mode"]').forEach(button => {
    button.setAttribute('aria-selected', String(button.dataset.mode === state.authMode))
    button.disabled = state.busy
  })
  fields.innerHTML = loginFieldsMarkup(false)
  updateLoginFormView()
  form.style.height = 'auto'
  const endHeight = form.scrollHeight
  form.style.height = `${startHeight}px`
  void form.offsetHeight
  window.requestAnimationFrame(() => { form.style.height = `${endHeight}px` })
  const clearHeight = () => {
    form.style.removeProperty('height')
    loginModeTransitionTimer = null
  }
  form.addEventListener('transitionend', event => {
    if (event.propertyName === 'height') clearHeight()
  }, { once: true })
  loginModeTransitionTimer = window.setTimeout(clearHeight, 320)
  syncPasswordToggles()
}

function scheduleImportPolling() {
  if (importPollTimer) { window.clearTimeout(importPollTimer); importPollTimer = null }
  if (!state.session || !state.jobs.some(job => ['queued', 'importing'].includes(job.status))) return
  importPollTimer = window.setTimeout(async () => {
    importPollTimer = null
    try { await refresh(); render() } catch { scheduleImportPolling() }
  }, 1200)
}

function scheduleDetailPolling() {
  clearDetailPolling()
  if (!state.session || !state.labDetailId || !state.labs.some(item => item.id === state.labDetailId)) return
  if (state.busyActions.length || state.jobs.some(job => ['queued', 'importing'].includes(job.status))) return
  detailPollTimer = window.setTimeout(async () => {
    detailPollTimer = null
    if (!state.session || !state.labDetailId || state.busyActions.length) return
    try {
      await refresh()
      if (state.session && state.labDetailId) render()
    } catch {
      if (state.session && state.labDetailId) scheduleDetailPolling()
    }
  }, DETAIL_POLL_INTERVAL)
}

const sleep = milliseconds => new Promise(resolve => window.setTimeout(resolve, milliseconds))

async function waitForStartedInstance(labId, jobId) {
  const deadline = Date.now() + START_WAIT_TIMEOUT_MS
  while (Date.now() < deadline) {
    await sleep(Math.min(1000, deadline - Date.now()))
    await refresh()
    if (state.instances.some(instance => instance.labId === labId && instance.status === 'running')) return
    const lab = state.labs.find(item => item.id === labId)
    const preparationJob = state.jobs.find(item => item.id === jobId)
    if (preparationJob?.error) throw new ApiError(preparationJob.error, 409)
    if (lab?.status === 'error' || preparationJob?.status === 'error') {
      throw new ApiError(preparationJob?.message ?? '靶场启动未完成，请稍后查看状态。', 409)
    }
  }
  throw new ApiError('靶场准备超时，请稍后重新查看。', 504)
}

function updateLabCanvasScrollState() {
  const canvas = app.querySelector('.lab-canvas')
  if (!canvas) return
  const hasScroll = canvas.scrollHeight > canvas.clientHeight + 1
  const atTop = canvas.scrollTop <= 1
  const atBottom = canvas.scrollTop + canvas.clientHeight >= canvas.scrollHeight - 1
  canvas.classList.toggle('has-scroll', hasScroll)
  canvas.classList.toggle('can-scroll-up', hasScroll && !atTop)
  canvas.classList.toggle('can-scroll-down', hasScroll && !atBottom)
}

function positionAuditActionMenu(details) {
  if (!(details instanceof HTMLDetailsElement) || !details.matches('.admin-action-select')) return
  const options = details.querySelector('.admin-action-options')
  const summary = details.querySelector('summary')
  const dialog = details.closest('.admin-dialog')
  if (!options || !summary || !dialog) return
  if (!details.open) {
    details.classList.remove('opens-up')
    options.style.removeProperty('left')
    options.style.removeProperty('top')
    options.style.removeProperty('bottom')
    options.style.maxHeight = ''
    return
  }
  const dialogBox = dialog.getBoundingClientRect()
  const summaryBox = summary.getBoundingClientRect()
  const gap = 4
  const naturalHeight = Math.min(options.scrollHeight, 240)
  const edge = 8
  const topEdge = Math.max(edge, dialogBox.top + edge)
  const bottomEdge = Math.min(window.innerHeight - edge, dialogBox.bottom - edge)
  const below = Math.max(0, bottomEdge - summaryBox.bottom - gap)
  const above = Math.max(0, summaryBox.top - topEdge - gap)
  const opensUp = above > below
  const available = opensUp ? above : below
  const menuWidth = 190
  const left = Math.max(edge, Math.min(summaryBox.left, window.innerWidth - menuWidth - edge))
  const height = Math.max(44, Math.min(naturalHeight, available || naturalHeight))
  details.classList.toggle('opens-up', opensUp)
  options.style.left = `${left}px`
  options.style.top = `${opensUp ? Math.max(topEdge, summaryBox.top - height - gap) : Math.min(bottomEdge - height, summaryBox.bottom + gap)}px`
  options.style.bottom = 'auto'
  options.style.maxHeight = `${height}px`
}

function positionOpenAuditActionMenus() {
  app.querySelectorAll('.admin-action-select[open]').forEach(positionAuditActionMenu)
}

function positionOaModeMenu() {
  const menu = app.querySelector('.oa-mode-menu')
  const trigger = app.querySelector('.oa-start-trigger')
  const dialog = app.querySelector('.lab-detail-dialog')
  if (!menu || !trigger || !dialog || !state.oaModeMenuOpen) return

  const dialogBox = dialog.getBoundingClientRect()
  const triggerBox = trigger.getBoundingClientRect()
  const edge = 12
  const gap = 8
  const width = Math.max(0, Math.min(224, dialog.clientWidth - edge * 2))
  const left = Math.max(edge, Math.min(triggerBox.right - dialogBox.left - dialog.clientLeft - width, dialog.clientWidth - width - edge))
  const topLimit = dialog.clientTop + edge
  const triggerTop = triggerBox.top - dialogBox.top - dialog.clientTop
  const availableAbove = Math.max(0, triggerTop - topLimit - gap)

  menu.style.left = `${left}px`
  menu.style.width = `${width}px`
  const naturalHeight = menu.scrollHeight + menu.offsetHeight - menu.clientHeight
  const height = Math.min(naturalHeight, availableAbove)
  menu.style.top = `${Math.max(topLimit, triggerTop - height - gap)}px`
  menu.style.maxHeight = `${height}px`
}

function patchLabs() {
  const canvas = app.querySelector('.lab-canvas')
  const visibleLabs = state.labs.filter(lab => lab.status !== 'disabled')
  if (state.error && !visibleLabs.length) {
    const content = `<div class="empty-state lab-empty-state"><p>${esc(state.error)}</p><button class="button button-primary" type="button" data-action="refresh-labs">重新连接</button></div>`
    if (canvas.innerHTML !== content) canvas.innerHTML = content
    return
  }
  if (!visibleLabs.length && state.session?.role !== 'admin') {
    const content = '<div class="empty-state lab-empty-state"><p>暂无可用靶场。</p><button class="button button-primary" type="button" data-action="refresh-labs">重新检查</button></div>'
    if (canvas.innerHTML !== content) canvas.innerHTML = content
    return
  }
  let grid = canvas.querySelector('.lab-grid')
  if (!grid) {
    canvas.innerHTML = '<div class="lab-grid"><div class="lab-card-grid" aria-label="靶场列表"></div></div>'
    grid = canvas.querySelector('.lab-grid')
  }
  let cardGrid = grid.querySelector('.lab-card-grid')
  if (!cardGrid) {
    cardGrid = document.createElement('div')
    cardGrid.className = 'lab-card-grid'
    cardGrid.setAttribute('aria-label', '靶场列表')
    grid.prepend(cardGrid)
    for (const card of [...grid.children].filter(child => child.classList.contains('lab-card'))) cardGrid.append(card)
  }
  let overflowGrid = grid.querySelector('.lab-card-overflow')
  const ensureOverflowGrid = () => {
    if (!overflowGrid) {
      overflowGrid = document.createElement('div')
      overflowGrid.className = 'lab-card-grid lab-card-overflow'
      overflowGrid.setAttribute('aria-label', '更多靶场')
      grid.append(overflowGrid)
    }
    return overflowGrid
  }
  const cards = new Map([...grid.querySelectorAll('.lab-card')].map(card => [card.querySelector('[data-id]')?.dataset.id, card]))
  visibleLabs.forEach((lab, index) => {
    const destination = index < 9 ? cardGrid : ensureOverflowGrid()
    let card = cards.get(lab.id)
    if (!card) {
      const template = document.createElement('template')
      template.innerHTML = labCard(lab, index)
      card = template.content.firstElementChild
    }
    const cardIndex = index < 9 ? index : index - 9
    if (destination.children[cardIndex] !== card) destination.insertBefore(card, destination.children[cardIndex] ?? null)
    cards.delete(lab.id)
    const view = labCardView(lab)
    card.dataset.state = view.cardState
    card.dataset.runtime = lab.runtimeKind ?? ''
    card.setAttribute('aria-label', `${lab.title}，${view.statusLabel}`)
    const cover = card.querySelector('[data-cover-image]')
    if (cover) {
      if (index < 3) cover.removeAttribute('loading')
      else cover.setAttribute('loading', 'lazy')
    }
    if (view.busy) card.setAttribute('aria-busy', 'true')
    else card.removeAttribute('aria-busy')
  })
  cards.forEach(card => card.remove())
  if (overflowGrid && !overflowGrid.querySelector('.lab-card') && state.session?.role !== 'admin') overflowGrid.remove()
  if (state.session?.role === 'admin') {
    if (!ensureOverflowGrid().querySelector('.lab-add-card')) overflowGrid.insertAdjacentHTML('beforeend', '<article class="lab-add-card"><button class="lab-add-card-button" type="button" data-action="open-admin-lab-form" aria-label="添加靶场"><span class="lab-add-card-icon" aria-hidden="true">+</span><span class="lab-add-card-label">添加靶场</span></button></article>')
    const addCard = overflowGrid.querySelector('.lab-add-card')
    if (overflowGrid.lastElementChild !== addCard) overflowGrid.append(addCard)
  } else {
    grid.querySelector('.lab-add-card')?.remove()
  }
  grid.classList.toggle('has-overflow', Boolean(overflowGrid?.querySelector('.lab-card') || state.session?.role === 'admin'))
}

function patchSlot(name, content, { focus = false, key = content } = {}) {
  const slot = app.querySelector(`[data-overlay-slot="${name}"]`)
  if (slot.__vulnlabKey === key && slot.__vulnlabContent === content) return
  const previousContent = slot.__vulnlabContent ?? slot.innerHTML
  if (name === 'admin' && !content && previousContent && !state.labDetailId && slot.querySelector('.dialog-backdrop')) {
    const backdrop = slot.querySelector('.dialog-backdrop')
    const dialog = slot.querySelector('[role="dialog"]')
    backdrop?.style.removeProperty('animation')
    dialog?.style.removeProperty('animation')
    backdrop?.classList.add('is-closing')
    slot.__vulnlabKey = key
    slot.__vulnlabContent = content
    window.setTimeout(() => {
      if (slot.__vulnlabKey === key && slot.__vulnlabContent === content) slot.innerHTML = ''
    }, OVERLAY_EXIT_DURATION)
    return
  }
  const hadDialog = focus && Boolean(slot.querySelector('[role="dialog"]'))
  const previousView = slot.querySelector('[data-admin-dialog-view]')?.dataset.adminDialogView
  const scrollTop = slot.querySelector('.admin-dialog-content')?.scrollTop
  const active = focus && slot.contains(document.activeElement)
    ? { action: document.activeElement.dataset.action ?? '', id: document.activeElement.dataset.id ?? '', section: document.activeElement.dataset.section ?? '', activityDate: document.activeElement.dataset.activityDate ?? '', recordSelect: document.activeElement.dataset.adminRecordSelect ?? '', selectAll: document.activeElement.dataset.adminSelectAll ?? '', auditExpand: document.activeElement.dataset.auditExpand ?? '' }
    : null
  slot.innerHTML = content
  slot.__vulnlabKey = key
  slot.__vulnlabContent = content
  if (scrollTop !== undefined && previousView === state.adminView) {
    const recordsDialog = slot.querySelector('.admin-dialog-content')
    if (recordsDialog) recordsDialog.scrollTop = scrollTop
  }
  if (!focus || !content) return
  if (hadDialog) {
    slot.querySelector('.dialog-backdrop')?.style.setProperty('animation', 'none')
    slot.querySelector('[role="dialog"]')?.style.setProperty('animation', 'none')
    if (previousView === state.adminView) {
      slot.querySelector('.admin-dialog-content')?.style.setProperty('animation', 'none')
      slot.querySelector('.admin-system-view')?.style.setProperty('animation', 'none')
    }
  }
  if (hadDialog && !active) return
  window.queueMicrotask(() => {
    const focusable = [...slot.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter(item => !item.disabled && item.tabIndex >= 0 && item.offsetParent !== null)
    const target = active && focusable.find(item => (item.dataset.action ?? '') === active.action && (item.dataset.id ?? '') === active.id && (item.dataset.section ?? '') === active.section && (item.dataset.activityDate ?? '') === active.activityDate && (item.dataset.adminRecordSelect ?? '') === active.recordSelect && (item.dataset.adminSelectAll ?? '') === active.selectAll && (item.dataset.auditExpand ?? '') === active.auditExpand)
    ;(target || focusable[0])?.focus({ preventScroll: true })
  })
}

function adminPanel() {
  if (!state.adminPanelOpen) return ''
  const isAdmin = state.session?.role === 'admin'
  const view = state.adminView
  const recordSelection = ['invitations', 'audit', 'users'].includes(view) ? adminRecordSelection() : null
  const profile = state.session ? (() => {
    return `<section class="profile-view" aria-labelledby="profile-title"><div class="profile-avatar-frame"><img class="profile-avatar" src="/favicon.png" alt="VulnLab项目图标" /></div><h3 id="profile-title" class="profile-name">${esc(state.session.userName)}</h3></section>`
  })() : ''
  const content = view === 'system' ? adminSystemPanel() : view === 'labs' ? adminLabsPanel() : recordSelection ? adminRecordsPanel(recordSelection) : profile
  const navItems = isAdmin ? [['profile', '个人中心'], ['system', '系统数据'], ['labs', '靶场管理'], ['users', '账号管理'], ['audit', '审计记录'], ['invitations', '邀请管理']] : [['profile', '个人中心']]
  const nav = navItems.map(([section, label]) => `<button class="admin-nav-button${view === section ? ' is-active' : ''}" type="button" data-action="open-admin-section" data-section="${section}" aria-label="${label}" aria-current="${view === section ? 'page' : 'false'}"><span>${label}</span></button>`).join('')
  const title = isAdmin ? '管理中心' : '个人中心'
  const generateLabel = busyFor('generate-invitation') ? '生成中…' : '生成邀请码'
  const footer = isAdmin && view === 'invitations' ? `<button class="button button-primary" type="button" data-action="generate-invitation" ${busyFor('generate-invitation') ? 'disabled' : ''}>${generateLabel}</button>` : ''
  const labAddAction = isAdmin && view === 'labs' && !state.adminLabEditorOpen ? '<button class="button button-primary" type="button" data-action="start-custom-lab-create">添加靶场</button>' : ''
  const selectionActions = recordSelection?.selectionActions ?? ''
  const logoutAction = view === 'profile' ? `<button class="button button-danger" type="button" data-action="logout" ${busyFor('logout') ? 'disabled' : ''}>退出系统</button>` : ''
  const dialogVariant = view === 'profile' ? 'admin-dialog-profile' : 'admin-dialog-records'
  const footerActions = footer || selectionActions || logoutAction || labAddAction
    ? `<div class="dialog-actions"><div class="admin-dialog-primary">${footer}</div>${selectionActions}${labAddAction}${logoutAction}</div>`
    : ''
  return `<div class="dialog-backdrop workspace-dialog-backdrop" data-action="close-admin-panel"><section class="dialog admin-dialog ${dialogVariant}" data-admin-dialog-view="${view}" role="dialog" aria-modal="true" aria-labelledby="admin-dialog-title"><div class="admin-layout"><aside class="admin-sidebar"><nav class="admin-nav" aria-label="${title}导航">${nav}</nav></aside><div class="admin-dialog-main"><h2 id="admin-dialog-title" class="sr-only">${title}</h2><div class="admin-dialog-tools"><button class="dialog-close" type="button" data-action="close-admin-panel" aria-label="关闭${title}">×</button></div><div class="admin-dialog-content">${content}</div>${footerActions}</div></div></section></div>`
}

function adminRecordSelection(panel = state.adminRecordsPanel) {
  const isInvitationPanel = panel === 'invitations'
  const isAuditPanel = panel === 'audit'
  const isUserPanel = panel === 'users'
  const records = isInvitationPanel ? state.invitations : isAuditPanel ? state.audit : state.users
  const selectableRecords = records.filter(item => isAdminRecordSelectable(panel, item))
  const recordId = item => isUserPanel ? item.userName : item.id
  const selectedIds = (state.adminSelectedRecordIds[panel] ?? []).filter(id => selectableRecords.some(item => recordId(item) === id))
  const selected = new Set(selectedIds)
  const selectedUsers = isUserPanel ? records.filter(item => item.kind !== 'system' && selected.has(item.userName)) : []
  const allSelectedUsersDisabled = selectedUsers.length > 0 && selectedUsers.every(item => item.disabled)
  const allSelected = selectableRecords.length > 0 && selectedIds.length === selectableRecords.length
  const recordLabel = isInvitationPanel ? '邀请码' : isAuditPanel ? '审计' : '账号'
  const selectAllInput = selectableRecords.length ? `<input type="checkbox" data-admin-select-all="${panel}" aria-label="全选已加载的${recordLabel}记录" ${allSelected ? 'checked' : ''}>` : ''
  const selectAllControl = selectAllInput ? `<label class="admin-select-all">${selectAllInput}</label>` : ''
  const selectionCount = selectedIds.length ? `<span class="admin-selection-count" aria-live="polite">已选 ${selectedIds.length} 条</span>` : ''
  const canManageAccountStatus = state.session?.role === 'admin' && state.session.userName.toLowerCase() === 'vulnlab'
  const bulkStatusControl = isUserPanel && canManageAccountStatus && selectableRecords.length ? `<button class="button button-outline admin-bulk-status" type="button" data-action="set-selected-user-status" ${selectedIds.length ? '' : 'disabled'}>${allSelectedUsersDisabled ? '启用' : '禁用'}</button>` : ''
  const bulkDeleteControl = selectableRecords.length ? `<button class="button button-danger admin-bulk-delete" type="button" data-action="delete-selected-admin-records" data-panel="${panel}" ${selectedIds.length ? '' : 'disabled'}>删除</button>` : ''
  const showSelectionActions = selectedIds.length > 0
  const selectionActions = !state.adminLoading && !state.adminError && records.length && showSelectionActions
    ? `<div class="admin-selection-actions">${selectionCount}${bulkStatusControl}${bulkDeleteControl}</div>`
    : ''
  return { records, selectableRecords, selectedIds, selected, allSelected, selectAllControl, selectionActions }
}

const customRuntimeModes = {
  'php-static': { kind: 'native-php', profile: 'static-php', label: 'PHP 网站' },
  'php-mysql': { kind: 'native-php', profile: 'mysql-php', label: 'PHP + MySQL' },
  node: { kind: 'native-node', profile: 'prebuilt-node', label: 'Node.js 项目' },
  'java-jar': { kind: 'native-java', profile: 'java-jar', label: 'Java JAR' },
  webgoat: { kind: 'native-java', profile: 'webgoat', label: 'WebGoat' },
  python: { kind: 'native-python', profile: 'python-script', label: 'Python 脚本' },
  django: { kind: 'native-python', profile: 'pygoat', label: 'Django 项目' },
}

function customRuntimeModeFor(lab) {
  const match = Object.entries(customRuntimeModes).find(([, mode]) => mode.kind === lab.runtimeKind && mode.profile === lab.runtimeConfig?.profile)
  return match?.[0] ?? ({ 'native-php': 'php-static', 'native-node': 'node', 'native-java': 'java-jar', 'native-python': 'python' })[lab.runtimeKind] ?? ''
}

function adminLabsPanel() {
  const draft = state.adminLabDraft
  const labs = state.labs
  const editorOpen = state.adminLabEditorOpen
  const statusLabels = { cataloged: '待准备', queued: '排队中', importing: '准备中', ready: '已就绪', error: '准备失败', disabled: '已停用' }
  const option = (value, label, current) => `<option value="${value}"${current === value ? ' selected' : ''}>${label}</option>`
  const runtimeMode = customRuntimeModes[draft.runtimeMode] ? draft.runtimeMode : customRuntimeModeFor(draft)
  const runtimeProfile = customRuntimeModes[runtimeMode]?.profile
  const editingLab = state.adminLabEditId ? labs.find(lab => lab.id === state.adminLabEditId && !lab.builtin) : null
  const runtimeField = (name, label, value, placeholder, type = 'text') => `<label>${label}<input name="${name}" type="${type}" value="${esc(value)}" placeholder="${esc(placeholder)}"></label>`
  let runtimeFields = ''
  if (runtimeProfile === 'static-php' || runtimeProfile === 'mysql-php') {
    runtimeFields = `${runtimeField('documentRoot', 'PHP 网站目录（可选）', draft.documentRoot, '留空使用项目根目录')}${runtimeField('entryPath', '入口文件', draft.entryPath || 'index.php', 'index.php')}${runtimeProfile === 'mysql-php' ? runtimeField('initSqlPath', '数据库初始化文件', draft.initSqlPath || 'init.sql', 'init.sql') : ''}`
  } else if (runtimeProfile === 'prebuilt-node') {
    runtimeFields = `${runtimeField('entryPath', 'Node.js 入口文件（可选）', draft.entryPath, '例如：server.js')}<label>启动参数（可选）<textarea name="nodeArgs" rows="2" placeholder="每行一个参数">${esc(draft.nodeArgs)}</textarea></label>`
  } else if (runtimeProfile === 'webgoat') {
    runtimeFields = runtimeField('entryPath', 'Java JAR 入口文件', draft.entryPath || 'webgoat.jar', 'webgoat.jar')
  } else if (runtimeProfile === 'java-jar') {
    runtimeFields = `${runtimeField('entryPath', 'Java JAR 文件', draft.entryPath || 'app.jar', 'app.jar')}${runtimeField('portArg', '端口参数（可选）', draft.portArg, '--server.port={port}')}<label>启动参数（可选）<textarea name="javaArgs" rows="2" placeholder="每行一个参数">${esc(draft.javaArgs)}</textarea></label>`
  } else if (runtimeProfile === 'python-script') {
    runtimeFields = `${runtimeField('entryPath', 'Python 入口文件', draft.entryPath || 'app.py', 'app.py')}${runtimeField('portArg', '端口参数（可选）', draft.portArg, '--port={port}')}<label>启动参数（可选）<textarea name="pythonArgs" rows="2" placeholder="每行一个参数">${esc(draft.pythonArgs)}</textarea></label>`
  } else if (runtimeProfile === 'pygoat') {
    runtimeFields = `${runtimeField('entryPath', 'Django 入口文件', draft.entryPath || 'manage.py', 'manage.py')}${runtimeField('settingsPath', 'Django 设置文件', draft.settingsPath || 'pygoat/settings.py', 'pygoat/settings.py')}`
  }
  const runtimeHelp = !runtimeProfile
    ? '该记录来自旧 Compose 配置；当前未接入 Compose 运行，请明确选择一个现有固定运行方式后再保存。'
    : runtimeProfile === 'prebuilt-node'
    ? '声明运行依赖时需提供 package-lock.json 或 npm-shrinkwrap.json；安装使用锁文件，且不执行项目安装脚本。'
    : runtimeProfile === 'python-script' || runtimeProfile === 'pygoat'
      ? '如包含 requirements.txt，需使用哈希锁定依赖，并提前准备本机离线 wheelhouse。'
      : runtimeProfile === 'java-jar' || runtimeProfile === 'webgoat'
        ? '项目需包含可运行的 JAR 文件。'
        : runtimeProfile === 'mysql-php'
          ? '项目需包含 PHP 入口和数据库初始化 SQL 文件。'
          : runtimeProfile === 'static-php'
            ? '项目需包含 PHP 入口文件。'
            : '需包含 Django manage.py 与 settings.py；第三方依赖仅从本机离线 wheelhouse 安装。'
  const sourceValueField = draft.sourceType === 'archive'
    ? `<label>ZIP 文件<input name="archiveFile" type="file" accept=".zip,application/zip,application/x-zip-compressed"><span class="admin-lab-file-hint" data-archive-file-name>${esc(draft.archiveFileName || (editingLab?.sourceType === 'archive' ? '留空保留当前压缩包，可重新选择' : draft.sourceUploadUrl ? '已选择一个 ZIP，可重新选择' : '最大 256 MiB'))}</span></label>`
    : `<label>公开仓库地址<input name="sourceUrl" type="url" required value="${esc(draft.sourceUrl)}" placeholder="https://github.com/组织/项目"></label>`
  const inspection = state.adminLabInspection
  const inspectionSuggestion = inspection?.suggestion
  const inspectionLabel = inspectionSuggestion?.mode ? customRuntimeModes[inspectionSuggestion.mode]?.label ?? '未识别' : '未识别固定运行方式'
  const inspectionView = inspection
    ? `<div class="admin-lab-inspection" role="status"><div><strong>结构建议：${esc(inspectionLabel)}</strong><span>${inspectionSuggestion?.confidence === 'high' ? '特征明确' : inspectionSuggestion?.confidence === 'medium' ? '建议复核' : '请手动选择'}</span></div>${inspectionSuggestion?.signals?.length ? `<p>识别到：${inspectionSuggestion.signals.map(esc).join('、')}</p>` : ''}${inspectionSuggestion?.warnings?.length ? `<ul>${inspectionSuggestion.warnings.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<p>未发现明显缺项；准备阶段仍会按固定契约校验文件。</p>'}${inspectionSuggestion?.mode ? `<button class="button button-quiet" type="button" data-action="apply-lab-inspection" data-mode="${esc(inspectionSuggestion.mode)}">采用此建议</button>` : ''}</div>`
    : state.adminLabInspectionError ? `<p class="admin-lab-inspection-error" role="alert">${esc(state.adminLabInspectionError)}</p>` : ''
  const sourceRefField = draft.sourceType === 'git' ? `<label>分支 / 版本<input name="sourceRef" value="${esc(draft.sourceRef)}" placeholder="留空使用仓库默认分支"></label>` : ''
  const rows = labs.length
    ? labs.map(lab => {
      const latestJob = state.jobs.filter(job => job.labId === lab.id).sort((left, right) => String(right.updatedAt ?? '').localeCompare(String(left.updatedAt ?? '')))[0]
      const progress = Math.max(0, Math.min(100, Number(latestJob?.progress ?? 0)))
      const progressView = ['queued', 'importing'].includes(lab.status)
        ? `<div class="admin-lab-row-progress" role="status" aria-label="${esc(latestJob?.message ?? '等待准备')}，${progress}%"><div><span>${esc(latestJob?.message ?? '等待准备')}</span><strong>${progress}%</strong></div><span class="admin-lab-progress-track"><i style="width:${progress}%"></i></span></div>`
        : ''
      const errorView = lab.status === 'error'
        ? `<details class="admin-lab-row-error"><summary>查看失败原因</summary><p>${esc(latestJob?.error ?? latestJob?.message ?? '没有更多错误信息。')}</p></details>`
        : ''
      const running = state.instances.some(instance => instance.labId === lab.id && instance.status === 'running')
      const sourceLabel = lab.sourceUrl.startsWith('bundle://')
        ? '项目资源包'
        : lab.sourceType === 'catalog'
          ? '官方目录'
          : lab.sourceType === 'git'
          ? (() => { try { const url = new URL(lab.sourceUrl); return `${url.hostname.replace(/^www\./, '')}/${url.pathname.replace(/^\/+|\/+$/g, '')}` } catch { return 'Git 仓库' } })()
          : 'ZIP 压缩包'
      const runtimeMode = customRuntimeModeFor(lab)
      const modeLabel = lab.runtimeConfig?.profile === 'oa-project' ? 'OA 靶场' : customRuntimeModes[runtimeMode]?.label ?? (String(lab.runtimeKind) === 'container' ? 'Compose（当前未接入）' : String(lab.runtimeKind) === 'vm' ? '虚拟机目录（当前未接入）' : '未识别运行方式')
      const addedAt = auditTimestamp(lab.createdAt)
      const stateView = `<span class="admin-lab-row-state admin-lab-row-state-${esc(lab.status)}">${esc(statusLabels[lab.status] ?? lab.status)}</span>`
      const actions = `<div class="admin-lab-row-actions">${lab.status === 'error' ? `<button class="button button-outline" type="button" data-action="retry-admin-lab" data-id="${esc(lab.id)}" ${busyFor('retry-admin-lab', lab.id) ? 'disabled' : ''}>${busyFor('retry-admin-lab', lab.id) ? '重试中…' : '重试'}</button>` : ''}${lab.builtin ? '' : `<button class="button button-quiet" type="button" data-action="edit-custom-lab" data-id="${esc(lab.id)}">编辑</button>`}<button class="button ${lab.status === 'disabled' ? 'button-outline' : 'button-quiet'}" type="button" data-action="toggle-admin-lab" data-id="${esc(lab.id)}" data-disabled="${lab.status !== 'disabled'}" ${running || ['queued', 'importing'].includes(lab.status) ? 'disabled' : ''}>${lab.status === 'disabled' ? '恢复' : '停用'}</button>${lab.builtin ? '' : `<button class="button button-danger" type="button" data-action="delete-custom-lab" data-id="${esc(lab.id)}" ${running || ['queued', 'importing'].includes(lab.status) ? 'disabled' : ''}>删除</button>`}</div>`
      const createdView = lab.builtin ? '' : `<time class="admin-lab-row-created" datetime="${esc(lab.createdAt)}" title="添加于 ${esc(addedAt.date)} ${esc(addedAt.time)}">添加于 ${esc(addedAt.date)} ${esc(addedAt.time.slice(0, 5))}</time>`
      const kindView = `<span class="admin-lab-row-kind">${lab.builtin ? '项目内置' : '自定义'}</span>`
      const runtimeSource = `${modeLabel} · ${sourceLabel}`
      return `<article class="admin-lab-row" data-lab-id="${esc(lab.id)}" data-builtin="${lab.builtin}"><div class="admin-lab-row-copy"><div class="admin-lab-row-heading"><strong title="${esc(lab.title)}">${esc(lab.title)}</strong>${stateView}${kindView}</div><div class="admin-lab-row-meta"><span class="admin-lab-row-runtime" title="${esc(runtimeSource)}">${esc(modeLabel)} <i aria-hidden="true">·</i> ${esc(sourceLabel)}</span>${createdView}</div></div>${progressView}${errorView}${actions}</article>`
    }).join('')
    : '<div class="admin-empty-state">暂无靶场记录。</div>'
  const form = `<form class="admin-lab-form" id="admin-lab-form">
      <div class="admin-lab-form-primary">
        <label>名称<input name="title" required maxlength="80" value="${esc(draft.title)}" placeholder="例如：OWASP WebGoat"></label>
        <div class="admin-lab-source-row"><fieldset class="admin-lab-source-toggle"><legend>来源</legend><input type="hidden" name="sourceType" value="${esc(draft.sourceType)}"><div role="group" aria-label="来源类型"><button class="${draft.sourceType === 'git' ? 'is-active' : ''}" type="button" data-action="select-lab-source" data-source="git" aria-pressed="${draft.sourceType === 'git'}">Git 仓库</button><button class="${draft.sourceType === 'archive' ? 'is-active' : ''}" type="button" data-action="select-lab-source" data-source="archive" aria-pressed="${draft.sourceType === 'archive'}">ZIP 文件</button></div></fieldset><div class="admin-lab-source-value">${sourceValueField}</div></div>
        <label>运行方式<select name="runtimeMode" required>${runtimeMode ? '' : '<option value="" selected disabled>请选择固定运行方式</option>'}${Object.entries(customRuntimeModes).map(([value, mode]) => option(value, mode.label, runtimeMode)).join('')}</select><span class="admin-lab-template-hint">${runtimeHelp}</span></label>
      </div>
      <section class="admin-lab-section admin-lab-precheck" aria-labelledby="admin-lab-precheck-title"><div class="admin-lab-section-heading"><div><h4 id="admin-lab-precheck-title">项目结构预检</h4><p>可选，只读识别，不执行项目脚本</p></div><button class="button button-quiet" type="button" data-action="inspect-custom-lab" ${state.adminLabInspectionLoading ? 'disabled' : ''}>${state.adminLabInspectionLoading ? '检查中…' : '检查结构'}</button></div>${inspectionView}</section>
      <section class="admin-lab-section admin-lab-runtime-settings" aria-labelledby="admin-lab-runtime-title"><div class="admin-lab-section-heading"><div><h4 id="admin-lab-runtime-title">运行参数</h4><p>按所选运行方式显示</p></div></div>${sourceRefField ? `<div class="admin-lab-source-ref">${sourceRefField}</div>` : ''}<div class="admin-lab-form-grid admin-lab-runtime-grid">${runtimeFields}</div></section>
      <section class="admin-lab-section admin-lab-display-settings" aria-labelledby="admin-lab-display-title"><div class="admin-lab-section-heading"><div><h4 id="admin-lab-display-title">展示资料</h4><p>用于主页面靶场卡片和详情</p></div></div><div class="admin-lab-display-grid"><label>分类<input name="category" value="${esc(draft.category)}" placeholder="Web"></label><label>难度<select name="difficulty">${option('入门', '入门', draft.difficulty)}${option('简单', '简单', draft.difficulty)}${option('中等', '中等', draft.difficulty)}${option('困难', '困难', draft.difficulty)}</select></label><label>许可证<input name="license" value="${esc(draft.license)}" placeholder="未声明"></label><label>标签<input name="tags" value="${esc(draft.tags)}" placeholder="SQL 注入, 文件上传"></label><label>简介<textarea name="summary" maxlength="240" placeholder="简短描述靶场内容">${esc(draft.summary)}</textarea></label></div></section>
      <div class="admin-lab-form-actions"><button class="button button-quiet" type="button" data-action="cancel-custom-lab-editor">取消</button><button class="button button-primary" type="submit" ${busyFor('save-lab') ? 'disabled' : ''}>${busyFor('save-lab') ? '保存中…' : editingLab ? '保存修改' : '添加靶场'}</button></div>
    </form>`
  const list = `<section class="admin-lab-list" aria-label="靶场列表">${rows}</section>`
  const heading = editorOpen ? `<div class="admin-lab-heading"><h3>${editingLab ? '编辑靶场' : '添加靶场'}</h3></div>` : ''
  return `<section class="admin-lab-view" data-admin-view="labs" data-editor-open="${editorOpen}" aria-label="靶场管理">
    ${heading}
    ${editorOpen ? form : list}
  </section>`
}

function adminSystemPanel() {
  const overview = state.adminOverview
  const activity = overview?.activity
  const refreshButton = '<button class="admin-system-refresh" type="button" data-action="refresh-system-data" aria-label="刷新系统数据" title="刷新系统数据" aria-busy="false"><span>刷新</span></button>'
  if (!activity) {
    const status = state.adminSystemLoading
      ? '<div class="admin-loading" role="status">正在读取系统数据…</div>'
      : `<div class="admin-inline-error" role="alert">${esc(state.adminSystemError || '系统数据暂时不可用。')}</div>${refreshButton}`
    return `<section class="admin-system-view" data-admin-view="system" aria-label="系统数据" aria-busy="${state.adminSystemLoading}">${status}</section>`
  }
  const number = value => Number(value ?? 0).toLocaleString('zh-CN')
  const stat = (key, label, value) => `<div class="admin-system-stat"><strong data-system-stat="${key}">${value}</strong><span>${label}</span></div>`
  const daily = activity.daily
  const selected = daily.find(item => item.date === state.adminActivityDate) ?? daily.at(-1)
  const startOffset = (new Date(`${daily[0].date}T12:00:00Z`).getUTCDay() + 6) % 7
  const weeks = Math.ceil((startOffset + daily.length) / 7)
  const cells = Array.from({ length: weeks * 7 }, (_, index) => {
    const item = daily[index - startOffset]
    if (!item) return '<span class="admin-activity-cell is-blank" aria-hidden="true"></span>'
    const level = item.count >= 8 ? 4 : item.count >= 4 ? 3 : item.count >= 2 ? 2 : item.count > 0 ? 1 : 0
    const label = `${item.date}：${item.count} 次靶场启动`
    return `<button class="admin-activity-cell is-level-${level}" type="button" data-action="open-audit-for-date" data-activity-date="${esc(item.date)}" tabindex="${item.date === selected.date ? 0 : -1}" aria-label="${esc(label)}" title="${esc(label)}"></button>`
  }).join('')
  const months = daily.flatMap((item, index) => {
    if (index !== 0 && item.date.slice(0, 7) === daily[index - 1].date.slice(0, 7)) return []
    const column = Math.floor((startOffset + index) / 7) + 1
    if (column > weeks - 2 || (index === 0 && Number(item.date.slice(-2)) > 20)) return []
    const month = Number(item.date.slice(5, 7))
    return `<span class="${month % 2 ? 'is-secondary-month' : ''}" style="grid-column:${column} / span 3">${month}月</span>`
  }).join('')
  const rankingMax = Math.max(1, ...activity.ranking.map(item => item.count))
  const ranking = activity.ranking.map((item, index) => `<button class="admin-lab-ranking" type="button" data-action="open-system-lab" data-id="${esc(item.labId)}" aria-label="查看 ${esc(item.title)}，${item.count} 次启动${item.running ? '，运行中' : ''}"><span class="admin-lab-ranking-order">${String(index + 1).padStart(2, '0')}</span><span class="admin-lab-ranking-main"><strong>${esc(item.title)}</strong><span class="admin-lab-ranking-track" aria-hidden="true"><span style="width:${item.count / rankingMax * 100}%"></span></span></span><span class="admin-lab-ranking-meta">${item.running ? '<i>运行中</i>' : ''}<span>${number(item.count)} <small>次</small></span></span></button>`).join('')
  return `<section class="admin-system-view" data-admin-view="system" aria-label="系统数据" aria-busy="false">
    ${state.adminSystemError ? `<div class="admin-inline-error" role="alert">更新失败，当前显示上次数据：${esc(state.adminSystemError)}</div>` : ''}
    <div class="admin-system-stats">${stat('labs', '靶场总数', number(overview.labCount))}${stat('ready', '已就绪', number(overview.readyCount))}${stat('running', '运行中 / 上限', `${number(overview.runningInstanceCount)} <small>/ ${number(overview.maxInstances)}</small>`)}${stat('launches', '365天启动', number(activity.launchCount))}</div>
    <section class="admin-activity-card" aria-labelledby="admin-activity-title" style="--activity-weeks:${weeks}"><div class="admin-activity-heading"><h3 id="admin-activity-title">靶场活动</h3><span>${esc(activity.rangeStart)} — ${esc(activity.rangeEnd)}</span>${refreshButton}</div>
      <span class="sr-only" id="admin-activity-help">上下方向键逐日查看，左右方向键逐周查看，Home 和 End 跳到首日与末日。</span>
      <div class="admin-activity-grid" role="group" aria-label="最近365天靶场启动活动" aria-describedby="admin-activity-help">${cells}</div><div class="admin-activity-months" aria-hidden="true">${months}</div>
      <div class="admin-activity-footer"><output class="admin-activity-selection" aria-live="polite">${esc(selected.date)} · ${number(selected.count)} 次启动</output><span>${number(activity.activeDays)} 天活跃</span><span class="admin-activity-legend" aria-label="颜色代表每日启动次数：0次、1次、2至3次、4至7次、8次及以上"><i>少</i><b></b><b class="is-level-1"></b><b class="is-level-2"></b><b class="is-level-3"></b><b class="is-level-4"></b><i>多</i></span></div>
      <span class="sr-only">统计保留的成功启动审计记录，清理这些记录会同步改变统计，日期以服务器本地时间为准。</span>
    </section>
    <section class="admin-system-card" aria-labelledby="admin-ranking-title"><div class="admin-system-card-heading"><h3 id="admin-ranking-title">靶场使用排行</h3><span>最近365天</span></div><div class="admin-lab-ranking-list">${ranking || '<div class="admin-system-empty">最近365天暂无靶场启动记录。</div>'}</div></section>
  </section>`
}

function adminRecordsPanel(selection) {
  if (!state.adminPanelOpen || !state.adminRecordsPanel) return ''
  const statusLabels = { active: '可邀请', expired: '已过期', used: '已使用', revoked: '已撤销' }
  const actionLabels = {
    'account.disable': '禁用账号',
    'account.enable': '启用账号',
    'account.delete': '删除账号',
    'import.completed': '导入完成',
    'import.failed': '导入失败',
    'import.queue': '导入排队',
    'instance.destroy': '停止靶场',
    'instance.expired': '实例过期回收',
    'instance.prepare': '准备靶场',
    'instance.recovered': '回收遗留实例',
    'instance.renew': '续期实例',
    'instance.start': '启动靶场',
    'instance.start.failed': '启动靶场失败',
    'invitation.create': '生成邀请码',
    'invitation.revoke': '撤销邀请码',
    'lab.install': '安装靶场',
    login: '登录系统',
    logout: '退出系统',
    register: '注册账号',
    'runtime.prepare': '准备运行环境',
    'runtime.prepare.failed': '运行环境准备失败',
    'settings.update': '更新运行设置',
  }
  const isInvitationPanel = state.adminRecordsPanel === 'invitations'
  const isAuditPanel = state.adminRecordsPanel === 'audit'
  const isUserPanel = state.adminRecordsPanel === 'users'
  const title = isInvitationPanel ? '邀请管理' : isAuditPanel ? '审计记录' : '账号管理'
  const invitation = state.invitation ? `<div class="invitation-card"><div class="invitation-card-heading"><span>当前邀请码</span><time datetime="${esc(state.invitation.expiresAt)}">有效至 ${esc(date(state.invitation.expiresAt))}</time></div><p class="invitation-one-time-note">本标签页生成的邀请码明文可在此查看；未过期且未使用的记录显示为“可邀请”，点击即可复制。</p><code>${esc(state.invitation.code)}</code><div class="invitation-card-actions"><button class="button button-outline" type="button" data-action="copy-invitation">复制邀请码</button><button class="button button-quiet" type="button" data-action="revoke-invitation" data-id="${esc(state.invitation.id)}">撤销</button></div></div>` : ''
  const { records, selected, selectAllControl } = selection
  const registeredUsers = isUserPanel ? records.filter(item => item.kind !== 'system') : []
  const hasRegisteredUsers = registeredUsers.length > 0
  const recordLabel = isInvitationPanel ? '邀请码' : isAuditPanel ? '审计' : '账号'
  const nextCursor = state.adminNextCursors[state.adminRecordsPanel]
  const pagination = nextCursor ? `<div class="admin-record-pagination"><span class="sr-only">还有更多${recordLabel}记录</span><button class="button button-outline admin-load-more" type="button" data-action="load-more-admin-records" data-panel="${state.adminRecordsPanel}" ${busyFor('load-more-admin-records', state.adminRecordsPanel) ? 'disabled' : ''}>${busyFor('load-more-admin-records', state.adminRecordsPanel) ? '加载中…' : '加载更多'}</button></div>` : ''
  const auditActions = isAuditPanel ? Object.entries(actionLabels).sort((left, right) => left[0].localeCompare(right[0])).map(([value, label]) => `<button class="admin-action-option" type="button" data-action="filter-audit-action" data-value="${esc(value)}" aria-pressed="${state.adminAuditAction === value}">${esc(label)}</button>`).join('') : ''
  const auditSelectAllControl = isAuditPanel && !state.adminLoading && !state.adminError && records.length ? selectAllControl : ''
  const auditActionLabel = actionLabels[state.adminAuditAction] ?? '全部操作'
  const auditActionFilter = `<div class="admin-record-filter"><span>操作类型</span><details class="admin-action-select" data-audit-action-filter="${esc(state.adminAuditAction)}"><summary aria-label="按操作类型筛选审计记录" aria-controls="admin-audit-action-options"><span>${esc(auditActionLabel)}</span></summary><div class="admin-action-options" id="admin-audit-action-options" role="group" aria-label="操作类型"><button class="admin-action-option" type="button" data-action="filter-audit-action" data-value="" aria-pressed="${!state.adminAuditAction}">全部操作</button>${auditActions}</div></details></div>`
  const clearAuditFilters = state.adminAuditDate || state.adminAuditAction ? '<button class="button button-quiet admin-clear-filters" type="button" data-action="clear-audit-filters">清除筛选</button>' : ''
  const auditFilters = isAuditPanel ? `<div class="admin-record-filters" aria-label="审计记录筛选">${auditSelectAllControl}<label class="admin-record-filter"><span>日期</span><input type="date" data-audit-filter="date" value="${esc(state.adminAuditDate)}" aria-label="按日期筛选审计记录"></label>${auditActionFilter}${clearAuditFilters}</div>` : ''
  const auditReturn = isAuditPanel && state.adminAuditReturnToSystem ? '<button class="admin-audit-return" type="button" data-action="return-to-system-data">返回系统数据</button>' : ''
  const systemAdmin = isUserPanel ? records.find(item => item.kind === 'system') : null
  const systemAdminRow = systemAdmin ? `<div class="admin-user-entry admin-user-system" data-id="${esc(systemAdmin.userName)}" data-kind="system"><div class="admin-user-system-profile"><img class="admin-user-avatar" src="/favicon.png" alt="" aria-hidden="true"><div class="admin-user-identity"><div class="admin-user-heading"><strong class="admin-user-name" title="${esc(systemAdmin.userName)}">${esc(systemAdmin.userName)}</strong><span class="admin-user-role">默认管理员</span></div></div></div></div>` : ''
  const emptyClass = `admin-empty-state${isAuditPanel ? ' admin-audit-empty-state' : ''}`
  const emptyMessage = isAuditPanel
    ? state.adminAuditDate && state.adminAuditAction === 'instance.start'
      ? '当天暂无启动记录。'
      : state.adminAuditDate || state.adminAuditAction
        ? '暂无符合条件的审计记录。'
        : '暂无审计记录。'
    : `暂无${isInvitationPanel ? '邀请码' : '注册账号'}记录。`
  const userRows = isUserPanel ? registeredUsers.map(item => {
    const timestamp = auditTimestamp(item.createdAt)
    const current = state.session?.userName?.toLowerCase() === item.userName.toLowerCase()
    const disabled = item.disabled === true
    const statusBadge = disabled ? '<span class="admin-user-disabled">已禁用</span>' : ''
    return `<div class="admin-user-entry${selected.has(item.userName) ? ' is-selected' : ''}${disabled ? ' is-disabled' : ''}" data-id="${esc(item.userName)}"><label class="admin-record-select"><input type="checkbox" data-admin-record-select="users" data-id="${esc(item.userName)}" aria-label="选择账号 ${esc(item.userName)}" ${selected.has(item.userName) ? 'checked' : ''}></label><div class="admin-user-content"><div class="admin-user-identity"><div class="admin-user-heading"><strong class="admin-user-name" title="${esc(item.userName)}">${esc(item.userName)}</strong><span class="admin-user-role">管理员</span>${statusBadge}${current ? '<span class="admin-user-current">当前登录</span>' : ''}</div></div><time class="admin-user-time" datetime="${esc(item.createdAt)}"><span class="admin-user-time-label">注册于</span><span class="admin-user-date">${esc(timestamp.date)}</span><span class="admin-user-clock">${esc(timestamp.time)}</span></time></div><div class="admin-user-actions"><button class="record-delete" type="button" data-action="delete-user-record" data-id="${esc(item.userName)}" aria-label="删除账号 ${esc(item.userName)}" title="删除账号">${deleteRecordIcon()}</button></div></div>`
  }).join('') : ''
  const content = state.adminLoading
    ? '<div class="admin-loading" role="status">正在更新记录…</div>'
    : state.adminError
      ? `<div class="admin-inline-error" role="alert"><span>${esc(state.adminError)}</span><button class="button button-outline admin-record-retry" type="button" data-action="retry-admin-records" data-panel="${esc(state.adminRecordsPanel)}">重试</button></div>`
      : records.length
        ? isInvitationPanel
          ? `<div class="invitation-history-head">${selectAllControl || '<span class="invitation-row-spacer" aria-hidden="true"></span>'}<span>状态</span><span>创建人 / 时间</span><span>使用账号 / 时间</span><span>有效期</span><span>操作</span></div><div class="admin-record-list invitation-history">${records.map(item => { const used = item.status === 'used'; const usedBy = used ? item.usedByUserName || '历史记录未记录使用者' : '—'; const createdAt = auditTimestamp(item.createdAt); const usedAt = item.usedAt ? auditTimestamp(item.usedAt) : null; const selection = used ? '<span class="invitation-row-spacer" aria-hidden="true"></span>' : `<label class="admin-record-select"><input type="checkbox" data-admin-record-select="invitations" data-id="${esc(item.id)}" aria-label="选择邀请码记录" ${selected.has(item.id) ? 'checked' : ''}></label>`; const status = item.status === 'active' ? `<button class="invitation-status-copy" type="button" data-action="copy-invitation-record" data-id="${esc(item.id)}" aria-label="点击复制邀请码" title="点击复制邀请码">可邀请</button>` : `<strong>${esc(statusLabels[item.status] ?? item.status)}</strong>`; return `<div class="invitation-history-card${selected.has(item.id) ? ' is-selected' : ''}" data-id="${esc(item.id)}" data-status="${esc(item.status)}">${selection}<div class="invitation-field invitation-field-status"><span class="invitation-field-label">状态</span>${status}</div><div class="invitation-field invitation-field-created"><span class="invitation-field-label">创建人 / 时间</span><span class="invitation-field-value"><span title="${esc(item.createdBy)}">${esc(item.createdBy)}</span><time datetime="${esc(item.createdAt)}"><span>${esc(createdAt.date)}</span><span>${esc(createdAt.time)}</span></time></span></div><div class="invitation-field invitation-field-used"><span class="invitation-field-label">使用账号 / 时间</span><span class="invitation-field-value"><span class="invitation-used-by" title="${esc(usedBy)}">${esc(usedBy)}</span>${usedAt ? `<time datetime="${esc(item.usedAt)}"><span>${esc(usedAt.date)}</span><span>${esc(usedAt.time)}</span></time>` : '<span>—</span>'}</span></div><div class="invitation-field invitation-field-expiry"><span class="invitation-field-label">有效期</span><span class="invitation-field-value"><time datetime="${esc(item.expiresAt)}">${esc(date(item.expiresAt))}</time></span></div><div class="invitation-operation">${used ? '<span class="invitation-retained">已保留</span>' : `<button class="record-delete" type="button" data-action="delete-invitation-record" data-id="${esc(item.id)}" aria-label="删除邀请码记录" title="删除邀请码记录">${deleteRecordIcon()}</button>`}</div></div>` }).join('')}</div>${pagination}`
          : isAuditPanel
            ? `<div class="admin-record-list audit-history">${records.map(item => { const timestamp = auditTimestamp(item.createdAt); const expanded = state.adminAuditExpandedId === item.id; const detailId = `audit-detail-${item.id}`; return `<div class="audit-entry${selected.has(item.id) ? ' is-selected' : ''}" data-id="${esc(item.id)}"><label class="admin-record-select"><input type="checkbox" data-admin-record-select="audit" data-id="${esc(item.id)}" aria-label="选择审计记录" ${selected.has(item.id) ? 'checked' : ''}></label><div class="audit-entry-content" role="button" tabindex="0" data-action="toggle-audit-detail" data-audit-expand="${esc(item.id)}" data-id="${esc(item.id)}" aria-expanded="${expanded}" aria-controls="${esc(detailId)}"><strong>${esc(actionLabels[item.action] ?? item.action)}</strong><div class="audit-entry-meta"><span class="audit-entry-actor" title="用户：${esc(item.actor)}"><span class="audit-entry-actor-label">用户</span><span class="audit-entry-actor-name">${esc(item.actor)}</span></span><time class="audit-entry-time" datetime="${esc(item.createdAt)}"><span class="audit-entry-date">${esc(timestamp.date)}</span><span class="audit-entry-clock">${esc(timestamp.time)}</span></time></div>${expanded ? `<div class="audit-entry-detail" id="${esc(detailId)}"><span class="audit-entry-detail-label">对象</span><span class="audit-entry-detail-value">${esc(item.target || '—')}</span><span class="audit-entry-detail-label">详情</span><span class="audit-entry-detail-value">${esc(item.detail || '—')}</span></div>` : ''}</div><button class="record-delete" type="button" data-action="delete-audit-record" data-id="${esc(item.id)}" aria-label="删除审计记录" title="删除审计记录">${deleteRecordIcon()}</button></div>` }).join('')}</div>${pagination}`
            : `${systemAdminRow}${hasRegisteredUsers ? `<div class="admin-user-table-head">${selectAllControl}<span>账号</span><span>注册时间</span><span>操作</span></div><div class="admin-record-list user-history">${userRows}</div>` : '<p class="admin-user-empty" role="status">暂无注册账号</p>'}${pagination}`
        : `<div class="${emptyClass}" role="status">${emptyMessage}</div>`
  return `<section class="admin-record-view" data-admin-view="${state.adminRecordsPanel}" aria-label="${title}" aria-busy="${state.adminLoading ? 'true' : 'false'}">${auditReturn}${auditFilters}${isInvitationPanel ? invitation : ''}${content}</section>`
}

async function refreshAdminPanel() {
  try {
    await Promise.all([loadAdminRecords('invitations'), loadAdminRecords('audit')])
    state.adminError = ''
  } catch (error) {
    state.adminError = error.message
  } finally {
    state.adminLoading = false
    render()
  }
}

async function refreshAdminUsers() {
  try {
    await loadAdminRecords('users')
    state.adminError = ''
  } catch (error) {
    state.adminError = error.message
  } finally {
    state.adminLoading = false
    render()
  }
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(value); return } catch { /* fall through to the document copy path */ }
  }
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.append(textarea)
  textarea.select()
  const copied = document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('copy failed')
}

function patchOverlays() {
  const successNotice = state.successNotice ? loginNoticeCard({ id: 'login-success-notice', title: state.successNotice.title, message: state.successNotice.message, action: 'dismiss-login-success', kind: 'success' }) : ''
  patchSlot('success', successNotice, { key: state.successNotice ?? '' })
  patchSlot('toast', state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status" aria-live="polite" aria-atomic="true">${esc(state.toast.message)}</div>` : '', { key: state.toast ?? '' })
  patchSlot('admin', adminPanel(), { focus: true, key: adminPanelKey() })
  patchSlot('detail', labDetailModal(), { focus: true })
  patchSlot('confirm', state.confirm ? `<div class="dialog-backdrop workspace-dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby="dialog-message"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p id="dialog-message">${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : '', { focus: true, key: state.confirm ?? '' })
}

function render() {
  scheduleSystemPolling()
  if (!state.session || !state.labDetailId) clearDetailPolling()
  document.body.classList.toggle('has-workspace', Boolean(state.session))
  document.body.classList.toggle('has-login-success-notice', Boolean(state.successNotice && state.session))
  document.body.classList.toggle('has-dialog', Boolean(state.confirm || state.labDetailId || state.adminPanelOpen || state.adminRecordsPanel))
  if (state.loading) {
    app.innerHTML = '<div class="loading-screen" role="status" aria-live="polite"><div class="loading-mark" aria-hidden="true"><span></span><span></span><span></span></div><span>正在打开 VulnLab…</span></div>'
    return
  }
  if (!state.session) {
    clearLoginSuccessNoticeTimer()
    app.innerHTML = loginPage()
    window.queueMicrotask(syncPasswordToggles)
    return
  }
  scheduleLoginSuccessNoticeDismiss()
  if (!app.querySelector('.labs-screen')) app.innerHTML = labsShell()
  patchLabs()
  updateLabCanvasScrollState()
  patchOverlays()
  positionOaModeMenu()
  scheduleImportPolling()
  scheduleDetailPolling()
}

function restoreModalFocus() {
  if (state.adminSystemReturnLabId && state.session) {
    const labId = state.adminSystemReturnLabId
    state.adminSystemReturnLabId = null
    state.adminPanelOpen = true
    state.adminView = 'system'
    render()
    const content = document.querySelector('.admin-dialog-content')
    if (content) content.scrollTop = state.adminSystemScrollTop
    void refreshAdminOverview({ showLoading: false }).then(() => {
      if (!state.adminPanelOpen || state.adminView !== 'system' || state.labDetailId) return
      const content = document.querySelector('.admin-dialog-content')
      if (content) content.scrollTop = state.adminSystemScrollTop
      const row = [...document.querySelectorAll('.admin-lab-ranking')].find(item => item.dataset.id === labId)
      ;(row || document.querySelector('[data-section="system"]'))?.focus({ preventScroll: true })
    })
    return
  }
  const target = modalReturnFocus
  modalReturnFocus = null
  const element = target?.element?.isConnected
    ? target.element
    : target
      ? [...document.querySelectorAll('[data-action]')].find(candidate => candidate.dataset.action === target.action && candidate.dataset.id === target.id)
      : null
  if (element) window.queueMicrotask(() => element.focus())
}

function restoreConfirmFocus() {
  const target = confirmReturnFocus
  confirmReturnFocus = null
  window.queueMicrotask(() => {
    if (target?.isConnected) {
      target.focus()
      return
    }
    const fallback = state.adminPanelOpen
      ? document.querySelector('.admin-user-table-head input, .admin-record-filters input[data-admin-select-all="audit"], .invitation-history-head input, .admin-nav-button, .admin-dialog .dialog-close')
      : null
    if (fallback) fallback.focus()
    else restoreModalFocus()
  })
}

function rememberModalFocus(element) {
  modalReturnFocus = element ? { element, action: element.dataset.action, id: element.dataset.id } : null
}

function restoreAdminRecordsFocus() {
  const target = state.adminRecordsReturnFocus
  state.adminRecordsReturnFocus = null
  const element = target?.element?.isConnected
    ? target.element
    : target
      ? [...document.querySelectorAll('[data-action="open-admin-section"], [data-action="open-admin-records"]')].find(candidate => (candidate.dataset.section ?? candidate.dataset.panel) === target.panel)
      : null
  if (element) window.queueMicrotask(() => element.focus())
}

function rememberAdminRecordsFocus(element) {
  state.adminRecordsReturnFocus = element ? { element, panel: element.dataset.panel } : null
}

function clearAuthenticatedState() {
  clearLoginSuccessNoticeTimer()
  state.successNotice = null
  state.authNotice = ''
  clearInvitationCodes()
  state.session = null
  state.csrfToken = ''
  state.labs = []
  state.jobs = []
  state.instances = []
  state.labDetailId = null
  state.adminPanelOpen = false
  state.adminView = 'profile'
  state.adminRecordsPanel = null
  resetAdminLabDraft()
  state.invitation = null
  resetAdminRecords()
  state.toast = null
  resetPasswordVisibility()
  location.hash = 'labs'
}

function openConfirm(title, message, action, confirmLabel = '继续') {
  const active = document.activeElement
  confirmReturnFocus = active instanceof HTMLElement && active !== document.body ? active : null
  state.confirm = { title, message, action, confirmLabel }
  render()
}

async function runAction(action, element) {
  if (action === 'open-instance-page') {
    window.setTimeout(() => {
      if (!state.labDetailId) return
      state.labDetailId = null
      render()
      restoreModalFocus()
    }, 0)
    return
  }
  const canRunWhileBusy = ['nav', 'open-lab-details', 'open-system-lab', 'open-audit-for-date', 'return-to-system-data', 'refresh-system-data', 'retry-admin-records', 'close-lab-details', 'open-admin-panel', 'open-admin-lab-form', 'open-admin-section', 'close-admin-panel', 'open-admin-records', 'close-admin-records', 'toggle-password', 'switch-auth-mode', 'dismiss-login-success', 'dismiss-auth-notice', 'cancel-confirm', 'start-custom-lab-create', 'cancel-custom-lab-editor', 'edit-custom-lab', 'cancel-custom-lab-edit', 'select-lab-source', 'apply-lab-inspection', 'inspect-custom-lab'].includes(action)
  const operationId = element?.dataset?.id ?? ''
  const duplicateOperation = state.busyActions.some(item => item.action === action && item.id === operationId)
  const logoutBusy = action === 'logout' && state.busyActions.length > 0
  if (!canRunWhileBusy && (duplicateOperation || logoutBusy)) {
    setToast('当前操作正在进行中，请稍候。', 'error')
    return
  }
  if (action === 'nav') { navigate(); return }
  if (action === 'refresh-system-data') { await refreshAdminOverview({ trigger: element }); return }
  if (action === 'retry-admin-records') {
    const panel = element.dataset.panel
    if (!['invitations', 'audit', 'users'].includes(panel)) return
    state.adminError = ''
    state.adminLoading = true
    render()
    if (panel === 'audit') await refreshAdminAudit()
    else if (panel === 'users') await refreshAdminUsers()
    else await refreshAdminPanel()
    return
  }
  if (action === 'start-custom-lab-create') {
    resetAdminLabDraft()
    state.adminLabEditorOpen = true
    render()
    focusAdminLabTitle()
    return
  }
  if (action === 'cancel-custom-lab-editor' || action === 'cancel-custom-lab-edit') {
    resetAdminLabDraft()
    render()
    app.querySelector('[data-action="start-custom-lab-create"]')?.focus({ preventScroll: true })
    return
  }
  if (action === 'select-lab-source') {
    const sourceType = element.dataset.source === 'archive' ? 'archive' : 'git'
    if (sourceType === state.adminLabDraft.sourceType) return
    state.adminLabDraft.sourceType = sourceType
    state.adminLabDraft.sourceUrl = ''
    state.adminLabDraft.sourceUploadUrl = ''
    state.adminLabDraft.sourceRef = ''
    state.adminLabDraft.archiveFileName = ''
    state.adminLabArchiveFile = null
    state.adminLabInspection = null
    state.adminLabInspectionError = ''
    render()
    return
  }
  if (action === 'inspect-custom-lab') {
    const form = app.querySelector('#admin-lab-form')
    if (!form || state.adminLabInspectionLoading) return
    const sourceType = state.adminLabDraft.sourceType
    const sourceUrl = String(form.querySelector('[name="sourceUrl"]')?.value ?? '').trim()
    const sourceRef = String(form.querySelector('[name="sourceRef"]')?.value ?? state.adminLabDraft.sourceRef).trim()
    const selectedFile = state.adminLabArchiveFile
    state.adminLabInspection = null
    state.adminLabInspectionError = ''
    state.adminLabInspectionLoading = true
    render()
    try {
      let inspectedSource = sourceUrl
      if (sourceType === 'archive') {
        if (selectedFile && !state.adminLabDraft.sourceUploadUrl) {
          if (Number(selectedFile.size) > LAB_ARCHIVE_MAX_BYTES) throw new ApiError('压缩包不能超过 256 MiB。', 413)
          const uploaded = await uploadLabArchive(selectedFile)
          state.adminLabDraft.sourceUploadUrl = uploaded.sourceUrl
          inspectedSource = uploaded.sourceUrl
        } else {
          inspectedSource = state.adminLabDraft.sourceUploadUrl || (state.adminLabEditId ? state.labs.find(lab => lab.id === state.adminLabEditId)?.sourceUrl ?? '' : '')
        }
        if (!inspectedSource) throw new ApiError('请先选择 ZIP 文件。', 400)
      } else if (!sourceUrl) throw new ApiError('请填写公开 GitHub 或 GitLab 仓库地址。', 400)
      const currentRuntimeMode = String(app.querySelector('#admin-lab-form [name="runtimeMode"]')?.value ?? state.adminLabDraft.runtimeMode)
      const result = await request('/api/lab-source-inspections', { method: 'POST', body: JSON.stringify({ sourceType, sourceUrl: inspectedSource, sourceRef, runtimeMode: currentRuntimeMode }) })
      const currentForm = app.querySelector('#admin-lab-form')
      const currentSourceUrl = String(currentForm?.querySelector('[name="sourceUrl"]')?.value ?? '').trim()
      const currentSourceRef = String(currentForm?.querySelector('[name="sourceRef"]')?.value ?? state.adminLabDraft.sourceRef).trim()
      if (state.adminLabDraft.sourceType === sourceType && String(currentForm?.querySelector('[name="runtimeMode"]')?.value ?? '') === currentRuntimeMode && (sourceType === 'archive' ? state.adminLabArchiveFile === selectedFile : currentSourceUrl === sourceUrl) && currentSourceRef === sourceRef) {
        state.adminLabInspection = result
      }
    } catch (error) {
      state.adminLabInspectionError = error.message
    } finally {
      state.adminLabInspectionLoading = false
      render()
    }
    return
  }
  if (action === 'apply-lab-inspection') {
    if (!Object.hasOwn(customRuntimeModes, element.dataset.mode)) return
    const mode = customRuntimeModes[element.dataset.mode]
    state.adminLabDraft.runtimeMode = element.dataset.mode
    state.adminLabDraft.runtimeKind = mode.kind
    state.adminLabDraft.runtimeProfile = mode.profile
    state.adminLabInspection = null
    state.adminLabInspectionError = ''
    for (const field of ['documentRoot', 'entryPath', 'initSqlPath', 'nodeArgs', 'javaArgs', 'pythonArgs', 'portArg', 'settingsPath']) state.adminLabDraft[field] = ''
    render()
    return
  }
  if (action === 'edit-custom-lab') {
    const lab = state.labs.find(item => item.id === element.dataset.id && !item.builtin)
    if (!lab) return
    state.adminLabEditId = lab.id
    state.adminLabEditorOpen = true
    state.adminLabArchiveFile = null
    state.adminLabDraft = {
      title: lab.title,
      sourceType: lab.sourceType,
      sourceUrl: lab.sourceType === 'git' ? lab.sourceUrl : '',
      sourceUploadUrl: lab.sourceType === 'archive' ? lab.sourceUrl : '',
      sourceRef: lab.sourceType === 'git' && lab.sourceRef.includes('@') ? lab.sourceRef.slice(lab.sourceRef.indexOf('@') + 1) : lab.sourceRef,
      archiveFileName: '',
      runtimeKind: lab.runtimeKind,
      runtimeProfile: lab.runtimeConfig?.profile ?? 'static-php',
      runtimeMode: customRuntimeModeFor(lab),
      documentRoot: lab.runtimeConfig?.documentRoot ?? '',
      entryPath: lab.runtimeConfig?.entryPath ?? '',
      initSqlPath: lab.runtimeConfig?.initSqlPath ?? '',
      nodeArgs: (lab.runtimeConfig?.nodeArgs ?? []).join('\n'),
      javaArgs: (lab.runtimeConfig?.javaArgs ?? []).join('\n'),
      pythonArgs: (lab.runtimeConfig?.pythonArgs ?? []).join('\n'),
      portArg: lab.runtimeConfig?.portArg ?? '',
      settingsPath: lab.runtimeConfig?.settingsPath ?? '',
      category: lab.category,
      difficulty: lab.difficulty,
      license: lab.license,
      summary: lab.summary,
      tags: lab.tags.join(', '),
    }
    state.adminLabInspection = null
    state.adminLabInspectionError = ''
    render()
    focusAdminLabTitle()
    return
  }
  if (action === 'retry-admin-lab') {
    const lab = state.labs.find(item => item.id === element.dataset.id && item.status === 'error')
    if (!lab || !beginBusy(action, lab.id)) return
    try {
      const result = await request(`/api/labs/${encodeURIComponent(lab.id)}/install`, { method: 'POST' })
      if (!result.started && result.job?.status === 'error') throw new ApiError(result.job.error ?? result.job.message ?? '靶场重试未能开始。', 409)
      await refresh()
      setToast(result.started ? '已重新开始准备靶场。' : '靶场准备任务已提交。')
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, lab.id); render() }
    return
  }
  if (action === 'toggle-admin-lab') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    if (!lab) return
    const disabled = element.dataset.disabled === 'true'
    if (disabled) {
      openConfirm('停用靶场', `停用“${lab.title}”后，它会从主页面隐藏，且无法启动；你可以随时恢复。`, { action: 'apply-admin-lab-status', id: lab.id, disabled: true }, '停用靶场')
      return
    }
    if (!beginBusy(action, lab.id)) return
    try {
      await request(`/api/labs/${encodeURIComponent(lab.id)}/status`, { method: 'PATCH', body: JSON.stringify({ disabled: false }) })
      await refresh()
      setToast('靶场已恢复。')
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, lab.id); render() }
    return
  }
  if (action === 'delete-custom-lab') {
    const lab = state.labs.find(item => item.id === element.dataset.id && !item.builtin)
    if (!lab) return
    openConfirm('删除靶场', `删除“${lab.title}”会移除这条配置、关联导入任务和独占导入副本；仍被其他靶场引用的 ZIP 会保留。此操作无法撤销。`, { action: 'confirm-delete-custom-lab', id: lab.id }, '删除靶场')
    return
  }
  if (action === 'confirm-delete-custom-lab') {
    const labId = element.dataset.id
    if (!labId || !beginBusy(action, labId)) return
    try {
      const result = await request(`/api/labs/${encodeURIComponent(labId)}`, { method: 'DELETE' })
      await refresh()
      setToast(result.cleanupPending ? '靶场记录已删除，部分本地资源待清理。' : '靶场及其独占资源已删除。', result.cleanupPending ? 'error' : 'success')
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, labId); render() }
    return
  }
  if (action === 'apply-admin-lab-status') {
    const labId = element.dataset.id
    if (!labId || !beginBusy(action, labId)) return
    try {
      await request(`/api/labs/${encodeURIComponent(labId)}/status`, { method: 'PATCH', body: JSON.stringify({ disabled: true }) })
      await refresh()
      setToast('靶场已停用。')
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, labId); render() }
    return
  }
  if (action === 'open-audit-for-date') {
    const dateValue = element.dataset.activityDate ?? ''
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateValue)) return
    state.adminAuditReturnToSystem = {
      date: dateValue,
      scrollTop: document.querySelector('.admin-dialog-content')?.scrollTop ?? 0,
    }
    state.adminActivityDate = dateValue
    state.adminAuditDate = dateValue
    state.adminAuditAction = 'instance.start'
    state.adminAuditExpandedId = null
    state.adminSelectedRecordIds.audit = []
    state.adminNextCursors.audit = null
    state.adminTotals.audit = 0
    state.adminView = 'audit'
    state.adminRecordsPanel = 'audit'
    state.adminLoading = true
    state.adminError = ''
    render()
    await refreshAdminAudit()
    return
  }
  if (action === 'return-to-system-data') {
    returnToSystemData()
    void refreshAdminOverview({ showLoading: false })
    return
  }
  if (action === 'clear-audit-filters') {
    await setAuditFilters('', '')
    return
  }
  if (action === 'filter-audit-action') {
    await setAuditFilters(app.querySelector('[data-audit-filter="date"]')?.value ?? '', element.dataset.value ?? '')
    app.querySelector('.admin-action-select > summary')?.focus()
    return
  }
  if (action === 'toggle-audit-detail') {
    state.adminAuditExpandedId = state.adminAuditExpandedId === element.dataset.id ? null : element.dataset.id
    render()
    return
  }
  if (action === 'open-system-lab') {
    const version = systemRequestVersion
    try { await refresh() } catch (error) { setToast(error.message, 'error'); return }
    if (version !== systemRequestVersion || !state.adminPanelOpen || state.adminView !== 'system') return
    if (!state.labs.some(item => item.id === element.dataset.id)) return
    state.adminSystemReturnLabId = element.dataset.id
    state.adminSystemScrollTop = document.querySelector('.admin-dialog-content')?.scrollTop ?? 0
    state.adminPanelOpen = false
    state.adminRecordsPanel = null
    state.labDetailId = element.dataset.id
    render()
    if (state.labs.find(item => item.id === element.dataset.id)?.runtimeKind === 'native-oa') void loadOaRuntimeModes(element.dataset.id)
    return
  }
  if (action === 'open-lab-details') {
    if (!state.labs.some(item => item.id === element.dataset.id)) return
    rememberModalFocus(element)
    state.labDetailId = element.dataset.id
    state.oaModeMenuOpen = false
    render()
    if (state.labs.find(item => item.id === element.dataset.id)?.runtimeKind === 'native-oa') void loadOaRuntimeModes(element.dataset.id)
    return
  }
  if (action === 'close-lab-details') {
    state.labDetailId = null
    state.oaModeMenuOpen = false
    render()
    restoreModalFocus()
    return
  }
  if (action === 'open-admin-panel') {
    rememberModalFocus(element)
    state.adminPanelOpen = true
    state.adminView = 'profile'
    state.adminRecordsPanel = null
    resetAdminLabDraft()
    resetAdminRecords()
    state.adminLoading = true
    state.adminError = ''
    render()
    await refreshAdminPanel()
    return
  }
  if (action === 'open-admin-lab-form') {
    if (!state.session || state.session.role !== 'admin') return
    rememberModalFocus(element)
    resetAdminLabDraft()
    state.adminLabEditorOpen = true
    state.adminPanelOpen = true
    state.adminView = 'labs'
    state.adminRecordsPanel = null
    state.adminLoading = false
    render()
    app.querySelector('#admin-lab-form [name="title"]')?.focus()
    return
  }
  if (action === 'open-admin-section') {
    const section = element.dataset.section
    if (!['invitations', 'audit', 'users', 'profile', 'system', 'labs'].includes(section)) return
    if (!state.session || section !== 'profile' && state.session.role !== 'admin') return
    if (section !== 'audit') state.adminAuditReturnToSystem = null
    state.adminView = section
    if (section === 'profile' || section === 'system' || section === 'labs') {
      state.adminRecordsPanel = null
      render()
      if (section === 'system') await refreshAdminOverview()
      document.querySelector('.admin-nav-button.is-active')?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
      return
    }
    state.adminRecordsPanel = section
    state.adminSelectedRecordIds[section] = []
    state.adminError = ''
    state.adminLoading = section === 'invitations' || section === 'users' || section === 'audit'
    render()
    if (section === 'invitations') {
      const requestVersion = state.adminRecordRequestVersions.invitations + 1
      try {
        await loadAdminRecords('invitations')
        if (requestVersion === state.adminRecordRequestVersions.invitations && state.adminRecordsPanel === section) state.adminError = ''
      } catch (error) {
        if (requestVersion === state.adminRecordRequestVersions.invitations && state.adminRecordsPanel === section) state.adminError = error.message
      } finally {
        if (requestVersion === state.adminRecordRequestVersions.invitations && state.adminRecordsPanel === section) {
          state.adminLoading = false
          render()
        }
      }
    }
    if (section === 'users') await refreshAdminUsers()
    if (section === 'audit') await refreshAdminAudit()
    document.querySelector('.admin-nav-button.is-active')?.scrollIntoView({ block: 'nearest', inline: 'nearest' })
    return
  }
  if (action === 'close-admin-panel') {
    state.adminPanelOpen = false
    state.adminView = 'profile'
    state.adminRecordsPanel = null
    resetAdminLabDraft()
    resetAdminRecords()
    render()
    restoreModalFocus()
    return
  }
  if (action === 'open-admin-records') {
    if (!['invitations', 'audit', 'users'].includes(element.dataset.panel)) return
    rememberAdminRecordsFocus(element)
    state.adminAuditReturnToSystem = null
    state.adminView = element.dataset.panel
    state.adminRecordsPanel = element.dataset.panel
    state.adminSelectedRecordIds[state.adminRecordsPanel] = []
    state.adminError = ''
    state.adminLoading = state.adminRecordsPanel === 'users' || state.adminRecordsPanel === 'audit'
    render()
    if (state.adminRecordsPanel === 'users') await refreshAdminUsers()
    if (state.adminRecordsPanel === 'audit') await refreshAdminAudit()
    return
  }
  if (action === 'close-admin-records') {
    if (state.adminRecordsPanel) state.adminSelectedRecordIds[state.adminRecordsPanel] = []
    state.adminRecordsPanel = null
    state.adminView = 'profile'
    render()
    restoreAdminRecordsFocus()
    return
  }
  if (action === 'load-more-admin-records') {
    const panel = element.dataset.panel
    if (!['invitations', 'audit', 'users'].includes(panel) || !state.adminNextCursors[panel]) return
    beginBusy(action, panel)
    try {
      await loadAdminRecords(panel, true)
      state.adminError = ''
    } catch (error) {
      setToast(error.message, 'error')
    } finally {
      endBusy(action, panel)
      render()
    }
    return
  }
  if (action === 'toggle-password') {
    const fieldName = element.dataset.passwordField ?? 'password'
    const input = document.querySelector(`#login-form input[name="${fieldName}"]`)
    const toggle = element
    if (!input || !toggle || !input.value) return
    const visibilityKey = passwordVisibilityKey(fieldName)
    state[visibilityKey] = !state[visibilityKey]
    input.type = state[visibilityKey] ? 'text' : 'password'
    toggle.setAttribute('aria-label', state[visibilityKey] ? '隐藏密码' : '显示密码')
    toggle.setAttribute('aria-pressed', String(state[visibilityKey]))
    toggle.innerHTML = passwordToggleIcon(state[visibilityKey])
    input.focus()
    return
  }
  if (action === 'dismiss-login-error') {
    state.error = ''
    state.loginErrorFields = []
    state.loginFieldErrors = {}
    updateLoginFormView()
    return
  }
  if (action === 'dismiss-auth-notice') {
    state.authNotice = ''
    document.querySelector('#auth-success-notice')?.remove()
    return
  }
  if (action === 'switch-auth-mode') {
    const mode = element.dataset.mode === 'register' ? 'register' : 'login'
    if (state.authMode === mode || state.busy) return
    state.authMode = mode
    state.error = ''
    state.authNotice = ''
    state.loginErrorFields = []
    state.loginFieldErrors = {}
    resetPasswordVisibility()
    updateLoginModeView()
    updateLoginNoticeView()
    return
  }
  if (action === 'dismiss-login-success') { clearLoginSuccessNoticeTimer(); state.successNotice = null; render(); return }
  if (action === 'cancel-confirm') { state.confirm = null; render(); restoreConfirmFocus(); return }
  if (action === 'confirm-action') {
    const next = state.confirm?.action
    state.confirm = null
    if (next) await runAction(next.action, { dataset: { ...next, ids: Array.isArray(next.ids) ? next.ids.join(',') : next.ids ?? '' } })
    else render()
    restoreConfirmFocus()
    return
  }
  if (action === 'generate-invitation') {
    beginBusy(action)
    try {
      state.invitation = await request('/api/auth/invitations', { method: 'POST' })
      saveInvitationCode(state.invitation)
      state.adminLoading = true
      setToast('邀请码已生成。')
      await refreshAdminPanel()
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action); render() }
    return
  }
  if (action === 'copy-invitation' || action === 'copy-invitation-record') {
    const code = action === 'copy-invitation-record' ? getInvitationCode(element.dataset.id) : state.invitation?.code
    if (!code) {
      setToast('该邀请码未在当前浏览器标签页生成，明文无法从记录恢复。', 'error')
      return
    }
    try {
      await copyText(code)
      setToast('邀请码已复制。')
    } catch { setToast('复制失败，请手动复制邀请码。', 'error') }
    return
  }
  if (action === 'revoke-invitation') {
    openConfirm('撤销邀请码', '撤销后该邀请码将立即失效。', { action: 'confirm-revoke-invitation', id: element.dataset.id }, '撤销邀请码')
    return
  }
  if (action === 'delete-invitation-record') {
    openConfirm('删除邀请码记录', '删除后该邀请码记录将从系统中移除，当前邀请码也会立即失效。', { action: 'confirm-delete-invitation-record', id: element.dataset.id }, '删除记录')
    return
  }
  if (action === 'delete-audit-record') {
    openConfirm('删除审计记录', '删除后这条审计记录将从系统中移除。', { action: 'confirm-delete-audit-record', id: element.dataset.id }, '删除记录')
    return
  }
  if (action === 'delete-user-record') {
    const isCurrent = element.dataset.id?.toLowerCase() === state.session?.userName?.toLowerCase()
    const message = isCurrent
      ? '删除当前账号后，该账号的全部登录会话会立即失效，并退出当前系统。此操作无法恢复。'
      : '删除后，该账号及其全部登录会话会立即失效，且无法恢复。'
    openConfirm('删除账号', message, { action: 'confirm-delete-selected-admin-records', panel: 'users', ids: [element.dataset.id] }, '删除账号')
    return
  }
  if (action === 'delete-selected-admin-records') {
    const panel = element.dataset.panel
    const ids = panel && state.adminSelectedRecordIds[panel]
    if (!panel || !ids?.length) return
    const label = panel === 'invitations' ? '邀请码' : panel === 'audit' ? '审计' : '账号'
    const currentIncluded = panel === 'users' && ids.some(id => id.toLowerCase() === state.session?.userName?.toLowerCase())
    const message = currentIncluded
      ? `已选中的 ${ids.length} 个账号包含当前账号，确认后当前登录会话将立即退出，且删除后无法恢复。`
      : `确定删除已选中的 ${ids.length} 个${label}${panel === 'users' ? '' : '记录'}吗？删除后无法恢复。`
    openConfirm(`删除选中的${label}${panel === 'users' ? '' : '记录'}`, message, { action: 'confirm-delete-selected-admin-records', panel, ids: [...ids] }, panel === 'users' ? '删除账号' : '删除')
    return
  }
  if (action === 'set-selected-user-status') {
    if (state.session?.role !== 'admin' || state.session.userName.toLowerCase() !== 'vulnlab') return
    const selectedUsers = state.users.filter(item => item.kind !== 'system' && state.adminSelectedRecordIds.users.includes(item.userName))
    const userNames = selectedUsers.map(item => item.userName)
    if (!userNames.length) return
    const disabled = !selectedUsers.every(item => item.disabled)
    const verb = disabled ? '禁用' : '启用'
    const message = disabled
      ? `确定禁用已选中的 ${userNames.length} 个账号？这些账号将立即退出所有登录会话，直到重新启用。`
      : `确定启用已选中的 ${userNames.length} 个账号？`
    openConfirm(`${verb}账号`, message, { action: 'apply-selected-user-status', userNames, disabled }, `${verb}账号`)
    return
  }
  if (action === 'apply-selected-user-status') {
    if (state.session?.role !== 'admin' || state.session.userName.toLowerCase() !== 'vulnlab') return
    const userNames = Array.isArray(element.dataset.userNames) ? element.dataset.userNames : []
    const disabled = element.dataset.disabled === true || element.dataset.disabled === 'true'
    if (!userNames.length || userNames.some(userName => typeof userName !== 'string')) return
    if (!beginBusy(action, 'users')) return
    try {
      const results = await Promise.allSettled(userNames.map(userName => request(`/api/auth/users/${encodeURIComponent(userName)}/status`, { method: 'PATCH', body: JSON.stringify({ disabled }) })))
      const failedNames = userNames.filter((_, index) => results[index].status === 'rejected')
      state.adminSelectedRecordIds.users = failedNames
      state.adminLoading = true
      await refreshAdminUsers()
      const updatedCount = userNames.length - failedNames.length
      setToast(failedNames.length ? `已${disabled ? '禁用' : '启用'} ${updatedCount} 个账号，${failedNames.length} 个未成功。` : `已${disabled ? '禁用' : '启用'} ${updatedCount} 个账号。`, failedNames.length ? 'error' : 'success')
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, 'users'); render() }
    return
  }
  if (action === 'confirm-revoke-invitation') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/auth/invitations/${element.dataset.id}`, { method: 'DELETE' }); forgetInvitationCode(element.dataset.id); if (state.invitation?.id === element.dataset.id) state.invitation = null; state.adminLoading = true; setToast('邀请码已撤销。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'confirm-delete-invitation-record') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/auth/invitations/${element.dataset.id}/record`, { method: 'DELETE' }); forgetInvitationCode(element.dataset.id); state.adminSelectedRecordIds.invitations = state.adminSelectedRecordIds.invitations.filter(id => id !== element.dataset.id); if (state.invitation?.id === element.dataset.id) state.invitation = null; state.adminLoading = true; setToast('邀请码记录已删除。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'confirm-delete-audit-record') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/audit/${element.dataset.id}`, { method: 'DELETE' }); state.adminSelectedRecordIds.audit = state.adminSelectedRecordIds.audit.filter(id => id !== element.dataset.id); state.adminAuditExpandedId = null; state.adminLoading = true; setToast('审计记录已删除。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'confirm-delete-selected-admin-records') {
    const panel = element.dataset.panel
    const ids = (element.dataset.ids ?? '').split(',').filter(Boolean)
    if (!panel || !ids.length) return
    beginBusy(action, panel)
    try {
      const isUserPanel = panel === 'users'
      const path = panel === 'invitations' ? '/api/auth/invitations' : isUserPanel ? '/api/auth/users' : '/api/audit'
      const body = isUserPanel ? { userNames: ids } : { ids }
      const result = await request(path, { method: 'DELETE', body: JSON.stringify(body) })
      if (result.deleted !== ids.length) throw new ApiError(`仅删除了 ${result.deleted ?? 0} 条记录，请刷新后重试。`, 409, 'RECORD_DELETE_INCOMPLETE')
      state.adminSelectedRecordIds[panel] = []
      if (panel === 'audit') state.adminAuditExpandedId = null
      if (panel === 'invitations') {
        ids.forEach(forgetInvitationCode)
        if (state.invitation && ids.includes(state.invitation.id)) state.invitation = null
      }
      if (result.signedOut) {
        clearAuthenticatedState()
        return
      }
      state.adminLoading = true
      setToast(`已删除 ${result.deleted ?? ids.length} 个${isUserPanel ? '账号' : panel === 'invitations' ? '邀请码' : '审计记录'}。`)
      if (isUserPanel) await refreshAdminUsers()
      else await refreshAdminPanel()
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, panel); render() }
    return
  }
  if (action === 'logout') {
    beginBusy('logout')
    try { await request('/api/auth/logout', { method: 'POST' }); clearAuthenticatedState() } catch (error) { setToast(error.message, 'error') } finally { endBusy('logout'); render() }
    return
  }
  if (action === 'refresh-labs') {
    beginBusy(action)
    try { await refresh(); setToast('靶场状态已更新。') } catch (error) { if (!state.labs.length) state.error = error.message; setToast(error.message, 'error') } finally { endBusy(action); render() }
    return
  }
  if (action === 'toggle-oa-start-menu') {
    state.oaModeMenuOpen = !state.oaModeMenuOpen
    render()
    if (state.oaModeMenuOpen) app.querySelector('.oa-mode-option')?.focus()
    else app.querySelector('[data-action="toggle-oa-start-menu"]')?.focus()
    return
  }
  if (action === 'start-instance') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    const mode = lab?.runtimeKind === 'native-oa' ? element.dataset.mode ?? state.oaMode : undefined
    if (mode === 'local' || mode === 'docker') state.oaMode = mode
    state.oaModeMenuOpen = false
    beginBusy(action, element.dataset.id)
    state.labDetailId = null
    render()
    restoreModalFocus()
    setToast(`${lab?.title ?? '靶场环境'}正在后台启动…`)
    try {
      const result = await request(`/api/labs/${element.dataset.id}/instances`, {
        method: 'POST', timeout: START_REQUEST_TIMEOUT_MS,
        ...(lab?.runtimeKind === 'native-oa' ? { body: JSON.stringify({ mode }) } : {}),
      })
      if (result?.status === 'preparing') await waitForStartedInstance(element.dataset.id, result.job?.id)
      else await refresh()
      setToast(`${lab?.title ?? '靶场环境'}已启动，可直接打开页面。`)
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'renew-instance') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/instances/${element.dataset.id}/renew`, { method: 'POST' }); await refresh(); setToast('实例已续期。') } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'destroy-instance') {
    state.labDetailId = null
    openConfirm('停止靶场环境', '停止后会释放运行端口和实例资源，下次启动会创建新的练习副本。', { action: 'confirm-destroy', id: element.dataset.id }, '停止环境')
    return
  }
  if (action === 'confirm-destroy') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/instances/${element.dataset.id}`, { method: 'DELETE' }); await refresh(); setToast('实例已结束。') } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render(); restoreModalFocus() }
  }
}

app.addEventListener('click', event => {
  const activityCell = event.target.closest?.('[data-activity-date]')
  if (activityCell && !activityCell.dataset.action) {
    event.preventDefault()
    selectActivityDate(activityCell.dataset.activityDate, true)
    return
  }
  const element = event.target.closest?.('[data-action]')
  if (!element) {
    if (state.oaModeMenuOpen && !event.target.closest?.('.oa-mode-menu')) {
      state.oaModeMenuOpen = false
      render()
    }
    return
  }
  if (['close-lab-details', 'close-admin-panel', 'close-admin-records'].includes(element.dataset.action) && element !== event.target) return
  if (element.dataset.action !== 'open-instance-page') event.preventDefault()
  runAction(element.dataset.action, element)
})

app.addEventListener('scroll', event => {
  if (event.target?.matches?.('.lab-canvas')) updateLabCanvasScrollState()
}, { capture: true, passive: true })

for (const type of ['mouseover', 'focusin']) {
  app.addEventListener(type, event => {
    const cell = event.target.closest?.('[data-activity-date]')
    if (cell) selectActivityDate(cell.dataset.activityDate)
  })
}

document.addEventListener('visibilitychange', () => {
  if (document.hidden) clearSystemPolling()
  else void refreshAdminOverview({ showLoading: false })
})

document.addEventListener('pointerdown', event => {
  if (event.target instanceof Element && event.target.closest('.admin-action-select')) return
  document.querySelectorAll('.admin-action-select[open]').forEach(menu => { menu.open = false })
})

window.addEventListener('resize', updateLabCanvasScrollState)
window.addEventListener('resize', positionOpenAuditActionMenus)
window.addEventListener('resize', positionOaModeMenu)

document.addEventListener('scroll', event => {
  if (event.target instanceof Element && event.target.closest('.lab-detail-body')) positionOaModeMenu()
  if (event.target instanceof Element && event.target.closest('.admin-dialog-content')) positionOpenAuditActionMenus()
}, true)

app.addEventListener('toggle', event => {
  const details = event.target
  if (!(details instanceof HTMLDetailsElement) || !details.matches('.admin-action-select')) return
  positionAuditActionMenu(details)
  window.requestAnimationFrame(() => positionAuditActionMenu(details))
}, true)

app.addEventListener('change', event => {
  const input = event.target
  if (!(input instanceof HTMLInputElement || input instanceof HTMLSelectElement || input instanceof HTMLTextAreaElement)) return
  if (input.form?.id === 'admin-lab-form' && input.name === 'archiveFile') {
    const file = input.files?.[0] ?? null
    state.adminLabArchiveFile = file
    state.adminLabDraft.archiveFileName = file?.name ?? ''
    state.adminLabDraft.sourceUploadUrl = ''
    state.adminLabInspection = null
    state.adminLabInspectionError = ''
    const hint = input.form.querySelector('[data-archive-file-name]')
    if (hint) hint.textContent = file ? `${file.name} · ${(file.size / (1024 * 1024)).toFixed(1)} MiB` : '最大 256 MiB'
    return
  }
  if (input.form?.id === 'admin-lab-form' && Object.hasOwn(state.adminLabDraft, input.name)) {
    state.adminLabDraft[input.name] = input.value
    if (input.name === 'runtimeMode') {
      const mode = Object.hasOwn(customRuntimeModes, input.value) ? customRuntimeModes[input.value] : customRuntimeModes['php-static']
      state.adminLabDraft.runtimeKind = mode.kind
      state.adminLabDraft.runtimeProfile = mode.profile
      for (const field of ['documentRoot', 'entryPath', 'initSqlPath', 'nodeArgs', 'javaArgs', 'pythonArgs', 'portArg', 'settingsPath']) state.adminLabDraft[field] = ''
      state.adminLabInspection = null
      state.adminLabInspectionError = ''
      render()
    }
    return
  }
  if (input.dataset.auditFilter) {
    const dateInput = app.querySelector('[data-audit-filter="date"]')
    const actionFilter = app.querySelector('[data-audit-action-filter]')
    void setAuditFilters(dateInput?.value ?? '', actionFilter?.dataset.auditActionFilter ?? '')
    return
  }
  if (input.classList.contains('admin-activity-date')) {
    selectActivityDate(input.value)
    return
  }
  const panel = input.dataset.adminRecordSelect ?? input.dataset.adminSelectAll
  if (!panel || state.adminRecordsPanel !== panel) return
  const selected = new Set(state.adminSelectedRecordIds[panel])
  const recordInputs = [...app.querySelectorAll('[data-admin-record-select]')].filter(item => item.dataset.adminRecordSelect === panel)
  if (input.dataset.adminSelectAll) {
    recordInputs.forEach(item => input.checked ? selected.add(item.dataset.id) : selected.delete(item.dataset.id))
  } else if (input.checked) selected.add(input.dataset.id)
  else selected.delete(input.dataset.id)
  state.adminSelectedRecordIds[panel] = [...selected].filter(Boolean)
  render()
})

app.addEventListener('error', event => {
  const image = event.target
  if (!(image instanceof HTMLImageElement) || image.dataset.coverImage !== 'true') return
  image.hidden = true
  image.closest('.lab-card-media')?.classList.add('cover-load-failed')
}, true)

app.addEventListener('submit', async event => {
  event.preventDefault()
  const form = event.target
  if (form.id === 'admin-lab-form') {
    const editing = Boolean(state.adminLabEditId)
    const editId = state.adminLabEditId ?? ''
    const operation = editing ? 'save-lab' : 'create-lab'
    if (!state.session || state.session.role !== 'admin' || busyFor(operation)) return
    const values = Object.fromEntries(new FormData(form).entries())
    const sourceType = state.adminLabDraft.sourceType
    const modeKey = String(values.runtimeMode ?? state.adminLabDraft.runtimeMode)
    if (!Object.hasOwn(customRuntimeModes, modeKey)) {
      setToast('请先选择当前支持的固定运行方式。', 'error')
      form.querySelector('[name="runtimeMode"]')?.focus()
      return
    }
    const mode = Object.hasOwn(customRuntimeModes, modeKey) ? customRuntimeModes[modeKey] : customRuntimeModes['php-static']
    const archiveValue = values.archiveFile
    const archiveFile = archiveValue && typeof archiveValue === 'object' && Number(archiveValue.size) > 0 ? archiveValue : state.adminLabArchiveFile
    const profile = mode.profile
    const runtimeConfig = { profile }
    const addConfigText = (name) => {
      const value = String(values[name] ?? '').trim()
      if (value) runtimeConfig[name] = value
    }
    if (profile === 'static-php' || profile === 'mysql-php') {
      addConfigText('documentRoot')
      addConfigText('entryPath')
      if (profile === 'mysql-php') addConfigText('initSqlPath')
    } else if (profile === 'prebuilt-node') {
      addConfigText('entryPath')
      const nodeArgs = String(values.nodeArgs ?? '').split(/[\r\n，,]/).map(item => item.trim()).filter(Boolean)
      if (nodeArgs.length) runtimeConfig.nodeArgs = nodeArgs
    } else if (profile === 'webgoat') {
      addConfigText('entryPath')
    } else if (profile === 'java-jar') {
      addConfigText('entryPath')
      addConfigText('portArg')
      const javaArgs = String(values.javaArgs ?? '').split(/[\r\n，,]/).map(item => item.trim()).filter(Boolean)
      if (javaArgs.length) runtimeConfig.javaArgs = javaArgs
    } else {
      addConfigText('entryPath')
      if (profile === 'python-script') {
        addConfigText('portArg')
        const pythonArgs = String(values.pythonArgs ?? '').split(/[\r\n，,]/).map(item => item.trim()).filter(Boolean)
        if (pythonArgs.length) runtimeConfig.pythonArgs = pythonArgs
      } else addConfigText('settingsPath')
    }
    const payload = {
      title: String(values.title ?? '').trim(),
      sourceType,
      sourceUrl: sourceType === 'git' ? String(values.sourceUrl ?? '').trim() : '',
      sourceRef: sourceType === 'git' ? String(values.sourceRef ?? '').trim() : '',
      runtimeMode: modeKey,
      runtimeKind: mode.kind,
      runtimeProfile: profile,
      profile,
      runtimeConfig,
      category: String(values.category ?? '').trim(),
      difficulty: String(values.difficulty ?? '入门'),
      license: String(values.license ?? '').trim(),
      summary: String(values.summary ?? '').trim(),
      tags: String(values.tags ?? '').split(/[，,]/).map(item => item.trim()).filter(Boolean),
    }
    if (!payload.title) {
      setToast('请填写靶场名称。', 'error')
      return
    }
    const currentLab = editing ? state.labs.find(lab => lab.id === editId) : null
    if (sourceType === 'git' && !payload.sourceUrl) {
      setToast('请填写靶场来源地址。', 'error')
      return
    }
    if (sourceType === 'archive' && !archiveFile && !state.adminLabDraft.sourceUploadUrl && (!editing || currentLab?.sourceType !== 'archive')) {
      setToast('请选择有效的 ZIP 压缩包。', 'error')
      return
    }
    if (sourceType === 'archive' && archiveFile && Number(archiveFile.size) > LAB_ARCHIVE_MAX_BYTES) {
      setToast('压缩包不能超过 256 MiB。', 'error')
      return
    }
    state.adminLabDraft = { ...state.adminLabDraft, ...payload, tags: payload.tags.join(', ') }
    beginBusy(operation, state.adminLabEditId ?? '')
    try {
      if (sourceType === 'archive' && archiveFile && !state.adminLabDraft.sourceUploadUrl) {
        const uploaded = await uploadLabArchive(archiveFile)
        state.adminLabDraft.sourceUploadUrl = uploaded.sourceUrl
      }
      if (sourceType === 'archive') payload.sourceUrl = state.adminLabDraft.sourceUploadUrl || currentLab?.sourceUrl || ''
      await request(editing ? `/api/labs/${encodeURIComponent(editId)}` : '/api/labs', { method: editing ? 'PATCH' : 'POST', body: JSON.stringify(payload), timeout: START_REQUEST_TIMEOUT_MS })
      await refresh()
      resetAdminLabDraft()
      state.adminView = 'labs'
      state.adminRecordsPanel = null
      setToast(editing ? '靶场修改已保存。' : '靶场已添加，资源将在后台准备。')
    } catch (error) {
      setToast(error.message, 'error')
    } finally {
      endBusy(operation, editing ? editId : '')
      render()
    }
    return
  }
  if (form.id === 'login-form' && state.busy) return
  const values = Object.fromEntries(new FormData(form).entries())
  if (form.id === 'login-form') {
    state.busy = true; state.error = ''; state.loginErrorFields = []; state.loginFieldErrors = {}
    updateLoginFormView()
    const userName = typeof values.userName === 'string' ? values.userName.trim() : ''
    const password = typeof values.password === 'string' ? values.password : ''
    state.loginUserName = userName
    if (state.authMode === 'register') {
      const validation = registrationValidation(values)
      if (validation) {
        state.loginFieldErrors = validation
        state.busy = false
        updateLoginFormView()
        document.querySelector(`[name="${Object.keys(validation)[0]}"]`)?.focus()
        return
      }
      try {
        await request('/api/auth/register', { method: 'POST', body: JSON.stringify(values) })
        state.authMode = 'login'
        state.authNotice = '注册成功，请使用新账号登录'
        state.busy = false
        resetPasswordVisibility()
        updateLoginModeView()
        updateLoginNoticeView()
        window.queueMicrotask(() => document.querySelector('[name="userName"]')?.focus())
      } catch (error) {
        state.error = authErrorMessage(error)
        state.loginErrorFields = []
        state.busy = false
        updateLoginFormView()
        document.querySelector('[name="userName"]')?.focus()
      }
      return
    }
    const missingFields = [!userName ? 'userName' : null, !password ? 'password' : null].filter(Boolean)
    if (missingFields.length) {
      state.loginFieldErrors = Object.fromEntries(missingFields.map(field => [field, field === 'userName' ? '请输入账号' : '请输入密码']))
      state.busy = false
      updateLoginFormView()
      document.querySelector(`[name="${missingFields[0]}"]`)?.focus()
      return
    }
    try {
      const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(values) })
      state.session = session
      state.csrfToken = session.csrfToken
      restoreInvitationCodes()
      state.authNotice = ''
      await refresh()
      state.successNotice = { title: '登录成功', message: '身份验证通过，正在进入系统' }
      resetPasswordVisibility()
      navigate('labs')
      state.busy = false
      render()
    } catch (error) {
      state.successNotice = null
      state.error = authErrorMessage(error)
      state.loginErrorFields = []
      state.busy = false
      if (state.session) render()
      else {
        updateLoginFormView()
        document.querySelector('[name="userName"]')?.focus()
      }
    }
    return
  }
})

app.addEventListener('input', event => {
  const input = event.target
  if (input.form?.id === 'admin-lab-form' && Object.hasOwn(state.adminLabDraft, input.name)) {
    state.adminLabDraft[input.name] = input.value
    if (input.name === 'sourceUrl' || input.name === 'sourceRef') {
      state.adminLabInspection = null
      state.adminLabInspectionError = ''
    }
    return
  }
  if (!input.form || input.form.id !== 'login-form') return
  if (['password', 'passwordConfirm'].includes(input.name)) syncPasswordToggles()
  if (input.name === 'userName') state.loginUserName = input.value
  if (state.authNotice) { state.authNotice = ''; document.querySelector('#auth-success-notice')?.remove() }
  const hadFieldError = Object.hasOwn(state.loginFieldErrors, input.name)
  delete state.loginFieldErrors[input.name]
  if (!state.error) {
    if (hadFieldError) updateLoginFormView()
    return
  }
  state.error = ''
  state.loginErrorFields = []
  state.loginFieldErrors = {}
  input.form.querySelector('#login-error')?.remove()
  input.form.querySelectorAll('input').forEach(field => {
    field.setAttribute('aria-invalid', 'false')
    field.removeAttribute('aria-describedby')
  })
})

document.addEventListener('keydown', event => {
  const auditSummary = event.target.closest?.('[data-action="toggle-audit-detail"]')
  if (auditSummary && (event.key === 'Enter' || event.key === ' ')) {
    event.preventDefault()
    void runAction('toggle-audit-detail', auditSummary)
    return
  }
  const activityCell = event.target.closest?.('[data-activity-date]')
  if (activityCell && ['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
    const cells = [...document.querySelectorAll('[data-activity-date]')]
    const index = cells.indexOf(activityCell)
    const delta = event.key === 'ArrowUp' ? -1 : event.key === 'ArrowDown' ? 1 : event.key === 'ArrowLeft' ? -7 : event.key === 'ArrowRight' ? 7 : 0
    const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? cells.length - 1 : index + delta
    event.preventDefault()
    if (index >= 0 && nextIndex >= 0 && nextIndex < cells.length) {
      selectActivityDate(cells[nextIndex].dataset.activityDate, true)
    }
    return
  }
  const dialogs = [...document.querySelectorAll('[role="dialog"]')]
  const dialog = dialogs[dialogs.length - 1]
  if (!dialog) return
  if (event.key === 'Escape') {
    if (state.oaModeMenuOpen) {
      event.preventDefault()
      state.oaModeMenuOpen = false
      render()
      app.querySelector('[data-action="toggle-oa-start-menu"]')?.focus()
      return
    }
    const actionMenu = dialog.querySelector('.admin-action-select[open]')
    if (actionMenu) {
      event.preventDefault()
      actionMenu.open = false
      actionMenu.querySelector('summary')?.focus()
      return
    }
    if (state.confirm) { state.confirm = null; render(); restoreConfirmFocus(); return }
    else if (state.adminRecordsPanel === 'audit' && state.adminAuditReturnToSystem) { returnToSystemData(); void refreshAdminOverview({ showLoading: false }); return }
    else if (state.adminRecordsPanel) { state.adminRecordsPanel = null; state.adminView = 'profile'; render(); restoreAdminRecordsFocus(); return }
    else if (state.labDetailId) { state.labDetailId = null; state.oaModeMenuOpen = false }
    else if (state.adminPanelOpen) { state.adminPanelOpen = false; state.adminView = 'profile'; render(); restoreModalFocus(); return }
    else return
    render()
    restoreModalFocus()
    return
  }
  if (event.key !== 'Tab') return
  const focusable = [...dialog.querySelectorAll('button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])')].filter(item => !item.disabled && item.tabIndex >= 0 && item.offsetParent !== null)
  if (!focusable.length) return
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
})

window.addEventListener('hashchange', render)
bootstrap()
