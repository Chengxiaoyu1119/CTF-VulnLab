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
const OVERLAY_EXIT_DURATION = 190
const accountPattern = /^[A-Za-z0-9._-]{3,32}$/

const state = {
  session: null,
  csrfToken: '',
  labs: [],
  jobs: [],
  instances: [],
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
  adminRecordsPanel: null,
  adminRecordsReturnFocus: null,
  adminSelectedRecordIds: { invitations: [], audit: [], users: [] },
  adminNextCursors: { invitations: null, audit: null, users: null },
  adminTotals: { invitations: 0, audit: 0, users: 0 },
  invitation: null,
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

const adminRecordPath = panel => panel === 'invitations' ? '/api/auth/invitations' : panel === 'users' ? '/api/auth/users' : '/api/audit'
const adminRecordId = (panel, item) => panel === 'users' ? item.userName : item.id

function resetAdminRecords() {
  systemRequestVersion += 1
  clearSystemPolling()
  state.adminSelectedRecordIds = { invitations: [], audit: [], users: [] }
  state.adminNextCursors = { invitations: null, audit: null, users: null }
  state.adminTotals = { invitations: 0, audit: 0, users: 0 }
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

async function loadAdminRecords(panel, append = false) {
  const cursor = append ? state.adminNextCursors[panel] : null
  const page = await request(`${adminRecordPath(panel)}${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, { cache: 'no-store', recordPage: true })
  const items = Array.isArray(page?.items) ? page.items : []
  state[panel] = append ? [...state[panel], ...items] : items
  state.adminNextCursors[panel] = typeof page?.nextCursor === 'string' ? page.nextCursor : null
  const total = Number(page?.total)
  state.adminTotals[panel] = Number.isSafeInteger(total) && total >= state[panel].length ? total : state[panel].length
  state.adminSelectedRecordIds[panel] = state.adminSelectedRecordIds[panel].filter(id => state[panel].some(item => adminRecordId(panel, item) === id))
}

async function refreshAdminOverview() {
  if (state.adminSystemLoading || !state.session || !state.adminPanelOpen || state.adminView !== 'system') return
  const version = systemRequestVersion
  state.adminSystemLoading = true
  state.adminSystemError = ''
  render()
  try {
    const overview = await request('/api/overview', { cache: 'no-store' })
    if (!overview?.activity || overview.activity.daily?.length !== 365) throw new ApiError('系统数据暂时不可用，请重试。', 502)
    if (version === systemRequestVersion) state.adminOverview = overview
  } catch (error) {
    if (version === systemRequestVersion) state.adminSystemError = error.message
  } finally {
    if (version === systemRequestVersion) {
      state.adminSystemLoading = false
      render()
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
  if (state.adminPanelOpen && state.adminView === 'system') await refreshAdminOverview()
}

async function bootstrap() {
  try {
    state.session = await request('/api/auth/session')
    state.csrfToken = state.session?.csrfToken ?? ''
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
    void refreshAdminOverview()
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
  return `<div class="labs-screen">
    <section class="lab-workspace">
      <div class="workspace-brand">
        <img class="workspace-brand-mark" src="/favicon.png" alt="" />
        <h1 class="workspace-brand-name" aria-label="VulnLab"><button class="workspace-brand-trigger" type="button" data-action="open-admin-panel" aria-label="管理中心" title="打开管理中心">VulnLab</button></h1>
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
  dvwa: '/covers/dvwa.png',
  pikachu: '/covers/pikachu.png',
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
  : ''
const latestFailedJob = lab => state.jobs
  .filter(job => job.labId === lab.id && job.status === 'error')
  .sort((left, right) => String(right.updatedAt ?? '').localeCompare(String(left.updatedAt ?? '')))[0] ?? null
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
  const failedJob = lab.status === 'error' ? latestFailedJob(lab) : null
  const failed = lab.status === 'error'
  const failureMessage = readableError(failedJob?.error)
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
    primaryAction = `<button class="button ${failed ? 'button-danger' : 'button-primary'} lab-detail-action" type="button" data-action="start-instance" data-id="${esc(lab.id)}">${failed ? '重试启动' : '启动环境'}</button>`
  } else {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待准备</span>'
  }
  const detailState = instance ? 'running' : starting ? 'starting' : preparing ? 'preparing' : failed ? 'error' : cataloged ? 'cataloged' : 'ready'
  const stateLabel = preparing ? '准备中' : ''
  const facts = [lab.category, lab.difficulty].filter(Boolean).map(esc).join('<span aria-hidden="true">·</span>')
  const tags = Array.isArray(lab.tags) && lab.tags.length ? `<div class="lab-detail-tags">${lab.tags.slice(0, 4).map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''
  const preparationInfo = preparing ? `<div class="lab-detail-progress" role="status" aria-live="polite"><div class="lab-detail-progress-head"><span>${esc(jobStageLabel(activeJob?.stage))}</span><strong>${jobProgress(activeJob)}%</strong></div><div class="lab-detail-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${jobProgress(activeJob)}"><span class="lab-detail-progress-fill" style="--progress:${jobProgress(activeJob)}%"></span></div><p class="lab-detail-progress-message">${esc(activeJob?.message ?? '正在准备靶场资源，请稍候。')}</p></div>` : ''
  const errorInfo = failureMessage ? `<p class="lab-detail-error" role="alert">${esc(failureMessage)}</p>` : ''
  const runningInfo = instance
    ? (() => { const lease = leaseDisplay(instance.expiresAt); return `<section class="lab-detail-runtime" aria-label="运行状态"><div class="lab-detail-runtime-head"><div><span class="lab-detail-running-dot" aria-hidden="true"></span><strong>运行中</strong></div><strong class="lab-detail-remaining">${esc(lease.remaining)}</strong></div><div class="lab-detail-runtime-meta"><time datetime="${esc(instance.expiresAt)}">${esc(lease.expires)}</time><div class="lab-detail-endpoint" aria-label="入口 ${esc(instance.endpoint)}"><code>${esc(instance.endpoint)}</code></div></div></section>` })()
    : ''
  const managementActions = instance && admin
    ? `<button class="button button-quiet lab-detail-stop lab-detail-action" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button><button class="button button-outline lab-detail-action" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button>`
    : ''
  return `<div class="dialog-backdrop workspace-dialog-backdrop lab-detail-backdrop" data-action="close-lab-details"><section class="dialog lab-detail-dialog" data-state="${detailState}" role="dialog" aria-modal="true" aria-labelledby="lab-detail-title"><div class="lab-card-media lab-detail-cover" data-cover="${coverVariant(lab)}">${coverArt(lab)}<button class="dialog-close lab-detail-close" type="button" data-action="close-lab-details" aria-label="关闭靶场信息">×</button></div><div class="lab-detail-body"><div class="lab-detail-heading"><div><h2 id="lab-detail-title">${esc(lab.title)}</h2><div class="lab-detail-facts">${facts}</div></div>${stateLabel ? `<span class="lab-detail-state">${esc(stateLabel)}</span>` : ''}</div>${lab.summary ? `<p class="lab-detail-summary">${esc(lab.summary)}</p>` : ''}${tags}${preparationInfo}${errorInfo}${runningInfo}<div class="lab-detail-actions">${managementActions}${primaryAction}</div></div></section></div>`
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

async function waitForStartedInstance(labId) {
  const deadline = Date.now() + START_WAIT_TIMEOUT_MS
  while (Date.now() < deadline) {
    await sleep(Math.min(1000, deadline - Date.now()))
    await refresh()
    if (state.instances.some(instance => instance.labId === labId && instance.status === 'running')) return
    const lab = state.labs.find(item => item.id === labId)
    const job = state.jobs.find(item => item.labId === labId && ['queued', 'importing'].includes(item.status))
    const completedWithError = state.jobs.find(item => item.labId === labId && item.status === 'completed' && item.error)
    if (completedWithError?.error) throw new ApiError(completedWithError.error, 409)
    if (lab?.status === 'error' || (!job && state.jobs.some(item => item.labId === labId && item.status === 'error'))) {
      const failedJob = state.jobs.find(item => item.labId === labId && item.status === 'error')
      throw new ApiError(failedJob?.error ?? '靶场启动未完成，请稍后查看状态。', 409)
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

function patchLabs() {
  const canvas = app.querySelector('.lab-canvas')
  const visibleLabs = state.labs
  if (state.error && !visibleLabs.length) {
    const content = `<div class="empty-state lab-empty-state"><p>${esc(state.error)}</p><button class="button button-primary" type="button" data-action="refresh-labs">重新连接</button></div>`
    if (canvas.innerHTML !== content) canvas.innerHTML = content
    return
  }
  if (!visibleLabs.length) {
    const content = '<div class="empty-state lab-empty-state"><p>暂无可用靶场。</p><button class="button button-primary" type="button" data-action="refresh-labs">重新检查</button></div>'
    if (canvas.innerHTML !== content) canvas.innerHTML = content
    return
  }
  let grid = canvas.querySelector('.lab-grid')
  if (!grid) {
    canvas.innerHTML = '<div class="lab-grid" aria-label="靶场列表"></div>'
    grid = canvas.querySelector('.lab-grid')
  }
  const cards = new Map([...grid.querySelectorAll('.lab-card')].map(card => [card.querySelector('[data-id]')?.dataset.id, card]))
  visibleLabs.forEach((lab, index) => {
    let card = cards.get(lab.id)
    if (!card) {
      const template = document.createElement('template')
      template.innerHTML = labCard(lab, index)
      card = template.content.firstElementChild
    }
    if (grid.children[index] !== card) grid.insertBefore(card, grid.children[index] ?? null)
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
    ? { action: document.activeElement.dataset.action ?? '', id: document.activeElement.dataset.id ?? '', section: document.activeElement.dataset.section ?? '', activityDate: document.activeElement.dataset.activityDate ?? '', recordSelect: document.activeElement.dataset.adminRecordSelect ?? '', selectAll: document.activeElement.dataset.adminSelectAll ?? '' }
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
    const focusable = [...slot.querySelectorAll('button, a[href], input, select, textarea')].filter(item => !item.disabled && item.tabIndex >= 0 && item.offsetParent !== null)
    const target = active && focusable.find(item => (item.dataset.action ?? '') === active.action && (item.dataset.id ?? '') === active.id && (item.dataset.section ?? '') === active.section && (item.dataset.activityDate ?? '') === active.activityDate && (item.dataset.adminRecordSelect ?? '') === active.recordSelect && (item.dataset.adminSelectAll ?? '') === active.selectAll)
    ;(target || focusable[0])?.focus({ preventScroll: true })
  })
}

function adminPanel() {
  if (!state.adminPanelOpen) return ''
  const isAdmin = state.session?.role === 'admin'
  const view = state.adminView
  const profile = state.session ? (() => {
    return `<section class="profile-view" aria-labelledby="profile-title"><div class="profile-avatar-frame"><img class="profile-avatar" src="/favicon.png" alt="VulnLab项目图标" /></div><h3 id="profile-title" class="profile-name">${esc(state.session.userName)}</h3></section>`
  })() : ''
  const content = view === 'system' ? adminSystemPanel() : ['invitations', 'audit', 'users'].includes(view) ? adminRecordsPanel() : profile
  const navItems = isAdmin ? [['profile', '个人中心'], ['system', '系统数据'], ['users', '账号管理'], ['audit', '审计记录'], ['invitations', '邀请管理']] : [['profile', '个人中心']]
  const nav = navItems.map(([section, label]) => `<button class="admin-nav-button${view === section ? ' is-active' : ''}" type="button" data-action="open-admin-section" data-section="${section}" aria-label="${label}" aria-current="${view === section ? 'page' : 'false'}"><span>${label}</span></button>`).join('')
  const title = isAdmin ? '管理中心' : '个人中心'
  const generateLabel = busyFor('generate-invitation') ? '生成中…' : '生成邀请码'
  const footer = isAdmin && view === 'invitations' ? `<button class="button button-primary" type="button" data-action="generate-invitation" ${busyFor('generate-invitation') ? 'disabled' : ''}>${generateLabel}</button>` : ''
  const dialogVariant = view === 'profile' ? 'admin-dialog-profile' : 'admin-dialog-records'
  return `<div class="dialog-backdrop workspace-dialog-backdrop" data-action="close-admin-panel"><section class="dialog admin-dialog ${dialogVariant}" data-admin-dialog-view="${view}" role="dialog" aria-modal="true" aria-labelledby="admin-dialog-title"><div class="admin-layout"><aside class="admin-sidebar"><nav class="admin-nav" aria-label="${title}导航">${nav}</nav></aside><div class="admin-dialog-main"><h2 id="admin-dialog-title" class="sr-only">${title}</h2><div class="admin-dialog-tools"><button class="dialog-close" type="button" data-action="close-admin-panel" aria-label="关闭${title}">×</button></div><div class="admin-dialog-content">${content}</div><div class="dialog-actions"><div class="admin-dialog-primary">${footer}</div><button class="button button-danger" type="button" data-action="logout" ${busyFor('logout') ? 'disabled' : ''}>退出系统</button></div></div></div></section></div>`
}

function adminSystemPanel() {
  const overview = state.adminOverview
  const activity = overview?.activity
  const refreshButton = `<button class="admin-system-refresh" type="button" data-action="refresh-system-data" aria-label="刷新系统数据" ${state.adminSystemLoading ? 'disabled' : ''}>${state.adminSystemLoading ? '更新中…' : '刷新'}</button>`
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
    return `<button class="admin-activity-cell is-level-${level}" type="button" data-activity-date="${esc(item.date)}" tabindex="${item.date === selected.date ? 0 : -1}" aria-label="${esc(label)}" title="${esc(label)}"></button>`
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
  return `<section class="admin-system-view" data-admin-view="system" aria-label="系统数据" aria-busy="${state.adminSystemLoading}">
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

function adminRecordsPanel() {
  if (!state.adminPanelOpen || !state.adminRecordsPanel) return ''
  const statusLabels = { active: '有效', expired: '已过期', used: '已使用', revoked: '已撤销' }
  const actionLabels = {
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
  const invitation = state.invitation ? `<div class="invitation-card"><div class="invitation-card-heading"><span>当前邀请码</span><time datetime="${esc(state.invitation.expiresAt)}">有效至 ${esc(date(state.invitation.expiresAt))}</time></div><code>${esc(state.invitation.code)}</code><div class="invitation-card-actions"><button class="button button-outline" type="button" data-action="copy-invitation">复制邀请码</button><button class="button button-quiet" type="button" data-action="revoke-invitation" data-id="${esc(state.invitation.id)}">撤销</button></div></div>` : ''
  const records = isInvitationPanel ? state.invitations : isAuditPanel ? state.audit : state.users
  const recordId = item => isUserPanel ? item.userName : item.id
  const selectedIds = (state.adminSelectedRecordIds[state.adminRecordsPanel] ?? []).filter(id => records.some(item => recordId(item) === id))
  const selected = new Set(selectedIds)
  const allSelected = records.length > 0 && selectedIds.length === records.length
  const recordLabel = isInvitationPanel ? '邀请码' : isAuditPanel ? '审计' : '账号'
  const total = state.adminTotals[state.adminRecordsPanel]
  const nextCursor = state.adminNextCursors[state.adminRecordsPanel]
  const selectionCount = selectedIds.length ? `<span class="admin-selection-count" aria-live="polite">已选 ${selectedIds.length} 条</span>` : ''
  const selectionToolbar = records.length ? `<div class="admin-record-toolbar"><label class="admin-select-all"><input type="checkbox" data-admin-select-all="${state.adminRecordsPanel}" aria-label="全选已加载的${recordLabel}记录" ${allSelected ? 'checked' : ''}><span>全选</span></label>${selectionCount}<button class="button button-danger admin-bulk-delete" type="button" data-action="delete-selected-admin-records" data-panel="${state.adminRecordsPanel}" ${selectedIds.length ? '' : 'disabled'}>删除所选</button></div>` : ''
  const pagination = nextCursor ? `<div class="admin-record-pagination"><span class="sr-only">还有更多${recordLabel}记录</span><button class="button button-outline admin-load-more" type="button" data-action="load-more-admin-records" data-panel="${state.adminRecordsPanel}" ${busyFor('load-more-admin-records', state.adminRecordsPanel) ? 'disabled' : ''}>${busyFor('load-more-admin-records', state.adminRecordsPanel) ? '加载中…' : '加载更多'}</button></div>` : ''
  const userRows = isUserPanel ? records.map(item => {
    const timestamp = auditTimestamp(item.createdAt)
    const current = state.session?.userName?.toLowerCase() === item.userName.toLowerCase()
    return `<div class="admin-user-entry${selected.has(item.userName) ? ' is-selected' : ''}" data-id="${esc(item.userName)}"><label class="admin-record-select"><input type="checkbox" data-admin-record-select="users" data-id="${esc(item.userName)}" aria-label="选择账号 ${esc(item.userName)}" ${selected.has(item.userName) ? 'checked' : ''}></label><div class="admin-user-content"><div class="admin-user-heading"><strong>账号 <span class="admin-user-name" title="${esc(item.userName)}">${esc(item.userName)}</span></strong>${current ? '<span class="admin-user-current">当前登录</span>' : ''}</div><time class="admin-user-time" datetime="${esc(item.createdAt)}"><span class="admin-user-time-label">注册于</span><span class="admin-user-date">${esc(timestamp.date)}</span><span class="admin-user-clock">${esc(timestamp.time)}</span></time></div><button class="record-delete" type="button" data-action="delete-user-record" data-id="${esc(item.userName)}" aria-label="删除账号 ${esc(item.userName)}" title="删除账号">${deleteRecordIcon()}</button></div>`
  }).join('') : ''
  const content = state.adminLoading
    ? '<div class="admin-loading" role="status">正在更新记录…</div>'
    : state.adminError
      ? `<div class="admin-inline-error" role="alert">${esc(state.adminError)}</div>`
      : records.length
        ? isInvitationPanel
          ? `${selectionToolbar}<div class="admin-record-list invitation-history">${records.map(item => `<div class="invitation-history-card${selected.has(item.id) ? ' is-selected' : ''}" data-id="${esc(item.id)}" data-status="${esc(item.status)}"><label class="admin-record-select"><input type="checkbox" data-admin-record-select="invitations" data-id="${esc(item.id)}" aria-label="选择邀请码记录" ${selected.has(item.id) ? 'checked' : ''}></label><div class="invitation-history-main"><strong>${esc(statusLabels[item.status] ?? item.status)}</strong><time datetime="${esc(item.createdAt)}">生成于 ${esc(date(item.createdAt))}</time></div><div class="invitation-history-meta"><span>有效至 ${esc(date(item.expiresAt))}</span><button class="record-delete" type="button" data-action="delete-invitation-record" data-id="${esc(item.id)}" aria-label="删除邀请码记录" title="删除邀请码记录">${deleteRecordIcon()}</button></div></div>`).join('')}</div>${pagination}`
          : isAuditPanel
            ? `${selectionToolbar}<div class="admin-record-list audit-history">${records.map(item => { const timestamp = auditTimestamp(item.createdAt); return `<div class="audit-entry${selected.has(item.id) ? ' is-selected' : ''}" data-id="${esc(item.id)}"><label class="admin-record-select"><input type="checkbox" data-admin-record-select="audit" data-id="${esc(item.id)}" aria-label="选择审计记录" ${selected.has(item.id) ? 'checked' : ''}></label><div class="audit-entry-content"><strong>${esc(actionLabels[item.action] ?? item.action)}</strong><div class="audit-entry-meta"><span class="audit-entry-actor" title="用户：${esc(item.actor)}"><span class="audit-entry-actor-label">用户</span><span class="audit-entry-actor-name">${esc(item.actor)}</span></span><time class="audit-entry-time" datetime="${esc(item.createdAt)}"><span class="audit-entry-date">${esc(timestamp.date)}</span><span class="audit-entry-clock">${esc(timestamp.time)}</span></time></div></div><button class="record-delete" type="button" data-action="delete-audit-record" data-id="${esc(item.id)}" aria-label="删除审计记录" title="删除审计记录">${deleteRecordIcon()}</button></div>` }).join('')}</div>${pagination}`
            : `${selectionToolbar}<div class="admin-record-list user-history">${userRows}</div>${pagination}`
        : `<div class="admin-empty-state" role="status">暂无${isInvitationPanel ? '邀请码' : isAuditPanel ? '相关审计' : '注册账号'}记录。</div>`
  return `<section class="admin-record-view" data-admin-view="${state.adminRecordsPanel}" aria-label="${title}" aria-busy="${state.adminLoading ? 'true' : 'false'}">${isInvitationPanel ? invitation : ''}${content}</section>`
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
  const adminRecordsKey = ['invitations', 'audit', 'users'].map(panel => `${state[panel].length}:${state.adminTotals[panel]}:${state.adminNextCursors[panel] ?? ''}`).join(':')
  const adminOverviewKey = state.adminOverview?.activity ? `${state.adminOverview.activity.rangeEnd}:${state.adminOverview.activity.launchCount}:${state.adminOverview.activity.activeDays}:${state.adminOverview.runningInstanceCount}` : ''
  patchSlot('admin', adminPanel(), { focus: true, key: state.adminPanelOpen ? `${state.adminView}:${state.invitation?.id ?? 'open'}:${state.adminLoading}:${state.adminSystemLoading}:${adminRecordsKey}:${adminOverviewKey}:${state.adminError}:${state.adminSystemError}` : '' })
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
    void refreshAdminOverview().then(() => {
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
      ? document.querySelector('.admin-record-toolbar input, .admin-nav-button, .admin-dialog .dialog-close')
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
  state.session = null
  state.csrfToken = ''
  state.labs = []
  state.jobs = []
  state.instances = []
  state.labDetailId = null
  state.adminPanelOpen = false
  state.adminView = 'profile'
  state.adminRecordsPanel = null
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
  const canRunWhileBusy = ['nav', 'open-lab-details', 'open-system-lab', 'refresh-system-data', 'close-lab-details', 'open-admin-panel', 'open-admin-section', 'close-admin-panel', 'open-admin-records', 'close-admin-records', 'toggle-password', 'switch-auth-mode', 'dismiss-login-success', 'dismiss-auth-notice', 'cancel-confirm'].includes(action)
  const operationId = element?.dataset?.id ?? ''
  const duplicateOperation = state.busyActions.some(item => item.action === action && item.id === operationId)
  const logoutBusy = action === 'logout' && state.busyActions.length > 0
  if (!canRunWhileBusy && (duplicateOperation || logoutBusy)) {
    setToast('当前操作正在进行中，请稍候。', 'error')
    return
  }
  if (action === 'nav') { navigate(); return }
  if (action === 'refresh-system-data') { await refreshAdminOverview(); return }
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
    return
  }
  if (action === 'open-lab-details') {
    if (!state.labs.some(item => item.id === element.dataset.id)) return
    rememberModalFocus(element)
    state.labDetailId = element.dataset.id
    render()
    return
  }
  if (action === 'close-lab-details') {
    state.labDetailId = null
    render()
    restoreModalFocus()
    return
  }
  if (action === 'open-admin-panel') {
    rememberModalFocus(element)
    state.adminPanelOpen = true
    state.adminView = 'profile'
    state.adminRecordsPanel = null
    resetAdminRecords()
    state.adminLoading = true
    state.adminError = ''
    render()
    await refreshAdminPanel()
    return
  }
  if (action === 'open-admin-section') {
    const section = element.dataset.section
    if (!['invitations', 'audit', 'users', 'profile', 'system'].includes(section)) return
    if (!state.session || section !== 'profile' && state.session.role !== 'admin') return
    state.adminView = section
    if (section === 'profile' || section === 'system') {
      state.adminRecordsPanel = null
      render()
      if (section === 'system') await refreshAdminOverview()
      return
    }
    state.adminRecordsPanel = section
    state.adminSelectedRecordIds[section] = []
    state.adminError = ''
    state.adminLoading = section === 'users'
    render()
    if (section === 'users') await refreshAdminUsers()
    return
  }
  if (action === 'close-admin-panel') {
    state.adminPanelOpen = false
    state.adminView = 'profile'
    state.adminRecordsPanel = null
    resetAdminRecords()
    render()
    restoreModalFocus()
    return
  }
  if (action === 'open-admin-records') {
    if (!['invitations', 'audit', 'users'].includes(element.dataset.panel)) return
    rememberAdminRecordsFocus(element)
    state.adminView = element.dataset.panel
    state.adminRecordsPanel = element.dataset.panel
    state.adminSelectedRecordIds[state.adminRecordsPanel] = []
    state.adminError = ''
    state.adminLoading = state.adminRecordsPanel === 'users'
    render()
    if (state.adminRecordsPanel === 'users') await refreshAdminUsers()
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
      state.adminLoading = true
      setToast('邀请码已生成。')
      await refreshAdminPanel()
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action); render() }
    return
  }
  if (action === 'copy-invitation') {
    if (!state.invitation?.code) return
    try {
      await copyText(state.invitation.code)
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
    openConfirm(`删除选中的${label}${panel === 'users' ? '' : '记录'}`, message, { action: 'confirm-delete-selected-admin-records', panel, ids: [...ids] }, panel === 'users' ? '删除账号' : '删除所选')
    return
  }
  if (action === 'confirm-revoke-invitation') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/auth/invitations/${element.dataset.id}`, { method: 'DELETE' }); state.invitation = null; state.adminLoading = true; setToast('邀请码已撤销。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'confirm-delete-invitation-record') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/auth/invitations/${element.dataset.id}/record`, { method: 'DELETE' }); state.adminSelectedRecordIds.invitations = state.adminSelectedRecordIds.invitations.filter(id => id !== element.dataset.id); if (state.invitation?.id === element.dataset.id) state.invitation = null; state.adminLoading = true; setToast('邀请码记录已删除。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'confirm-delete-audit-record') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/audit/${element.dataset.id}`, { method: 'DELETE' }); state.adminSelectedRecordIds.audit = state.adminSelectedRecordIds.audit.filter(id => id !== element.dataset.id); state.adminLoading = true; setToast('审计记录已删除。'); await refreshAdminPanel() } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
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
      if (panel === 'invitations' && state.invitation && ids.includes(state.invitation.id)) state.invitation = null
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
  if (action === 'start-instance') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    beginBusy(action, element.dataset.id)
    state.labDetailId = null
    render()
    restoreModalFocus()
    setToast(`${lab?.title ?? '靶场环境'}正在后台启动…`)
    try {
      const result = await request(`/api/labs/${element.dataset.id}/instances`, { method: 'POST', timeout: START_REQUEST_TIMEOUT_MS })
      if (result?.status === 'preparing') await waitForStartedInstance(element.dataset.id)
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
  if (activityCell) {
    event.preventDefault()
    selectActivityDate(activityCell.dataset.activityDate, true)
    return
  }
  const element = event.target.closest?.('[data-action]')
  if (!element) return
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
  else void refreshAdminOverview()
})

window.addEventListener('resize', updateLabCanvasScrollState)

app.addEventListener('change', event => {
  const input = event.target
  if (!(input instanceof HTMLInputElement)) return
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
    if (state.confirm) { state.confirm = null; render(); restoreConfirmFocus(); return }
    else if (state.adminRecordsPanel) { state.adminRecordsPanel = null; state.adminView = 'profile'; render(); restoreAdminRecordsFocus(); return }
    else if (state.labDetailId) state.labDetailId = null
    else if (state.adminPanelOpen) { state.adminPanelOpen = false; state.adminView = 'profile'; render(); restoreModalFocus(); return }
    else return
    render()
    restoreModalFocus()
    return
  }
  if (event.key !== 'Tab') return
  const focusable = [...dialog.querySelectorAll('button, a[href], input, select, textarea')].filter(item => !item.disabled && item.tabIndex >= 0 && item.offsetParent !== null)
  if (!focusable.length) return
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
})

window.addEventListener('hashchange', render)
bootstrap()
