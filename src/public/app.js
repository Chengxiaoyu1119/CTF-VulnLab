const app = document.querySelector('#app')
let importPollTimer = null
let detailPollTimer = null
let modalReturnFocus = null
let loginSuccessNoticeTimer = null
let toastTimer = null

const LOGIN_NOTICE_DURATION = 4200
const DETAIL_POLL_INTERVAL = 5000

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
  loginPasswordVisible: false,
  successNotice: null,
  toast: null,
  confirm: null,
  labDetailId: null,
}

const esc = value => String(value ?? '').replace(/[&<>'"]/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
}[character]))

const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const busyFor = (action, id = '') => state.busyActions.some(item => item.action === action && (!id || item.id === id))

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options = {}) {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers ?? {}) }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !path.endsWith('/auth/login') && state.csrfToken) headers['X-CSRF-Token'] = state.csrfToken
  let response
  try {
    response = await fetch(path, { ...options, credentials: 'same-origin', headers })
  } catch {
    throw new ApiError('本地服务连接失败，请确认 VulnLab 服务正在运行。', 0)
  }
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) throw new ApiError(payload.message ?? `请求失败（${response.status}）`, response.status)
  return payload
}

async function refresh() {
  const [labs, jobs, instances] = await Promise.all([
    request('/api/labs'), request('/api/import-jobs'), request('/api/instances'),
  ])
  state.labs = labs
  state.jobs = jobs
  state.instances = instances
  state.error = ''
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

function labsShell() {
  return `<div class="labs-screen">
    <section class="lab-workspace">
      <main class="lab-canvas" tabindex="-1"></main>
    </section>
    <div data-overlay-slot="success"></div>
    <div data-overlay-slot="toast"></div>
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
const coverArt = (lab, imageClass = 'lab-card-cover') => coverAssets[lab.slug]
  ? `<img class="${esc(imageClass)}" data-cover-image="true" src="${coverAssets[lab.slug]}" alt="${esc(lab.title)} 封面" loading="lazy" decoding="async" />`
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

function labCard(lab) {
  const view = labCardView(lab)
  return `<article class="lab-card" data-state="${view.cardState}" data-runtime="${esc(lab.runtimeKind ?? '')}" aria-label="${esc(lab.title)}，${view.statusLabel}" aria-live="polite"${view.busy ? ' aria-busy="true"' : ''}>
    <button class="lab-card-media" type="button" data-action="open-lab-details" data-id="${esc(lab.id)}" data-cover="${coverVariant(lab)}" aria-label="查看 ${esc(lab.title)} 信息">${coverArt(lab)}<span class="lab-card-caption" title="${esc(lab.title)}"><span class="lab-card-title">${esc(lab.title)}</span></span></button>
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
  const failureMessage = readableError(failedJob?.error ?? (lab.status === 'error' ? '靶场准备失败，请重试。' : ''))
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
    primaryAction = `<button class="button ${failed ? 'button-danger' : 'button-primary'} lab-detail-action" type="button" data-action="start-instance" data-id="${esc(lab.id)}">${failed ? '重试启动' : cataloged ? '准备并启动' : '启动环境'}</button>`
  } else {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待准备</span>'
  }
  const detailState = instance ? 'running' : starting ? 'starting' : preparing ? 'preparing' : failed ? 'error' : cataloged ? 'cataloged' : 'ready'
  const stateLabel = instance ? '运行中' : starting ? '启动中' : preparing ? '准备中' : failed ? '准备失败' : cataloged ? '待准备' : ''
  const facts = [lab.category, lab.difficulty].filter(Boolean).map(esc).join('<span aria-hidden="true">·</span>')
  const tags = Array.isArray(lab.tags) && lab.tags.length ? `<div class="lab-detail-tags">${lab.tags.slice(0, 4).map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''
  const preparationInfo = preparing ? `<div class="lab-detail-progress" role="status" aria-live="polite"><div class="lab-detail-progress-head"><span>${esc(jobStageLabel(activeJob?.stage))}</span><strong>${jobProgress(activeJob)}%</strong></div><div class="lab-detail-progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${jobProgress(activeJob)}"><span class="lab-detail-progress-fill" style="--progress:${jobProgress(activeJob)}%"></span></div><p class="lab-detail-progress-message">${esc(activeJob?.message ?? '正在准备靶场资源，请稍候。')}</p></div>` : ''
  const errorInfo = failureMessage ? `<p class="lab-detail-error" role="alert">${esc(failureMessage)}</p>` : ''
  const runningInfo = instance
    ? `<div class="lab-detail-running"><div><span class="lab-detail-running-dot" aria-hidden="true"></span><strong>运行中</strong></div><time>到期 ${date(instance.expiresAt)}</time></div><div class="lab-detail-endpoint"><span>入口</span><code>${esc(instance.endpoint)}</code></div>`
    : ''
  const managementActions = instance && admin
    ? `<button class="button button-outline lab-detail-action" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button><button class="button button-quiet lab-detail-stop" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button>`
    : ''
  return `<div class="dialog-backdrop workspace-dialog-backdrop lab-detail-backdrop" data-action="close-lab-details"><section class="dialog lab-detail-dialog" data-state="${detailState}" role="dialog" aria-modal="true" aria-labelledby="lab-detail-title"><div class="lab-card-media lab-detail-cover" data-cover="${coverVariant(lab)}">${coverArt(lab)}<button class="dialog-close lab-detail-close" type="button" data-action="close-lab-details" aria-label="关闭靶场信息">×</button></div><div class="lab-detail-body"><div class="lab-detail-heading"><div><h2 id="lab-detail-title">${esc(lab.title)}</h2><div class="lab-detail-facts">${facts}</div></div>${stateLabel ? `<span class="lab-detail-state">${esc(stateLabel)}</span>` : ''}</div>${lab.summary ? `<p class="lab-detail-summary">${esc(lab.summary)}</p>` : ''}${tags}${preparationInfo}${errorInfo}${runningInfo}<div class="lab-detail-actions">${managementActions}${primaryAction}</div></div></section></div>`
}

function passwordToggleIcon(visible) {
  return visible
    ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 3 18 18M10.6 6.3A10.7 10.7 0 0 1 12 6c6 0 9.5 6 9.5 6a16.8 16.8 0 0 1-3.1 3.7M6.1 6.9C3.8 8.4 2.5 12 2.5 12S6 18 12 18c1 0 1.9-.2 2.8-.5"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>'
    : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.8"/></svg>'
}

function loginErrorMarkup() {
  return `<p class="login-form-error" id="login-error" role="alert" aria-live="polite">${esc(state.error)}</p>`
}

function loginPage() {
  const userNameInvalid = state.loginErrorFields.includes('userName')
  const passwordInvalid = state.loginErrorFields.includes('password')
  const describedBy = state.error ? 'aria-describedby="login-error"' : ''
  const passwordType = state.loginPasswordVisible ? 'text' : 'password'
  const toggleLabel = state.loginPasswordVisible ? '隐藏密码' : '显示密码'
  return `<div class="login-page"><form class="login-form" id="login-form" novalidate><div class="login-brand"><img src="/favicon.png?v=16" alt=""><h1>VulnLab</h1><p>攻防控制台</p></div><div class="login-mode">登录</div>${state.error ? loginErrorMarkup() : ''}<label class="login-field" for="login-username"><span class="login-field-label">账号</span><span class="login-input-wrap" data-field="user"><input id="login-username" name="userName" autocomplete="username" placeholder="请输入账号" required aria-invalid="${userNameInvalid}" ${describedBy}></span></label><label class="login-field" for="login-password"><span class="login-field-label">密码</span><span class="login-input-wrap" data-field="password"><input id="login-password" name="password" type="${passwordType}" autocomplete="current-password" placeholder="请输入密码" required aria-invalid="${passwordInvalid}" ${describedBy}><button class="password-toggle" type="button" data-action="toggle-password" aria-label="${toggleLabel}" aria-pressed="${state.loginPasswordVisible}">${passwordToggleIcon(state.loginPasswordVisible)}</button></span></label><button class="button button-primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '登录中…' : '进入靶场'}</button></form></div>`
}

function updateLoginFormView() {
  const form = document.querySelector('#login-form')
  if (!form) return
  const error = form.querySelector('#login-error')
  if (state.error && !error) form.querySelector('.login-mode')?.insertAdjacentHTML('afterend', loginErrorMarkup())
  else if (!state.error) error?.remove()
  form.querySelectorAll('input[name]').forEach(input => {
    const invalid = state.loginErrorFields.includes(input.name)
    input.setAttribute('aria-invalid', String(invalid))
    if (state.error) input.setAttribute('aria-describedby', 'login-error')
    else input.removeAttribute('aria-describedby')
  })
  const submit = form.querySelector('button[type="submit"]')
  if (submit) { submit.disabled = state.busy; submit.textContent = state.busy ? '登录中…' : '进入靶场' }
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
  for (let attempt = 0; attempt < 600; attempt += 1) {
    await sleep(1000)
    await refresh()
    if (state.instances.some(instance => instance.labId === labId && instance.status === 'running')) return
    const lab = state.labs.find(item => item.id === labId)
    const job = state.jobs.find(item => item.labId === labId && ['queued', 'importing'].includes(item.status))
    const completedWithError = state.jobs.find(item => item.labId === labId && item.status === 'completed' && item.error)
    if (completedWithError?.error) throw new ApiError(completedWithError.error, 409)
    if (lab?.status === 'error' || (!job && state.jobs.some(item => item.labId === labId && item.status === 'error'))) {
      const failedJob = state.jobs.find(item => item.labId === labId && item.status === 'error')
      throw new ApiError(failedJob?.error ?? '靶场准备失败，请重试。', 409)
    }
  }
  throw new ApiError('靶场准备超时，请稍后重新查看。', 504)
}

function patchLabs() {
  const canvas = app.querySelector('.lab-canvas')
  const visibleLabs = state.labs.slice(0, 9)
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
    canvas.innerHTML = '<h1 class="sr-only">靶场</h1><div class="lab-grid" aria-label="靶场列表"></div>'
    grid = canvas.querySelector('.lab-grid')
  }
  const cards = new Map([...grid.querySelectorAll('.lab-card')].map(card => [card.querySelector('[data-id]')?.dataset.id, card]))
  visibleLabs.forEach((lab, index) => {
    let card = cards.get(lab.id)
    if (!card) {
      const template = document.createElement('template')
      template.innerHTML = labCard(lab)
      card = template.content.firstElementChild
    }
    if (grid.children[index] !== card) grid.insertBefore(card, grid.children[index] ?? null)
    cards.delete(lab.id)
    const view = labCardView(lab)
    card.dataset.state = view.cardState
    card.dataset.runtime = lab.runtimeKind ?? ''
    card.setAttribute('aria-label', `${lab.title}，${view.statusLabel}`)
    if (view.busy) card.setAttribute('aria-busy', 'true')
    else card.removeAttribute('aria-busy')
  })
  cards.forEach(card => card.remove())
}

function patchSlot(name, content, { focus = false, key = content } = {}) {
  const slot = app.querySelector(`[data-overlay-slot="${name}"]`)
  if (slot.__vulnlabKey === key && slot.__vulnlabContent === content) return
  const hadDialog = focus && Boolean(slot.querySelector('[role="dialog"]'))
  const active = focus && slot.contains(document.activeElement)
    ? { action: document.activeElement.dataset.action ?? '', id: document.activeElement.dataset.id ?? '' }
    : null
  slot.innerHTML = content
  slot.__vulnlabKey = key
  slot.__vulnlabContent = content
  if (!focus || !content) return
  if (hadDialog) {
    slot.querySelector('.dialog-backdrop')?.style.setProperty('animation', 'none')
    slot.querySelector('[role="dialog"]')?.style.setProperty('animation', 'none')
  }
  window.queueMicrotask(() => {
    const focusable = [...slot.querySelectorAll('button, a[href], input, select, textarea')].filter(item => !item.disabled && item.offsetParent !== null)
    const target = active && focusable.find(item => item.dataset.action === active.action && (item.dataset.id ?? '') === active.id)
    ;(target || focusable[0])?.focus()
  })
}

function patchOverlays() {
  const successNotice = state.successNotice ? loginNoticeCard({ id: 'login-success-notice', title: state.successNotice.title, message: state.successNotice.message, action: 'dismiss-login-success', kind: 'success' }) : ''
  patchSlot('success', successNotice, { key: state.successNotice ?? '' })
  patchSlot('toast', state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status">${esc(state.toast.message)}</div>` : '', { key: state.toast ?? '' })
  patchSlot('detail', labDetailModal(), { focus: true })
  patchSlot('confirm', state.confirm ? `<div class="dialog-backdrop workspace-dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p>${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : '', { focus: true, key: state.confirm ?? '' })
}

function render() {
  if (!state.session || !state.labDetailId) clearDetailPolling()
  document.body.classList.toggle('has-workspace', Boolean(state.session))
  document.body.classList.toggle('has-login-success-notice', Boolean(state.successNotice && state.session))
  document.body.classList.toggle('has-dialog', Boolean(state.confirm || state.labDetailId))
  if (state.loading) {
    app.innerHTML = '<div class="loading-screen" role="status" aria-live="polite"><div class="loading-mark" aria-hidden="true"><span></span><span></span><span></span></div><span>正在打开 VulnLab…</span></div>'
    return
  }
  if (!state.session) { clearLoginSuccessNoticeTimer(); app.innerHTML = loginPage(); return }
  scheduleLoginSuccessNoticeDismiss()
  if (!app.querySelector('.labs-screen')) app.innerHTML = labsShell()
  patchLabs()
  patchOverlays()
  scheduleImportPolling()
  scheduleDetailPolling()
}

function restoreModalFocus() {
  const target = modalReturnFocus
  modalReturnFocus = null
  const element = target?.element?.isConnected
    ? target.element
    : target
      ? [...document.querySelectorAll('[data-action]')].find(candidate => candidate.dataset.action === target.action && candidate.dataset.id === target.id)
      : null
  if (element) window.queueMicrotask(() => element.focus())
}

function rememberModalFocus(element) {
  modalReturnFocus = element ? { element, action: element.dataset.action, id: element.dataset.id } : null
}

function openConfirm(title, message, action, confirmLabel = '继续') {
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
  const canRunWhileBusy = ['nav', 'open-lab-details', 'close-lab-details', 'toggle-password', 'dismiss-login-success', 'cancel-confirm'].includes(action)
  const operationId = element?.dataset?.id ?? ''
  const duplicateOperation = state.busyActions.some(item => item.action === action && item.id === operationId)
  const logoutBusy = action === 'logout' && state.busyActions.length > 0
  if (!canRunWhileBusy && (duplicateOperation || logoutBusy)) {
    setToast('当前操作正在进行中，请稍候。', 'error')
    return
  }
  if (action === 'nav') { navigate(); return }
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
  if (action === 'toggle-password') {
    const input = document.querySelector('#login-password')
    const toggle = document.querySelector('[data-action="toggle-password"]')
    if (!input || !toggle) return
    state.loginPasswordVisible = !state.loginPasswordVisible
    input.type = state.loginPasswordVisible ? 'text' : 'password'
    toggle.setAttribute('aria-label', state.loginPasswordVisible ? '隐藏密码' : '显示密码')
    toggle.setAttribute('aria-pressed', String(state.loginPasswordVisible))
    toggle.innerHTML = passwordToggleIcon(state.loginPasswordVisible)
    input.focus()
    return
  }
  if (action === 'dismiss-login-success') { clearLoginSuccessNoticeTimer(); state.successNotice = null; render(); return }
  if (action === 'cancel-confirm') { state.confirm = null; render(); restoreModalFocus(); return }
  if (action === 'confirm-action') {
    const next = state.confirm?.action
    state.confirm = null
    if (next) await runAction(next.action, { dataset: next })
    else { render(); restoreModalFocus() }
    return
  }
  if (action === 'logout') {
    beginBusy('logout')
    try { await request('/api/auth/logout', { method: 'POST' }); clearLoginSuccessNoticeTimer(); state.successNotice = null; state.session = null; state.csrfToken = ''; state.labs = []; state.jobs = []; state.instances = []; state.labDetailId = null; state.loginPasswordVisible = false; location.hash = 'labs' } catch (error) { setToast(error.message, 'error') } finally { endBusy('logout'); render() }
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
    try {
      const result = await request(`/api/labs/${element.dataset.id}/instances`, { method: 'POST' })
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
  const element = event.target.closest?.('[data-action]')
  if (!element) return
  if (element.dataset.action === 'close-lab-details' && element !== event.target) return
  if (element.dataset.action !== 'open-instance-page') event.preventDefault()
  runAction(element.dataset.action, element)
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
    state.busy = true; state.error = ''; state.loginErrorFields = []
    updateLoginFormView()
    const userName = typeof values.userName === 'string' ? values.userName.trim() : ''
    const password = typeof values.password === 'string' ? values.password : ''
    const missingFields = [!userName ? 'userName' : null, !password ? 'password' : null].filter(Boolean)
    if (missingFields.length) {
      state.loginErrorFields = missingFields
      state.error = !userName && !password ? '请输入账号和密码' : !userName ? '请输入账号' : '请输入密码'
      state.busy = false
      updateLoginFormView()
      document.querySelector(`[name="${missingFields[0]}"]`)?.focus()
      return
    }
    try {
      const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(values) })
      state.session = session
      state.csrfToken = session.csrfToken
      await refresh()
      state.successNotice = { title: '登录成功', message: '身份验证通过，正在进入系统' }
      state.loginPasswordVisible = false
      navigate('labs')
      state.busy = false
      render()
    } catch (error) {
      state.successNotice = null
      state.error = error.message
      state.loginErrorFields = state.session ? [] : ['userName']
      state.busy = false
      if (state.session) render()
      else {
        updateLoginFormView()
        document.querySelector(`[name="${state.loginErrorFields[0] ?? 'userName'}"]`)?.focus()
      }
    }
    return
  }
})

app.addEventListener('input', event => {
  const input = event.target
  if (!input.form || input.form.id !== 'login-form' || !state.error) return
  state.error = ''
  state.loginErrorFields = []
  input.form.querySelector('#login-error')?.remove()
  input.form.querySelectorAll('input').forEach(field => {
    field.setAttribute('aria-invalid', 'false')
    field.removeAttribute('aria-describedby')
  })
})

document.addEventListener('keydown', event => {
  const dialog = document.querySelector('[role="dialog"]')
  if (!dialog) return
  if (event.key === 'Escape') {
    if (state.confirm) state.confirm = null
    else if (state.labDetailId) state.labDetailId = null
    render()
    restoreModalFocus()
    return
  }
  if (event.key !== 'Tab') return
  const focusable = [...dialog.querySelectorAll('button, a[href], input, select, textarea')].filter(item => !item.disabled && item.offsetParent !== null)
  if (!focusable.length) return
  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
})

window.addEventListener('hashchange', render)
bootstrap()
