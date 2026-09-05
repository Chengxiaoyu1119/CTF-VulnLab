const app = document.querySelector('#app')
let importPollTimer = null
let modalReturnFocus = null
let loginNoticeTimer = null
let loginSuccessNoticeTimer = null
let toastTimer = null

const LOGIN_NOTICE_DURATION = 4200

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
  successNotice: null,
  toast: null,
  confirm: null,
  labDetailId: null,
  dialogFocusSelector: '',
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
  state.dialogFocusSelector = ''
  if (location.hash !== '#labs') location.hash = 'labs'
}

function setToast(message, type = 'success') {
  if (toastTimer) { window.clearTimeout(toastTimer); toastTimer = null }
  state.toast = { message, type }
  render()
  toastTimer = window.setTimeout(() => {
    toastTimer = null
    state.toast = null
    render()
  }, 3600)
}

function clearLoginNoticeTimer() {
  if (loginNoticeTimer) { window.clearTimeout(loginNoticeTimer); loginNoticeTimer = null }
}

function scheduleLoginNoticeDismiss() {
  clearLoginNoticeTimer()
  if (!state.error || state.session) return
  loginNoticeTimer = window.setTimeout(() => {
    loginNoticeTimer = null
    if (!state.session && state.error) {
      state.error = ''
      state.loginErrorFields = []
      render()
    }
  }, LOGIN_NOTICE_DURATION)
}

function clearLoginSuccessNoticeTimer() {
  if (loginSuccessNoticeTimer) { window.clearTimeout(loginSuccessNoticeTimer); loginSuccessNoticeTimer = null }
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

function overlays() {
  const successNotice = state.successNotice ? loginNoticeCard({ id: 'login-success-notice', title: state.successNotice.title, message: state.successNotice.message, action: 'dismiss-login-success', kind: 'success' }) : ''
  return `${successNotice}${state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status">${esc(state.toast.message)}</div>` : ''}
    ${labDetailModal()}
    ${state.confirm ? `<div class="dialog-backdrop workspace-dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p>${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : ''}
    `
}

function labsShell(content) {
  return `<div class="labs-screen">
    <section class="lab-workspace">
      <main class="lab-canvas" tabindex="-1">${content}</main>
    </section>
    ${overlays()}
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
function labCard(lab) {
  const ready = lab.status === 'ready'
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const starting = busyFor('start-instance', lab.id)
  const cardState = instance ? 'running' : starting ? 'starting' : importing ? 'preparing' : queued ? 'preparing' : failed ? 'error' : ready ? 'ready' : 'idle'
  const statusLabel = instance ? '运行中' : starting ? '启动中' : importing || queued ? '准备中' : failed ? '准备失败' : ready ? '已就绪' : '待启动'
  const accessibleState = statusLabel || '等待处理'
  return `<article class="lab-card" data-state="${cardState}" data-runtime="${esc(lab.runtimeKind ?? '')}" aria-label="${esc(lab.title)}，${accessibleState}" aria-live="polite"${starting || importing || queued ? ' aria-busy="true"' : ''}>
    <button class="lab-card-media" type="button" data-action="open-lab-details" data-id="${esc(lab.id)}" data-cover="${coverVariant(lab)}" aria-label="查看 ${esc(lab.title)} 信息">${coverArt(lab)}<span class="lab-card-caption" title="${esc(lab.title)}"><span class="lab-card-title">${esc(lab.title)}</span></span></button>
  </article>`
}

function labsPage() {
  const visibleLabs = state.labs.slice(0, 9)
  if (state.error && !state.labs.length) {
    return `<div class="empty-state lab-empty-state"><p>${esc(state.error)}</p><button class="button button-primary" type="button" data-action="refresh-labs">重新连接</button></div>`
  }
  return visibleLabs.length
    ? `<h1 class="sr-only">靶场</h1><div class="lab-grid" aria-label="靶场列表">${visibleLabs.map(labCard).join('')}</div>`
    : '<div class="empty-state lab-empty-state"><p>暂无可用靶场。</p><button class="button button-primary" type="button" data-action="refresh-labs">重新检查</button></div>'
}

function labDetailModal() {
  const lab = state.labs.find(item => item.id === state.labDetailId)
  if (!lab) return ''
  const admin = state.session.role === 'admin'
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
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
    primaryAction = `<button class="button ${failed ? 'button-danger' : 'button-primary'} lab-detail-action" type="button" data-action="start-instance" data-id="${esc(lab.id)}">${failed ? '重试启动' : '启动环境'}</button>`
  } else {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待准备</span>'
  }
  const detailState = instance ? 'running' : starting ? 'starting' : preparing ? 'preparing' : failed ? 'error' : 'ready'
  const stateLabel = instance ? '运行中' : starting ? '启动中' : preparing ? '准备中' : failed ? '准备失败' : ''
  const facts = [lab.category, lab.difficulty, lab.version].filter(Boolean).map(esc).join('<span aria-hidden="true">·</span>')
  const tags = Array.isArray(lab.tags) && lab.tags.length ? `<div class="lab-detail-tags">${lab.tags.slice(0, 4).map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''
  const runningInfo = instance
    ? `<div class="lab-detail-running"><div><span class="lab-detail-running-dot" aria-hidden="true"></span><strong>运行中</strong></div><time>到期 ${date(instance.expiresAt)}</time></div><div class="lab-detail-endpoint"><span>入口</span><code>${esc(instance.endpoint)}</code></div>`
    : ''
  const managementActions = instance && admin
    ? `<button class="button button-outline lab-detail-action" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button><button class="button button-quiet lab-detail-stop" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button>`
    : ''
  return `<div class="dialog-backdrop workspace-dialog-backdrop lab-detail-backdrop" data-action="close-lab-details"><section class="dialog lab-detail-dialog" data-state="${detailState}" role="dialog" aria-modal="true" aria-labelledby="lab-detail-title"><div class="lab-card-media lab-detail-cover" data-cover="${coverVariant(lab)}">${coverArt(lab)}<button class="dialog-close lab-detail-close" type="button" data-action="close-lab-details" aria-label="关闭靶场信息">×</button></div><div class="lab-detail-body"><div class="lab-detail-heading"><div><h2 id="lab-detail-title">${esc(lab.title)}</h2><div class="lab-detail-facts">${facts}</div></div>${stateLabel ? `<span class="lab-detail-state">${esc(stateLabel)}</span>` : ''}</div>${lab.summary ? `<p class="lab-detail-summary">${esc(lab.summary)}</p>` : ''}${tags}${runningInfo}<div class="lab-detail-actions">${managementActions}${primaryAction}</div></div></section></div>`
}

function loginPage() {
  const userNameInvalid = state.loginErrorFields.includes('userName')
  const passwordInvalid = state.loginErrorFields.includes('password')
  const notice = state.error ? loginNoticeCard({ id: 'login-notice', title: '登录失败', message: state.error, action: 'dismiss-login-error' }) : ''
  const describedBy = state.error ? 'aria-describedby="login-notice"' : ''
  return `<div class="login-page"><form class="login-form" id="login-form" novalidate><div class="login-brand"><img src="/favicon.svg" alt=""><h1>VulnLab</h1><p>本地靶场控制台</p></div><div class="login-mode">登录</div><label><span class="sr-only">账号</span><input name="userName" autocomplete="username" placeholder="请输入账号" required aria-invalid="${userNameInvalid}" ${describedBy}></label><label><span class="sr-only">密码</span><input name="password" type="password" autocomplete="current-password" placeholder="请输入密码" required aria-invalid="${passwordInvalid}" ${describedBy}></label><button class="button button-primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '登录中…' : '进入靶场'}</button></form>${notice}</div>`
}

function scheduleImportPolling() {
  if (importPollTimer) { window.clearTimeout(importPollTimer); importPollTimer = null }
  if (!state.session || !state.jobs.some(job => ['queued', 'importing'].includes(job.status))) return
  importPollTimer = window.setTimeout(async () => {
    importPollTimer = null
    try { await refresh(); render() } catch { scheduleImportPolling() }
  }, 1200)
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

function render() {
  document.body.classList.toggle('has-workspace', Boolean(state.session))
  document.body.classList.toggle('has-login-success-notice', Boolean(state.successNotice && state.session))
  document.body.classList.toggle('has-dialog', Boolean(state.confirm || state.labDetailId))
  if (state.loading) {
    app.innerHTML = '<div class="loading-screen" role="status" aria-live="polite"><div class="loading-mark" aria-hidden="true"><span></span><span></span><span></span></div><span>正在打开 VulnLab…</span></div>'
    return
  }
  if (!state.session) { clearLoginSuccessNoticeTimer(); app.innerHTML = loginPage(); scheduleLoginNoticeDismiss(); return }
  clearLoginNoticeTimer()
  scheduleLoginSuccessNoticeDismiss()
  app.innerHTML = labsShell(labsPage())
  window.queueMicrotask(() => {
    const dialog = [...document.querySelectorAll('[role="dialog"]')].at(-1)
    if (!dialog) return
    const selector = state.dialogFocusSelector
    state.dialogFocusSelector = ''
    const focusable = (selector && dialog.querySelector(selector)) || dialog.querySelector('button, a[href], input, select, textarea')
    focusable?.focus()
  })
  scheduleImportPolling()
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
  const canRunWhileBusy = ['nav', 'open-lab-details', 'close-lab-details', 'dismiss-login-error', 'dismiss-login-success', 'cancel-confirm'].includes(action)
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
  if (action === 'dismiss-login-error') { clearLoginNoticeTimer(); state.error = ''; state.loginErrorFields = []; render(); return }
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
    try { await request('/api/auth/logout', { method: 'POST' }); clearLoginSuccessNoticeTimer(); state.successNotice = null; state.session = null; state.csrfToken = ''; state.labs = []; state.jobs = []; state.instances = []; state.labDetailId = null; location.hash = 'labs' } catch (error) { setToast(error.message, 'error') } finally { endBusy('logout'); render() }
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
    const userName = typeof values.userName === 'string' ? values.userName.trim() : ''
    const password = typeof values.password === 'string' ? values.password : ''
    const missingFields = [!userName ? 'userName' : null, !password ? 'password' : null].filter(Boolean)
    if (missingFields.length) {
      state.loginErrorFields = missingFields
      state.error = !userName && !password ? '请输入账号和密码' : !userName ? '请输入账号' : '请输入密码'
      state.busy = false
      render()
      document.querySelector(`[name="${missingFields[0]}"]`)?.focus()
      return
    }
    try { const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(values) }); state.session = session; state.csrfToken = session.csrfToken; await refresh(); state.successNotice = { title: '登录成功', message: '身份验证通过，正在进入系统' }; navigate('labs') } catch (error) { state.successNotice = null; state.error = error.message } finally { state.busy = false; render() }
    return
  }
})

app.addEventListener('input', event => {
  const input = event.target
  if (!input.form || input.form.id !== 'login-form' || !state.error) return
  clearLoginNoticeTimer()
  state.error = ''
  state.loginErrorFields = []
  document.querySelector('#login-notice')?.remove()
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
