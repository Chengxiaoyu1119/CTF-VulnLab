const app = document.querySelector('#app')
let importPollTimer = null
let catalogPollTimer = null
let modalReturnFocus = null
let loginNoticeTimer = null
let loginSuccessNoticeTimer = null
let toastTimer = null

const LOGIN_NOTICE_DURATION = 4200

const state = {
  session: null,
  csrfToken: '',
  overview: null,
  labs: [],
  jobs: [],
  vmDownloads: [],
  instances: [],
  runtimeStatus: { dependencies: [], labs: {} },
  loading: true,
  busy: false,
  busyActions: [],
  busyAction: null,
  error: '',
  loginErrorFields: [],
  successNotice: null,
  toast: null,
  confirm: null,
  catalog: null,
  labDetailId: null,
  runtimeDialogLabId: null,
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
  const [overview, labs, jobs, vmDownloads, instances, runtimeStatus] = await Promise.all([
    request('/api/overview'), request('/api/labs'), request('/api/import-jobs'), request('/api/vm-downloads'), request('/api/instances'), request('/api/runtime-status'),
  ])
  state.overview = overview
  state.labs = labs
  state.jobs = jobs
  state.vmDownloads = vmDownloads
  state.instances = instances
  state.runtimeStatus = runtimeStatus
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
  state.catalog = null
  state.labDetailId = null
  state.runtimeDialogLabId = null
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

function catalogDialog() {
  const catalog = state.catalog
  if (!catalog) return ''
  if (catalog.loading) {
    return `<div class="dialog-backdrop catalog-backdrop"><section class="dialog catalog-dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"><div class="catalog-dialog-head"><h2 id="catalog-dialog-title">选择 VulnHub 启动环境</h2><button class="dialog-close" type="button" data-action="close-catalog" aria-label="关闭目录">×</button></div><div class="catalog-loading">正在读取目录…</div></section></div>`
  }
  const entries = Array.isArray(catalog.entries) ? catalog.entries : []
  const downloads = Array.isArray(catalog.downloads) ? catalog.downloads : []
  const requestedIndex = Number.isInteger(catalog.selectedIndex) ? catalog.selectedIndex : 0
  const selectedIndex = entries.length ? Math.max(0, Math.min(entries.length - 1, requestedIndex)) : null
  const entry = selectedIndex === null ? null : entries[selectedIndex]
  const downloadFor = index => downloads.find(item => item.entryIndex === index)
  const downloadLabel = download => download?.status === 'completed' ? '已下载' : download?.status === 'downloading' ? `${download.progress}%` : download?.status === 'error' ? '重试' : null
  const value = item => item || '—'
  const download = downloadFor(selectedIndex)
  const downloadButtons = entry?.downloadUrls?.length
    ? entry.downloadUrls.map((url, index) => {
      const isCurrent = download?.downloadUrl === url
      const label = isCurrent ? downloadLabel(download) : null
      const downloadBusy = busyFor('download-catalog-entry', `${catalog.labId}:${selectedIndex}:${index}`)
      if (downloadBusy) return '<span class="download-state">下载中…</span>'
      return label === '已下载'
        ? '<span class="download-state is-complete">已下载</span>'
        : label && download?.status === 'downloading'
          ? `<span class="download-state">下载中 ${esc(label)}</span>`
        : `<button class="button button-quiet is-download" type="button" data-action="download-catalog-entry" data-index="${selectedIndex}" data-download-index="${index}">${label === '重试' ? '重试下载' : '下载镜像'}</button>`
    }).join('')
    : '<span class="download-state">暂无官方镜像</span>'
  const vmStarting = busyFor('start-vm-instance', catalog.labId)
  const vmStartButton = vmStarting
    ? '<span class="download-state">启动中…</span>'
    : download?.status === 'completed'
    ? state.runtimeStatus.labs?.vulnhub?.available
      ? `<button class="button button-primary is-start" type="button" data-action="start-vm-instance" data-lab-id="${esc(catalog.labId)}" data-download-id="${esc(download.id)}">启动环境</button>`
      : `<button class="button button-quiet" type="button" data-action="open-runtime-dialog" data-id="${esc(catalog.labId)}">查看启动条件</button>`
    : ''
  return `<div class="dialog-backdrop catalog-backdrop"><section class="dialog catalog-dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"><div class="catalog-dialog-head"><div><h2 id="catalog-dialog-title">选择 VulnHub 启动环境</h2><span>${esc(catalog.labTitle)}</span></div><button class="dialog-close" type="button" data-action="close-catalog" aria-label="关闭目录">×</button></div>${entries.length ? `<div class="catalog-layout"><div class="catalog-list" role="listbox" aria-label="可选 VulnHub 启动环境"><div class="catalog-list-scroll">${entries.map((item, index) => `<button id="catalog-option-${index}" class="catalog-entry${index === selectedIndex ? ' is-selected' : ''}" type="button" role="option" aria-label="选择启动环境：${esc(item.title)}" aria-selected="${index === selectedIndex}" data-action="select-catalog-entry" data-index="${index}"><strong>${esc(item.title)}</strong><span>${esc(downloadLabel(downloadFor(index)) ?? value(item.difficulty))}</span></button>`).join('')}</div></div><article class="catalog-detail"><div class="catalog-detail-title"><h3>${esc(entry.title)}</h3></div><div class="catalog-facts"><div><span>作者</span><strong>${esc(value(entry.author))}</strong></div><div><span>难度</span><strong>${esc(value(entry.difficulty))}</strong></div><div><span>文件</span><strong>${esc(value(entry.filename))}</strong></div><div><span>大小</span><strong>${esc(value(entry.fileSize))}</strong></div><div><span>MD5</span><strong class="catalog-hash">${esc(value(entry.md5))}</strong></div><div><span>SHA1</span><strong class="catalog-hash">${esc(value(entry.sha1))}</strong></div></div><div class="catalog-links"><a class="button button-outline" href="${esc(entry.url)}" target="_blank" rel="noreferrer">官方详情 ↗</a>${downloadButtons}${vmStartButton}</div></article></div>` : '<div class="empty-state">没有可选择的启动环境。</div>'}</section></div>`
}

function overlays() {
  const successNotice = state.successNotice ? loginNoticeCard({ id: 'login-success-notice', title: state.successNotice.title, message: state.successNotice.message, action: 'dismiss-login-success', kind: 'success' }) : ''
  return `${successNotice}${state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status">${esc(state.toast.message)}</div>` : ''}
    ${labDetailModal()}
    ${runtimeRequirementsDialog()}
    ${state.confirm ? `<div class="dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p>${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : ''}
    ${catalogDialog()}`
}

function runtimePanel() {
  const overview = state.overview ?? {}
  const dependencies = state.runtimeStatus?.dependencies ?? []
  const allLabsReady = state.labs.length > 0 && overview.readyCount === state.labs.length
  const logs = [
    ['CORE', 'OK', 'VulnLab 服务已就绪'],
    ['LABS', allLabsReady ? 'OK' : 'RUN', allLabsReady ? '靶场资源已就绪' : '仍有靶场待安装'],
    ['RUN', overview.runningInstanceCount ? 'RUN' : 'WAIT', overview.runningInstanceCount ? '有环境正在运行' : '暂无运行环境'],
    ...dependencies.map(item => [item.label.toUpperCase().slice(0, 6), item.available ? 'OK' : 'WAIT', item.detail]),
  ]
  return `<aside class="runtime-panel" aria-label="运行状态">
    <pre class="runtime-ascii" aria-label="Chengxiaoyu ASCII 字符图形">${esc(chengxiaoyuAsciiArt)}</pre>
    <div class="runtime-log" aria-live="polite">${logs.map(([time, level, message]) => `<div class="runtime-line"><span class="runtime-line-key">${time}</span><b class="log-${level.toLowerCase()}">[${level}]</b><span>${esc(message)}</span></div>`).join('')}</div>
    <button class="runtime-account" type="button" data-action="logout" aria-label="退出登录">${esc(state.session.userName)}</button>
  </aside>`
}

function labsShell(content) {
  return `<div class="labs-screen">
    ${runtimePanel()}
    <section class="lab-workspace">
      <main class="lab-canvas" tabindex="-1">${content}</main>
    </section>
    ${overlays()}
  </div>`
}

const chengxiaoyuAsciiArt = [
  "   ____ _                           _                         ",
  "  / ___| |__   ___ _ __   __ ___  _(_) __ _  ___  _   _ _   _ ",
  " | |   | '_ \\ / _ \\ '_ \\ / _` \\ \\/ / |/ _` |/ _ \\| | | | | | |",
  " | |___| | | |  __/ | | | (_| |>  <| | (_| | (_) | |_| | |_| |",
  "  \\____|_| |_\\___|_| |_\\__, /_/\\_\\_|\\__,_|\\___/ \\__, |\\__,_|",
  "                         |___/                    |___/       ",
].join('\n')

const coverAssets = Object.freeze({
  dvwa: '/covers/dvwa.png',
  pikachu: '/covers/pikachu.png',
  'sqli-labs': '/covers/sqli-labs.jpg',
  'upload-labs': '/covers/upload-labs.jpg',
  vulnhub: '/covers/vulnhub.png',
  'juice-shop': '/covers/juice-shop.png',
  webgoat: '/covers/webgoat.png',
  mutillidae: '/lab-cover/mutillidae',
  pygoat: '/lab-cover/pygoat',
})
const installedCoverSlugs = new Set(['mutillidae', 'pygoat'])
const coverVariant = lab => Object.hasOwn(coverAssets, lab.slug) ? lab.slug : 'default'
const coverArt = (lab, imageClass = 'lab-card-cover') => coverAssets[lab.slug] && (!installedCoverSlugs.has(lab.slug) || lab.status === 'ready')
  ? `<img class="${esc(imageClass)}" src="${coverAssets[lab.slug]}" alt="${esc(lab.title)} 封面" loading="lazy" decoding="async" />`
  : ''
const labRuntimeSupported = lab => {
  if (!state.runtimeStatus.labs?.[lab.slug]?.available) return false
  if (lab.runtimeKind !== 'vm') return true
  return state.vmDownloads.some(download => download.labId === lab.id && download.status === 'completed' && download.localPath)
}

function labCard(lab) {
  const ready = lab.status === 'ready'
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const starting = busyFor('start-instance', lab.id)
  const installing = busyFor('install-lab', lab.id)
  const cardState = instance ? 'running' : starting ? 'starting' : installing ? 'installing' : importing ? 'importing' : queued ? 'queued' : failed ? 'error' : ready ? 'ready' : 'idle'
  const statusLabel = instance ? '运行中' : starting ? '启动中' : importing ? '安装中' : installing ? '准备中' : queued ? '排队中' : failed ? '安装失败' : ready ? '已就绪' : '待安装'
  const accessibleState = statusLabel || '等待处理'
  return `<article class="lab-card" data-state="${cardState}" data-runtime="${esc(lab.runtimeKind ?? '')}" aria-label="${esc(lab.title)}，${accessibleState}" aria-live="polite"${starting || installing || importing ? ' aria-busy="true"' : ''}>
    <button class="lab-card-media" type="button" data-action="open-lab-details" data-id="${esc(lab.id)}" data-cover="${coverVariant(lab)}" aria-label="查看 ${esc(lab.title)} 信息">${coverArt(lab)}<span class="lab-card-caption" title="${esc(lab.title)}"><span class="lab-card-title">${esc(lab.title)}</span></span></button>
  </article>`
}

function labsPage() {
  const visibleLabs = state.labs.slice(0, 9)
  return visibleLabs.length
    ? `<h1 class="sr-only">靶场</h1><div class="lab-grid" aria-label="靶场列表">${visibleLabs.map(labCard).join('')}</div>`
    : '<div class="empty-state lab-empty-state"><p>暂无可用靶场。</p><button class="button button-primary" type="button" data-action="refresh-runtime">重新检查</button></div>'
}

function labDetailModal() {
  const lab = state.labs.find(item => item.id === state.labDetailId)
  if (!lab) return ''
  const admin = state.session.role === 'admin'
  const ready = lab.status === 'ready'
  const runtime = state.runtimeStatus.labs?.[lab.slug] ?? {}
  const runnable = ready && labRuntimeSupported(lab)
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const installJob = state.jobs.find(item => item.labId === lab.id && ['queued', 'importing'].includes(item.status))
  const missing = state.runtimeStatus.labs?.[lab.slug]?.missing ?? []
  const requiresSetup = ready && lab.slug !== 'vulnhub' && (!runtime.available || missing.length > 0)
  const starting = busyFor('start-instance', lab.id)
  const installing = busyFor('install-lab', lab.id)
  let primaryAction = ''
  if (instance) {
    primaryAction = `<a class="button button-primary lab-detail-action lab-detail-open" href="${esc(instance.endpoint)}" target="_blank" rel="noreferrer" data-action="open-instance-page">打开页面</a>`
  } else if (starting) {
    primaryAction = '<span class="button button-quiet lab-detail-action" aria-busy="true">启动中…</span>'
  } else if (installing) {
    primaryAction = '<span class="button button-quiet lab-detail-action" aria-busy="true">准备中…</span>'
  } else if (requiresSetup) {
    primaryAction = `<button class="button button-outline lab-detail-action" type="button" data-action="open-runtime-dialog" data-id="${esc(lab.id)}">查看启动条件</button>`
  } else if (lab.slug === 'vulnhub' && ready) {
    primaryAction = `<button class="button button-primary lab-detail-action lab-detail-select" type="button" data-action="view-catalog" data-id="${esc(lab.id)}">选择启动环境</button>`
  } else if (runnable) {
    primaryAction = `<button class="button button-primary lab-detail-action" type="button" data-action="start-instance" data-id="${esc(lab.id)}">启动环境</button>`
  } else if (importing) {
    primaryAction = `<span class="button button-quiet lab-detail-action" aria-busy="true">安装中 ${Math.max(1, installJob?.progress ?? 1)}%</span>`
  } else if (queued) {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待安装</span>'
  } else if (admin) {
    primaryAction = `<button class="button ${failed ? 'button-danger' : 'button-primary'} lab-detail-action" type="button" data-action="install-lab" data-id="${esc(lab.id)}">${failed ? '重试安装' : lab.slug === 'vulnhub' ? '加载目录' : '安装靶场'}</button>`
  } else {
    primaryAction = '<span class="button button-quiet lab-detail-action">等待安装</span>'
  }
  const stateLabel = instance ? '运行中' : starting ? '启动中' : installing ? '准备中' : importing ? '安装中' : queued ? '排队中' : failed ? '安装失败' : requiresSetup ? '待配置' : ''
  const facts = [lab.category, lab.difficulty, lab.version].filter(Boolean).map(esc).join('<span aria-hidden="true">·</span>')
  const tags = Array.isArray(lab.tags) && lab.tags.length ? `<div class="lab-detail-tags">${lab.tags.slice(0, 4).map(tag => `<span>${esc(tag)}</span>`).join('')}</div>` : ''
  const runningInfo = instance
    ? `<div class="lab-detail-running"><div><span class="lab-detail-running-dot" aria-hidden="true"></span><strong>运行中</strong></div><time>到期 ${date(instance.expiresAt)}</time></div><div class="lab-detail-endpoint"><span>入口</span><code>${esc(instance.endpoint)}</code></div>`
    : ''
  const managementActions = instance && admin
    ? `<button class="button button-outline lab-detail-action" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button><button class="button button-quiet lab-detail-stop" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button>`
    : ''
  return `<div class="dialog-backdrop lab-detail-backdrop"><section class="dialog lab-detail-dialog" role="dialog" aria-modal="true" aria-labelledby="lab-detail-title"><div class="lab-card-media lab-detail-cover" data-cover="${coverVariant(lab)}">${coverArt(lab)}<button class="dialog-close lab-detail-close" type="button" data-action="close-lab-details" aria-label="关闭靶场信息">×</button></div><div class="lab-detail-body"><div class="lab-detail-heading"><div><h2 id="lab-detail-title">${esc(lab.title)}</h2><div class="lab-detail-facts">${facts}</div></div>${stateLabel ? `<span class="lab-detail-state">${esc(stateLabel)}</span>` : ''}</div>${lab.summary ? `<p class="lab-detail-summary">${esc(lab.summary)}</p>` : ''}${tags}${runningInfo}<div class="lab-detail-actions">${managementActions}${primaryAction}</div></div></section></div>`
}

function runtimeRequirementsDialog() {
  const lab = state.labs.find(item => item.id === state.runtimeDialogLabId)
  if (!lab) return ''
  const admin = state.session?.role === 'admin'
  const readiness = state.runtimeStatus?.labs?.[lab.slug] ?? {}
  const missing = Array.isArray(readiness.missing) ? readiness.missing : []
  const dependencies = Array.isArray(state.runtimeStatus?.dependencies) ? state.runtimeStatus.dependencies : []
  const missingDetails = missing.map(label => dependencies.find(item => item.label === label)).filter(Boolean)
  const preparing = busyFor('prepare-runtime')
  const refreshing = busyFor('refresh-runtime')
  const canPrepare = admin && missingDetails.some(item => item.action === 'prepare')
  const ready = readiness.available === true && lab.status === 'ready'
  const statusText = ready ? '可以启动' : missing.length ? '待处理' : '正在检查'
  const statusDetail = ready ? '项目运行时已就绪' : missing.length ? '启动前需要完成以下条件' : '正在读取当前靶场的启动条件'
  const requirementRows = missing.length
    ? missing.map(label => {
      const dependency = dependencies.find(item => item.label === label)
      return `<li><i class="runtime-requirement-dot" aria-hidden="true"></i><span><strong>${esc(label)}</strong><small>${esc(dependency?.detail ?? '尚未满足启动条件')}</small></span></li>`
    }).join('')
    : ready
      ? '<li class="is-ready"><i class="runtime-requirement-dot" aria-hidden="true"></i><span><strong>启动条件已满足</strong><small>返回详情即可启动这个靶场。</small></span></li>'
      : '<li><i class="runtime-requirement-dot" aria-hidden="true"></i><span><strong>正在检查启动条件</strong><small>请稍候，或重新检查当前状态。</small></span></li>'
  return `<div class="dialog-backdrop runtime-dialog-backdrop"><section class="dialog runtime-dialog" role="dialog" aria-modal="true" aria-labelledby="runtime-dialog-title"><div class="runtime-dialog-head"><div><span class="runtime-dialog-kicker">启动条件</span><h2 id="runtime-dialog-title">${esc(lab.title)}</h2></div><button class="dialog-close" type="button" data-action="close-runtime-dialog" aria-label="关闭启动条件">×</button></div><div class="runtime-dialog-body"><div class="runtime-dialog-status${ready ? ' is-ready' : ''}"><i aria-hidden="true"></i><strong>${statusText}</strong><span>${statusDetail}</span></div><ul class="runtime-requirements" aria-label="启动条件列表">${requirementRows}</ul><div class="runtime-dialog-actions">${canPrepare ? `<button class="button button-primary" type="button" data-action="prepare-runtime" ${preparing ? 'disabled' : ''}>${preparing ? '准备中…' : '准备运行时'}</button>` : ''}<button class="button button-quiet" type="button" data-action="refresh-runtime" ${refreshing ? 'disabled' : ''}>${refreshing ? '检查中…' : '重新检查'}</button><button class="button button-quiet runtime-dialog-close-action" type="button" data-action="close-runtime-dialog">返回详情</button></div></div></section></div>`
}

function loginPage() {
  const userNameInvalid = state.loginErrorFields.includes('userName')
  const passwordInvalid = state.loginErrorFields.includes('password')
  const notice = state.error ? loginNoticeCard({ id: 'login-notice', title: '登录失败', message: state.error, action: 'dismiss-login-error' }) : ''
  const describedBy = state.error ? 'aria-describedby="login-notice"' : ''
  return `<div class="login-page"><div class="login-mark"><img src="/favicon.svg" alt=""><span>VulnLab</span></div><form class="login-form" id="login-form" novalidate><h1>进入靶场</h1><label>账号<input name="userName" autocomplete="username" required aria-invalid="${userNameInvalid}" ${describedBy}></label><label>密码<input name="password" type="password" autocomplete="current-password" required aria-invalid="${passwordInvalid}" ${describedBy}></label><button class="button button-primary" type="submit" ${state.busy ? 'disabled' : ''}>${state.busy ? '登录中…' : '登录'}</button></form>${notice}</div>`
}

function scheduleImportPolling() {
  if (importPollTimer) { window.clearTimeout(importPollTimer); importPollTimer = null }
  if (!state.session || !state.jobs.some(job => job.status === 'importing')) return
  importPollTimer = window.setTimeout(async () => {
    importPollTimer = null
    try { await refresh(); render() } catch { scheduleImportPolling() }
  }, 1200)
}

function scheduleCatalogPolling() {
  if (catalogPollTimer) { window.clearTimeout(catalogPollTimer); catalogPollTimer = null }
  if (!state.catalog?.labId || !state.catalog.downloads?.some(download => download.status === 'downloading')) return
  const labId = state.catalog.labId
  const selectedIndex = state.catalog.selectedIndex
  catalogPollTimer = window.setTimeout(async () => {
    catalogPollTimer = null
    try {
      const catalog = await request(`/api/labs/${labId}/catalog`)
      state.catalog = { ...catalog, selectedIndex }
      render()
    } catch {
      scheduleCatalogPolling()
    }
  }, 1200)
}

function render() {
  document.body.classList.toggle('has-workspace', Boolean(state.session))
  document.body.classList.toggle('has-login-success-notice', Boolean(state.successNotice && state.session))
  document.body.classList.toggle('has-dialog', Boolean(state.catalog || state.confirm || state.labDetailId || state.runtimeDialogLabId))
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
  scheduleCatalogPolling()
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
  const canRunWhileBusy = ['nav', 'open-lab-details', 'close-lab-details', 'dismiss-login-error', 'dismiss-login-success', 'cancel-confirm', 'select-catalog-entry', 'close-catalog', 'close-runtime-dialog', 'open-runtime-dialog'].includes(action)
  const operationId = action === 'download-catalog-entry'
    ? `${state.catalog?.labId}:${element.dataset.index}:${element.dataset.downloadIndex}`
    : element?.dataset?.id ?? element?.dataset?.labId ?? ''
  const runtimeActions = ['prepare-runtime', 'refresh-runtime']
  const duplicateOperation = state.busyActions.some(item => item.action === action && item.id === operationId)
  const runtimeBusy = runtimeActions.includes(action) && state.busyActions.some(item => runtimeActions.includes(item.action))
  const logoutBusy = action === 'logout' && state.busyActions.length > 0
  if (!canRunWhileBusy && (duplicateOperation || runtimeBusy || logoutBusy)) {
    setToast(runtimeBusy ? '运行环境正在处理，请稍候。' : '当前操作正在进行中，请稍候。', 'error')
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
  if (action === 'open-runtime-dialog') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    if (!lab) return
    const cardTrigger = [...document.querySelectorAll('.lab-card-media')].find(candidate => candidate.dataset.id === lab.id)
    rememberModalFocus(state.catalog ? (cardTrigger ?? element) : element)
    if (state.catalog) {
      state.catalog = null
      state.labDetailId = lab.id
    }
    state.runtimeDialogLabId = lab.id
    state.dialogFocusSelector = '[data-action="close-runtime-dialog"]'
    render()
    return
  }
  if (action === 'close-runtime-dialog') {
    state.runtimeDialogLabId = null
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
    restoreModalFocus()
    if (next) await runAction(next.action, { dataset: next })
    return
  }
  if (action === 'logout') {
    beginBusy('logout')
    try { await request('/api/auth/logout', { method: 'POST' }); clearLoginSuccessNoticeTimer(); state.successNotice = null; state.session = null; state.csrfToken = ''; state.overview = null; state.labs = []; state.jobs = []; state.vmDownloads = []; state.instances = []; state.catalog = null; state.labDetailId = null; state.runtimeDialogLabId = null; location.hash = 'labs' } catch (error) { setToast(error.message, 'error') } finally { endBusy('logout'); render() }
    return
  }
  if (action === 'prepare-runtime' || action === 'refresh-runtime') {
    beginBusy(action)
    try {
      if (action === 'prepare-runtime') {
        const result = await request('/api/runtime/prepare', { method: 'POST' })
        state.runtimeStatus = { ...state.runtimeStatus, project: result.project }
        if (!result.ok) throw new ApiError(result.message ?? '项目运行环境准备失败。', 409)
      }
      await refresh()
      setToast(action === 'prepare-runtime' ? '项目运行环境已准备完成。' : '运行环境状态已更新。')
      } catch (error) { setToast(error.message, 'error') } finally { endBusy(action); render() }
    return
  }
  if (action === 'install-lab') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/labs/${element.dataset.id}/install`, { method: 'POST' }); await refresh(); setToast('靶场安装已开始。') } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'view-catalog') {
    const labId = element.dataset.id
    state.labDetailId = null
    const cardTrigger = [...document.querySelectorAll('.lab-card-media')].find(candidate => candidate.dataset.id === labId)
    rememberModalFocus(cardTrigger ?? element)
    state.catalog = { loading: true, labId }
    beginBusy(action, labId)
    try {
      const catalog = await request(`/api/labs/${labId}/catalog`)
      if (state.catalog?.labId === labId) state.catalog = { ...catalog, selectedIndex: catalog.entries.length ? 0 : null }
    } catch (error) {
      if (state.catalog?.labId === labId) state.catalog = null
      setToast(error.message, 'error')
    } finally {
      endBusy(action, labId)
      render()
    }
    return
  }
  if (action === 'close-catalog') {
    state.catalog = null
    state.dialogFocusSelector = ''
    render(); restoreModalFocus()
    return
  }
  if (action === 'select-catalog-entry') {
    const index = Number(element.dataset.index)
    if (state.catalog && Number.isInteger(index) && index >= 0 && index < state.catalog.entries.length) {
      state.catalog.selectedIndex = index
      state.dialogFocusSelector = `[data-action="select-catalog-entry"][data-index="${index}"]`
      render()
    }
    return
  }
  if (action === 'download-catalog-entry') {
    if (!state.catalog?.labId) return
    const labId = state.catalog.labId
    const busyId = `${labId}:${element.dataset.index}:${element.dataset.downloadIndex}`
    state.dialogFocusSelector = `[data-action="download-catalog-entry"][data-index="${element.dataset.index}"][data-download-index="${element.dataset.downloadIndex}"]`
    beginBusy(action, busyId)
    try {
      await request(`/api/labs/${labId}/catalog/entries/${element.dataset.index}/download`, { method: 'POST', body: JSON.stringify({ downloadIndex: Number(element.dataset.downloadIndex) }) })
      const catalog = await request(`/api/labs/${labId}/catalog`)
      if (state.catalog?.labId === labId) state.catalog = { ...catalog, selectedIndex: Number(element.dataset.index) }
      setToast('镜像下载已登记，完成后会自动核对校验值。')
    } catch (error) {
      setToast(error.message, 'error')
    } finally {
      endBusy(action, busyId)
      render()
    }
    return
  }
  if (action === 'start-instance') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    const vmDownload = lab?.runtimeKind === 'vm' ? state.vmDownloads.find(item => item.labId === lab.id && item.status === 'completed' && item.localPath) : null
    beginBusy(action, element.dataset.id)
    try {
      await request(`/api/labs/${element.dataset.id}/instances`, { method: 'POST', ...(vmDownload ? { body: JSON.stringify({ vmDownloadId: vmDownload.id }) } : {}) })
      await refresh()
      setToast(`${lab?.runtimeKind === 'vm' ? '虚拟机' : '靶场环境'}已启动，可直接打开页面。`)
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'start-vm-instance') {
    beginBusy(action, element.dataset.labId)
    try {
      const instance = await request(`/api/labs/${element.dataset.labId}/instances`, { method: 'POST', body: JSON.stringify({ vmDownloadId: element.dataset.downloadId }) })
      state.catalog = null
      await refresh()
      navigate('labs')
      setToast(`QEMU 虚拟机已创建：${instance.endpoint}`)
    } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.labId); render() }
    return
  }
  if (action === 'renew-instance') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/instances/${element.dataset.id}/renew`, { method: 'POST' }); await refresh(); setToast('实例已续期。') } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
    return
  }
  if (action === 'destroy-instance') {
    rememberModalFocus(element)
    state.labDetailId = null
    openConfirm('停止靶场环境', '停止后会释放运行端口和实例资源，下次启动会创建新的练习副本。', { action: 'confirm-destroy', id: element.dataset.id }, '停止环境')
    return
  }
  if (action === 'confirm-destroy') {
    beginBusy(action, element.dataset.id)
    try { await request(`/api/instances/${element.dataset.id}`, { method: 'DELETE' }); await refresh(); setToast('实例已结束。') } catch (error) { setToast(error.message, 'error') } finally { endBusy(action, element.dataset.id); render() }
  }
}

app.addEventListener('click', event => {
  const element = event.target.closest?.('[data-action]')
  if (!element) return
  if (element.dataset.action !== 'open-instance-page') event.preventDefault()
  runAction(element.dataset.action, element)
})

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

function moveCatalogSelection(index) {
  const entries = state.catalog?.entries ?? []
  if (!entries.length) return
  const nextIndex = Math.max(0, Math.min(entries.length - 1, index))
  state.catalog.selectedIndex = nextIndex
  state.dialogFocusSelector = `[data-action="select-catalog-entry"][data-index="${nextIndex}"]`
  render()
}

document.addEventListener('keydown', event => {
  const dialog = document.querySelector('[role="dialog"]')
  if (!dialog) return
  if (event.key === 'Escape') {
    if (state.catalog) state.catalog = null
    else if (state.confirm) state.confirm = null
    else if (state.runtimeDialogLabId) state.runtimeDialogLabId = null
    else if (state.labDetailId) state.labDetailId = null
    render()
    restoreModalFocus()
    return
  }
  const catalogEntry = event.target.closest?.('.catalog-entry')
  if (state.catalog && catalogEntry && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
    const currentIndex = Number(catalogEntry.dataset.index)
    const nextIndex = event.key === 'ArrowDown'
      ? currentIndex + 1
      : event.key === 'ArrowUp'
        ? currentIndex - 1
        : event.key === 'Home' ? 0 : (state.catalog.entries?.length ?? 1) - 1
    event.preventDefault()
    moveCatalogSelection(nextIndex)
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
