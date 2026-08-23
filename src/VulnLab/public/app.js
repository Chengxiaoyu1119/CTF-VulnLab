const app = document.querySelector('#app')
let importPollTimer = null
let catalogPollTimer = null

const state = {
  session: null,
  csrfToken: '',
  overview: null,
  labs: [],
  jobs: [],
  vmDownloads: [],
  instances: [],
  settings: null,
  audit: [],
  selectedLabId: null,
  loading: true,
  busy: false,
  error: '',
  toast: null,
  confirm: null,
  catalog: null,
  logPaused: false,
}

const esc = value => String(value ?? '').replace(/[&<>'"]/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
}[character]))

const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const jobLabel = value => ({ queued: '等待适配', importing: '导入中', completed: '已完成', error: '失败' }[value] ?? value)
const instanceLabel = value => ({ running: '运行中', expired: '已过期', destroyed: '已结束' }[value] ?? value)
const currentView = () => {
  const value = location.hash.slice(1)
  if (value.startsWith('lab/')) return 'labs'
  return ['labs', 'imports', 'instances', 'settings', 'audit'].includes(value) ? value : 'labs'
}

const syncSelectedLab = () => {
  const value = location.hash.slice(1)
  if (!value.startsWith('lab/')) return
  const slug = decodeURIComponent(value.slice(4))
  const lab = state.labs.find(item => item.slug === slug)
  if (lab) state.selectedLabId = lab.id
}

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
  const [overview, labs, jobs, vmDownloads, instances, settings] = await Promise.all([
    request('/api/overview'), request('/api/labs'), request('/api/import-jobs'), request('/api/vm-downloads'), request('/api/instances'), request('/api/settings'),
  ])
  state.overview = overview
  state.labs = labs
  state.jobs = jobs
  state.vmDownloads = vmDownloads
  state.instances = instances
  state.settings = settings
  if (!state.selectedLabId) state.selectedLabId = labs[1]?.id ?? labs[0]?.id ?? null
  if (state.session.role === 'admin') state.audit = await request('/api/audit')
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

function navigate(view) {
  state.catalog = null
  location.hash = view
}

function setToast(message, type = 'success') {
  state.toast = { message, type }
  render()
  window.setTimeout(() => {
    if (state.toast?.message === message) { state.toast = null; render() }
  }, 3600)
}

function catalogDialog() {
  const catalog = state.catalog
  if (!catalog) return ''
  if (catalog.loading) {
    return `<div class="dialog-backdrop catalog-backdrop"><section class="dialog catalog-dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"><div class="catalog-dialog-head"><h2 id="catalog-dialog-title">VulnHub 机器目录</h2><button class="dialog-close" type="button" data-action="close-catalog" aria-label="关闭目录">×</button></div><div class="catalog-loading">正在读取目录…</div></section></div>`
  }
  const entries = Array.isArray(catalog.entries) ? catalog.entries : []
  const downloads = Array.isArray(catalog.downloads) ? catalog.downloads : []
  const selectedIndex = Number.isInteger(catalog.selectedIndex) ? catalog.selectedIndex : 0
  const entry = entries[selectedIndex]
  const downloadFor = index => downloads.find(item => item.entryIndex === index)
  const downloadLabel = download => download?.status === 'completed' ? '已下载' : download?.status === 'downloading' ? `${download.progress}%` : download?.status === 'error' ? '重试' : null
  const value = item => item || '—'
  const download = downloadFor(selectedIndex)
  const downloadButtons = entry?.downloadUrls?.length
    ? entry.downloadUrls.map((url, index) => {
      const isCurrent = download?.downloadUrl === url
      const label = isCurrent ? downloadLabel(download) : null
      return label === '已下载'
        ? '<span class="download-state is-complete">已下载</span>'
        : label && download?.status === 'downloading'
          ? `<span class="download-state">下载中 ${esc(label)}</span>`
          : `<button class="button button-quiet" type="button" data-action="download-catalog-entry" data-index="${selectedIndex}" data-download-index="${index}">${label === '重试' ? '重试下载' : '下载镜像'}</button>`
    }).join('')
    : '<span class="download-state">暂无官方镜像</span>'
  const vmStartButton = download?.status === 'completed' && state.settings?.provider === 'qemu-vm'
    ? `<button class="button button-primary" type="button" data-action="start-vm-instance" data-lab-id="${esc(catalog.labId)}" data-download-id="${esc(download.id)}">启动这台机器</button>`
    : ''
  return `<div class="dialog-backdrop catalog-backdrop"><section class="dialog catalog-dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"><div class="catalog-dialog-head"><div><h2 id="catalog-dialog-title">VulnHub 机器目录</h2><span>${esc(catalog.labTitle)} · ${entries.length} 台</span></div><button class="dialog-close" type="button" data-action="close-catalog" aria-label="关闭目录">×</button></div>${entries.length ? `<div class="catalog-layout"><div class="catalog-list" role="listbox" aria-label="VulnHub 机器"><div class="catalog-list-scroll">${entries.map((item, index) => `<button class="catalog-entry${index === selectedIndex ? ' is-selected' : ''}" type="button" role="option" aria-selected="${index === selectedIndex}" data-action="select-catalog-entry" data-index="${index}"><strong>${esc(item.title)}</strong><span>${esc(downloadLabel(downloadFor(index)) ?? value(item.difficulty))}</span></button>`).join('')}</div></div><article class="catalog-detail"><div class="catalog-detail-title"><span class="eyebrow">${String(selectedIndex + 1).padStart(2, '0')}</span><h3>${esc(entry.title)}</h3></div><div class="catalog-facts"><div><span>作者</span><strong>${esc(value(entry.author))}</strong></div><div><span>难度</span><strong>${esc(value(entry.difficulty))}</strong></div><div><span>文件</span><strong>${esc(value(entry.filename))}</strong></div><div><span>大小</span><strong>${esc(value(entry.fileSize))}</strong></div><div><span>MD5</span><strong class="catalog-hash">${esc(value(entry.md5))}</strong></div><div><span>SHA1</span><strong class="catalog-hash">${esc(value(entry.sha1))}</strong></div></div><div class="catalog-links"><a class="button button-outline" href="${esc(entry.url)}" target="_blank" rel="noreferrer">官方详情 ↗</a>${downloadButtons}${vmStartButton}</div><p class="catalog-note">下载只在点击后开始，完成后会核对目录中的 MD5/SHA1；已下载镜像可交给 QEMU Provider 启动，未安装 QEMU 时仍只保留目录和校验结果。</p></article></div>` : '<div class="empty-state">目录中没有机器记录。</div>'}</section></div>`
}

function overlays() {
  return `${state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status">${esc(state.toast.message)}</div>` : ''}
    ${state.confirm ? `<div class="dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p>${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : ''}
    ${catalogDialog()}`
}

function shell(content) {
  const admin = state.session.role === 'admin'
  const view = currentView()
  const nav = [
    ['labs', '靶场'],
    ['imports', '导入'],
    ['instances', '运行'],
    ['settings', '环境'],
    ...(admin ? [['audit', '审计']] : []),
  ]
  return `<div class="app-shell">
    <header class="topbar">
      <div class="topbar-inner">
        <button class="brand" type="button" data-action="nav" data-view="labs" aria-label="返回靶场目录">
          <img src="/favicon.svg" alt="" /><span>VulnLab</span>
        </button>
        <nav class="topnav" aria-label="工作区导航">${nav.map(([key, label]) => `<button class="topnav-link${view === key ? ' is-active' : ''}" type="button" data-action="nav" data-view="${key}">${label}</button>`).join('')}</nav>
        <div class="account"><span class="avatar">${esc(state.session.userName.slice(0, 1).toUpperCase())}</span><span class="account-name">${esc(state.session.userName)}</span><button class="text-button" type="button" data-action="logout">退出</button></div>
      </div>
    </header>
    <main class="main-content" tabindex="-1">${content}</main>
    ${overlays()}
  </div>`
}

function runtimePanel() {
  const overview = state.overview ?? {}
  const running = overview.runningInstanceCount ?? 0
  const provider = state.settings?.provider === 'simulated' ? 'simulated-runtime' : state.settings?.provider ?? '-'
  const logs = [
    ['10:00:00', 'INFO', 'API 接口已就绪'],
    ['10:00:01', 'OK', '靶场目录已挂载'],
    ['10:00:02', 'OK', `运行时 ${provider}`],
    ['10:00:03', running > 0 ? 'RUN' : 'WAIT', running > 0 ? '实例正在运行' : '等待启动实例'],
    ['10:00:04', 'INFO', '事件流已接入'],
    ['10:00:05', 'INFO', '运行状态已记录'],
    ['10:00:06', 'INFO', '等待下一条运行事件'],
    ['10:00:07', 'INFO', '本地工作区保持就绪'],
  ]
  return `<aside class="runtime-panel" aria-label="运行状态">
    <pre class="runtime-ascii" aria-label="Chengxiaoyu ASCII 字符图形">${esc(chengxiaoyuAsciiArt)}</pre>
    <div class="runtime-log" aria-live="polite">${state.logPaused ? '<div class="runtime-paused">日志跟随已暂停</div>' : logs.map(([time, level, message]) => `<div class="runtime-line"><time>${time}</time><b class="log-${level.toLowerCase()}">[${level}]</b><span>${esc(message)}</span></div>`).join('')}</div>
  </aside>`
}

function labsShell(content) {
  const accountLabel = state.session.role === 'admin' ? 'admin' : 'learner'
  return `<div class="labs-screen">
    ${runtimePanel()}
    <section class="lab-workspace">
      <header class="lab-workspace-head"><button class="workspace-back" type="button" data-action="nav" data-view="labs" aria-label="返回靶场目录">‹</button><h1>靶场</h1><button class="workspace-account" type="button" data-action="logout" aria-label="退出登录">${accountLabel}⌄</button></header>
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

function pageHeader(title, description, action = '') {
  return `<div class="page-header"><div><h1>${esc(title)}</h1><p>${esc(description)}</p></div>${action}</div>`
}

const labCode = lab => ({ Web: 'WEB', VM: 'PWN', API: 'API', Misc: 'MIS' }[lab.category] ?? lab.category.slice(0, 3).toUpperCase())
const coverAssets = Object.freeze({
  dvwa: '/covers/dvwa.png',
  pikachu: '/covers/pikachu.png',
  'sqli-labs': '/covers/sqli-labs.jpg',
  'upload-labs': '/covers/upload-labs.jpg',
  vulnhub: '/covers/vulnhub.png',
  vulhub: '/covers/vulhub.png',
  'juice-shop': '/covers/juice-shop.png',
  webgoat: '/covers/webgoat.png',
  crapi: '/covers/crapi.png',
})
const coverVariant = lab => Object.hasOwn(coverAssets, lab.slug) ? lab.slug : 'default'
const coverArt = lab => coverAssets[lab.slug] ? `<img class="lab-card-cover" src="${coverAssets[lab.slug]}" alt="" loading="lazy" decoding="async" />` : ''
const labRuntimeSupported = lab => {
  if (lab.runtimeKind === 'native-php' || lab.runtimeKind === 'simulated') return true
  if (lab.runtimeKind !== 'vm' || state.settings?.provider !== 'qemu-vm') return false
  return state.vmDownloads.some(download => download.labId === lab.id && download.status === 'completed' && download.localPath)
}

function labCard(lab) {
  const admin = state.session.role === 'admin'
  const isSelected = state.selectedLabId === lab.id
  const ready = lab.status === 'ready'
  const runnable = ready && labRuntimeSupported(lab)
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const code = labCode(lab)
  const source = lab.sourceUrl
  const secondaryAction = isSelected && ready
    ? `<a class="content-link" href="${esc(source)}" target="_blank" rel="noreferrer">内容&nbsp;↗</a>${runnable ? '<button class="card-plain-button" type="button" data-action="nav" data-view="settings">环境</button>' : '<span></span>'}`
    : admin && failed
      ? `<button class="card-plain-button" type="button" data-action="queue-import" data-id="${esc(lab.id)}">重试导入</button>`
      : admin && !ready && !importing && !queued
        ? `<button class="card-plain-button" type="button" data-action="queue-import" data-id="${esc(lab.id)}">添加环境</button>`
        : '<span></span>'
  const primaryAction = runnable
    ? `<button class="card-primary-button" type="button" data-action="start-instance" data-id="${esc(lab.id)}">启动</button>`
    : importing
      ? '<span class="card-primary-button is-disabled">处理中</span>'
      : queued
        ? '<span class="card-primary-button is-disabled">已排队</span>'
        : `<a class="card-primary-button" href="${esc(source)}" target="_blank" rel="noreferrer">打开项目</a>`
  return `<article class="lab-card${isSelected ? ' is-selected' : ''}">
    <button class="lab-card-head" type="button" data-action="select-lab" data-id="${esc(lab.id)}" aria-label="查看 ${esc(lab.title)}"><span>${esc(lab.title)}</span><em>${esc(code)}</em></button>
    <button class="lab-card-media" type="button" data-cover="${coverVariant(lab)}" data-action="select-lab" data-id="${esc(lab.id)}" aria-label="打开 ${esc(lab.title)}">${coverArt(lab)}</button>
    <div class="lab-card-actions">${secondaryAction}${primaryAction}</div>
  </article>`
}

function addCard() {
  return `<button class="lab-card lab-card-add" type="button" data-action="nav" data-view="imports" aria-label="添加靶场环境"><span class="add-mark">＋</span><strong>添加靶场环境</strong></button>`
}

function labsPage() {
  // The 3×3 workspace is a stable directory, not a status queue. Importing
  // or ready state changes the card body only; it must not move the user's
  // known labs into different slots.
  const visibleLabs = state.labs.slice(0, 8)
  return `<div class="lab-grid" aria-label="靶场列表">${visibleLabs.map(labCard).join('')}${addCard()}</div>`
}

function jobsPage() {
  const admin = state.session.role === 'admin'
  return `${pageHeader('导入', '登记来源、固定版本、下载并生成可审计的本地清单。', admin ? '<span class="page-note">只下载和解包，不执行外部代码</span>' : '')}
    <div class="import-layout">
      ${admin ? `<form class="surface-form" id="import-form"><div class="form-heading"><h2>登记新来源</h2><span>GitHub / GitLab 可直接导入</span></div><label>来源地址<input name="sourceUrl" type="url" required placeholder="https://github.com/... 或 https://gitlab.com/..."></label><div class="form-row"><label>显示名称<input name="title" placeholder="自动从来源提取"></label><label>分支或版本<input name="ref" placeholder="默认分支"></label></div><div class="form-row"><label>分类<select name="category"><option>Web</option><option>API</option><option>VM</option><option>Misc</option></select></label><label>运行类型<select name="runtimeKind"><option value="container">container</option><option value="native-php">native-php（原生 PHP）</option><option value="vm">vm</option><option value="simulated">simulated</option></select></label></div><label>许可证<input name="license" placeholder="待核验"></label><label>一句话说明<textarea name="summary" rows="3" placeholder="只写对选择有帮助的信息"></textarea></label><button class="button button-primary" type="submit">登记导入任务</button></form>` : ''}
      <section class="jobs-surface"><div class="section-line"><h2>导入任务</h2><span>${state.jobs.length} 条记录</span></div>${state.jobs.length ? `<div class="job-list">${state.jobs.map(job => { const lab = state.labs.find(item => item.id === job.labId); const action = admin && job.status === 'queued' ? `<button class="small-button" type="button" data-action="run-import" data-id="${esc(job.id)}">开始导入</button>` : job.status === 'importing' ? '<span class="job-running">处理中</span>' : ''; const catalogAction = job.status === 'completed' && job.manifest?.adapterId === 'vulnhub-catalog' ? `<button class="small-button" type="button" data-action="view-catalog" data-id="${esc(lab?.id ?? job.labId)}">查看机器</button>` : ''; const warnings = job.manifest?.warnings?.length ? ` · 警告：${job.manifest.warnings.join('；')}` : ''; const evidence = job.manifest ? `${job.manifest.resolvedRef} · sha256:${job.manifest.archiveSha256.slice(0, 12)}${warnings}` : job.error ? job.error : ''; return `<article class="job-row"><div><strong>${esc(lab?.title ?? job.labId)}</strong><span>${esc(job.stage)} · ${esc(job.message)}</span>${evidence ? `<small class="job-evidence">${esc(evidence)}</small>` : ''}</div><div class="job-progress"><span>${esc(jobLabel(job.status))}</span><i><b style="width:${Math.max(0, Math.min(100, job.progress))}%"></b></i></div><div class="job-side"><time>${date(job.updatedAt)}</time>${catalogAction}${action}</div></article>` }).join('')}</div>` : '<div class="empty-state">还没有导入任务。</div>'}</section>
    </div>`
}

function instancesPage() {
  const admin = state.session.role === 'admin'
  return `${pageHeader('运行', '查看模拟入口和实例生命周期。', '<span class="page-note">simulated Provider</span>')}
    <section class="instances-surface"><div class="section-line"><h2>实例列表</h2><span>${state.instances.length} 条记录</span></div>${state.instances.length ? `<div class="instance-list">${state.instances.map(instance => `<article class="instance-row"><div class="instance-main"><span class="instance-status ${instance.status}"></span><div><strong>${esc(instance.labTitle)}</strong><span>${esc(instance.provider)} · ${esc(instance.endpoint)}</span></div></div><div class="instance-time"><span>${esc(instanceLabel(instance.status))}</span><time>到期 ${date(instance.expiresAt)}</time></div>${admin && instance.status === 'running' ? `<div class="instance-actions"><a class="small-button" href="${esc(instance.endpoint)}" target="_blank" rel="noreferrer">打开</a><button class="small-button" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button><button class="small-button danger-text" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">结束</button></div>` : ''}</article>`).join('')}</div>` : '<div class="empty-state">还没有运行实例。去靶场目录选择一个入口。</div>'}</section>`
}

function settingsPage() {
  const settings = state.settings ?? {}
  const admin = state.session.role === 'admin'
  return `${pageHeader('环境', '这里只配置运行参数，不混入靶场 3×3 展示。', '<span class="page-note">单机运行 · 端口修改后重启生效</span>')}
    <form class="settings-layout" id="settings-form"><section class="settings-surface"><div class="form-heading"><h2>运行环境</h2><span>Provider 与容量</span></div><label>Provider<select name="provider" ${admin ? '' : 'disabled'}><option value="simulated" ${settings.provider === 'simulated' ? 'selected' : ''}>simulated</option><option value="native-php" ${settings.provider === 'native-php' ? 'selected' : ''}>native-php（原生 PHP）</option><option value="qemu-vm" ${settings.provider === 'qemu-vm' ? 'selected' : ''}>qemu-vm（可选 QEMU）</option><option value="container" disabled>container（不在主服务中启用）</option></select></label><div class="form-row"><label>监听地址<input name="bindHost" value="${esc(settings.bindHost)}" ${admin ? '' : 'disabled'}></label><label>端口<input name="port" type="number" min="1024" max="65535" value="${esc(settings.port)}" ${admin ? '' : 'disabled'}></label></div><label>最大并发实例<input name="maxInstances" type="number" min="1" max="99" value="${esc(settings.maxInstances)}" ${admin ? '' : 'disabled'}></label><label class="toggle-line"><input name="autoCleanup" type="checkbox" ${settings.autoCleanup === 'true' ? 'checked' : ''} ${admin ? '' : 'disabled'}><span>过期后自动回收运行资源</span></label></section><section class="settings-surface settings-readout"><div class="form-heading"><h2>数据</h2><span>本机路径</span></div><label>状态目录<input value="${esc(settings.dataDir)}" readonly aria-readonly="true"></label><div class="readout"><span>当前运行</span><strong>${state.overview?.runningInstanceCount ?? 0} / ${state.overview?.maxInstances ?? 0}</strong></div><div class="readout"><span>数据存储</span><strong>SQLite</strong></div><div class="readout"><span>原生 PHP</span><strong>Upload-Labs 自动使用</strong></div><div class="readout"><span>QEMU</span><strong>可选 · 需本机安装</strong></div></section>${admin ? '<button class="button button-primary settings-save" type="submit">保存环境</button>' : ''}</form>`
}

function auditPage() {
  return `${pageHeader('审计', '只保留对运行和导入有用的操作记录。', '')}<section class="audit-surface">${state.audit.length ? `<div class="audit-list">${state.audit.map(item => `<article class="audit-row"><time>${date(item.created_at ?? item.createdAt)}</time><strong>${esc(item.action)}</strong><span>${esc(item.target)}</span><p>${esc(item.detail)}</p><small>${esc(item.actor)}</small></article>`).join('')}</div>` : '<div class="empty-state">还没有审计记录。</div>'}</section>`
}

function loginPage() {
  return `<div class="login-page"><div class="login-mark"><img src="/favicon.svg" alt=""><span>VulnLab</span></div><form class="login-form" id="login-form"><h1>进入工作台</h1><p>管理靶场来源、导入状态和单机运行环境。</p><label>账号<input name="userName" autocomplete="username" required placeholder="vulnlab-admin"></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label>${state.error ? `<div class="form-error" role="alert">${esc(state.error)}</div>` : ''}<button class="button button-primary" type="submit">登录</button></form></div>`
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
  if (state.loading) { app.innerHTML = '<div class="loading-screen">正在打开 VulnLab…</div>'; return }
  if (!state.session) { app.innerHTML = loginPage(); return }
  syncSelectedLab()
  const view = currentView()
  const page = view === 'imports' ? jobsPage() : view === 'instances' ? instancesPage() : view === 'settings' ? settingsPage() : view === 'audit' ? auditPage() : labsPage()
  app.innerHTML = view === 'labs' ? labsShell(page) : shell(page)
  scheduleImportPolling()
  scheduleCatalogPolling()
}

function openConfirm(title, message, action, confirmLabel = '继续') {
  state.confirm = { title, message, action, confirmLabel }
  render()
}

async function runAction(action, element) {
  if (state.busy) return
  if (action === 'nav') { navigate(element.dataset.view); return }
  if (action === 'toggle-log-pause') { state.logPaused = !state.logPaused; render(); return }
  if (action === 'select-lab') {
    const lab = state.labs.find(item => item.id === element.dataset.id)
    if (lab) navigate(`lab/${encodeURIComponent(lab.slug)}`)
    return
  }
  if (action === 'cancel-confirm') { state.confirm = null; render(); return }
  if (action === 'confirm-action') {
    const next = state.confirm?.action
    state.confirm = null
    if (next) await runAction(next.action, { dataset: next })
    return
  }
  if (action === 'logout') {
    state.busy = true
    try { await request('/api/auth/logout', { method: 'POST' }); state.session = null; state.csrfToken = ''; state.overview = null; state.labs = []; state.jobs = []; state.vmDownloads = []; state.instances = []; state.audit = []; state.catalog = null; location.hash = 'labs' } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'queue-import') {
    if (element.textContent?.includes('排队')) return
    state.busy = true
    try { await request(`/api/labs/${element.dataset.id}/import`, { method: 'POST' }); await refresh(); setToast('导入任务已登记。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'run-import') {
    state.busy = true
    try { await request(`/api/import-jobs/${element.dataset.id}/run`, { method: 'POST' }); await refresh(); setToast('导入已开始，页面会显示下载和解包进度。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'view-catalog') {
    state.busy = true
    state.catalog = { loading: true }
    render()
    try {
      const catalog = await request(`/api/labs/${element.dataset.id}/catalog`)
      state.catalog = { ...catalog, selectedIndex: catalog.entries.length ? 0 : null }
    } catch (error) {
      state.catalog = null
      setToast(error.message, 'error')
    } finally {
      state.busy = false
      render()
    }
    return
  }
  if (action === 'close-catalog') {
    state.catalog = null
    render()
    return
  }
  if (action === 'select-catalog-entry') {
    const index = Number(element.dataset.index)
    if (state.catalog && Number.isInteger(index) && index >= 0 && index < state.catalog.entries.length) {
      state.catalog.selectedIndex = index
      render()
    }
    return
  }
  if (action === 'download-catalog-entry') {
    if (!state.catalog?.labId) return
    state.busy = true
    try {
      await request(`/api/labs/${state.catalog.labId}/catalog/entries/${element.dataset.index}/download`, { method: 'POST', body: JSON.stringify({ downloadIndex: Number(element.dataset.downloadIndex) }) })
      const catalog = await request(`/api/labs/${state.catalog.labId}/catalog`)
      state.catalog = { ...catalog, selectedIndex: Number(element.dataset.index) }
      setToast('镜像下载已登记，完成后会自动核对校验值。')
    } catch (error) {
      setToast(error.message, 'error')
    } finally {
      state.busy = false
      render()
    }
    return
  }
  if (action === 'start-instance') {
    state.busy = true
    const lab = state.labs.find(item => item.id === element.dataset.id)
    const vmDownload = lab?.runtimeKind === 'vm' ? state.vmDownloads.find(item => item.labId === lab.id && item.status === 'completed' && item.localPath) : null
    try {
      const instance = await request(`/api/labs/${element.dataset.id}/instances`, { method: 'POST', ...(vmDownload ? { body: JSON.stringify({ vmDownloadId: vmDownload.id }) } : {}) })
      await refresh()
      navigate('instances')
      setToast(`${lab?.runtimeKind === 'vm' ? 'QEMU 虚拟机' : '运行入口'}已创建：${instance.endpoint}`)
    } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'start-vm-instance') {
    state.busy = true
    try {
      const instance = await request(`/api/labs/${element.dataset.labId}/instances`, { method: 'POST', body: JSON.stringify({ vmDownloadId: element.dataset.downloadId }) })
      state.catalog = null
      await refresh()
      navigate('instances')
      setToast(`QEMU 虚拟机已创建：${instance.endpoint}`)
    } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'renew-instance') {
    state.busy = true
    try { await request(`/api/instances/${element.dataset.id}/renew`, { method: 'POST' }); await refresh(); setToast('实例已续期。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'destroy-instance') {
    openConfirm('结束运行实例', '结束后该模拟入口会关闭，运行记录仍会保留在审计中。', { action: 'confirm-destroy', id: element.dataset.id }, '结束实例')
    return
  }
  if (action === 'confirm-destroy') {
    state.busy = true
    try { await request(`/api/instances/${element.dataset.id}`, { method: 'DELETE' }); await refresh(); setToast('实例已结束。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
  }
}

app.addEventListener('click', event => {
  const element = event.target.closest?.('[data-action]')
  if (!element) return
  event.preventDefault()
  runAction(element.dataset.action, element)
})

app.addEventListener('submit', async event => {
  event.preventDefault()
  if (state.busy) return
  const form = event.target
  const values = Object.fromEntries(new FormData(form).entries())
  if (form.id === 'login-form') {
    state.busy = true; state.error = ''
    try { const session = await request('/api/auth/login', { method: 'POST', body: JSON.stringify(values) }); state.session = session; state.csrfToken = session.csrfToken; await refresh(); navigate('labs') } catch (error) { state.error = error.message } finally { state.busy = false; render() }
    return
  }
  if (form.id === 'import-form') {
    state.busy = true
    try { await request('/api/labs/import', { method: 'POST', body: JSON.stringify(values) }); await refresh(); form.reset(); setToast('来源已登记，等待适配器。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (form.id === 'settings-form') {
    state.busy = true
    try { const payload = { ...values, autoCleanup: values.autoCleanup === 'on' ? 'true' : 'false' }; await request('/api/settings', { method: 'PUT', body: JSON.stringify(payload) }); await refresh(); setToast('运行环境已保存。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
  }
})

window.addEventListener('hashchange', render)
bootstrap()
