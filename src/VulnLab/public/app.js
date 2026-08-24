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
  runtimeStatus: { dependencies: [], labs: {} },
  loading: true,
  busy: false,
  error: '',
  toast: null,
  confirm: null,
  catalog: null,
}

const esc = value => String(value ?? '').replace(/[&<>'"]/g, character => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
}[character]))

const date = value => value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
const instanceLabel = value => ({ running: '运行中', expired: '已过期', destroyed: '已结束' }[value] ?? value)
const currentView = () => {
  const value = location.hash.slice(1)
  return ['labs', 'instances', 'settings'].includes(value) ? value : 'labs'
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
  const [overview, labs, jobs, vmDownloads, instances, settings, runtimeStatus] = await Promise.all([
    request('/api/overview'), request('/api/labs'), request('/api/import-jobs'), request('/api/vm-downloads'), request('/api/instances'), request('/api/settings'), request('/api/runtime-status'),
  ])
  state.overview = overview
  state.labs = labs
  state.jobs = jobs
  state.vmDownloads = vmDownloads
  state.instances = instances
  state.settings = settings
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
  const vmStartButton = download?.status === 'completed' && state.runtimeStatus.labs?.vulnhub?.available
    ? `<button class="button button-primary" type="button" data-action="start-vm-instance" data-lab-id="${esc(catalog.labId)}" data-download-id="${esc(download.id)}">启动这台机器</button>`
    : ''
  return `<div class="dialog-backdrop catalog-backdrop"><section class="dialog catalog-dialog" role="dialog" aria-modal="true" aria-labelledby="catalog-dialog-title"><div class="catalog-dialog-head"><div><h2 id="catalog-dialog-title">VulnHub 机器目录</h2><span>${esc(catalog.labTitle)} · ${entries.length} 台</span></div><button class="dialog-close" type="button" data-action="close-catalog" aria-label="关闭目录">×</button></div>${entries.length ? `<div class="catalog-layout"><div class="catalog-list" role="listbox" aria-label="VulnHub 机器"><div class="catalog-list-scroll">${entries.map((item, index) => `<button class="catalog-entry${index === selectedIndex ? ' is-selected' : ''}" type="button" role="option" aria-selected="${index === selectedIndex}" data-action="select-catalog-entry" data-index="${index}"><strong>${esc(item.title)}</strong><span>${esc(downloadLabel(downloadFor(index)) ?? value(item.difficulty))}</span></button>`).join('')}</div></div><article class="catalog-detail"><div class="catalog-detail-title"><h3>${esc(entry.title)}</h3></div><div class="catalog-facts"><div><span>作者</span><strong>${esc(value(entry.author))}</strong></div><div><span>难度</span><strong>${esc(value(entry.difficulty))}</strong></div><div><span>文件</span><strong>${esc(value(entry.filename))}</strong></div><div><span>大小</span><strong>${esc(value(entry.fileSize))}</strong></div><div><span>MD5</span><strong class="catalog-hash">${esc(value(entry.md5))}</strong></div><div><span>SHA1</span><strong class="catalog-hash">${esc(value(entry.sha1))}</strong></div></div><div class="catalog-links"><a class="button button-outline" href="${esc(entry.url)}" target="_blank" rel="noreferrer">官方详情 ↗</a>${downloadButtons}${vmStartButton}</div><p class="catalog-note">镜像下载完成后自动校验文件，运行条件就绪即可启动。</p></article></div>` : '<div class="empty-state">目录中没有机器记录。</div>'}</section></div>`
}

function overlays() {
  return `${state.toast ? `<div class="toast ${state.toast.type === 'error' ? 'toast-error' : ''}" role="status">${esc(state.toast.message)}</div>` : ''}
    ${state.confirm ? `<div class="dialog-backdrop" role="presentation"><section class="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><h2 id="dialog-title">${esc(state.confirm.title)}</h2><p>${esc(state.confirm.message)}</p><div class="dialog-actions"><button class="button button-quiet" type="button" data-action="cancel-confirm">取消</button><button class="button button-danger" type="button" data-action="confirm-action">${esc(state.confirm.confirmLabel ?? '继续')}</button></div></section></div>` : ''}
    ${catalogDialog()}`
}

function runtimePanel() {
  const overview = state.overview ?? {}
  const dependencies = state.runtimeStatus?.dependencies ?? []
  const logs = [
    ['CORE', 'OK', 'VulnLab 服务已就绪'],
    ['LABS', overview.readyCount === state.labs.length ? 'OK' : 'RUN', `${overview.readyCount ?? 0}/${state.labs.length} 个靶场已安装`],
    ['RUN', overview.runningInstanceCount ? 'RUN' : 'WAIT', `${overview.runningInstanceCount ?? 0} 个环境正在运行`],
    ...dependencies.map(item => [item.label.toUpperCase().slice(0, 6), item.available ? 'OK' : 'WAIT', item.detail]),
  ]
  return `<aside class="runtime-panel" aria-label="运行状态">
    <pre class="runtime-ascii" aria-label="Chengxiaoyu ASCII 字符图形">${esc(chengxiaoyuAsciiArt)}</pre>
    <div class="runtime-log" aria-live="polite">${logs.map(([time, level, message]) => `<div class="runtime-line"><time>${time}</time><b class="log-${level.toLowerCase()}">[${level}]</b><span>${esc(message)}</span></div>`).join('')}</div>
  </aside>`
}

function labsShell(content) {
  const view = currentView()
  const nav = [['labs', '靶场'], ['instances', '运行'], ['settings', '环境']]
  return `<div class="labs-screen">
    ${runtimePanel()}
    <section class="lab-workspace">
      <header class="lab-workspace-head"><button class="workspace-brand" type="button" data-action="nav" data-view="labs">VulnLab</button><nav class="workspace-nav" aria-label="工作区导航">${nav.map(([key, label]) => `<button class="workspace-nav-link${view === key ? ' is-active' : ''}" type="button" data-action="nav" data-view="${key}">${label}</button>`).join('')}</nav><button class="workspace-account" type="button" data-action="logout" aria-label="退出登录">${esc(state.session.userName)}</button></header>
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
const coverArt = lab => coverAssets[lab.slug] && (!installedCoverSlugs.has(lab.slug) || lab.status === 'ready')
  ? `<img class="lab-card-cover" src="${coverAssets[lab.slug]}" alt="" loading="lazy" decoding="async" />`
  : ''
const labRuntimeSupported = lab => {
  if (!state.runtimeStatus.labs?.[lab.slug]?.available) return false
  if (lab.runtimeKind !== 'vm') return true
  return state.vmDownloads.some(download => download.labId === lab.id && download.status === 'completed' && download.localPath)
}

function labCard(lab) {
  const admin = state.session.role === 'admin'
  const ready = lab.status === 'ready'
  const runnable = ready && labRuntimeSupported(lab)
  const importing = lab.status === 'importing'
  const queued = lab.status === 'queued'
  const failed = lab.status === 'error'
  const instance = state.instances.find(item => item.labId === lab.id && item.status === 'running')
  const installJob = state.jobs.find(item => item.labId === lab.id && ['queued', 'importing'].includes(item.status))
  const missing = state.runtimeStatus.labs?.[lab.slug]?.missing ?? []
  const missingLabel = missing.some(item => item.includes('MySQL') || item.includes('mysqli')) ? '需配置数据库' : `缺少 ${missing.join(' / ')}`
  const secondaryAction = instance && admin
    ? `<button class="card-plain-button" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">停止</button>`
    : '<span></span>'
  const primaryAction = instance
    ? `<a class="card-primary-button" href="${esc(instance.endpoint)}" target="_blank" rel="noreferrer">打开页面</a>`
    : lab.slug === 'vulnhub' && ready
      ? `<button class="card-primary-button" type="button" data-action="view-catalog" data-id="${esc(lab.id)}">查看机器</button>`
    : runnable
      ? `<button class="card-primary-button" type="button" data-action="start-instance" data-id="${esc(lab.id)}">启动环境</button>`
    : importing
      ? `<span class="card-primary-button is-disabled">安装中 ${Math.max(1, installJob?.progress ?? 1)}%</span>`
      : queued
        ? '<span class="card-primary-button is-disabled">等待安装</span>'
        : ready && missing.length
          ? `<span class="card-primary-button is-disabled">${esc(missingLabel)}</span>`
        : admin
          ? `<button class="card-primary-button${failed ? ' is-retry' : ''}" type="button" data-action="install-lab" data-id="${esc(lab.id)}">${failed ? '重试安装' : lab.slug === 'vulnhub' ? '加载目录' : '安装'}</button>`
          : '<span class="card-primary-button is-disabled">等待安装</span>'
  return `<article class="lab-card">
    <div class="lab-card-head"><span>${esc(lab.title)}</span></div>
    <div class="lab-card-media" data-cover="${coverVariant(lab)}">${coverArt(lab)}</div>
    <div class="lab-card-actions">${secondaryAction}${primaryAction}</div>
  </article>`
}

function labsPage() {
  const visibleLabs = state.labs.slice(0, 9)
  return `<div class="lab-grid" aria-label="靶场列表">${visibleLabs.map(labCard).join('')}</div>`
}

function instancesPage() {
  const admin = state.session.role === 'admin'
  const activeInstances = state.instances.filter(instance => instance.status === 'running')
  return `${pageHeader('运行', '已启动环境与到期时间。')}
    <section class="instances-surface"><div class="section-line"><h2>实例列表</h2><span>${activeInstances.length} 个运行中</span></div>${activeInstances.length ? `<div class="instance-list">${activeInstances.map(instance => `<article class="instance-row"><div class="instance-main"><span class="instance-status ${instance.status}"></span><div><strong>${esc(instance.labTitle)}</strong><span>${esc(instance.endpoint)}</span></div></div><div class="instance-time"><span>${esc(instanceLabel(instance.status))}</span><time>到期 ${date(instance.expiresAt)}</time></div>${admin ? `<div class="instance-actions"><a class="small-button" href="${esc(instance.endpoint)}" target="_blank" rel="noreferrer">打开</a><button class="small-button" type="button" data-action="renew-instance" data-id="${esc(instance.id)}">续期</button><button class="small-button danger-text" type="button" data-action="destroy-instance" data-id="${esc(instance.id)}">结束</button></div>` : ''}</article>`).join('')}</div>` : '<div class="empty-state">还没有运行实例。去靶场目录选择一个入口。</div>'}</section>`
}

function settingsPage() {
  const settings = state.settings ?? {}
  const admin = state.session.role === 'admin'
  const dependencies = state.runtimeStatus?.dependencies ?? []
  return `${pageHeader('环境', '本机运行能力与服务参数。', '<span class="page-note">参数保存后重启生效</span>')}
    <form class="settings-layout" id="settings-form"><section class="settings-surface"><div class="form-heading"><h2>服务</h2><span>单机运行</span></div><div class="form-row"><label>监听地址<input name="bindHost" value="${esc(settings.bindHost)}" ${admin ? '' : 'disabled'}></label><label>端口<input name="port" type="number" min="1024" max="65535" value="${esc(settings.port)}" ${admin ? '' : 'disabled'}></label></div><label>最大并发环境<input name="maxInstances" type="number" min="1" max="99" value="${esc(settings.maxInstances)}" ${admin ? '' : 'disabled'}></label><label class="toggle-line"><input name="autoCleanup" type="checkbox" ${settings.autoCleanup === 'true' ? 'checked' : ''} ${admin ? '' : 'disabled'}><span>到期后自动停止环境</span></label><label>数据目录<input value="${esc(settings.dataDir)}" readonly aria-readonly="true"></label></section><section class="settings-surface settings-readout"><div class="form-heading"><h2>运行依赖</h2><span>自动检测</span></div><div class="dependency-list">${dependencies.map(item => `<div class="dependency-row"><i class="${item.available ? 'is-ready' : ''}"></i><span><strong>${esc(item.label)}</strong><small>${esc(item.detail)}</small></span><em>${item.available ? '可用' : '待配置'}</em></div>`).join('')}</div></section>${admin ? '<button class="button button-primary settings-save" type="submit">保存设置</button>' : ''}</form>`
}

function loginPage() {
  return `<div class="login-page"><div class="login-mark"><img src="/favicon.svg" alt=""><span>VulnLab</span></div><form class="login-form" id="login-form"><h1>进入工作台</h1><p>安装、启动和管理本机靶场。</p><label>账号<input name="userName" autocomplete="username" required placeholder="vulnlab-admin"></label><label>密码<input name="password" type="password" autocomplete="current-password" required></label>${state.error ? `<div class="form-error" role="alert">${esc(state.error)}</div>` : ''}<button class="button button-primary" type="submit">登录</button></form></div>`
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
  const view = currentView()
  const page = view === 'instances' ? instancesPage() : view === 'settings' ? settingsPage() : labsPage()
  app.innerHTML = labsShell(page)
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
  if (action === 'cancel-confirm') { state.confirm = null; render(); return }
  if (action === 'confirm-action') {
    const next = state.confirm?.action
    state.confirm = null
    if (next) await runAction(next.action, { dataset: next })
    return
  }
  if (action === 'logout') {
    state.busy = true
    try { await request('/api/auth/logout', { method: 'POST' }); state.session = null; state.csrfToken = ''; state.overview = null; state.labs = []; state.jobs = []; state.vmDownloads = []; state.instances = []; state.catalog = null; location.hash = 'labs' } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
    return
  }
  if (action === 'install-lab') {
    state.busy = true
    try { await request(`/api/labs/${element.dataset.id}/install`, { method: 'POST' }); await refresh(); setToast('靶场安装已开始。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
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
      await request(`/api/labs/${element.dataset.id}/instances`, { method: 'POST', ...(vmDownload ? { body: JSON.stringify({ vmDownloadId: vmDownload.id }) } : {}) })
      await refresh()
      setToast(`${lab?.runtimeKind === 'vm' ? '虚拟机' : '靶场环境'}已启动，可直接打开页面。`)
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
    openConfirm('停止靶场环境', '停止后会释放运行端口和实例资源，下次启动会创建新的练习副本。', { action: 'confirm-destroy', id: element.dataset.id }, '停止环境')
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
  if (form.id === 'settings-form') {
    state.busy = true
    try { const payload = { ...values, autoCleanup: values.autoCleanup === 'on' ? 'true' : 'false' }; await request('/api/settings', { method: 'PUT', body: JSON.stringify(payload) }); await refresh(); setToast('运行环境已保存。') } catch (error) { setToast(error.message, 'error') } finally { state.busy = false; render() }
  }
})

window.addEventListener('hashchange', render)
bootstrap()
