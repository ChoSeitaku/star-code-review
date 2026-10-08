/**
 * 后端接口封装（对应 §1.4.10 接口要求）。
 * 统一处理登录令牌注入与 401 跳转。
 */

const TOKEN_KEY = 'star_review_token'
const USER_KEY = 'star_review_user'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function getStoredUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY) || 'null')
  } catch {
    return null
  }
}

export function saveSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  // 登录态失效：清理并回到登录页
  if (response.status === 401) {
    clearSession()
    if (!window.location.hash.includes('/login')) {
      window.location.hash = '#/login'
    }
    throw new ApiError('登录态已过期，请重新登录', 401)
  }

  const text = await response.text()
  let payload = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = { detail: text }
    }
  }

  if (!response.ok) {
    const detail =
      (payload && (payload.detail || payload.message)) || `请求失败（${response.status}）`
    throw new ApiError(typeof detail === 'string' ? detail : JSON.stringify(detail), response.status)
  }

  return payload
}

const get = (path) => request('GET', path)
const post = (path, body) => request('POST', path, body)
const put = (path, body) => request('PUT', path, body)
const del = (path) => request('DELETE', path)

// ---------------------------------------------------------------------------
// 认证模块
// ---------------------------------------------------------------------------
export const systemApi = {
  init: (payload) => post('/api/system/init', payload),
  login: (username, password) => post('/api/system/login', { username, password }),
  logout: () => post('/api/system/logout'),
  me: () => get('/api/system/me'),
  config: () => get('/api/system/config'),
  updateConfig: (items) => put('/api/system/config', { items }),
  overview: () => get('/api/system/overview'),
  rules: () => get('/api/rules'),
}

// ---------------------------------------------------------------------------
// 项目模块
// ---------------------------------------------------------------------------
export const projectApi = {
  list: () => get('/api/projects'),
  create: (payload) => post('/api/projects', payload),
  detail: (id) => get(`/api/projects/${id}`),
  start: (id) => post(`/api/projects/${id}/start`),
  stop: (id) => post(`/api/projects/${id}/stop`),
  remove: (id) => del(`/api/projects/${id}`),
  sandbox: (id) => get(`/api/projects/${id}/sandbox`),
}

// ---------------------------------------------------------------------------
// 结果模块
// ---------------------------------------------------------------------------
export const resultApi = {
  stages: (id) => get(`/api/projects/${id}/stages`),
  workers: (id) => get(`/api/projects/${id}/workers`),
  roles: (id) => get(`/api/projects/${id}/roles`),
  snapshot: (id) => get(`/api/projects/${id}/snapshot`),
  vulnerabilities: (id, params = {}) => {
    const search = new URLSearchParams()
    if (params.risk_level) search.set('risk_level', params.risk_level)
    if (params.verify_status) search.set('verify_status', params.verify_status)
    const suffix = search.toString() ? `?${search}` : ''
    return get(`/api/projects/${id}/vulnerabilities${suffix}`)
  },
  vulnerability: (id, vulnId) => get(`/api/projects/${id}/vulnerabilities/${vulnId}`),
  attackPaths: (id) => get(`/api/projects/${id}/attack-paths`),
  report: (id) => get(`/api/projects/${id}/report`),
  reportDownloadUrl: (id) => `/api/projects/${id}/report/download`,
  logs: (id, limit = 500) => get(`/api/projects/${id}/logs?limit=${limit}`),
  resources: (id, limit = 300) => get(`/api/projects/${id}/resources?limit=${limit}`),
  messages: (id, limit = 300) => get(`/api/projects/${id}/messages?limit=${limit}`),
}

/** 带鉴权的下载：报告下载接口需要 Authorization 头。 */
export async function downloadReport(projectId, projectName) {
  const response = await fetch(resultApi.reportDownloadUrl(projectId), {
    headers: { Authorization: `Bearer ${getToken()}` },
  })
  if (!response.ok) {
    throw new ApiError('报告下载失败，请确认报告已生成', response.status)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${projectName || 'project'}_安全评估报告.html`
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}
