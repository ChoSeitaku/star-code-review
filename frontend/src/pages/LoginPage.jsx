/** 登录页（§1.4.3）：输入用户名和密码，登录成功后进入项目列表页。 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { saveSession, systemApi } from '../api'
import { Alert as AlertBox } from '../components/ui'

export default function LoginPage() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin123')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  const handleInit = async () => {
    setError('')
    setNotice('')
    setBusy(true)
    try {
      const result = await systemApi.init({ username, password })
      setNotice(result.message || '系统初始化完成')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const handleLogin = async (event) => {
    event.preventDefault()
    setError('')
    setNotice('')
    setBusy(true)
    try {
      const result = await systemApi.login(username, password)
      saveSession(result.token, { username: result.username, role: result.role })
      navigate('/projects', { replace: true })
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={handleLogin}>
        <div className="login-brand">
          <div className="brand-shield">⛨</div>
          <div className="login-title">自动化安全评估系统</div>
          <div className="login-sub">源码接入 · 隔离分析 · 漏洞验证 · 报告输出</div>
        </div>

        {error && <AlertBox tone="error">{error}</AlertBox>}
        {notice && <AlertBox tone="success">{notice}</AlertBox>}

        {!notice && (
          <AlertBox tone="info">
            首次使用请先点击下方「初始化系统」创建管理员账户（默认 admin / admin123）。
          </AlertBox>
        )}

        <div className="field">
          <label htmlFor="username">用户名</label>
          <input
            id="username"
            className="input"
            value={username}
            autoComplete="username"
            onChange={(event) => setUsername(event.target.value)}
            placeholder="请输入用户名"
          />
        </div>

        <div className="field">
          <label htmlFor="password">密码</label>
          <input
            id="password"
            className="input"
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(event) => setPassword(event.target.value)}
            placeholder="请输入密码"
          />
        </div>

        <button
          className="btn btn-primary"
          style={{ width: '100%', marginBottom: 10 }}
          disabled={busy || !username || !password}
          type="submit"
        >
          {busy ? '处理中…' : '登录'}
        </button>

        <button
          className="btn"
          style={{ width: '100%' }}
          type="button"
          disabled={busy || !username || password.length < 6}
          onClick={handleInit}
        >
          初始化系统（创建管理员）
        </button>
      </form>
    </div>
  )
}
