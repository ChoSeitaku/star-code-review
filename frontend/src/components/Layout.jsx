/** 应用骨架：侧边导航 + 顶栏（§1.4.6 前端模块划分）。 */

import { NavLink, useNavigate, useParams } from 'react-router-dom'
import { clearSession, getStoredUser } from '../api'

const NAV_SECTIONS = [
  {
    title: '项目',
    items: [
      { to: '/projects', icon: '▤', label: '项目列表', end: true },
      { to: '/projects/new', icon: '＋', label: '新建项目' },
    ],
  },
]

function ProjectNav({ projectId }) {
  if (!projectId) return null
  const base = `/projects/${projectId}`
  return (
    <div className="nav-group">
      <div className="nav-group-title">当前项目</div>
      {[
        { to: base, icon: '◉', label: '项目详情', end: true },
        { to: `${base}/monitor`, icon: '◈', label: '实时监控' },
        { to: `${base}/vulnerabilities`, icon: '⚠', label: '漏洞列表' },
        { to: `${base}/attack-paths`, icon: '⇢', label: '攻击路径' },
        { to: `${base}/report`, icon: '▣', label: '评估报告' },
      ].map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <span className="nav-icon">{item.icon}</span>
          {item.label}
        </NavLink>
      ))}
    </div>
  )
}

export default function Layout({ children, title, actions }) {
  const navigate = useNavigate()
  const { projectId } = useParams()
  const user = getStoredUser()

  const handleLogout = () => {
    clearSession()
    navigate('/login', { replace: true })
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <span className="brand-shield">⛨</span>
            <span>安全评估系统</span>
          </div>
          <div className="brand-sub">SOURCE SECURITY ASSESSMENT</div>
        </div>

        <nav className="nav">
          {NAV_SECTIONS.map((section) => (
            <div className="nav-group" key={section.title}>
              <div className="nav-group-title">{section.title}</div>
              {section.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}

          <ProjectNav projectId={projectId} />

          <div className="nav-group">
            <div className="nav-group-title">系统</div>
            <NavLink
              to="/config"
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <span className="nav-icon">⚙</span>
              系统配置
            </NavLink>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <span>
              {user?.username || '未登录'}
              {user?.role === 'admin' && ' · 管理员'}
            </span>
            <button className="btn btn-ghost btn-sm" onClick={handleLogout}>
              退出
            </button>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="topbar-title">{title}</div>
          <div className="topbar-actions">{actions}</div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  )
}
