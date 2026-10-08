import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { getToken } from './api'

import LoginPage from './pages/LoginPage'
import ProjectListPage from './pages/ProjectListPage'
import ProjectCreatePage from './pages/ProjectCreatePage'
import ProjectDetailPage from './pages/ProjectDetailPage'
import MonitorPage from './pages/MonitorPage'
import VulnerabilitiesPage from './pages/VulnerabilitiesPage'
import AttackPathsPage from './pages/AttackPathsPage'
import ReportPage from './pages/ReportPage'
import SystemConfigPage from './pages/SystemConfigPage'

/** 登录守卫：未登录统一跳转到登录页。 */
function RequireAuth({ children }) {
  const location = useLocation()
  if (!getToken()) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }
  return children
}

const guard = (element) => <RequireAuth>{element}</RequireAuth>

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />

      <Route path="/" element={<Navigate to="/projects" replace />} />
      <Route path="/projects" element={guard(<ProjectListPage />)} />
      <Route path="/projects/new" element={guard(<ProjectCreatePage />)} />
      <Route path="/projects/:projectId" element={guard(<ProjectDetailPage />)} />
      <Route path="/projects/:projectId/monitor" element={guard(<MonitorPage />)} />
      <Route path="/projects/:projectId/vulnerabilities" element={guard(<VulnerabilitiesPage />)} />
      <Route path="/projects/:projectId/attack-paths" element={guard(<AttackPathsPage />)} />
      <Route path="/projects/:projectId/report" element={guard(<ReportPage />)} />
      <Route path="/config" element={guard(<SystemConfigPage />)} />

      <Route path="*" element={<Navigate to="/projects" replace />} />
    </Routes>
  )
}
