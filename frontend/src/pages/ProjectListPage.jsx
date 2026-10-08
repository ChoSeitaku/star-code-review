/** 项目列表页（§1.4.3）：项目名称、源码来源、项目状态、最近启动/完成时间。 */

import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { projectApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Badge, Empty, Loading } from '../components/ui'
import { PROJECT_STATUS, shortTime } from '../constants'

export default function ProjectListPage() {
  const navigate = useNavigate()
  const [projects, setProjects] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busyId, setBusyId] = useState(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      setProjects(await projectApi.list())
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // 存在执行中的项目时轮询刷新，便于观察状态流转
  useEffect(() => {
    const hasRunning = projects.some((item) => item.project_status === 'running')
    if (!hasRunning) return undefined
    const timer = setInterval(() => load(true), 3000)
    return () => clearInterval(timer)
  }, [projects, load])

  const handleStart = async (project, event) => {
    event.stopPropagation()
    setBusyId(project.id)
    setError('')
    try {
      await projectApi.start(project.id)
      navigate(`/projects/${project.id}/monitor`)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  const handleDelete = async (project, event) => {
    event.stopPropagation()
    const confirmed = window.confirm(
      `确认删除项目「${project.project_name}」？\n\n` +
        '将同时删除关联的漏洞记录、攻击路径、聊天消息、日志与资源记录，' +
        '并清理日志目录、报告目录与临时目录。该操作不可恢复。',
    )
    if (!confirmed) return

    setBusyId(project.id)
    setError('')
    try {
      await projectApi.remove(project.id)
      await load(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  return (
    <Layout
      title="项目列表"
      actions={
        <>
          <button className="btn btn-sm" onClick={() => load()}>
            ⟳ 刷新
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/projects/new')}>
            ＋ 新建项目
          </button>
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      {loading ? (
        <Loading text="正在加载项目列表…" />
      ) : projects.length === 0 ? (
        <div className="card">
          <Empty
            icon="📁"
            text="还没有评估项目。点击右上角「新建项目」接入源码目录，开始第一次安全评估。"
          />
        </div>
      ) : (
        <div className="table-wrap">
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 56 }}>编号</th>
                <th>项目名称</th>
                <th style={{ width: 190 }}>源码来源</th>
                <th style={{ width: 110 }}>项目状态</th>
                <th style={{ width: 165 }}>最近启动时间</th>
                <th style={{ width: 165 }}>最近完成时间</th>
                <th style={{ width: 210 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {projects.map((project) => {
                const running = project.project_status === 'running'
                return (
                  <tr
                    key={project.id}
                    className="clickable"
                    onClick={() => navigate(`/projects/${project.id}`)}
                  >
                    <td className="text-faint mono">#{project.id}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{project.project_name}</div>
                      <div className="text-faint" style={{ fontSize: 11.5 }}>
                        {project.sandbox_code
                          ? `隔离环境 ${project.sandbox_code}`
                          : '尚未创建隔离环境'}
                      </div>
                    </td>
                    <td>
                      <div className="text-dim" style={{ fontSize: 12.5 }}>
                        {project.source_type === 'git' ? 'Git 仓库' : '本地目录'}
                      </div>
                      <div
                        className="text-faint mono"
                        style={{ fontSize: 11, wordBreak: 'break-all' }}
                      >
                        {project.source_path}
                      </div>
                    </td>
                    <td>
                      <Badge map={PROJECT_STATUS} value={project.project_status} dot />
                    </td>
                    <td className="text-dim mono" style={{ fontSize: 12 }}>
                      {shortTime(project.last_started_at)}
                    </td>
                    <td className="text-dim mono" style={{ fontSize: 12 }}>
                      {shortTime(project.last_finished_at)}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          className="btn btn-sm"
                          disabled={running || busyId === project.id}
                          onClick={(event) => handleStart(project, event)}
                        >
                          {running ? '执行中' : '▶ 启动'}
                        </button>
                        <button
                          className="btn btn-sm"
                          onClick={(event) => {
                            event.stopPropagation()
                            navigate(`/projects/${project.id}/monitor`)
                          }}
                        >
                          监控
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          disabled={busyId === project.id}
                          onClick={(event) => handleDelete(project, event)}
                        >
                          删除
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Layout>
  )
}
