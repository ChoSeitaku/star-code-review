/** 实时监控页（§1.4.3）：当前阶段、角色执行状态、聊天消息、日志滚动、资源消耗。
 *
 * 数据来源：首屏用 /snapshot 一次性加载，之后由 WebSocket 增量推送（§1.4.11）。
 */

import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { projectApi, resultApi } from '../api'
import { useProjectStream } from '../ws'
import Layout from '../components/Layout'
import StageStepper from '../components/StageStepper'
import RoleCard from '../components/RoleCard'
import LogPanel from '../components/LogPanel'
import ChatPanel from '../components/ChatPanel'
import ResourceChart from '../components/ResourceChart'
import { Alert, Badge, Card, Loading } from '../components/ui'
import { PROJECT_STATUS, STAGE_NAME, shortTime } from '../constants'

const WS_STATUS_LABEL = {
  connecting: { label: '连接中', tone: 'medium' },
  connected: { label: '实时通道已连接', tone: 'low' },
  reconnecting: { label: '重连中', tone: 'medium' },
  unauthorized: { label: '登录态失效', tone: 'high' },
  not_found: { label: '项目不存在', tone: 'high' },
  idle: { label: '未连接', tone: 'muted' },
}

// 日志与消息在前端保留的最大条数，避免长时间运行后内存膨胀
const MAX_LOGS = 800
const MAX_MESSAGES = 400
const MAX_SAMPLES = 240

export default function MonitorPage() {
  const { projectId } = useParams()
  const navigate = useNavigate()

  const [state, setState] = useState(null)
  const [stages, setStages] = useState([])
  const [roles, setRoles] = useState([])
  const [logs, setLogs] = useState([])
  const [messages, setMessages] = useState([])
  const [resources, setResources] = useState([])
  const [vulnCount, setVulnCount] = useState(0)
  const [pathCount, setPathCount] = useState(0)
  const [reportId, setReportId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refreshStages = useCallback(async () => {
    try {
      setStages(await resultApi.stages(projectId))
    } catch {
      /* 忽略瞬时错误，等待下一次推送 */
    }
  }, [projectId])

  const refreshRoles = useCallback(async () => {
    try {
      setRoles(await resultApi.roles(projectId))
    } catch {
      /* 同上 */
    }
  }, [projectId])

  const refreshProject = useCallback(async () => {
    try {
      const detail = await projectApi.detail(projectId)
      setState((prev) => (prev ? { ...prev, project: detail } : prev))
      setVulnCount(detail.vulnerability_count || 0)
      setPathCount(detail.attack_path_count || 0)
      setReportId(detail.report_id || null)
    } catch {
      /* 同上 */
    }
  }, [projectId])

  // 首屏快照
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      setLoading(true)
      try {
        const snapshot = await resultApi.snapshot(projectId)
        if (cancelled) return
        setState(snapshot)
        setStages(snapshot.stages || [])
        setRoles(snapshot.roles || [])
        setLogs(snapshot.logs || [])
        setMessages(snapshot.messages || [])
        setResources(snapshot.resources || [])
        setVulnCount(snapshot.vulnerability_count || 0)
        setPathCount(snapshot.attack_path_count || 0)
        setReportId(snapshot.report_id || null)
        setError('')
      } catch (err) {
        if (!cancelled) setError(err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [projectId])

  // 实时事件处理
  const handleEvent = useCallback(
    (type, data) => {
      switch (type) {
        case 'project_status':
          setState((prev) =>
            prev ? { ...prev, project: { ...prev.project, project_status: data.project_status } } : prev,
          )
          refreshProject()
          break

        case 'stage_status':
          refreshStages()
          break

        case 'worker_status':
          refreshRoles()
          break

        case 'chat_message':
          setMessages((prev) =>
            [...prev, { id: `${Date.now()}-${prev.length}`, ...data }].slice(-MAX_MESSAGES),
          )
          break

        case 'runtime_log':
          setLogs((prev) =>
            [...prev, { id: `${Date.now()}-${prev.length}`, ...data }].slice(-MAX_LOGS),
          )
          break

        case 'resource_usage':
          setResources((prev) => [...prev, data].slice(-MAX_SAMPLES))
          break

        case 'vulnerability_found':
          setVulnCount((prev) => prev + 1)
          break

        case 'report_ready':
          setReportId(data.report_id)
          refreshProject()
          break

        default:
          break
      }
    },
    [refreshProject, refreshRoles, refreshStages],
  )

  const { status: wsStatus } = useProjectStream(Number(projectId), handleEvent)

  const handleStop = async () => {
    try {
      await projectApi.stop(projectId)
      refreshProject()
      refreshStages()
      refreshRoles()
    } catch (err) {
      setError(err.message)
    }
  }

  const handleStart = async () => {
    try {
      await projectApi.start(projectId)
      refreshProject()
    } catch (err) {
      setError(err.message)
    }
  }

  if (loading) {
    return (
      <Layout title="实时监控">
        <Loading text="正在建立实时通道…" />
      </Layout>
    )
  }

  if (!state) {
    return (
      <Layout title="实时监控">
        <Alert tone="error">{error || '无法加载项目监控数据'}</Alert>
      </Layout>
    )
  }

  const project = state.project
  const running = project.project_status === 'running'
  const currentStage = state.current_stage
  const wsMeta = WS_STATUS_LABEL[wsStatus] || WS_STATUS_LABEL.idle

  return (
    <Layout
      title={`实时监控 · ${project.project_name}`}
      actions={
        <>
          <span className={`badge badge-${wsMeta.tone}`}>
            <i className={`dot ${wsStatus === 'connected' ? 'dot-pulse' : ''}`} />
            {wsMeta.label}
          </span>
          {running ? (
            <button className="btn btn-danger btn-sm" onClick={handleStop}>
              ■ 停止任务
            </button>
          ) : (
            <button className="btn btn-primary btn-sm" onClick={handleStart}>
              ▶ 启动任务
            </button>
          )}
          <button className="btn btn-sm" onClick={() => navigate(`/projects/${projectId}`)}>
            项目详情
          </button>
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        <div className="stat">
          <div className="stat-value" style={{ fontSize: 19 }}>
            <Badge map={PROJECT_STATUS} value={project.project_status} dot />
          </div>
          <div className="stat-label">项目状态</div>
          <div className="stat-foot">隔离环境 {state.sandbox?.sandbox_code || '尚未创建'}</div>
        </div>
        <div className="stat">
          <div className="stat-value" style={{ fontSize: 19 }}>
            {currentStage ? STAGE_NAME[currentStage.stage_name] || currentStage.stage_name : '未开始'}
          </div>
          <div className="stat-label">当前阶段</div>
          <div className="stat-foot">
            {currentStage ? shortTime(currentStage.started_at) : '启动任务后进入环境扫描'}
          </div>
        </div>
        <div className="stat">
          <div className="stat-value text-high" style={{ fontSize: 24 }}>
            {vulnCount}
          </div>
          <div className="stat-label">发现漏洞</div>
          <div className="stat-foot">含已验证与待验证记录</div>
        </div>
        <div className="stat">
          <div className="stat-value text-accent" style={{ fontSize: 24 }}>
            {pathCount}
          </div>
          <div className="stat-label">攻击路径</div>
          <div className="stat-foot">
            {reportId ? (
              <button
                className="btn btn-ghost btn-sm"
                style={{ padding: 0 }}
                onClick={() => navigate(`/projects/${projectId}/report`)}
              >
                报告已就绪，点击查看 →
              </button>
            ) : (
              '报告待生成'
            )}
          </div>
        </div>
      </div>

      <Card title="执行阶段">
        <StageStepper stages={stages} />
      </Card>

      <div style={{ marginTop: 16 }}>
        <h3 className="card-title" style={{ marginBottom: 12 }}>
          <span>角色执行状态</span>
          <span className="card-subtle">共 6 类执行角色</span>
        </h3>
        <div className="grid grid-3">
          {roles.map((role) => (
            <RoleCard key={role.worker_role} role={role} />
          ))}
        </div>
      </div>

      <div className="grid grid-2" style={{ marginTop: 16, alignItems: 'start' }}>
        <Card
          title="运行日志"
          extra={
            <span className="card-subtle">
              共 {logs.length} 条 · 实时滚动
            </span>
          }
        >
          <LogPanel logs={logs} height="tall" />
        </Card>

        <Card title="角色消息" extra={<span className="card-subtle">共 {messages.length} 条</span>}>
          <ChatPanel messages={messages} />
        </Card>
      </div>

      <div style={{ marginTop: 16 }}>
        <Card title="资源消耗" extra={<span className="card-subtle">运维辅助角色采样</span>}>
          <ResourceChart samples={resources} />
        </Card>
      </div>
    </Layout>
  )
}
