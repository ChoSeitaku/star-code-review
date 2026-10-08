/** 项目详情页（§1.4.3）：基本信息、阶段状态、漏洞数量、攻击路径数量、报告状态。 */

import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { projectApi, resultApi } from '../api'
import Layout from '../components/Layout'
import StageStepper from '../components/StageStepper'
import { Alert, Badge, Card, KeyValue, Loading, Stat } from '../components/ui'
import { PROJECT_STATUS, STAGE_NAME, TASK_STATUS, shortTime } from '../constants'

export default function ProjectDetailPage() {
  const { projectId } = useParams()
  const navigate = useNavigate()

  const [project, setProject] = useState(null)
  const [stages, setStages] = useState([])
  const [workers, setWorkers] = useState([])
  const [sandboxInfo, setSandboxInfo] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true)
      try {
        const [detail, stageList, workerList, sandbox] = await Promise.all([
          projectApi.detail(projectId),
          resultApi.stages(projectId),
          resultApi.workers(projectId),
          projectApi.sandbox(projectId).catch(() => null),
        ])
        setProject(detail)
        setStages(stageList)
        setWorkers(workerList)
        setSandboxInfo(sandbox)
        setError('')
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    },
    [projectId],
  )

  useEffect(() => {
    load()
  }, [load])

  // 执行中时轮询刷新
  useEffect(() => {
    if (project?.project_status !== 'running') return undefined
    const timer = setInterval(() => load(true), 2500)
    return () => clearInterval(timer)
  }, [project?.project_status, load])

  const handleStart = async () => {
    setBusy(true)
    setError('')
    try {
      await projectApi.start(projectId)
      navigate(`/projects/${projectId}/monitor`)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const handleStop = async () => {
    setBusy(true)
    setError('')
    try {
      await projectApi.stop(projectId)
      await load(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <Layout title="项目详情">
        <Loading text="正在加载项目详情…" />
      </Layout>
    )
  }

  if (!project) {
    return (
      <Layout title="项目详情">
        <Alert tone="error">{error || '项目不存在'}</Alert>
      </Layout>
    )
  }

  const running = project.project_status === 'running'
  const reportReady = project.report_status === 'ready'

  return (
    <Layout
      title={project.project_name}
      actions={
        <>
          <button className="btn btn-sm" onClick={() => load()}>
            ⟳ 刷新
          </button>
          <button className="btn btn-sm" onClick={() => navigate(`/projects/${projectId}/monitor`)}>
            ◈ 实时监控
          </button>
          {running ? (
            <button className="btn btn-danger btn-sm" disabled={busy} onClick={handleStop}>
              ■ 停止任务
            </button>
          ) : (
            <button className="btn btn-primary btn-sm" disabled={busy} onClick={handleStart}>
              ▶ 启动任务
            </button>
          )}
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      <div className="grid grid-4" style={{ marginBottom: 18 }}>
        <Stat
          value={project.vulnerability_count ?? 0}
          label="漏洞总数"
          foot={`其中高危 ${project.high_risk_count ?? 0} 个`}
          tone="text-high"
        />
        <Stat
          value={project.verified_count ?? 0}
          label="已验证漏洞"
          foot={`共 ${project.vulnerability_count ?? 0} 条候选`}
          tone="text-low"
        />
        <Stat
          value={project.attack_path_count ?? 0}
          label="攻击路径"
          foot="由已验证漏洞串联而成"
          tone="text-accent"
        />
        <Stat
          value={reportReady ? '已生成' : '待生成'}
          label="报告状态"
          foot={reportReady ? `生成于 ${shortTime(project.report_created_at)}` : '完成评估后自动生成'}
          tone={reportReady ? 'text-low' : 'text-dim'}
        />
      </div>

      <div className="grid" style={{ gap: 16, marginBottom: 18 }}>
        <Card title="执行阶段" extra={<span className="card-subtle">共 {stages.length} 条阶段记录</span>}>
          <StageStepper stages={stages} />
          {stages.length > 0 && (
            <div className="table-wrap" style={{ marginTop: 16 }}>
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 140 }}>阶段</th>
                    <th style={{ width: 100 }}>状态</th>
                    <th style={{ width: 165 }}>开始时间</th>
                    <th style={{ width: 165 }}>结束时间</th>
                    <th style={{ width: 90 }}>耗时</th>
                    <th>备注</th>
                  </tr>
                </thead>
                <tbody>
                  {stages.map((stage) => (
                    <tr key={stage.id}>
                      <td>{STAGE_NAME[stage.stage_name] || stage.stage_name}</td>
                      <td>
                        <Badge
                          map={{
                            idle: { label: '待执行', tone: 'muted' },
                            running: { label: '执行中', tone: 'info', pulse: true },
                            success: { label: '成功', tone: 'low' },
                            failed: { label: '失败', tone: 'high' },
                            stopped: { label: '已停止', tone: 'medium' },
                          }}
                          value={stage.stage_status}
                          dot
                        />
                      </td>
                      <td className="mono text-dim" style={{ fontSize: 12 }}>
                        {shortTime(stage.started_at)}
                      </td>
                      <td className="mono text-dim" style={{ fontSize: 12 }}>
                        {shortTime(stage.finished_at)}
                      </td>
                      <td className="mono text-dim" style={{ fontSize: 12 }}>
                        {stage.duration_seconds != null ? `${stage.duration_seconds}s` : '--'}
                      </td>
                      <td className="text-faint" style={{ fontSize: 12 }}>
                        {stage.error_message || '--'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <Card title="项目基本信息">
          <KeyValue
            items={[
              { label: '项目编号', value: `#${project.id}` },
              {
                label: '项目状态',
                value: <Badge map={PROJECT_STATUS} value={project.project_status} dot />,
              },
              {
                label: '源码类型',
                value: project.source_type === 'git' ? 'Git 仓库地址' : '本地源码目录',
              },
              { label: '源码路径', value: <span className="mono">{project.source_path}</span> },
              { label: '隔离环境编号', value: project.sandbox_code || '尚未创建' },
              {
                label: '隔离环境类型',
                value: sandboxInfo?.isolation_type === 'docker' ? 'Docker 容器' : '模拟隔离环境',
              },
              { label: '隔离环境状态', value: sandboxInfo?.sandbox_status || '--' },
              { label: '任务说明', value: project.task_content || '（未填写）' },
              { label: '创建时间', value: project.created_at },
              { label: '最近启动', value: project.last_started_at || '--' },
              { label: '最近完成', value: project.last_finished_at || '--' },
            ]}
          />
        </Card>

        <Card
          title="角色执行记录"
          extra={<span className="card-subtle">{workers.length} 条记录</span>}
        >
          {workers.length === 0 ? (
            <div className="text-faint" style={{ fontSize: 12.5 }}>
              尚无角色执行记录，启动评估任务后产生。
            </div>
          ) : (
            <div style={{ maxHeight: 380, overflowY: 'auto' }}>
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 100 }}>角色</th>
                    <th style={{ width: 84 }}>状态</th>
                    <th>执行结果</th>
                    <th style={{ width: 74 }}>耗时</th>
                  </tr>
                </thead>
                <tbody>
                  {workers.map((worker) => (
                    <tr key={worker.id}>
                      <td style={{ fontSize: 12.5 }}>{worker.role_label}</td>
                      <td>
                        <Badge map={TASK_STATUS} value={worker.task_status} />
                      </td>
                      <td className="text-dim" style={{ fontSize: 12 }}>
                        {worker.result_summary || '--'}
                      </td>
                      <td className="mono text-faint" style={{ fontSize: 11.5 }}>
                        {worker.duration_seconds != null ? `${worker.duration_seconds}s` : '--'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      <div className="grid grid-3" style={{ marginTop: 16 }}>
        <button
          className="btn"
          style={{ padding: '18px', flexDirection: 'column', gap: 6 }}
          onClick={() => navigate(`/projects/${projectId}/vulnerabilities`)}
        >
          <span style={{ fontSize: 18 }}>⚠</span>
          查看漏洞列表
        </button>
        <button
          className="btn"
          style={{ padding: '18px', flexDirection: 'column', gap: 6 }}
          onClick={() => navigate(`/projects/${projectId}/attack-paths`)}
        >
          <span style={{ fontSize: 18 }}>⇢</span>
          查看攻击路径
        </button>
        <button
          className="btn"
          style={{ padding: '18px', flexDirection: 'column', gap: 6 }}
          disabled={!reportReady}
          onClick={() => navigate(`/projects/${projectId}/report`)}
        >
          <span style={{ fontSize: 18 }}>▣</span>
          {reportReady ? '查看评估报告' : '报告待生成'}
        </button>
      </div>
    </Layout>
  )
}
