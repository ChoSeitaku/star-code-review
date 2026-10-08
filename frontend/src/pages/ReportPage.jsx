/** 报告页（§1.4.3）：展示完整安全评估报告，支持下载。 */

import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { downloadReport, projectApi, resultApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Card, Empty, Loading } from '../components/ui'

export default function ReportPage() {
  const { projectId } = useParams()
  const navigate = useNavigate()

  const [report, setReport] = useState(null)
  const [projectName, setProjectName] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const detail = await projectApi.detail(projectId)
      setProjectName(detail.project_name)
      setReport(await resultApi.report(projectId))
      setError('')
    } catch (err) {
      setError(err.message)
      setReport(null)
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    load()
  }, [load])

  const handleDownload = async () => {
    setBusy(true)
    try {
      await downloadReport(projectId, projectName)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Layout
      title="评估报告"
      actions={
        <>
          <button className="btn btn-sm" onClick={load}>
            ⟳ 刷新
          </button>
          <button className="btn btn-primary btn-sm" disabled={!report || busy} onClick={handleDownload}>
            {busy ? '下载中…' : '⬇ 下载报告'}
          </button>
        </>
      }
    >
      {error && !report && (
        <div className="card">
          <Empty icon="▣" text={error} />
          <div style={{ textAlign: 'center', marginTop: 10 }}>
            <button className="btn btn-sm" onClick={() => navigate(`/projects/${projectId}`)}>
              返回项目详情
            </button>
          </div>
        </div>
      )}

      {error && report && <Alert tone="error">{error}</Alert>}

      {loading ? (
        <Loading text="正在加载报告…" />
      ) : (
        report && (
          <>
            <div className="grid grid-4" style={{ marginBottom: 16 }}>
              <div className="stat">
                <div className="stat-value" style={{ fontSize: 18 }}>
                  #{report.id}
                </div>
                <div className="stat-label">报告编号</div>
              </div>
              <div className="stat">
                <div className="stat-value" style={{ fontSize: 18 }}>
                  {projectName}
                </div>
                <div className="stat-label">所属项目</div>
              </div>
              <div className="stat">
                <div className="stat-value" style={{ fontSize: 18 }}>
                  {report.created_at}
                </div>
                <div className="stat-label">生成时间</div>
              </div>
              <div className="stat">
                <div className="stat-value" style={{ fontSize: 18 }}>
                  {Math.round((report.report_markdown || '').length / 100) / 10}k
                </div>
                <div className="stat-label">报告字符数</div>
              </div>
            </div>

            <Card
              title="报告预览"
              extra={<span className="card-subtle">HTML 渲染 · 可直接下载留存</span>}
            >
              <iframe
                className="report-frame"
                title="安全评估报告"
                srcDoc={report.report_html || '<p style="font-family:sans-serif;padding:20px">报告内容为空</p>'}
                sandbox=""
              />
            </Card>
          </>
        )
      )}
    </Layout>
  )
}
