/** 攻击路径页（§1.4.3）：路径编号、关联漏洞、利用顺序、最终影响。 */

import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { resultApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Badge, Card, Empty, Loading } from '../components/ui'
import { RISK_LEVEL, VERIFY_STATUS } from '../constants'

export default function AttackPathsPage() {
  const { projectId } = useParams()
  const navigate = useNavigate()

  const [paths, setPaths] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setPaths(await resultApi.attackPaths(projectId))
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    load()
  }, [load])

  return (
    <Layout
      title="攻击路径"
      actions={
        <>
          <span className="text-faint" style={{ fontSize: 12 }}>
            共 {paths.length} 条
          </span>
          <button className="btn btn-sm" onClick={load}>
            ⟳ 刷新
          </button>
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      {loading ? (
        <Loading text="正在加载攻击路径…" />
      ) : paths.length === 0 ? (
        <div className="card">
          <Empty
            icon="⇢"
            text="暂无攻击路径。攻击路径需要至少两个相互衔接的已验证漏洞，完成漏洞验证阶段后自动编排。"
          />
        </div>
      ) : (
        <div className="grid" style={{ gap: 18 }}>
          {paths.map((path) => (
            <Card
              key={path.id}
              title={
                <span>
                  <span className="mono text-accent" style={{ marginRight: 8 }}>
                    {path.path_code}
                  </span>
                  {path.path_title}
                </span>
              }
              extra={<span className="card-subtle">{path.step_count} 个利用步骤</span>}
            >
              <div className="grid grid-2" style={{ alignItems: 'start', gap: 22 }}>
                <div>
                  <div
                    style={{
                      fontSize: 12,
                      color: 'var(--text-faint)',
                      marginBottom: 6,
                      letterSpacing: 0.4,
                    }}
                  >
                    路径概述
                  </div>
                  <p style={{ margin: '0 0 18px', fontSize: 13, lineHeight: 1.75 }}>
                    {path.path_summary}
                  </p>

                  <div
                    style={{
                      fontSize: 12,
                      color: 'var(--text-faint)',
                      marginBottom: 6,
                      letterSpacing: 0.4,
                    }}
                  >
                    最终影响
                  </div>
                  <p style={{ margin: 0, fontSize: 13, lineHeight: 1.75, color: '#c4d0de' }}>
                    {path.final_impact_text}
                  </p>
                </div>

                <div>
                  <div
                    style={{
                      fontSize: 12,
                      color: 'var(--text-faint)',
                      marginBottom: 10,
                      letterSpacing: 0.4,
                    }}
                  >
                    利用顺序与关联漏洞
                  </div>

                  <div className="timeline">
                    {path.items.map((step, index) => (
                      <div
                        key={`${path.id}-${step.step_order}`}
                        className={`timeline-item ${index < path.items.length - 1 ? 'is-done' : 'is-active'}`}
                      >
                        <div className="timeline-title">
                          <span className="mono text-faint" style={{ marginRight: 7 }}>
                            STEP {step.step_order}
                          </span>
                          <span
                            className="mono text-accent"
                            style={{ cursor: 'pointer', marginRight: 7 }}
                            onClick={() => navigate(`/projects/${projectId}/vulnerabilities`)}
                          >
                            {step.vuln_code}
                          </span>
                          {step.vuln_title}
                          {step.risk_level && (
                            <span style={{ marginLeft: 7 }}>
                              <Badge map={RISK_LEVEL} value={step.risk_level} />
                            </span>
                          )}
                        </div>
                        {/* 步骤文案中已包含文件位置，此处不再重复展示 */}
                        <div className="timeline-text">{step.step_text}</div>
                        {step.verify_status && (
                          <div style={{ marginTop: 6 }}>
                            <Badge map={VERIFY_STATUS} value={step.verify_status} />
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </Layout>
  )
}
