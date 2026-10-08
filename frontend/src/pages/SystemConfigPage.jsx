/** 系统配置页（§1.4.3）：隔离环境配置、默认超时时间、并发数、保留天数。 */

import { useCallback, useEffect, useState } from 'react'
import { getStoredUser, systemApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Card, Empty, Loading, Stat } from '../components/ui'
import { shortTime } from '../constants'

export default function SystemConfigPage() {
  const user = getStoredUser()
  const isAdmin = user?.role === 'admin'

  const [items, setItems] = useState([])
  const [draft, setDraft] = useState({})
  const [overview, setOverview] = useState(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [config, stats] = await Promise.all([
        systemApi.config(),
        systemApi.overview().catch(() => null),
      ])
      setItems(config.items || [])
      setDraft(
        Object.fromEntries((config.items || []).map((item) => [item.config_key, item.config_value])),
      )
      setOverview(stats)
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

  const handleSave = async () => {
    setBusy(true)
    setError('')
    setNotice('')
    try {
      const payload = items
        .filter((item) => String(draft[item.config_key] ?? '') !== String(item.config_value ?? ''))
        .map((item) => ({
          config_key: item.config_key,
          config_value: String(draft[item.config_key] ?? ''),
        }))

      if (payload.length === 0) {
        setNotice('没有需要保存的改动')
        return
      }
      const result = await systemApi.updateConfig(payload)
      setNotice(result.message)
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const counts = overview?.stats

  return (
    <Layout
      title="系统配置"
      actions={
        <>
          <button className="btn btn-sm" onClick={load}>
            ⟳ 刷新
          </button>
          <button className="btn btn-primary btn-sm" disabled={!isAdmin || busy} onClick={handleSave}>
            {busy ? '保存中…' : '保存配置'}
          </button>
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}
      {notice && <Alert tone="success">{notice}</Alert>}
      {!isAdmin && (
        <Alert tone="warn">
          当前账户为普通使用者，仅可查看配置。修改配置需要管理员权限。
        </Alert>
      )}

      {loading ? (
        <Loading text="正在加载系统配置…" />
      ) : (
        <>
          {counts && (
            <div className="grid grid-4" style={{ marginBottom: 18 }}>
              <Stat value={counts.project_total} label="项目总数" foot={`执行中 ${counts.project_running} 个`} />
              <Stat value={counts.vulnerability_total} label="漏洞总数" tone="text-high" />
              <Stat value={counts.attack_path_total} label="攻击路径" tone="text-accent" />
              <Stat
                value={overview?.resource_summary?.total_tokens ?? 0}
                label="累计 Token 估算"
                foot={`峰值内存 ${overview?.resource_summary?.peak_memory ?? 0} MB`}
              />
            </div>
          )}

          <div className="grid grid-2" style={{ alignItems: 'start' }}>
            <Card
              title="运行配置"
              extra={<span className="card-subtle">{items.length} 项</span>}
            >
              {items.map((item) => (
                <div className="field" key={item.config_key}>
                  <label htmlFor={item.config_key}>
                    <span className="mono" style={{ fontSize: 12.5 }}>
                      {item.config_key}
                    </span>
                  </label>

                  {item.config_key.startsWith('isolation_') ? (
                    <select
                      id={item.config_key}
                      className="select"
                      disabled={!isAdmin}
                      value={draft[item.config_key] ?? ''}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, [item.config_key]: event.target.value }))
                      }
                    >
                      {item.config_key === 'isolation_type' && (
                        <>
                          <option value="simulated">simulated（模拟隔离环境）</option>
                          <option value="docker">docker（容器隔离）</option>
                        </>
                      )}
                      {item.config_key === 'isolation_readonly_mount' && (
                        <>
                          <option value="true">true（源码只读挂载）</option>
                          <option value="false">false（允许写入）</option>
                        </>
                      )}
                      {item.config_key === 'isolation_network' && (
                        <>
                          <option value="none">none（禁网）</option>
                          <option value="limited">limited（受限）</option>
                          <option value="full">full（放开）</option>
                        </>
                      )}
                    </select>
                  ) : (
                    <input
                      id={item.config_key}
                      className="input"
                      disabled={!isAdmin}
                      value={draft[item.config_key] ?? ''}
                      onChange={(event) =>
                        setDraft((prev) => ({ ...prev, [item.config_key]: event.target.value }))
                      }
                    />
                  )}

                  <div className="hint">
                    {item.description}
                    {item.updated_at ? ` · 更新于 ${shortTime(item.updated_at)}` : ''}
                  </div>
                </div>
              ))}
            </Card>

            <div className="grid" style={{ gap: 16 }}>
              <Card title="隔离环境实例">
                {overview?.active_sandboxes?.length ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {overview.active_sandboxes.map((sandbox) => (
                      <div
                        key={sandbox.sandbox_code}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          fontSize: 12.5,
                          paddingBottom: 9,
                          borderBottom: '1px solid var(--border-soft)',
                        }}
                      >
                        <span className="mono text-accent">{sandbox.sandbox_code}</span>
                        <span className="text-faint">项目 #{sandbox.project_id}</span>
                        <span style={{ marginLeft: 'auto' }}>
                          <span
                            className={`badge badge-${sandbox.sandbox_status === 'running' ? 'low' : 'muted'}`}
                          >
                            {sandbox.sandbox_status}
                          </span>
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty icon="🛡️" text="当前没有活跃的隔离环境实例" />
                )}
              </Card>

              <Card title="最近系统日志" extra={<span className="card-subtle">最新 30 条</span>}>
                {overview?.recent_logs?.length ? (
                  <div className="console console-mid">
                    {overview.recent_logs.map((log) => (
                      <div key={log.id} className={`log-line log-${log.log_level}`}>
                        <span className="log-time">{shortTime(log.created_at)}</span>
                        <span className="log-level">{log.log_level}</span>
                        <span className="log-text">
                          [#{log.project_id}] {log.log_content}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty icon="📋" text="暂无系统日志" />
                )}
              </Card>
            </div>
          </div>
        </>
      )}
    </Layout>
  )
}
