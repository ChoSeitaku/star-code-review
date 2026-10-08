/** 漏洞列表页（§1.4.3）：漏洞编号、标题、风险等级、验证状态、文件位置 + 详情。 */

import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { resultApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Badge, Card, Empty, Loading } from '../components/ui'
import { RISK_LEVEL, VERIFY_STATUS } from '../constants'

const RISK_FILTERS = [
  { value: '', label: '全部风险' },
  { value: 'high', label: '高危' },
  { value: 'medium', label: '中危' },
  { value: 'low', label: '低危' },
]

const VERIFY_FILTERS = [
  { value: '', label: '全部状态' },
  { value: 'verified', label: '已验证' },
  { value: 'unverified', label: '待验证' },
  { value: 'failed', label: '未通过验证' },
]

export default function VulnerabilitiesPage() {
  const { projectId } = useParams()

  const [items, setItems] = useState([])
  const [riskLevel, setRiskLevel] = useState('')
  const [verifyStatus, setVerifyStatus] = useState('')
  const [selected, setSelected] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await resultApi.vulnerabilities(projectId, {
        risk_level: riskLevel,
        verify_status: verifyStatus,
      })
      setItems(list)
      setSelected((prev) => {
        if (prev && list.some((item) => item.vuln_id === prev.vuln_id)) {
          return list.find((item) => item.vuln_id === prev.vuln_id)
        }
        return list[0] || null
      })
      setError('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [projectId, riskLevel, verifyStatus])

  useEffect(() => {
    load()
  }, [load])

  const counts = items.reduce(
    (acc, item) => {
      acc[item.risk_level] = (acc[item.risk_level] || 0) + 1
      return acc
    },
    { high: 0, medium: 0, low: 0 },
  )

  return (
    <Layout
      title="漏洞列表"
      actions={
        <>
          <span className="text-faint" style={{ fontSize: 12 }}>
            共 {items.length} 条
          </span>
          <button className="btn btn-sm" onClick={load}>
            ⟳ 刷新
          </button>
        </>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      <div className="toolbar">
        <select
          className="select"
          style={{ width: 130 }}
          value={riskLevel}
          onChange={(event) => setRiskLevel(event.target.value)}
        >
          {RISK_FILTERS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <select
          className="select"
          style={{ width: 150 }}
          value={verifyStatus}
          onChange={(event) => setVerifyStatus(event.target.value)}
        >
          {VERIFY_FILTERS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <div className="spacer" />

        <span className="badge badge-high">高危 {counts.high}</span>
        <span className="badge badge-medium">中危 {counts.medium}</span>
        <span className="badge badge-low">低危 {counts.low}</span>
      </div>

      {loading ? (
        <Loading text="正在加载漏洞列表…" />
      ) : items.length === 0 ? (
        <div className="card">
          <Empty
            icon="🛡️"
            text="暂无漏洞记录。启动评估任务并完成代码分析阶段后，漏洞将展示在此处。"
          />
        </div>
      ) : (
        <div
          className="grid"
          style={{ gridTemplateColumns: 'minmax(0, 1.35fr) minmax(0, 1fr)', alignItems: 'start' }}
        >
          <div className="table-wrap" style={{ maxHeight: '74vh', overflowY: 'auto' }}>
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 92 }}>漏洞编号</th>
                  <th>漏洞标题</th>
                  <th style={{ width: 80 }}>风险等级</th>
                  <th style={{ width: 100 }}>验证状态</th>
                  <th style={{ width: 190 }}>文件位置</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item) => (
                  <tr
                    key={item.vuln_id}
                    className={`clickable ${selected?.vuln_id === item.vuln_id ? 'selected' : ''}`}
                    onClick={() => setSelected(item)}
                  >
                    <td className="mono text-accent" style={{ fontSize: 12 }}>
                      {item.vuln_code}
                    </td>
                    <td style={{ fontWeight: 500 }}>{item.vuln_title}</td>
                    <td>
                      <Badge map={RISK_LEVEL} value={item.risk_level} />
                    </td>
                    <td>
                      <Badge map={VERIFY_STATUS} value={item.verify_status} />
                    </td>
                    <td className="mono text-faint" style={{ fontSize: 11.5, wordBreak: 'break-all' }}>
                      {item.file_path}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div style={{ position: 'sticky', top: 76 }}>
            {selected ? <VulnerabilityDetail vuln={selected} /> : <Empty text="请选择一条漏洞查看详情" />}
          </div>
        </div>
      )}
    </Layout>
  )
}

/** 漏洞详情：影响说明、触发条件、证据内容、复现步骤、验证代码（§1.4.12）。 */
function VulnerabilityDetail({ vuln }) {
  return (
    <Card
      title={`${vuln.vuln_code} ${vuln.vuln_title}`}
      extra={<Badge map={RISK_LEVEL} value={vuln.risk_level} />}
    >
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <Badge map={VERIFY_STATUS} value={vuln.verify_status} />
        <span className="badge badge-muted mono">{vuln.rule_key}</span>
      </div>

      <div style={{ maxHeight: '62vh', overflowY: 'auto', paddingRight: 4 }}>
        <Section title="影响说明">{vuln.impact_text}</Section>
        <Section title="触发条件">{vuln.condition_text}</Section>

        <Section title="文件位置">
          <span className="mono text-accent" style={{ fontSize: 12 }}>
            {vuln.file_path}
          </span>
        </Section>

        <Section title="证据内容">
          <pre className="code evidence">{vuln.evidence_text || '（无）'}</pre>
        </Section>

        <Section title="复现步骤">
          <div style={{ whiteSpace: 'pre-wrap', fontSize: 12.5, lineHeight: 1.7 }}>
            {vuln.reproduce_steps_text || '（该漏洞未通过验证，未生成复现步骤）'}
          </div>
        </Section>

        <Section title="验证代码">
          {vuln.verify_code_text ? (
            <pre className="code">{vuln.verify_code_text}</pre>
          ) : (
            <span className="text-faint" style={{ fontSize: 12.5 }}>
              （该漏洞未通过验证，未生成验证代码）
            </span>
          )}
        </Section>

        {vuln.remediation_text && (
          <Section title="修复建议">
            <div style={{ fontSize: 12.5, lineHeight: 1.7 }}>{vuln.remediation_text}</div>
          </Section>
        )}
      </div>
    </Card>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div
        style={{
          fontSize: 12,
          color: 'var(--text-faint)',
          marginBottom: 6,
          letterSpacing: 0.4,
        }}
      >
        {title}
      </div>
      <div style={{ fontSize: 13, lineHeight: 1.7 }}>{children}</div>
    </div>
  )
}
