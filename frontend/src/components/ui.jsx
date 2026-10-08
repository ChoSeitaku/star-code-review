/** 通用展示组件。 */

import { RISK_LEVEL, statusMeta } from '../constants'

export function Badge({ map, value, dot = false, className = '' }) {
  const meta = statusMeta(map, value)
  return (
    <span className={`badge badge-${meta.tone} ${className}`}>
      {dot && <i className={`dot ${meta.pulse ? 'dot-pulse' : ''}`} />}
      {meta.label}
    </span>
  )
}

export function RiskBadge({ level }) {
  const meta = statusMeta(RISK_LEVEL, level)
  return <span className={`badge badge-${meta.tone}`}>{meta.label}</span>
}

export function Stat({ value, label, foot, tone = '' }) {
  return (
    <div className="stat">
      <div className={`stat-value ${tone}`}>{value}</div>
      <div className="stat-label">{label}</div>
      {foot && <div className="stat-foot">{foot}</div>}
    </div>
  )
}

export function Empty({ icon = '📭', text = '暂无数据' }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      {text}
    </div>
  )
}

export function Loading({ text = '加载中…' }) {
  return (
    <div className="loading">
      <div className="spinner" />
      {text}
    </div>
  )
}

export function Alert({ tone = 'info', children }) {
  const icon = { error: '✕', success: '✓', warn: '!', info: 'i' }[tone] || 'i'
  return (
    <div className={`alert alert-${tone}`}>
      <strong style={{ flexShrink: 0 }}>{icon}</strong>
      <div style={{ minWidth: 0 }}>{children}</div>
    </div>
  )
}

export function Card({ title, extra, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || extra) && (
        <h3 className="card-title">
          <span>{title}</span>
          {extra}
        </h3>
      )}
      {children}
    </section>
  )
}

export function KeyValue({ items }) {
  return (
    <dl className="kv">
      {items.map((item) => (
        <div key={item.label} style={{ display: 'contents' }}>
          <dt>{item.label}</dt>
          <dd>{item.value ?? '--'}</dd>
        </div>
      ))}
    </dl>
  )
}
