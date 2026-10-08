/** 角色执行状态卡片（§1.4.5 六类执行角色）。 */

import { ROLE_ICON, ROLE_NAME, TASK_STATUS, statusMeta } from '../constants'
import { shortTime } from '../constants'

export default function RoleCard({ role }) {
  const meta = statusMeta(TASK_STATUS, role.task_status)
  const tone = meta.tone
  const color =
    tone === 'info' ? 'var(--accent)'
      : tone === 'low' ? 'var(--low)'
        : tone === 'high' ? 'var(--high)'
          : 'var(--text-faint)'

  return (
    <div className={`role-card is-${role.task_status}`}>
      <div className="role-head">
        <span className="role-name">
          {ROLE_ICON[role.worker_role] || '•'} {role.role_label || ROLE_NAME[role.worker_role]}
        </span>
        <span className="badge" style={{ background: 'transparent', color, borderColor: color }}>
          <i className={`dot ${meta.pulse ? 'dot-pulse' : ''}`} />
          {meta.label}
        </span>
      </div>

      <div className="role-summary">
        {role.result_summary || (role.task_status === 'running' ? '正在执行任务…' : '暂无执行记录')}
      </div>

      <div className="role-time">
        {role.started_at ? `开始 ${shortTime(role.started_at)}` : '--'}
        {role.finished_at ? ` · 结束 ${shortTime(role.finished_at)}` : ''}
      </div>
    </div>
  )
}
