/** 执行阶段步进器：展示 §1.4.4 五个阶段的推进与耗时。 */

import { STAGE_NAME, STAGE_ORDER } from '../constants'
import { shortTime } from '../constants'

export default function StageStepper({ stages = [] }) {
  const byName = {}
  stages.forEach((stage) => {
    // 同名阶段保留最新一条
    byName[stage.stage_name] = stage
  })

  return (
    <div className="stepper">
      {STAGE_ORDER.map((name) => {
        const stage = byName[name]
        const status = stage?.stage_status || 'idle'
        const duration =
          stage?.duration_seconds !== null && stage?.duration_seconds !== undefined
            ? `${stage.duration_seconds}s`
            : null

        return (
          <div key={name} className={`step is-${status}`}>
            <div className="step-name">
              <i className={`dot ${status === 'running' ? 'dot-pulse' : ''}`} />
              {STAGE_NAME[name] || name}
            </div>
            <div className="step-meta">
              {status === 'idle'
                ? '待执行'
                : `${shortTime(stage?.started_at)}${duration ? ` · ${duration}` : ''}`}
            </div>
          </div>
        )
      })}
    </div>
  )
}
