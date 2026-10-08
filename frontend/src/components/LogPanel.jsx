/** 运行日志滚动面板：自动贴底、支持级别筛选。 */

import { useEffect, useMemo, useRef, useState } from 'react'
import { shortTime } from '../constants'

const LEVELS = ['ALL', 'INFO', 'WARN', 'ERROR', 'DEBUG']

export default function LogPanel({ logs = [], height = 'tall', autoScroll = true }) {
  const [level, setLevel] = useState('ALL')
  const [stick, setStick] = useState(true)
  const boxRef = useRef(null)

  const filtered = useMemo(
    () => (level === 'ALL' ? logs : logs.filter((log) => log.log_level === level)),
    [logs, level],
  )

  // 仅在用户停留在底部时自动滚动，避免打断向上翻阅
  useEffect(() => {
    if (!stick || !autoScroll) return
    const box = boxRef.current
    if (box) box.scrollTop = box.scrollHeight
  }, [filtered, stick, autoScroll])

  const handleScroll = () => {
    const box = boxRef.current
    if (!box) return
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40
    setStick(atBottom)
  }

  return (
    <div>
      <div className="toolbar" style={{ marginBottom: 10 }}>
        <select
          className="select"
          style={{ width: 110 }}
          value={level}
          onChange={(event) => setLevel(event.target.value)}
        >
          {LEVELS.map((item) => (
            <option key={item} value={item}>
              {item === 'ALL' ? '全部级别' : item}
            </option>
          ))}
        </select>
        <span className="text-faint" style={{ fontSize: 12 }}>
          共 {filtered.length} 条
        </span>
        <div className="spacer" />
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => setStick((value) => !value)}
          title="开启后新日志会自动滚动到底部"
        >
          {stick ? '⤓ 自动滚动中' : '⤓ 已暂停滚动'}
        </button>
      </div>

      <div
        ref={boxRef}
        onScroll={handleScroll}
        className={`console ${height === 'tall' ? 'console-tall' : 'console-mid'}`}
      >
        {filtered.length === 0 ? (
          <div className="text-faint" style={{ padding: '8px 2px' }}>
            暂无日志输出
          </div>
        ) : (
          filtered.map((log) => (
            <div key={log.id} className={`log-line log-${log.log_level}`}>
              <span className="log-time">{shortTime(log.created_at)}</span>
              <span className="log-level">{log.log_level}</span>
              <span className="log-text">{log.log_content}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
