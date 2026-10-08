/** 资源消耗曲线（§1.4.3 实时监控页资源消耗）。
 *
 * 手写 SVG 折线，避免引入图表库；CPU 与内存各一条曲线。
 */

function buildPath(values, width, height, max) {
  if (values.length === 0) return ''
  if (values.length === 1) {
    const y = height - (values[0] / max) * height
    return `M 0 ${y} L ${width} ${y}`
  }

  const stepX = width / (values.length - 1)
  return values
    .map((value, index) => {
      const x = index * stepX
      const y = height - (value / max) * height
      return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
    })
    .join(' ')
}

export default function ResourceChart({ samples = [], height = 132 }) {
  const width = 640
  const cpuValues = samples.map((item) => Number(item.cpu_usage) || 0)
  const memoryValues = samples.map((item) => Number(item.memory_usage) || 0)

  const cpuMax = Math.max(100, ...cpuValues)
  const memoryMax = Math.max(64, ...memoryValues) * 1.15

  const latest = samples[samples.length - 1]
  const peakMemory = memoryValues.length ? Math.max(...memoryValues) : 0
  const peakCpu = cpuValues.length ? Math.max(...cpuValues) : 0
  const tokens = latest ? latest.token_count : 0

  return (
    <div>
      <div className="grid grid-3" style={{ gap: 12, marginBottom: 14 }}>
        <div>
          <div className="stat-value text-accent" style={{ fontSize: 20 }}>
            {latest ? `${Number(latest.cpu_usage).toFixed(1)}%` : '--'}
          </div>
          <div className="stat-label">当前 CPU 占用</div>
        </div>
        <div>
          <div className="stat-value text-low" style={{ fontSize: 20 }}>
            {latest ? `${Number(latest.memory_usage).toFixed(1)} MB` : '--'}
          </div>
          <div className="stat-label">当前内存占用</div>
        </div>
        <div>
          <div className="stat-value" style={{ fontSize: 20 }}>
            {tokens.toLocaleString()}
          </div>
          <div className="stat-label">累计 Token 估算</div>
        </div>
      </div>

      {samples.length === 0 ? (
        <div className="empty" style={{ padding: '26px 12px' }}>
          暂无资源采样数据，启动评估任务后自动采集
        </div>
      ) : (
        <>
          <svg
            viewBox={`0 0 ${width} ${height}`}
            preserveAspectRatio="none"
            style={{ width: '100%', height, display: 'block' }}
          >
            {[0.25, 0.5, 0.75].map((ratio) => (
              <line
                key={ratio}
                x1="0"
                x2={width}
                y1={height * ratio}
                y2={height * ratio}
                stroke="#1c2531"
                strokeWidth="1"
              />
            ))}
            <path
              d={buildPath(cpuValues, width, height, cpuMax)}
              fill="none"
              stroke="#4d8df6"
              strokeWidth="2"
              vectorEffect="non-scaling-stroke"
            />
            <path
              d={buildPath(memoryValues, width, height, memoryMax)}
              fill="none"
              stroke="#3fb950"
              strokeWidth="2"
              vectorEffect="non-scaling-stroke"
            />
          </svg>

          <div className="chart-legend">
            <span>
              <i className="chart-swatch" style={{ background: '#4d8df6' }} />
              CPU 占用（峰值 {peakCpu.toFixed(1)}%）
            </span>
            <span>
              <i className="chart-swatch" style={{ background: '#3fb950' }} />
              内存占用（峰值 {peakMemory.toFixed(1)} MB）
            </span>
            <span className="text-faint">共 {samples.length} 个采样点</span>
          </div>
        </>
      )}
    </div>
  )
}
