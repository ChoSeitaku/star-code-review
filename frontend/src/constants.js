/** 全局枚举与中文标签映射（与后端 §1.4.4 状态定义保持一致）。 */

export const PROJECT_STATUS = {
  created: { label: '已创建', tone: 'muted' },
  running: { label: '执行中', tone: 'info', pulse: true },
  completed: { label: '已完成', tone: 'low' },
  failed: { label: '失败', tone: 'high' },
  stopped: { label: '已停止', tone: 'medium' },
}

export const STAGE_STATUS = {
  idle: { label: '待执行', tone: 'muted' },
  running: { label: '执行中', tone: 'info', pulse: true },
  success: { label: '成功', tone: 'low' },
  failed: { label: '失败', tone: 'high' },
  stopped: { label: '已停止', tone: 'medium' },
}

export const TASK_STATUS = {
  idle: { label: '空闲', tone: 'muted' },
  running: { label: '执行中', tone: 'info', pulse: true },
  success: { label: '成功', tone: 'low' },
  failed: { label: '失败', tone: 'high' },
}

export const VERIFY_STATUS = {
  unverified: { label: '待验证', tone: 'muted' },
  verified: { label: '已验证', tone: 'low' },
  failed: { label: '未通过验证', tone: 'medium' },
}

export const RISK_LEVEL = {
  high: { label: '高危', tone: 'high' },
  medium: { label: '中危', tone: 'medium' },
  low: { label: '低危', tone: 'low' },
}

export const STAGE_NAME = {
  environment_scan: '环境扫描',
  code_analysis: '代码分析',
  vulnerability_verify: '漏洞验证',
  report_generate: '报告生成',
  done: '评估完成',
}

/** 阶段推进顺序，用于步进器展示。 */
export const STAGE_ORDER = [
  'environment_scan',
  'code_analysis',
  'vulnerability_verify',
  'report_generate',
  'done',
]

export const ROLE_NAME = {
  general_processor: '通用处理',
  env_checker: '环境检查',
  code_analyzer: '代码分析',
  vuln_verifier: '漏洞验证',
  report_writer: '报告整理',
  ops_helper: '运维辅助',
}

export const ROLE_ICON = {
  general_processor: '🧭',
  env_checker: '🛡️',
  code_analyzer: '🔍',
  vuln_verifier: '🎯',
  report_writer: '📄',
  ops_helper: '⚙️',
}

export const MESSAGE_TYPE_LABEL = {
  info: '信息',
  thinking: '分析中',
  result: '结果',
  warning: '警告',
}

export function statusMeta(map, key, fallback = '未知') {
  return map[key] || { label: key || fallback, tone: 'muted' }
}

/** 格式化时间戳，仅保留 月-日 时:分:秒，便于日志与消息面板阅读。 */
export function shortTime(value) {
  if (!value) return '--'
  const parts = String(value).split(' ')
  if (parts.length < 2) return value
  const date = parts[0].slice(5)
  return `${date} ${parts[1]}`
}

export function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '--'
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds % 60)
  return `${minutes}m ${rest}s`
}
