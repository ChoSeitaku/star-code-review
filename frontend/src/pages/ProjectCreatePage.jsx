/** 项目创建页（§1.4.3）：项目名称、源码路径或仓库地址、任务说明、隔离环境类型。 */

import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { projectApi, systemApi } from '../api'
import Layout from '../components/Layout'
import { Alert, Card } from '../components/ui'

export default function ProjectCreatePage() {
  const navigate = useNavigate()

  const [form, setForm] = useState({
    project_name: '',
    source_type: 'local',
    source_path: 'examples/vuln-demo',
    task_content: '对示例业务服务进行源码安全评估，重点关注注入类缺陷与凭据泄露。',
    isolation_type: 'simulated',
  })
  const [rules, setRules] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // 载入内置规则清单，便于填写任务说明时了解检测覆盖范围
  useEffect(() => {
    systemApi
      .rules()
      .then(setRules)
      .catch(() => setRules([]))
  }, [])

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }))

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')

    if (!form.project_name.trim()) {
      setError('请填写项目名称')
      return
    }
    if (!form.source_path.trim()) {
      setError(form.source_type === 'git' ? '请填写仓库地址' : '请填写源码路径')
      return
    }

    setBusy(true)
    try {
      const project = await projectApi.create({
        project_name: form.project_name.trim(),
        source_type: form.source_type,
        source_path: form.source_path.trim(),
        task_content: form.task_content.trim(),
        isolation_type: form.isolation_type,
      })
      navigate(`/projects/${project.id}`)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Layout
      title="新建评估项目"
      actions={
        <button className="btn btn-sm" onClick={() => navigate('/projects')}>
          返回列表
        </button>
      }
    >
      {error && <Alert tone="error">{error}</Alert>}

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <Card title="项目信息">
          <form onSubmit={handleSubmit}>
            <div className="field">
              <label htmlFor="project_name">项目名称 *</label>
              <input
                id="project_name"
                className="input"
                value={form.project_name}
                onChange={(event) => update('project_name', event.target.value)}
                placeholder="例如：示例业务服务安全评估"
                maxLength={120}
              />
            </div>

            <div className="field">
              <label htmlFor="source_type">源码类型 *</label>
              <select
                id="source_type"
                className="select"
                value={form.source_type}
                onChange={(event) => {
                  const value = event.target.value
                  update('source_type', value)
                  update('source_path', value === 'git' ? '' : 'examples/vuln-demo')
                }}
              >
                <option value="local">本地源码目录</option>
                <option value="git">Git 仓库地址</option>
              </select>
              <div className="hint">
                {form.source_type === 'local'
                  ? '填写项目根目录下的相对路径或绝对路径，例如 examples/vuln-demo'
                  : '填写可克隆的仓库地址，系统会先克隆到工作区再只读挂载'}
              </div>
            </div>

            <div className="field">
              <label htmlFor="source_path">
                {form.source_type === 'git' ? '仓库地址' : '源码路径'} *
              </label>
              <input
                id="source_path"
                className="input mono"
                value={form.source_path}
                onChange={(event) => update('source_path', event.target.value)}
                placeholder={form.source_type === 'git' ? 'https://…/repo.git' : 'examples/vuln-demo'}
              />
            </div>

            <div className="field">
              <label htmlFor="task_content">任务说明</label>
              <textarea
                id="task_content"
                className="textarea"
                value={form.task_content}
                onChange={(event) => update('task_content', event.target.value)}
                placeholder="描述本次评估的关注重点，例如：重点关注 SQL 注入与命令注入风险"
                maxLength={4000}
              />
            </div>

            <div className="field">
              <label htmlFor="isolation_type">隔离环境类型 *</label>
              <select
                id="isolation_type"
                className="select"
                value={form.isolation_type}
                onChange={(event) => update('isolation_type', event.target.value)}
              >
                <option value="simulated">模拟隔离环境（推荐，源码只读挂载 + 命令白名单）</option>
                <option value="docker">Docker 容器隔离</option>
              </select>
              <div className="hint">
                每个项目会分配唯一隔离环境编号，源码以只读方式挂载，写入操作被限制在工作区内。
              </div>
            </div>

            <button className="btn btn-primary" type="submit" disabled={busy}>
              {busy ? '创建中…' : '创建项目'}
            </button>
          </form>
        </Card>

        <div className="grid" style={{ gap: 16 }}>
          <Card title="内置规则库覆盖范围" extra={<span className="card-subtle">{rules.length} 条规则</span>}>
            {rules.length === 0 ? (
              <div className="text-faint" style={{ fontSize: 12.5 }}>
                规则清单加载中…
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                {rules.map((rule) => (
                  <div
                    key={rule.rule_key}
                    style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 12.5 }}
                  >
                    <span
                      className={`badge badge-${
                        rule.risk_level === 'high'
                          ? 'high'
                          : rule.risk_level === 'medium'
                            ? 'medium'
                            : 'low'
                      }`}
                    >
                      {rule.risk_level === 'high' ? '高危' : rule.risk_level === 'medium' ? '中危' : '低危'}
                    </span>
                    <span>{rule.title}</span>
                    <span className="text-faint mono" style={{ marginLeft: 'auto', fontSize: 11 }}>
                      {rule.rule_key}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="执行流程">
            <div className="timeline">
              {[
                { title: '隔离环境准备', text: '创建唯一隔离环境，源码只读挂载，校验可读性' },
                { title: '源码静态分析', text: '目录遍历 + 规则引擎扫描，产出漏洞候选' },
                { title: '漏洞验证', text: '静态证据复核，排除误报，生成复现步骤与验证代码' },
                { title: '攻击路径编排', text: '把已验证漏洞按杀伤链串联为完整利用路径' },
                { title: '报告生成', text: '汇总生成 Markdown / HTML 报告，支持预览与下载' },
              ].map((step) => (
                <div className="timeline-item" key={step.title}>
                  <div className="timeline-title">{step.title}</div>
                  <div className="timeline-text">{step.text}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </Layout>
  )
}
