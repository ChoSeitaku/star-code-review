"""报告生成（§1.4.12 最终报告：项目概述、执行过程、漏洞汇总、攻击路径、风险结论、修复建议）。"""

from __future__ import annotations

import html as html_lib
import re

from .. import config, db
from ..utils import elapsed_seconds, now_str

RISK_LABEL = {"high": "高危", "medium": "中危", "low": "低危"}
VERIFY_LABEL = {"verified": "已验证", "failed": "未通过验证", "unverified": "待验证"}


def generate_report(project_id: int) -> dict:
    """汇总项目全部结果，生成 Markdown 与 HTML 报告并落库。"""
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if project is None:
        raise ValueError(f"项目不存在：{project_id}")

    stages = db.query_all(
        "SELECT * FROM runtime_stages WHERE project_id = ? ORDER BY id", (project_id,)
    )
    workers = db.query_all(
        "SELECT * FROM worker_tasks WHERE project_id = ? ORDER BY id", (project_id,)
    )
    vulnerabilities = db.query_all(
        "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY id", (project_id,)
    )
    paths = db.query_all(
        "SELECT * FROM attack_paths WHERE project_id = ? ORDER BY id", (project_id,)
    )
    sandbox = db.query_one(
        "SELECT * FROM sandboxes WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,),
    )

    markdown = build_markdown(
        project, stages, workers, vulnerabilities, paths, sandbox
    )
    html = markdown_to_html(markdown, title=f"安全评估报告 - {project['project_name']}")

    report_dir = config.project_report_dir(project_id)
    report_dir.mkdir(parents=True, exist_ok=True)
    md_path = report_dir / "report.md"
    html_path = report_dir / "report.html"
    md_path.write_text(markdown, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")

    existing = db.query_one(
        "SELECT id FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1", (project_id,)
    )
    payload = {
        "project_id": project_id,
        "report_markdown": markdown,
        "report_html": html,
        "report_file_path": str(html_path),
        "created_at": now_str(),
    }
    if existing:
        db.update("reports", payload, "id = ?", (existing["id"],))
        report_id = existing["id"]
    else:
        report_id = db.insert("reports", payload)

    return {
        "report_id": report_id,
        "project_id": project_id,
        "report_markdown": markdown,
        "report_html": html,
        "report_file_path": str(html_path),
        "created_at": payload["created_at"],
    }


# ---------------------------------------------------------------------------
# Markdown 组装
# ---------------------------------------------------------------------------
def build_markdown(
    project: dict,
    stages: list[dict],
    workers: list[dict],
    vulnerabilities: list[dict],
    paths: list[dict],
    sandbox: dict | None,
) -> str:
    lines: list[str] = []

    total = len(vulnerabilities)
    verified = [v for v in vulnerabilities if v["verify_status"] == "verified"]
    high = [v for v in vulnerabilities if v["risk_level"] == "high"]
    medium = [v for v in vulnerabilities if v["risk_level"] == "medium"]
    low = [v for v in vulnerabilities if v["risk_level"] == "low"]

    # ---------------- 标题与项目概述 ----------------
    lines.append(f"# 安全评估报告：{project['project_name']}")
    lines.append("")
    lines.append(f"**报告生成时间**：{now_str()}")
    lines.append("")

    lines.append("## 一、项目概述")
    lines.append("")
    lines.append("| 项目 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 项目编号 | {project['id']} |")
    lines.append(f"| 项目名称 | {project['project_name']} |")
    lines.append(f"| 源码来源 | {_source_label(project['source_type'])} |")
    lines.append(f"| 源码路径 | `{project['source_path']}` |")
    lines.append(f"| 隔离环境编号 | {sandbox['sandbox_code'] if sandbox else '未创建'} |")
    lines.append(
        f"| 隔离环境类型 | {sandbox['isolation_type'] if sandbox else 'simulated'} "
        f"（源码只读挂载） |"
    )
    lines.append(f"| 任务说明 | {project.get('task_content') or '（未填写）'} |")
    lines.append(f"| 项目状态 | {project['project_status']} |")
    lines.append(f"| 创建时间 | {project['created_at']} |")
    lines.append(f"| 更新时间 | {project['updated_at']} |")
    lines.append("")

    # ---------------- 执行过程 ----------------
    lines.append("## 二、执行过程")
    lines.append("")
    if stages:
        lines.append("| 阶段 | 状态 | 开始时间 | 结束时间 | 耗时(秒) | 备注 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for stage in stages:
            duration = elapsed_seconds(stage.get("started_at"), stage.get("finished_at"))
            note = stage.get("error_message") or "-"
            lines.append(
                f"| {stage['stage_name']} | {stage['stage_status']} "
                f"| {stage.get('started_at') or '-'} | {stage.get('finished_at') or '-'} "
                f"| {duration if duration is not None else '-'} | {note} |"
            )
    else:
        lines.append("暂无阶段执行记录。")
    lines.append("")

    if workers:
        lines.append("### 2.1 角色执行记录")
        lines.append("")
        lines.append("| 角色 | 所属阶段 | 任务状态 | 执行结果 | 耗时(秒) |")
        lines.append("| --- | --- | --- | --- | --- |")
        stage_names = {stage["id"]: stage["stage_name"] for stage in stages}
        for worker in workers:
            duration = elapsed_seconds(worker.get("started_at"), worker.get("finished_at"))
            summary = (worker.get("result_summary") or "-").replace("\n", " ")
            if len(summary) > 80:
                summary = summary[:77] + "..."
            lines.append(
                f"| {worker['worker_role']} "
                f"| {stage_names.get(worker.get('stage_id'), '-')} "
                f"| {worker['task_status']} | {summary} "
                f"| {duration if duration is not None else '-'} |"
            )
        lines.append("")

    # ---------------- 漏洞汇总 ----------------
    lines.append("## 三、漏洞汇总")
    lines.append("")
    lines.append(
        f"本次评估共发现 **{total}** 个安全缺陷，其中高危 **{len(high)}** 个、"
        f"中危 **{len(medium)}** 个、低危 **{len(low)}** 个；"
        f"经静态证据复核，**{len(verified)}** 个通过验证。"
    )
    lines.append("")

    if vulnerabilities:
        lines.append("| 漏洞编号 | 漏洞标题 | 风险等级 | 文件位置 | 验证状态 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for vuln in vulnerabilities:
            location = f"{vuln.get('file_path') or '-'}"
            lines.append(
                f"| {vuln['vuln_code']} | {vuln['vuln_title']} "
                f"| {RISK_LABEL.get(vuln['risk_level'], vuln['risk_level'])} "
                f"| `{location}` "
                f"| {VERIFY_LABEL.get(vuln['verify_status'], vuln['verify_status'])} |"
            )
        lines.append("")

        lines.append("### 3.1 漏洞详情")
        lines.append("")
        for vuln in vulnerabilities:
            lines.append(
                f"#### {vuln['vuln_code']} {vuln['vuln_title']}"
                f"（{RISK_LABEL.get(vuln['risk_level'], vuln['risk_level'])}）"
            )
            lines.append("")
            lines.append(f"- **文件位置**：`{vuln.get('file_path') or '-'}`")
            lines.append(
                f"- **验证状态**：{VERIFY_LABEL.get(vuln['verify_status'], vuln['verify_status'])}"
            )
            lines.append(f"- **影响说明**：{_text(vuln.get('condition_text'))}")
            lines.append("")
            lines.append("**证据内容**")
            lines.append("")
            lines.append("```")
            lines.append(_text(vuln.get("evidence_text")))
            lines.append("```")
            lines.append("")
            lines.append("**复现步骤**")
            lines.append("")
            lines.append(_text(vuln.get("reproduce_steps_text")))
            lines.append("")
            lines.append("**验证代码**")
            lines.append("")
            lines.append("```python")
            lines.append(_text(vuln.get("verify_code_text")))
            lines.append("```")
            lines.append("")
    else:
        lines.append("本次评估未发现安全缺陷。")
        lines.append("")

    # ---------------- 攻击路径 ----------------
    lines.append("## 四、攻击路径")
    lines.append("")
    if paths:
        vuln_by_id = {vuln["id"]: vuln for vuln in vulnerabilities}
        for path in paths:
            items = db.query_all(
                "SELECT * FROM attack_path_items WHERE path_id = ? ORDER BY step_order",
                (path["id"],),
            )
            lines.append(f"### {path['path_code']} {path['path_title']}")
            lines.append("")
            lines.append(f"**路径概述**：{_text(path.get('path_summary'))}")
            lines.append("")
            lines.append(f"**关联漏洞数**：{len(items)}")
            lines.append("")
            lines.append("| 利用顺序 | 关联漏洞 | 利用说明 |")
            lines.append("| --- | --- | --- |")
            for item in items:
                vuln = vuln_by_id.get(item["vuln_id"])
                code = vuln["vuln_code"] if vuln else f"#{item['vuln_id']}"
                title = vuln["vuln_title"] if vuln else "（漏洞记录已删除）"
                lines.append(
                    f"| {item['step_order']} | {code} {title} | {_text(item.get('step_text'))} |"
                )
            lines.append("")
            lines.append(f"**最终影响**：{_text(path.get('final_impact_text'))}")
            lines.append("")
    else:
        lines.append("未编排到完整的攻击路径（需要至少两个相互衔接的已验证漏洞）。")
        lines.append("")

    # ---------------- 风险结论 ----------------
    lines.append("## 五、风险结论")
    lines.append("")
    lines.append(_risk_conclusion(total, len(high), len(medium), len(low), len(paths)))
    lines.append("")

    # ---------------- 修复建议 ----------------
    lines.append("## 六、修复建议")
    lines.append("")
    lines.append("按优先级排列，建议先处理高危项：")
    lines.append("")
    remediations = _collect_remediations(vulnerabilities)
    if remediations:
        for index, (title, remediation, count) in enumerate(remediations, start=1):
            suffix = f"（涉及 {count} 处）" if count > 1 else ""
            lines.append(f"{index}. **{title}**{suffix}：{remediation}")
    else:
        lines.append("暂无需要修复的安全缺陷。")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "本报告由自动化安全评估系统生成。所有分析均在只读隔离环境内完成，"
        "验证过程不产生真实破坏。建议在修复后重新发起评估，确认缺陷已闭环。"
    )
    lines.append("")

    return "\n".join(lines)


def _source_label(source_type: str) -> str:
    return {"local": "本地源码目录", "git": "Git 仓库地址"}.get(source_type, source_type)


def _text(value: str | None) -> str:
    if not value:
        return "（无）"
    return value.strip()


def _risk_conclusion(total: int, high: int, medium: int, low: int, path_count: int) -> str:
    if total == 0:
        return (
            "本次评估未发现安全缺陷，源码在当前规则覆盖范围内未暴露出明显的注入、"
            "凭据泄露与文件访问风险。建议保持定期复评，并结合动态测试补充覆盖。"
        )

    if high > 0:
        level = "**高风险**"
        advice = (
            "存在可直接导致数据泄露或服务器接管的缺陷，建议立即安排修复，"
            "并在修复前评估是否需要临时下线或加装访问控制。"
        )
    elif medium > 0:
        level = "**中风险**"
        advice = "存在可被利用的缺陷，建议在近期迭代中安排修复，并补充监控告警。"
    else:
        level = "**低风险**"
        advice = "未发现直接可利用的高危缺陷，建议随版本迭代逐步加固。"

    path_note = (
        f"其中已编排到 {path_count} 条完整攻击路径，说明缺陷之间可以相互衔接，"
        "单点修复不足以消除风险，需要按路径整体治理。"
        if path_count
        else "暂未编排到完整攻击路径，但仍需逐项修复。"
    )

    return (
        f"综合评定风险等级为 {level}。本次共发现 {total} 个缺陷"
        f"（高危 {high}、中危 {medium}、低危 {low}）。{path_note}{advice}"
    )


def _collect_remediations(vulnerabilities: list[dict]) -> list[tuple[str, str, int]]:
    """按风险等级与出现次数汇总修复建议。"""
    order = {"high": 0, "medium": 1, "low": 2}
    grouped: dict[str, dict] = {}

    for vuln in vulnerabilities:
        title = vuln["vuln_title"]
        entry = grouped.setdefault(
            title,
            {"risk": vuln["risk_level"], "remediation": "", "count": 0},
        )
        entry["count"] += 1
        if not entry["remediation"] and vuln.get("remediation_text"):
            entry["remediation"] = vuln["remediation_text"]

    result = [
        (title, entry["remediation"] or "参照对应缺陷类型的通用修复方案加固。", entry["count"])
        for title, entry in grouped.items()
    ]
    result.sort(key=lambda item: order.get(grouped[item[0]]["risk"], 9))
    return result


# ---------------------------------------------------------------------------
# 极简 Markdown → HTML 渲染（避免引入额外依赖）
# ---------------------------------------------------------------------------
_INLINE_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")


def _inline(text: str) -> str:
    escaped = html_lib.escape(text, quote=False)
    escaped = _INLINE_CODE.sub(lambda m: f"<code>{m.group(1)}</code>", escaped)
    escaped = _BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", escaped)
    return escaped


def markdown_to_html(markdown: str, title: str = "安全评估报告") -> str:
    body: list[str] = []
    lines = markdown.split("\n")
    index = 0
    in_code = False
    code_buffer: list[str] = []
    list_buffer: list[str] = []
    table_buffer: list[str] = []

    def flush_list() -> None:
        if list_buffer:
            body.append("<ul>" + "".join(f"<li>{item}</li>" for item in list_buffer) + "</ul>")
            list_buffer.clear()

    def flush_table() -> None:
        if not table_buffer:
            return
        rows = [row.strip().strip("|").split("|") for row in table_buffer]
        table_buffer.clear()
        if not rows:
            return
        head = rows[0]
        data_rows = [row for row in rows[2:]] if len(rows) > 1 and set(
            "".join(rows[1]).replace(" ", "")
        ) <= set("-:|") else rows[1:]

        parts = ["<table><thead><tr>"]
        parts.extend(f"<th>{_inline(cell.strip())}</th>" for cell in head)
        parts.append("</tr></thead><tbody>")
        for row in data_rows:
            parts.append("<tr>")
            parts.extend(f"<td>{_inline(cell.strip())}</td>" for cell in row)
            parts.append("</tr>")
        parts.append("</tbody></table>")
        body.append("".join(parts))

    while index < len(lines):
        line = lines[index]

        if line.strip().startswith("```"):
            if in_code:
                body.append(
                    "<pre><code>"
                    + html_lib.escape("\n".join(code_buffer))
                    + "</code></pre>"
                )
                code_buffer.clear()
                in_code = False
            else:
                flush_list()
                flush_table()
                in_code = True
            index += 1
            continue

        if in_code:
            code_buffer.append(line)
            index += 1
            continue

        stripped = line.strip()

        if not stripped:
            flush_list()
            flush_table()
            index += 1
            continue

        if stripped.startswith("|"):
            flush_list()
            table_buffer.append(stripped)
            index += 1
            continue
        flush_table()

        if stripped.startswith("#"):
            flush_list()
            level = min(len(stripped) - len(stripped.lstrip("#")), 6)
            body.append(f"<h{level}>{_inline(stripped[level:].strip())}</h{level}>")
            index += 1
            continue

        if stripped.startswith("- "):
            list_buffer.append(_inline(stripped[2:].strip()))
            index += 1
            continue

        ordered = re.match(r"^(\d+)\.\s+(.*)$", stripped)
        if ordered:
            flush_list()
            # 有序列表在此实现中统一渲染为带序号的段落，保证编号稳定
            body.append(f"<p>{ordered.group(1)}. {_inline(ordered.group(2))}</p>")
            index += 1
            continue

        if stripped == "---":
            flush_list()
            body.append("<hr/>")
            index += 1
            continue

        flush_list()
        body.append(f"<p>{_inline(stripped)}</p>")
        index += 1

    if in_code and code_buffer:
        body.append("<pre><code>" + html_lib.escape("\n".join(code_buffer)) + "</code></pre>")
    flush_list()
    flush_table()

    return _HTML_SHELL.format(title=html_lib.escape(title), body="\n".join(body))


_HTML_SHELL = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{
    margin: 0; padding: 40px 20px; background: #f5f6f8; color: #1f2430;
    font-family: "Microsoft YaHei", "PingFang SC", "Segoe UI", Arial, sans-serif;
    line-height: 1.75;
  }}
  .sheet {{
    max-width: 900px; margin: 0 auto; background: #fff; padding: 48px 56px;
    border-radius: 10px; box-shadow: 0 2px 14px rgba(16,24,40,.08);
  }}
  h1 {{ font-size: 26px; border-bottom: 3px solid #2563eb; padding-bottom: 14px; }}
  h2 {{ font-size: 20px; margin-top: 36px; color: #1d4ed8; }}
  h3 {{ font-size: 17px; margin-top: 26px; }}
  h4 {{ font-size: 15px; margin-top: 22px; color: #334155; }}
  code {{
    background: #eef2f7; padding: 2px 6px; border-radius: 4px;
    font-family: Consolas, "Courier New", monospace; font-size: 13px;
  }}
  pre {{
    background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 8px;
    overflow-x: auto; font-size: 13px; line-height: 1.6;
  }}
  pre code {{ background: none; color: inherit; padding: 0; }}
  table {{ border-collapse: collapse; width: 100%; margin: 14px 0; font-size: 14px; }}
  th, td {{ border: 1px solid #d7dee8; padding: 8px 12px; text-align: left; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  hr {{ border: none; border-top: 1px solid #e2e8f0; margin: 32px 0; }}
  strong {{ color: #0f172a; }}
  ul {{ padding-left: 22px; }}
</style>
</head>
<body>
<div class="sheet">
{body}
</div>
</body>
</html>
"""
