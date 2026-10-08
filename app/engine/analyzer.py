"""代码分析：遍历源码 → 应用规则库 → 产出漏洞候选（§1.4.4 code_analysis 阶段）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..utils import truncate
from . import rules, sandbox

# 同一条规则在同一文件中最多上报的命中数，避免噪声淹没真实问题
MAX_HITS_PER_RULE_PER_FILE = 2

# 滑动窗口行数：覆盖跨行的危险调用写法
WINDOW_LINES = 3

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Finding:
    """一条漏洞候选。"""

    rule_key: str
    title: str
    risk_level: str
    category: str
    file_path: str
    line_no: int
    evidence: str
    condition: str
    impact: str
    remediation: str
    context: list[str] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return (RISK_ORDER.get(self.risk_level, 9), self.file_path, self.line_no)


def analyze_source(project_id: int, on_file=None) -> list[Finding]:
    """执行代码分析，返回按风险等级排序的漏洞候选列表。

    on_file: 可选回调 (index, total, relative_path)，用于上报进度。
    """
    root = sandbox.resolve_source_root(project_id).resolve()
    entries = sandbox.walk_source(project_id)
    findings: list[Finding] = []

    for index, entry in enumerate(entries, start=1):
        if on_file is not None:
            on_file(index, len(entries), entry["relative_path"])

        suffix = entry["suffix"]
        applicable = rules.rules_for_suffix(suffix)
        if not applicable:
            continue

        try:
            content = (root / entry["relative_path"]).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue

        findings.extend(_scan_content(entry["relative_path"], content, applicable))

    findings.sort(key=lambda item: item.sort_key)
    return findings


def _scan_content(relative_path: str, content: str, applicable: list[rules.Rule]) -> list[Finding]:
    lines = content.splitlines()
    hits_per_rule: dict[str, int] = {}
    findings: list[Finding] = []
    reported_lines: set[tuple[str, int]] = set()

    for line_index, line in enumerate(lines):
        stripped = line.strip()
        # 过短的行（如单独的 `pass`）仍可能是规则命中的锚点，
        # 因此这里只过滤掉空行与极短片段，窗口匹配负责判断上下文。
        if not stripped or len(stripped) < 5:
            continue

        window = "\n".join(lines[line_index : line_index + WINDOW_LINES])
        for rule in applicable:
            if hits_per_rule.get(rule.rule_key, 0) >= MAX_HITS_PER_RULE_PER_FILE:
                continue

            match = rule.match_window(window)
            if match is None:
                continue

            # 匹配发生在「当前行 + 后 N 行」的窗口内，需换算回真实行号，
            # 否则证据会指向窗口起始行（常常是注释或 docstring）而非危险调用本身。
            matched_index = line_index + window[: match.start()].count("\n")
            matched_line = lines[matched_index].strip()
            if not matched_line:
                continue

            line_no = matched_index + 1
            dedup_key = (rule.rule_key, line_no)
            if dedup_key in reported_lines:
                continue
            reported_lines.add(dedup_key)

            findings.append(
                Finding(
                    rule_key=rule.rule_key,
                    title=rule.title,
                    risk_level=rule.risk_level,
                    category=rule.category,
                    file_path=relative_path,
                    line_no=line_no,
                    evidence=truncate(matched_line, 400),
                    condition=rule.condition,
                    impact=rule.impact,
                    remediation=rule.remediation,
                    context=_snippet(lines, matched_index),
                )
            )
            hits_per_rule[rule.rule_key] = hits_per_rule.get(rule.rule_key, 0) + 1

    return findings


def _snippet(lines: list[str], center: int, radius: int = 2) -> list[str]:
    """截取命中行上下若干行，作为证据上下文。"""
    start = max(center - radius, 0)
    end = min(center + radius + 1, len(lines))
    return [
        f"{number + 1:>5} | {lines[number].rstrip()}"
        for number in range(start, end)
    ]


def summarize(findings: list[Finding]) -> dict:
    """汇总统计信息，供日志与报告使用。"""
    by_risk: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    by_rule: dict[str, int] = {}
    files: set[str] = set()

    for finding in findings:
        by_risk[finding.risk_level] = by_risk.get(finding.risk_level, 0) + 1
        by_rule[finding.title] = by_rule.get(finding.title, 0) + 1
        files.add(finding.file_path)

    return {
        "total": len(findings),
        "by_risk": by_risk,
        "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
        "affected_files": sorted(files),
        "affected_file_count": len(files),
    }


def scan_root_for_display(project_id: int) -> str:
    """返回展示用的源码根路径（相对项目根，便于报告阅读）。"""
    root = sandbox.resolve_source_root(project_id)
    try:
        return Path(root).relative_to(config.BASE_DIR).as_posix()
    except ValueError:
        return str(root)
