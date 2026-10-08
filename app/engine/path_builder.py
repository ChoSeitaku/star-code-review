"""攻击路径编排（§1.4.12 攻击路径：路径编号、关联漏洞、利用顺序、最终影响）。

把已验证的漏洞按「杀伤链」顺序串联成完整攻击路径：
    初始立足（凭据/配置泄露） → 执行与注入 → 影响扩大（文件访问/横向）

同一漏洞不重复出现在多条路径中，保证每条路径都是独立可信的利用链。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PathTemplate:
    path_code: str
    path_title: str
    path_summary: str
    final_impact_text: str
    steps: tuple[tuple[str, ...], ...]   # 每步可接受的 rule_key 集合
    min_steps: int = 2


PATH_TEMPLATES: tuple[PathTemplate, ...] = (
    PathTemplate(
        path_code="PATH-001",
        path_title="源码凭据泄露 → 任意命令执行 → 服务器完全接管",
        path_summary=(
            "攻击者先通过源码中泄露的明文凭据获得系统访问入口，"
            "随后利用命令注入缺陷在应用服务器上执行任意系统命令，最终取得主机控制权。"
        ),
        final_impact_text=(
            "服务器被完全接管：攻击者可以任意读写业务数据、植入持久化后门、"
            "以内网跳板横向渗透至数据库与其它业务系统，造成数据泄露与业务中断。"
        ),
        steps=(
            ("HARDCODED_SECRET", "PLAINTEXT_PASSWORD", "WEAK_CRYPTO"),
            ("COMMAND_INJECTION", "CODE_INJECTION", "INSECURE_DESERIALIZATION"),
            ("PATH_TRAVERSAL", "SSRF"),
        ),
    ),
    PathTemplate(
        path_code="PATH-002",
        path_title="配置与凭据泄露 → SQL 注入 → 全量数据窃取",
        path_summary=(
            "攻击者从调试模式暴露的堆栈信息或源码泄露的凭据中获取表结构与文件路径，"
            "据此构造 SQL 注入载荷绕过查询条件，逐步拖取整库数据。"
        ),
        final_impact_text=(
            "数据库全量数据泄露，包含用户身份信息与业务敏感数据；"
            "若数据库账户权限过高，还可通过写入文件进一步升级为服务器控制权。"
        ),
        steps=(
            ("DEBUG_ENABLED", "HARDCODED_SECRET"),
            ("SQL_INJECTION",),
            ("WEAK_CRYPTO", "PLAINTEXT_PASSWORD"),
        ),
    ),
    PathTemplate(
        path_code="PATH-003",
        path_title="路径遍历 → 敏感文件读取 → 凭据二次利用",
        path_summary=(
            "攻击者利用文件路径拼接缺陷跳出允许目录，读取隔离环境内的敏感文件，"
            "再从配置或密钥文件中提取凭据用于下一阶段攻击。"
        ),
        final_impact_text=(
            "配置文件、密钥材料与源代码被读取，攻击者据此获取数据库与第三方服务的访问凭据，"
            "并可挑选更隐蔽的持久化攻击面。"
        ),
        steps=(
            ("PATH_TRAVERSAL", "SSRF"),
            ("HARDCODED_SECRET", "PLAINTEXT_PASSWORD", "WEAK_CRYPTO"),
        ),
    ),
    PathTemplate(
        path_code="PATH-004",
        path_title="XSS 会话劫持 → 账户体系失陷",
        path_summary=(
            "攻击者利用跨站脚本缺陷窃取用户会话 Cookie，"
            "结合口令保护不足的问题进一步接管账户。"
        ),
        final_impact_text=(
            "用户会话被劫持、账户被接管；管理员账户失陷后攻击者可直接操作后台功能，"
            "并可能借助后台能力扩大影响范围。"
        ),
        steps=(
            ("XSS",),
            ("PLAINTEXT_PASSWORD", "WEAK_CRYPTO"),
        ),
    ),
)


@dataclass
class AttackPathDraft:
    path_code: str
    path_title: str
    path_summary: str
    final_impact_text: str
    steps: list[tuple[int, str]]   # (vuln_id, step_text)


def build_attack_paths(vulnerabilities: list[dict]) -> list[AttackPathDraft]:
    """根据已验证漏洞编排攻击路径。

    vulnerabilities: 已验证漏洞列表，需包含 id / rule_key / vuln_title /
                     file_path / risk_level 字段。
    """
    verified = [v for v in vulnerabilities if v.get("verify_status") == "verified"]
    if not verified:
        return []

    used_vuln_ids: set[int] = set()
    drafts: list[AttackPathDraft] = []

    for template in PATH_TEMPLATES:
        steps: list[tuple[int, str]] = []

        for step_index, acceptable_keys in enumerate(template.steps):
            candidate = _pick_vuln(verified, acceptable_keys, used_vuln_ids)
            if candidate is None:
                continue
            used_vuln_ids.add(candidate["id"])
            steps.append(
                (
                    candidate["id"],
                    _step_text(step_index, candidate),
                )
            )

        # 步骤不足则丢弃该路径，避免出现只有一步的「伪链路」
        if len(steps) < template.min_steps:
            # 回滚已占用的漏洞，让其它模板有机会使用
            for vuln_id, _ in steps:
                used_vuln_ids.discard(vuln_id)
            continue

        drafts.append(
            AttackPathDraft(
                path_code=template.path_code,
                path_title=template.path_title,
                path_summary=template.path_summary,
                final_impact_text=template.final_impact_text,
                steps=steps,
            )
        )

    return drafts


def _pick_vuln(
    verified: list[dict], acceptable_keys: tuple[str, ...], used: set[int]
) -> dict | None:
    """按风险等级优先挑选未被占用的漏洞。"""
    order = {"high": 0, "medium": 1, "low": 2}
    candidates = [
        vuln
        for vuln in verified
        if vuln.get("rule_key") in acceptable_keys and vuln["id"] not in used
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda v: order.get(v.get("risk_level", "low"), 9))
    return candidates[0]


_STEP_VERBS = {
    0: "获取初始立足点",
    1: "执行核心攻击动作",
    2: "扩大战果",
}

_RISK_LABEL = {"high": "高危", "medium": "中危", "low": "低危"}


def _step_text(step_index: int, vuln: dict) -> str:
    verb = _STEP_VERBS.get(step_index, f"第 {step_index + 1} 步")
    location = vuln.get("file_path") or "未知位置"
    risk = _RISK_LABEL.get(vuln.get("risk_level", "low"), "低危")
    return (
        f"{verb}：利用「{vuln['vuln_title']}」（{vuln.get('vuln_code', '')}，"
        f"风险等级{risk}），位置 {location}。"
    )
