"""调度模块（§1.4.7 调度模块）。

负责：阶段推进、角色任务分发、状态汇总、停止控制。

阶段顺序（§1.4.4）：
    environment_scan → code_analysis → vulnerability_verify → report_generate → done

每个阶段由若干执行角色承担（§1.4.5 六类角色），每个角色单独落一条 worker_tasks
记录，包含任务内容、开始/结束时间、执行结果与错误信息，并可通过
project_id + stage_id 回溯到所属项目与阶段。
"""

from __future__ import annotations

import asyncio
import time

from .. import config, db
from ..utils import estimate_tokens, now_str, truncate
from ..ws import manager
from . import analyzer, metrics, path_builder, reporter, sandbox, verifier

# ---------------------------------------------------------------------------
# 阶段与角色定义
# ---------------------------------------------------------------------------
STAGE_SEQUENCE = (
    "environment_scan",
    "code_analysis",
    "vulnerability_verify",
    "report_generate",
    "done",
)

STAGE_LABELS = {
    "environment_scan": "隔离环境准备与检查",
    "code_analysis": "源码静态分析",
    "vulnerability_verify": "漏洞验证",
    "report_generate": "报告生成",
    "done": "评估完成",
}

ROLE_LABELS = {
    "general_processor": "通用处理角色",
    "env_checker": "环境检查角色",
    "code_analyzer": "代码分析角色",
    "vuln_verifier": "漏洞验证角色",
    "report_writer": "报告整理角色",
    "ops_helper": "运维辅助角色",
}

# 各阶段的角色分工
STAGE_ROLES = {
    "environment_scan": ("env_checker", "ops_helper", "general_processor"),
    "code_analysis": ("code_analyzer", "general_processor", "ops_helper"),
    "vulnerability_verify": ("vuln_verifier", "code_analyzer", "ops_helper"),
    "report_generate": ("report_writer", "code_analyzer", "general_processor"),
}

# 演示节奏：每个步骤之间的停顿，使实时监控页能观察到阶段推进
STEP_DELAY = 0.35
ROLE_DELAY = 0.25


class TaskStopped(Exception):
    """用户请求停止任务时抛出，用于中断阶段执行。"""


# ---------------------------------------------------------------------------
# 停止控制
# ---------------------------------------------------------------------------
class StopRegistry:
    def __init__(self) -> None:
        self._stopped: set[int] = set()
        self._tasks: dict[int, asyncio.Task] = {}

    def request_stop(self, project_id: int) -> None:
        self._stopped.add(project_id)

    def is_stopped(self, project_id: int) -> bool:
        return project_id in self._stopped

    def clear(self, project_id: int) -> None:
        self._stopped.discard(project_id)

    def register(self, project_id: int, task: asyncio.Task) -> None:
        self._tasks[project_id] = task

    def unregister(self, project_id: int) -> None:
        self._tasks.pop(project_id, None)

    def is_task_alive(self, project_id: int) -> bool:
        task = self._tasks.get(project_id)
        return task is not None and not task.done()

    def get_task(self, project_id: int) -> asyncio.Task | None:
        return self._tasks.get(project_id)

    def active_projects(self) -> list[int]:
        return list(self._tasks.keys())

    def cancel(self, project_id: int) -> None:
        task = self._tasks.get(project_id)
        if task is not None and not task.done():
            task.cancel()


registry = StopRegistry()


# ---------------------------------------------------------------------------
# 事件发射：落库 + WebSocket 广播（§1.4.11）
# ---------------------------------------------------------------------------
async def emit_log(
    project_id: int,
    log_level: str,
    log_content: str,
    stage_id: int | None = None,
    worker_task_id: int | None = None,
) -> None:
    created_at = now_str()
    db.insert(
        "runtime_logs",
        {
            "project_id": project_id,
            "stage_id": stage_id,
            "worker_task_id": worker_task_id,
            "log_level": log_level,
            "log_content": log_content,
            "created_at": created_at,
        },
    )
    await manager.broadcast(
        project_id,
        "runtime_log",
        {
            "log_level": log_level,
            "log_content": log_content,
            "stage_id": stage_id,
            "worker_task_id": worker_task_id,
            "created_at": created_at,
        },
    )


async def emit_chat(
    project_id: int, worker_role: str, message_type: str, message_text: str
) -> None:
    created_at = now_str()
    db.insert(
        "chat_messages",
        {
            "project_id": project_id,
            "worker_role": worker_role,
            "message_type": message_type,
            "message_text": message_text,
            "created_at": created_at,
        },
    )
    await manager.broadcast(
        project_id,
        "chat_message",
        {
            "project_id": project_id,
            "worker_role": worker_role,
            "message_type": message_type,
            "message_text": message_text,
            "created_at": created_at,
        },
    )


async def emit_resource(project_id: int, sampler: metrics.ResourceSampler) -> dict:
    cpu_usage, memory_usage = sampler.sample()
    recorded_at = now_str()
    db.insert(
        "resource_usages",
        {
            "project_id": project_id,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "token_count": sampler.token_count,
            "recorded_at": recorded_at,
        },
    )
    payload = {
        "project_id": project_id,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "token_count": sampler.token_count,
        "recorded_at": recorded_at,
    }
    await manager.broadcast(project_id, "resource_usage", payload)
    return payload


async def emit_project_status(project_id: int, project_status: str) -> None:
    await manager.broadcast(
        project_id,
        "project_status",
        {"project_id": project_id, "project_status": project_status},
    )


async def emit_stage_status(
    project_id: int, stage_name: str, stage_status: str, stage_id: int | None = None
) -> None:
    await manager.broadcast(
        project_id,
        "stage_status",
        {
            "project_id": project_id,
            "stage_id": stage_id,
            "stage_name": stage_name,
            "stage_status": stage_status,
        },
    )


async def emit_worker_status(
    project_id: int, worker_task_id: int, worker_role: str, task_status: str
) -> None:
    await manager.broadcast(
        project_id,
        "worker_status",
        {
            "worker_task_id": worker_task_id,
            "worker_role": worker_role,
            "task_status": task_status,
        },
    )


async def emit_vulnerability(project_id: int, vuln: dict) -> None:
    await manager.broadcast(
        project_id,
        "vulnerability_found",
        {
            "vuln_id": vuln["id"],
            "vuln_code": vuln.get("vuln_code"),
            "vuln_title": vuln.get("vuln_title"),
            "risk_level": vuln.get("risk_level"),
            "file_path": vuln.get("file_path"),
        },
    )


# ---------------------------------------------------------------------------
# 阶段与角色记账
# ---------------------------------------------------------------------------
def _create_stage(project_id: int, stage_name: str) -> int:
    return db.insert(
        "runtime_stages",
        {
            "project_id": project_id,
            "stage_name": stage_name,
            "stage_status": "running",
            "started_at": now_str(),
            "finished_at": None,
            "error_message": None,
        },
    )


def _finish_stage(stage_id: int, status_value: str, error: str | None = None) -> None:
    db.update(
        "runtime_stages",
        {
            "stage_status": status_value,
            "finished_at": now_str(),
            "error_message": error,
        },
        "id = ?",
        (stage_id,),
    )


def _create_worker(
    project_id: int, stage_id: int, worker_role: str, task_content: str
) -> int:
    return db.insert(
        "worker_tasks",
        {
            "project_id": project_id,
            "stage_id": stage_id,
            "worker_role": worker_role,
            "task_content": task_content,
            "task_status": "running",
            "result_summary": None,
            "error_message": None,
            "started_at": now_str(),
            "finished_at": None,
        },
    )


def _finish_worker(
    worker_id: int, status_value: str, result_summary: str, error: str | None = None
) -> None:
    db.update(
        "worker_tasks",
        {
            "task_status": status_value,
            "result_summary": result_summary,
            "error_message": error,
            "finished_at": now_str(),
        },
        "id = ?",
        (worker_id,),
    )


def _set_project_status(project_id: int, status_value: str) -> None:
    db.update(
        "projects",
        {"project_status": status_value, "updated_at": now_str()},
        "id = ?",
        (project_id,),
    )


# ---------------------------------------------------------------------------
# 停止检查
# ---------------------------------------------------------------------------
def _check_stop(project_id: int, deadline: float) -> None:
    if registry.is_stopped(project_id):
        raise TaskStopped("用户请求停止任务")
    if time.monotonic() > deadline:
        raise TaskStopped("任务执行超时")


async def _pause(project_id: int, deadline: float, seconds: float = STEP_DELAY) -> None:
    """带停止检查的等待，用于演示节奏控制。"""
    await asyncio.sleep(seconds)
    _check_stop(project_id, deadline)


# ---------------------------------------------------------------------------
# 任务入口
# ---------------------------------------------------------------------------
async def start_project(project_id: int) -> dict:
    """启动评估任务（后台执行，立即返回）。"""
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if project is None:
        raise ValueError(f"项目不存在：{project_id}")

    if project["project_status"] == "running" or registry.is_task_alive(project_id):
        raise ValueError("该项目正在执行中，请先停止后再启动")

    running_count = db.count("projects", "project_status = 'running'")
    max_concurrency = config.get_int_config("max_concurrency", 3)
    if running_count >= max_concurrency:
        raise ValueError(
            f"并发任务数已达上限（{max_concurrency}），请等待其它任务结束"
        )

    registry.clear(project_id)
    _set_project_status(project_id, "running")
    await emit_project_status(project_id, "running")

    task = asyncio.create_task(_run_project(project_id))
    registry.register(project_id, task)
    return {"project_id": project_id, "project_status": "running"}


async def stop_project(project_id: int) -> dict:
    """停止评估任务：当前阶段不再继续执行，已保存的数据保留。"""
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if project is None:
        raise ValueError(f"项目不存在：{project_id}")

    registry.request_stop(project_id)
    sandbox.stop_sandbox(project_id)

    # 若项目已不在运行，直接落停止态
    if project["project_status"] != "running":
        _set_project_status(project_id, "stopped")
        await emit_project_status(project_id, "stopped")
        return {"project_id": project_id, "project_status": "stopped"}

    # 等待后台任务自行退出（超时则强制取消）
    task = registry.get_task(project_id)
    if task is not None and not task.done():
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=10.0)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()
        except Exception:
            pass

    return {"project_id": project_id, "project_status": "stopped"}


async def _run_project(project_id: int) -> None:
    """后台任务主体：准备隔离环境 → 依次执行各阶段。"""
    timeout_seconds = config.get_int_config("default_timeout_seconds", 600)
    deadline = time.monotonic() + timeout_seconds
    sampler = metrics.ResourceSampler()
    current_stage_id: int | None = None

    try:
        await emit_log(project_id, "INFO", "评估任务已启动，开始准备隔离环境")
        await emit_chat(
            project_id,
            "general_processor",
            "info",
            "收到评估任务，正在编排执行计划：环境检查 → 代码分析 → 漏洞验证 → 报告生成。",
        )

        # ------------------------------------------------------------------
        # 阶段 1：environment_scan
        # ------------------------------------------------------------------
        current_stage_id = await _stage_environment_scan(
            project_id, deadline, sampler
        )

        # ------------------------------------------------------------------
        # 阶段 2：code_analysis
        # ------------------------------------------------------------------
        current_stage_id = await _stage_code_analysis(project_id, deadline, sampler)

        # ------------------------------------------------------------------
        # 阶段 3：vulnerability_verify
        # ------------------------------------------------------------------
        current_stage_id = await _stage_vulnerability_verify(
            project_id, deadline, sampler
        )

        # ------------------------------------------------------------------
        # 阶段 4：report_generate
        # ------------------------------------------------------------------
        current_stage_id = await _stage_report_generate(project_id, deadline, sampler)

        # ------------------------------------------------------------------
        # 阶段 5：done
        # ------------------------------------------------------------------
        done_stage_id = _create_stage(project_id, "done")
        await emit_stage_status(project_id, "done", "running", done_stage_id)
        _finish_stage(done_stage_id, "success")
        await emit_stage_status(project_id, "done", "success", done_stage_id)

        _set_project_status(project_id, "completed")
        await emit_project_status(project_id, "completed")
        await emit_log(project_id, "INFO", "评估任务全部完成，项目状态更新为 completed")
        await emit_chat(
            project_id,
            "general_processor",
            "result",
            "评估流程结束，全部阶段执行成功，报告已就绪。",
        )

    except TaskStopped as exc:
        reason = str(exc)
        if current_stage_id is not None:
            _finish_stage(current_stage_id, "stopped", reason)
            stage = db.query_one(
                "SELECT stage_name FROM runtime_stages WHERE id = ?", (current_stage_id,)
            )
            if stage:
                await emit_stage_status(
                    project_id, stage["stage_name"], "stopped", current_stage_id
                )
        _set_project_status(project_id, "stopped")
        await emit_project_status(project_id, "stopped")
        await emit_log(project_id, "WARN", f"任务已停止：{reason}。已保存的数据继续保留。")
        await emit_chat(
            project_id,
            "general_processor",
            "warning",
            f"任务已停止（{reason}）。当前阶段不再继续执行，已完成的分析结果与数据均已保留。",
        )

    except asyncio.CancelledError:
        if current_stage_id is not None:
            _finish_stage(current_stage_id, "stopped", "任务被强制取消")
        _set_project_status(project_id, "stopped")
        await emit_project_status(project_id, "stopped")
        raise

    except Exception as exc:  # noqa: BLE001 - 兜底保证项目状态不会卡在 running
        message = f"{type(exc).__name__}: {exc}"
        if current_stage_id is not None:
            _finish_stage(current_stage_id, "failed", message)
        _set_project_status(project_id, "failed")
        await emit_project_status(project_id, "failed")
        await emit_log(project_id, "ERROR", f"任务执行失败：{message}")
        await emit_chat(
            project_id,
            "general_processor",
            "warning",
            f"任务执行失败：{message}",
        )

    finally:
        registry.unregister(project_id)


# ---------------------------------------------------------------------------
# 阶段 1：隔离环境准备与检查
# ---------------------------------------------------------------------------
async def _stage_environment_scan(
    project_id: int, deadline: float, sampler: metrics.ResourceSampler
) -> int:
    stage_name = "environment_scan"
    stage_id = _create_stage(project_id, stage_name)
    await emit_stage_status(project_id, stage_name, "running", stage_id)
    await emit_log(
        project_id,
        "INFO",
        f"进入阶段「{STAGE_LABELS[stage_name]}」，开始准备隔离环境",
        stage_id,
    )

    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))

    # ---- 角色 1：环境检查 ----
    worker_id = _create_worker(
        project_id, stage_id, "env_checker",
        f"为项目「{project['project_name']}」创建隔离环境，校验源码目录可读性与只读挂载",
    )
    await emit_worker_status(project_id, worker_id, "env_checker", "running")
    await emit_chat(project_id, "env_checker", "thinking", "正在创建隔离环境并挂载源码目录……")

    try:
        _check_stop(project_id, deadline)
        isolation_type = config.get_config("isolation_type", "simulated")
        sandbox_info = sandbox.create_sandbox(
            project_id,
            project["source_path"],
            project["source_type"],
            isolation_type,
        )
        _check_stop(project_id, deadline)
        env_report = sandbox.inspect_environment(project_id)

        summary = (
            f"隔离环境 {sandbox_info['sandbox_code']} 已就绪，"
            f"源码只读挂载于 {sandbox_info['source_mount_path']}，"
            f"可扫描文件 {env_report['file_count']} 个"
        )
        _finish_worker(worker_id, "success", summary)
        await emit_worker_status(project_id, worker_id, "env_checker", "success")
        await emit_log(project_id, "INFO", summary, stage_id, worker_id)
        await emit_chat(
            project_id,
            "env_checker",
            "result",
            f"隔离环境 {sandbox_info['sandbox_code']} 创建完成；源码以只读方式挂载，"
            f"网络策略 {env_report['network']}，共发现 {env_report['file_count']} 个可扫描文件。",
        )
    except TaskStopped:
        _finish_worker(worker_id, "failed", "任务被停止", "任务被停止")
        await emit_worker_status(project_id, worker_id, "env_checker", "failed")
        raise
    except Exception as exc:  # noqa: BLE001
        _finish_worker(worker_id, "failed", "隔离环境准备失败", str(exc))
        await emit_worker_status(project_id, worker_id, "env_checker", "failed")
        await emit_log(project_id, "ERROR", f"隔离环境准备失败：{exc}", stage_id, worker_id)
        _finish_stage(stage_id, "failed", str(exc))
        await emit_stage_status(project_id, stage_name, "failed", stage_id)
        raise

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 2：运维辅助（资源采样） ----
    ops_id = _create_worker(
        project_id, stage_id, "ops_helper", "采集隔离环境资源占用基线并记录日志目录"
    )
    await emit_worker_status(project_id, ops_id, "ops_helper", "running")
    _check_stop(project_id, deadline)

    log_dir = config.project_log_dir(project_id)
    log_dir.mkdir(parents=True, exist_ok=True)
    resource = await emit_resource(project_id, sampler)

    ops_summary = (
        f"资源基线采集完成：CPU {resource['cpu_usage']}%，"
        f"内存 {resource['memory_usage']} MB；日志目录 {log_dir.name}/ 已就绪"
    )
    _finish_worker(ops_id, "success", ops_summary)
    await emit_worker_status(project_id, ops_id, "ops_helper", "success")
    await emit_log(project_id, "INFO", ops_summary, stage_id, ops_id)

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 3：通用处理（任务登记与校验） ----
    general_id = _create_worker(
        project_id, stage_id, "general_processor",
        f"登记评估任务说明并校验项目配置：{truncate(project.get('task_content') or '（未填写）', 120)}",
    )
    await emit_worker_status(project_id, general_id, "general_processor", "running")
    _check_stop(project_id, deadline)

    general_summary = (
        f"任务说明已登记；源码来源 {project['source_type']}，"
        f"隔离环境类型 {isolation_type}，超时上限 "
        f"{config.get_int_config('default_timeout_seconds', 600)} 秒"
    )
    _finish_worker(general_id, "success", general_summary)
    await emit_worker_status(project_id, general_id, "general_processor", "success")
    await emit_log(project_id, "INFO", general_summary, stage_id, general_id)

    await emit_resource(project_id, sampler)
    _finish_stage(stage_id, "success")
    await emit_stage_status(project_id, stage_name, "success", stage_id)
    await emit_log(project_id, "INFO", f"阶段「{STAGE_LABELS[stage_name]}」执行完成", stage_id)
    return stage_id


# ---------------------------------------------------------------------------
# 阶段 2：源码静态分析
# ---------------------------------------------------------------------------
async def _stage_code_analysis(
    project_id: int, deadline: float, sampler: metrics.ResourceSampler
) -> int:
    stage_name = "code_analysis"
    stage_id = _create_stage(project_id, stage_name)
    await emit_stage_status(project_id, stage_name, "running", stage_id)
    await emit_log(
        project_id, "INFO", f"进入阶段「{STAGE_LABELS[stage_name]}」", stage_id
    )

    # ---- 角色 1：环境检查（目录遍历，为分析准备文件清单） ----
    env_id = _create_worker(
        project_id, stage_id, "env_checker", "遍历源码目录，生成待扫描文件清单"
    )
    await emit_worker_status(project_id, env_id, "env_checker", "running")
    _check_stop(project_id, deadline)

    entries = sandbox.walk_source(project_id)
    suffix_stats: dict[str, int] = {}
    for entry in entries:
        suffix_stats[entry["suffix"]] = suffix_stats.get(entry["suffix"], 0) + 1
    top_suffix = ", ".join(
        f"{suffix}×{count}"
        for suffix, count in sorted(suffix_stats.items(), key=lambda kv: -kv[1])[:5]
    )
    env_summary = f"目录遍历完成，待扫描文件 {len(entries)} 个（{top_suffix}）"
    _finish_worker(env_id, "success", env_summary)
    await emit_worker_status(project_id, env_id, "env_checker", "success")
    await emit_log(project_id, "INFO", env_summary, stage_id, env_id)
    await emit_chat(project_id, "env_checker", "result", env_summary)

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 2：代码分析（规则引擎扫描） ----
    analyzer_id = _create_worker(
        project_id, stage_id, "code_analyzer",
        f"对 {len(entries)} 个源码文件执行规则引擎扫描，识别注入、凭据泄露、文件访问等缺陷",
    )
    await emit_worker_status(project_id, analyzer_id, "code_analyzer", "running")
    await emit_chat(
        project_id, "code_analyzer", "thinking", "开始执行静态规则扫描，正在逐文件匹配缺陷模式……"
    )

    progress_state = {"last_report": 0}
    # analyze_source 是同步函数，进度日志通过 create_task 异步投递；
    # 持有强引用防止任务在完成前被垃圾回收。
    progress_tasks: set[asyncio.Task] = set()

    def on_file(index: int, total: int, relative_path: str) -> None:
        # 每 10% 上报一次进度，避免日志与消息被淹没
        step = max(total // 10, 1)
        if index - progress_state["last_report"] < step and index != total:
            return
        progress_state["last_report"] = index
        _check_stop(project_id, deadline)
        task = asyncio.create_task(
            emit_log(
                project_id,
                "DEBUG",
                f"扫描进度 {index}/{total}：{relative_path}",
                stage_id,
                analyzer_id,
            )
        )
        progress_tasks.add(task)
        task.add_done_callback(progress_tasks.discard)

    findings = analyzer.analyze_source(project_id, on_file=on_file)
    _check_stop(project_id, deadline)

    # 漏洞落库，编号 VULN-001 递增
    existing_count = db.count("vulnerabilities", "project_id = ?", (project_id,))
    saved: list[dict] = []
    for offset, finding in enumerate(findings, start=1):
        vuln_code = f"VULN-{existing_count + offset:03d}"
        vuln_id = db.insert(
            "vulnerabilities",
            {
                "project_id": project_id,
                "vuln_code": vuln_code,
                "vuln_title": finding.title,
                "risk_level": finding.risk_level,
                "file_path": finding.file_path,
                "condition_text": finding.condition,
                "impact_text": finding.impact,
                "evidence_text": f"{finding.file_path}:{finding.line_no}\n" + finding.evidence,
                "verify_status": "unverified",
                "reproduce_steps_text": None,
                "verify_code_text": None,
                "remediation_text": finding.remediation,
                "created_at": now_str(),
                "rule_key": finding.rule_key,
                "line_no": finding.line_no,
                "category": finding.category,
            },
        )
        saved.append({"id": vuln_id, "vuln_code": vuln_code, **finding.__dict__})
        sampler.add_tokens(
            estimate_tokens(finding.evidence + finding.condition + finding.impact)
        )
        await emit_vulnerability(
            project_id,
            {
                "id": vuln_id,
                "vuln_code": vuln_code,
                "vuln_title": finding.title,
                "risk_level": finding.risk_level,
                "file_path": finding.file_path,
            },
        )
        await _pause(project_id, deadline, 0.12)

    stats = analyzer.summarize(findings)
    analyzer_summary = (
        f"静态分析完成：命中 {stats['total']} 个缺陷"
        f"（高危 {stats['by_risk'].get('high', 0)}、中危 {stats['by_risk'].get('medium', 0)}、"
        f"低危 {stats['by_risk'].get('low', 0)}），涉及 {stats['affected_file_count']} 个文件"
    )
    _finish_worker(analyzer_id, "success", analyzer_summary)
    await emit_worker_status(project_id, analyzer_id, "code_analyzer", "success")
    await emit_log(project_id, "INFO", analyzer_summary, stage_id, analyzer_id)
    await emit_chat(
        project_id,
        "code_analyzer",
        "result",
        f"{analyzer_summary}。主要问题类型："
        + "、".join(f"{name}×{count}" for name, count in list(stats["by_rule"].items())[:4]),
    )

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 3：运维辅助（资源采样） ----
    ops_id = _create_worker(
        project_id, stage_id, "ops_helper", "记录代码分析阶段的资源消耗"
    )
    await emit_worker_status(project_id, ops_id, "ops_helper", "running")
    _check_stop(project_id, deadline)
    resource = await emit_resource(project_id, sampler)
    ops_summary = (
        f"分析阶段资源记录：CPU {resource['cpu_usage']}%，"
        f"内存 {resource['memory_usage']} MB，累计 token 估算 {resource['token_count']}"
    )
    _finish_worker(ops_id, "success", ops_summary)
    await emit_worker_status(project_id, ops_id, "ops_helper", "success")
    await emit_log(project_id, "INFO", ops_summary, stage_id, ops_id)

    # ---- 角色 4：通用处理（阶段汇总） ----
    general_id = _create_worker(
        project_id, stage_id, "general_processor", "汇总代码分析阶段产出并交接给验证阶段"
    )
    await emit_worker_status(project_id, general_id, "general_processor", "running")
    general_summary = f"已交接 {len(saved)} 条漏洞记录至漏洞验证阶段"
    _finish_worker(general_id, "success", general_summary)
    await emit_worker_status(project_id, general_id, "general_processor", "success")
    await emit_log(project_id, "INFO", general_summary, stage_id, general_id)

    _finish_stage(stage_id, "success")
    await emit_stage_status(project_id, stage_name, "success", stage_id)
    await emit_log(project_id, "INFO", f"阶段「{STAGE_LABELS[stage_name]}」执行完成", stage_id)
    return stage_id


# ---------------------------------------------------------------------------
# 阶段 3：漏洞验证
# ---------------------------------------------------------------------------
async def _stage_vulnerability_verify(
    project_id: int, deadline: float, sampler: metrics.ResourceSampler
) -> int:
    stage_name = "vulnerability_verify"
    stage_id = _create_stage(project_id, stage_name)
    await emit_stage_status(project_id, stage_name, "running", stage_id)
    await emit_log(
        project_id, "INFO", f"进入阶段「{STAGE_LABELS[stage_name]}」", stage_id
    )

    vulnerabilities = db.query_all(
        "SELECT * FROM vulnerabilities WHERE project_id = ? ORDER BY id", (project_id,)
    )
    source_root = sandbox.resolve_source_root(project_id)

    verifier_id = _create_worker(
        project_id, stage_id, "vuln_verifier",
        f"对 {len(vulnerabilities)} 条漏洞候选执行静态证据复核与误报判定",
    )
    await emit_worker_status(project_id, verifier_id, "vuln_verifier", "running")
    await emit_chat(
        project_id, "vuln_verifier", "thinking", "开始逐条复核漏洞证据，并排除已有防护的误报……"
    )

    verified_count = 0
    failed_count = 0

    for vuln in vulnerabilities:
        _check_stop(project_id, deadline)

        finding = analyzer.Finding(
            rule_key=vuln.get("rule_key") or "",
            title=vuln["vuln_title"],
            risk_level=vuln["risk_level"],
            category=vuln.get("category") or "",
            file_path=vuln.get("file_path") or "",
            line_no=vuln.get("line_no") or 1,
            evidence=(vuln.get("evidence_text") or "").split("\n", 1)[-1],
            condition=vuln.get("condition_text") or "",
            impact=vuln.get("impact_text") or "",
            remediation=vuln.get("remediation_text") or "",
        )

        result = verifier.verify_finding(project_id, finding, source_root)
        db.update(
            "vulnerabilities",
            {
                "verify_status": result.verify_status,
                "reproduce_steps_text": result.reproduce_steps,
                "verify_code_text": result.verify_code,
            },
            "id = ?",
            (vuln["id"],),
        )

        if result.verify_status == "verified":
            verified_count += 1
            await emit_log(
                project_id,
                "INFO",
                f"{vuln['vuln_code']} {vuln['vuln_title']} 验证通过：{result.note}",
                stage_id,
                verifier_id,
            )
        else:
            failed_count += 1
            await emit_log(
                project_id,
                "WARN",
                f"{vuln['vuln_code']} {vuln['vuln_title']} 未通过验证：{result.note}",
                stage_id,
                verifier_id,
            )

        sampler.add_tokens(
            estimate_tokens(result.reproduce_steps + result.verify_code + result.note)
        )
        await _pause(project_id, deadline, 0.15)

    verify_summary = (
        f"验证完成：共复核 {len(vulnerabilities)} 条，通过 {verified_count} 条，"
        f"判定为误报或证据失效 {failed_count} 条"
    )
    _finish_worker(verifier_id, "success", verify_summary)
    await emit_worker_status(project_id, verifier_id, "vuln_verifier", "success")
    await emit_log(project_id, "INFO", verify_summary, stage_id, verifier_id)
    await emit_chat(project_id, "vuln_verifier", "result", verify_summary)

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 2：代码分析（攻击路径编排） ----
    path_worker_id = _create_worker(
        project_id, stage_id, "code_analyzer", "基于已验证漏洞编排攻击路径与利用顺序"
    )
    await emit_worker_status(project_id, path_worker_id, "code_analyzer", "running")
    _check_stop(project_id, deadline)
    await emit_chat(
        project_id, "code_analyzer", "thinking", "正在把已验证漏洞按杀伤链顺序编排为攻击路径……"
    )

    verified_vulns = db.query_all(
        "SELECT * FROM vulnerabilities WHERE project_id = ? AND verify_status = 'verified' "
        "ORDER BY id",
        (project_id,),
    )
    drafts = path_builder.build_attack_paths(verified_vulns)

    for draft in drafts:
        path_id = db.insert(
            "attack_paths",
            {
                "project_id": project_id,
                "path_code": draft.path_code,
                "path_title": draft.path_title,
                "path_summary": draft.path_summary,
                "final_impact_text": draft.final_impact_text,
                "created_at": now_str(),
            },
        )
        for order, (vuln_id, step_text) in enumerate(draft.steps, start=1):
            db.insert(
                "attack_path_items",
                {
                    "path_id": path_id,
                    "vuln_id": vuln_id,
                    "step_order": order,
                    "step_text": step_text,
                },
            )
        await emit_log(
            project_id,
            "INFO",
            f"已编排攻击路径 {draft.path_code}：{draft.path_title}（{len(draft.steps)} 步）",
            stage_id,
            path_worker_id,
        )

    path_summary = f"攻击路径编排完成，共生成 {len(drafts)} 条可利用链路"
    _finish_worker(path_worker_id, "success", path_summary)
    await emit_worker_status(project_id, path_worker_id, "code_analyzer", "success")
    await emit_chat(project_id, "code_analyzer", "result", path_summary)

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 3：运维辅助 ----
    ops_id = _create_worker(project_id, stage_id, "ops_helper", "记录漏洞验证阶段的资源消耗")
    await emit_worker_status(project_id, ops_id, "ops_helper", "running")
    _check_stop(project_id, deadline)
    resource = await emit_resource(project_id, sampler)
    ops_summary = (
        f"验证阶段资源记录：CPU {resource['cpu_usage']}%，"
        f"内存 {resource['memory_usage']} MB，累计 token 估算 {resource['token_count']}"
    )
    _finish_worker(ops_id, "success", ops_summary)
    await emit_worker_status(project_id, ops_id, "ops_helper", "success")
    await emit_log(project_id, "INFO", ops_summary, stage_id, ops_id)

    _finish_stage(stage_id, "success")
    await emit_stage_status(project_id, stage_name, "success", stage_id)
    await emit_log(project_id, "INFO", f"阶段「{STAGE_LABELS[stage_name]}」执行完成", stage_id)
    return stage_id


# ---------------------------------------------------------------------------
# 阶段 4：报告生成
# ---------------------------------------------------------------------------
async def _stage_report_generate(
    project_id: int, deadline: float, sampler: metrics.ResourceSampler
) -> int:
    stage_name = "report_generate"
    stage_id = _create_stage(project_id, stage_name)
    await emit_stage_status(project_id, stage_name, "running", stage_id)
    await emit_log(
        project_id, "INFO", f"进入阶段「{STAGE_LABELS[stage_name]}」", stage_id
    )

    # ---- 角色 1：通用处理（结果汇总统计） ----
    general_id = _create_worker(
        project_id, stage_id, "general_processor", "汇总漏洞、攻击路径与阶段执行数据"
    )
    await emit_worker_status(project_id, general_id, "general_processor", "running")
    _check_stop(project_id, deadline)

    vuln_total = db.count("vulnerabilities", "project_id = ?", (project_id,))
    verified_total = db.count(
        "vulnerabilities", "project_id = ? AND verify_status = 'verified'", (project_id,)
    )
    path_total = db.count("attack_paths", "project_id = ?", (project_id,))
    worker_total = db.count("worker_tasks", "project_id = ?", (project_id,))
    log_total = db.count("runtime_logs", "project_id = ?", (project_id,))

    general_summary = (
        f"汇总完成：漏洞 {vuln_total} 条（已验证 {verified_total}），"
        f"攻击路径 {path_total} 条，角色任务 {worker_total} 条，日志 {log_total} 条"
    )
    _finish_worker(general_id, "success", general_summary)
    await emit_worker_status(project_id, general_id, "general_processor", "success")
    await emit_log(project_id, "INFO", general_summary, stage_id, general_id)

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 2：报告整理（生成报告正文） ----
    writer_id = _create_worker(
        project_id, stage_id, "report_writer",
        "生成包含项目概述、执行过程、漏洞汇总、攻击路径、风险结论与修复建议的最终报告",
    )
    await emit_worker_status(project_id, writer_id, "report_writer", "running")
    _check_stop(project_id, deadline)
    await emit_chat(
        project_id, "report_writer", "thinking", "正在汇总各阶段结果并生成评估报告……"
    )

    report = reporter.generate_report(project_id)
    sampler.add_tokens(estimate_tokens(report["report_markdown"]))

    writer_summary = (
        f"报告生成完成，共 {len(report['report_markdown'])} 字符，"
        f"已保存至 {report['report_file_path']}"
    )
    _finish_worker(writer_id, "success", writer_summary)
    await emit_worker_status(project_id, writer_id, "report_writer", "success")
    await emit_log(project_id, "INFO", writer_summary, stage_id, writer_id)
    await emit_chat(
        project_id,
        "report_writer",
        "result",
        f"安全评估报告已生成（报告编号 {report['report_id']}），可在报告页预览与下载。",
    )

    await manager.broadcast(
        project_id,
        "report_ready",
        {"project_id": project_id, "report_id": report["report_id"]},
    )

    await _pause(project_id, deadline, ROLE_DELAY)

    # ---- 角色 3：运维辅助（收尾与资源归档） ----
    ops_id = _create_worker(
        project_id, stage_id, "ops_helper", "归档资源消耗数据，销毁隔离环境"
    )
    await emit_worker_status(project_id, ops_id, "ops_helper", "running")
    _check_stop(project_id, deadline)

    resource = await emit_resource(project_id, sampler)
    sandbox.destroy_sandbox(project_id)

    ops_summary = (
        f"资源归档完成：峰值内存 {sampler.peak_memory_mb} MB，"
        f"累计 token 估算 {resource['token_count']}；隔离环境已销毁，临时目录已清理"
    )
    _finish_worker(ops_id, "success", ops_summary)
    await emit_worker_status(project_id, ops_id, "ops_helper", "success")
    await emit_log(project_id, "INFO", ops_summary, stage_id, ops_id)

    _finish_stage(stage_id, "success")
    await emit_stage_status(project_id, stage_name, "success", stage_id)
    await emit_log(project_id, "INFO", f"阶段「{STAGE_LABELS[stage_name]}」执行完成", stage_id)
    return stage_id
