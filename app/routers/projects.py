"""项目模块路由（§1.4.7 / §1.4.10）。"""

from __future__ import annotations

import shutil

from fastapi import APIRouter, Depends, HTTPException, Query, status

from .. import auth, config, db
from ..engine import sandbox, scheduler
from ..schemas import ProjectCreateRequest
from ..utils import now_str
from ..ws import manager

router = APIRouter(prefix="/api/projects", tags=["项目管理"])


# ---------------------------------------------------------------------------
# 公共辅助
# ---------------------------------------------------------------------------
def _get_project_or_404(project_id: int) -> dict:
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"项目不存在：{project_id}"
        )
    return project


def _decorate(project: dict, with_counts: bool = False) -> dict:
    """补全项目展示字段（最近启动/完成时间、各类数量）。"""
    project_id = project["id"]

    last_started = db.query_scalar(
        "SELECT MAX(started_at) FROM runtime_stages WHERE project_id = ?", (project_id,)
    )
    last_finished = db.query_scalar(
        "SELECT MAX(finished_at) FROM runtime_stages WHERE project_id = ?", (project_id,)
    )
    sandbox_row = db.query_one(
        "SELECT sandbox_code, isolation_type, sandbox_status FROM sandboxes "
        "WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,),
    )

    project["last_started_at"] = last_started
    project["last_finished_at"] = last_finished
    project["sandbox_code"] = sandbox_row["sandbox_code"] if sandbox_row else None
    project["isolation_type"] = (
        sandbox_row["isolation_type"] if sandbox_row else config.get_config("isolation_type")
    )
    project["sandbox_status"] = sandbox_row["sandbox_status"] if sandbox_row else None

    if with_counts:
        vuln_total = db.count("vulnerabilities", "project_id = ?", (project_id,))
        project["vulnerability_count"] = vuln_total
        project["verified_count"] = db.count(
            "vulnerabilities",
            "project_id = ? AND verify_status = 'verified'",
            (project_id,),
        )
        project["high_risk_count"] = db.count(
            "vulnerabilities",
            "project_id = ? AND risk_level = 'high'",
            (project_id,),
        )
        project["attack_path_count"] = db.count("attack_paths", "project_id = ?", (project_id,))
        project["worker_task_count"] = db.count("worker_tasks", "project_id = ?", (project_id,))
        project["log_count"] = db.count("runtime_logs", "project_id = ?", (project_id,))
        report = db.query_one(
            "SELECT id, created_at, report_file_path FROM reports "
            "WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        )
        project["report_id"] = report["id"] if report else None
        project["report_created_at"] = report["created_at"] if report else None
        project["report_status"] = "ready" if report else "pending"
        project["report_file_path"] = report["report_file_path"] if report else None

    return project


# ---------------------------------------------------------------------------
# POST /api/projects —— 创建项目
# ---------------------------------------------------------------------------
@router.post("", summary="创建评估项目", status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreateRequest, user: dict = Depends(auth.get_current_user)
):
    # 源码可接入性预检：本地目录必须存在
    if payload.source_type == "local":
        from pathlib import Path

        candidate = Path(payload.source_path)
        if not candidate.is_absolute():
            candidate = (config.BASE_DIR / candidate).resolve()
        if not candidate.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"源码路径不存在：{candidate}",
            )
        if not candidate.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"源码路径不是目录：{candidate}",
            )

    project_id = db.insert(
        "projects",
        {
            "project_name": payload.project_name,
            "source_type": payload.source_type,
            "source_path": payload.source_path,
            "task_content": payload.task_content,
            "project_status": "created",
            "created_by": user["id"],
            "created_at": now_str(),
            "updated_at": now_str(),
        },
    )

    # 隔离环境类型作为项目级配置记录在系统配置中（演示环境为全局配置）
    if payload.isolation_type:
        config.set_config("isolation_type", payload.isolation_type)

    project = _get_project_or_404(project_id)
    return _decorate(project, with_counts=True)


# ---------------------------------------------------------------------------
# GET /api/projects —— 项目列表
# ---------------------------------------------------------------------------
@router.get("", summary="查询项目列表")
def list_projects(
    project_status: str | None = Query(default=None, description="按项目状态筛选"),
    user: dict = Depends(auth.get_current_user),
):
    sql = "SELECT * FROM projects"
    params: list = []
    if project_status:
        sql += " WHERE project_status = ?"
        params.append(project_status)
    sql += " ORDER BY id DESC"

    rows = db.query_all(sql, tuple(params))
    return [_decorate(row) for row in rows]


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id} —— 项目详情
# ---------------------------------------------------------------------------
@router.get("/{project_id}", summary="查询项目详情")
def get_project(project_id: int, user: dict = Depends(auth.get_current_user)):
    return _decorate(_get_project_or_404(project_id), with_counts=True)


# ---------------------------------------------------------------------------
# POST /api/projects/{project_id}/start —— 启动评估任务
# ---------------------------------------------------------------------------
@router.post("/{project_id}/start", summary="启动评估任务")
async def start_project(project_id: int, user: dict = Depends(auth.get_current_user)):
    project = _get_project_or_404(project_id)
    if project["project_status"] == "running":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="该项目正在执行中"
        )

    try:
        result = await scheduler.start_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "message": "评估任务已启动，正在准备隔离环境",
        **result,
        "project": _decorate(_get_project_or_404(project_id), with_counts=True),
    }


# ---------------------------------------------------------------------------
# POST /api/projects/{project_id}/stop —— 停止评估任务
# ---------------------------------------------------------------------------
@router.post("/{project_id}/stop", summary="停止评估任务")
async def stop_project(project_id: int, user: dict = Depends(auth.get_current_user)):
    _get_project_or_404(project_id)
    try:
        result = await scheduler.stop_project(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return {
        "message": "评估任务已停止，已保存的数据继续保留",
        **result,
        "project": _decorate(_get_project_or_404(project_id), with_counts=True),
    }


# ---------------------------------------------------------------------------
# DELETE /api/projects/{project_id} —— 删除项目
# ---------------------------------------------------------------------------
@router.delete("/{project_id}", summary="删除项目及其全部关联数据")
async def delete_project(project_id: int, user: dict = Depends(auth.get_current_user)):
    project = _get_project_or_404(project_id)

    # 1. 若任务在运行，先停止
    scheduler.registry.request_stop(project_id)
    task = scheduler.registry.get_task(project_id)
    if task is not None and not task.done():
        task.cancel()

    # 2. 销毁隔离环境与临时目录
    sandbox.destroy_sandbox(project_id)

    # 3. 删除关联记录（§1.4.4：级联删除漏洞、攻击路径、聊天消息、日志、资源记录）
    deleted_counts: dict[str, int] = {}
    for table in (
        "attack_path_items",
        "runtime_logs",
        "chat_messages",
        "resource_usages",
        "reports",
        "worker_tasks",
        "runtime_stages",
        "vulnerabilities",
        "sandboxes",
    ):
        if table == "attack_path_items":
            deleted_counts[table] = db.execute(
                "DELETE FROM attack_path_items WHERE path_id IN "
                "(SELECT id FROM attack_paths WHERE project_id = ?)",
                (project_id,),
            )
        else:
            deleted_counts[table] = db.execute(
                f"DELETE FROM {table} WHERE project_id = ?", (project_id,)
            )

    deleted_counts["attack_paths"] = db.execute(
        "DELETE FROM attack_paths WHERE project_id = ?", (project_id,)
    )
    db.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    # 4. 删除文件目录（§1.4.9：日志目录、报告目录、临时目录）
    removed_dirs: list[str] = []
    for directory in (
        config.project_log_dir(project_id),
        config.project_report_dir(project_id),
        config.project_workspace_dir(project_id),
    ):
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
            removed_dirs.append(str(directory))

    # 5. 通知订阅者
    await manager.broadcast_project_deleted(project_id)
    scheduler.registry.unregister(project_id)
    scheduler.registry.clear(project_id)

    return {
        "message": "项目已删除，关联记录与文件目录已清理",
        "project_id": project_id,
        "project_name": project["project_name"],
        "deleted_records": deleted_counts,
        "removed_directories": removed_dirs,
    }


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/sandbox —— 隔离环境信息
# ---------------------------------------------------------------------------
@router.get("/{project_id}/sandbox", summary="查询项目隔离环境信息")
def get_sandbox(project_id: int, user: dict = Depends(auth.get_current_user)):
    _get_project_or_404(project_id)
    row = sandbox.get_sandbox(project_id)
    if row is None:
        return {
            "project_id": project_id,
            "sandbox_code": None,
            "sandbox_status": "not_created",
            "message": "尚未创建隔离环境，启动评估任务后自动创建",
        }
    return row
