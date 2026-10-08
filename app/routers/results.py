"""结果查询路由：阶段、角色、漏洞、攻击路径、报告、日志、资源、实时流（§1.4.10）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status

from .. import auth, db
from ..engine import sandbox, scheduler
from ..utils import elapsed_seconds
from ..ws import manager

router = APIRouter(prefix="/api/projects", tags=["结果查询"])


def _ensure_project(project_id: int) -> dict:
    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"项目不存在：{project_id}"
        )
    return project


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/stages —— 阶段状态
# ---------------------------------------------------------------------------
@router.get("/{project_id}/stages", summary="查询阶段状态")
def get_stages(project_id: int, user: dict = Depends(auth.get_current_user)):
    _ensure_project(project_id)
    rows = db.query_all(
        "SELECT * FROM runtime_stages WHERE project_id = ? ORDER BY id", (project_id,)
    )
    for row in rows:
        row["duration_seconds"] = elapsed_seconds(row.get("started_at"), row.get("finished_at"))
        row["stage_label"] = scheduler.STAGE_LABELS.get(row["stage_name"], row["stage_name"])
    return rows


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/workers —— 角色执行状态
# ---------------------------------------------------------------------------
@router.get("/{project_id}/workers", summary="查询角色执行状态")
def get_workers(
    project_id: int,
    stage_id: int | None = Query(default=None, description="按阶段筛选"),
    user: dict = Depends(auth.get_current_user),
):
    _ensure_project(project_id)
    sql = "SELECT * FROM worker_tasks WHERE project_id = ?"
    params: list = [project_id]
    if stage_id is not None:
        sql += " AND stage_id = ?"
        params.append(stage_id)
    sql += " ORDER BY id"

    rows = db.query_all(sql, tuple(params))
    stage_names = {
        row["id"]: row["stage_name"]
        for row in db.query_all(
            "SELECT id, stage_name FROM runtime_stages WHERE project_id = ?", (project_id,)
        )
    }
    for row in rows:
        row["duration_seconds"] = elapsed_seconds(row.get("started_at"), row.get("finished_at"))
        row["role_label"] = scheduler.ROLE_LABELS.get(row["worker_role"], row["worker_role"])
        row["stage_name"] = stage_names.get(row.get("stage_id"))
    return rows


@router.get("/{project_id}/roles", summary="查询六类执行角色的当前状态汇总")
def get_role_states(project_id: int, user: dict = Depends(auth.get_current_user)):
    """按角色汇总最新状态，供实时监控页的角色卡片展示。"""
    _ensure_project(project_id)
    states: dict[str, dict] = {}
    for role, label in scheduler.ROLE_LABELS.items():
        states[role] = {
            "worker_role": role,
            "role_label": label,
            "task_status": "idle",
            "worker_task_id": None,
            "result_summary": None,
            "started_at": None,
            "finished_at": None,
        }

    rows = db.query_all(
        "SELECT * FROM worker_tasks WHERE project_id = ? ORDER BY id", (project_id,)
    )
    for row in rows:
        role = row["worker_role"]
        if role in states:
            states[role].update(
                {
                    "task_status": row["task_status"],
                    "worker_task_id": row["id"],
                    "result_summary": row["result_summary"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                }
            )
    return list(states.values())


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/vulnerabilities —— 漏洞列表
# ---------------------------------------------------------------------------
@router.get("/{project_id}/vulnerabilities", summary="查询漏洞列表")
def get_vulnerabilities(
    project_id: int,
    risk_level: str | None = Query(default=None, description="按风险等级筛选"),
    verify_status: str | None = Query(default=None, description="按验证状态筛选"),
    user: dict = Depends(auth.get_current_user),
):
    _ensure_project(project_id)
    sql = "SELECT * FROM vulnerabilities WHERE project_id = ?"
    params: list = [project_id]
    if risk_level:
        sql += " AND risk_level = ?"
        params.append(risk_level)
    if verify_status:
        sql += " AND verify_status = ?"
        params.append(verify_status)
    sql += " ORDER BY CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id"

    rows = db.query_all(sql, tuple(params))
    return [_vuln_payload(row) for row in rows]


def _vuln_payload(row: dict) -> dict:
    """按 §1.4.12 输出格式整理漏洞字段。"""
    file_path = row.get("file_path") or ""
    line_no = row.get("line_no")
    location = f"{file_path}:{line_no}" if line_no else file_path

    return {
        # 列表必需字段
        "vuln_id": row["id"],
        "vuln_code": row["vuln_code"],
        "vuln_title": row["vuln_title"],
        "risk_level": row["risk_level"],
        "file_path": location,
        "verify_status": row["verify_status"],
        # 详情扩展字段
        "project_id": row["project_id"],
        "rule_key": row.get("rule_key"),
        "category": row.get("category"),
        "condition_text": row.get("condition_text"),
        "impact_text": row.get("impact_text"),
        "evidence_text": row.get("evidence_text"),
        "reproduce_steps_text": row.get("reproduce_steps_text"),
        "verify_code_text": row.get("verify_code_text"),
        "remediation_text": row.get("remediation_text"),
        "created_at": row["created_at"],
    }


@router.get("/{project_id}/vulnerabilities/{vuln_id}", summary="查询漏洞详情")
def get_vulnerability(
    project_id: int, vuln_id: int, user: dict = Depends(auth.get_current_user)
):
    _ensure_project(project_id)
    row = db.query_one(
        "SELECT * FROM vulnerabilities WHERE id = ? AND project_id = ?",
        (vuln_id, project_id),
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"漏洞不存在：{vuln_id}"
        )
    return _vuln_payload(row)


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/attack-paths —— 攻击路径列表
# ---------------------------------------------------------------------------
@router.get("/{project_id}/attack-paths", summary="查询攻击路径列表")
def get_attack_paths(project_id: int, user: dict = Depends(auth.get_current_user)):
    _ensure_project(project_id)
    paths = db.query_all(
        "SELECT * FROM attack_paths WHERE project_id = ? ORDER BY id", (project_id,)
    )

    vuln_map = {
        row["id"]: row
        for row in db.query_all(
            "SELECT id, vuln_code, vuln_title, risk_level, file_path, verify_status "
            "FROM vulnerabilities WHERE project_id = ?",
            (project_id,),
        )
    }

    for path in paths:
        items = db.query_all(
            "SELECT * FROM attack_path_items WHERE path_id = ? ORDER BY step_order",
            (path["id"],),
        )
        steps = []
        for item in items:
            vuln = vuln_map.get(item["vuln_id"], {})
            steps.append(
                {
                    "step_order": item["step_order"],
                    "vuln_id": item["vuln_id"],
                    "vuln_code": vuln.get("vuln_code"),
                    "vuln_title": vuln.get("vuln_title"),
                    "risk_level": vuln.get("risk_level"),
                    "file_path": vuln.get("file_path"),
                    "verify_status": vuln.get("verify_status"),
                    "step_text": item.get("step_text"),
                }
            )

        path["items"] = steps
        path["step_count"] = len(steps)
        path["related_vulns"] = [
            {"vuln_id": step["vuln_id"], "vuln_code": step["vuln_code"],
             "vuln_title": step["vuln_title"]}
            for step in steps
        ]

    return paths


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/report —— 最终报告
# ---------------------------------------------------------------------------
@router.get("/{project_id}/report", summary="查询最终报告")
def get_report(project_id: int, user: dict = Depends(auth.get_current_user)):
    _ensure_project(project_id)
    row = db.query_one(
        "SELECT * FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,),
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="报告尚未生成，请先启动评估任务并等待报告生成阶段完成",
        )
    return row


@router.get("/{project_id}/report/download", summary="下载报告（HTML 文件）")
def download_report(project_id: int, user: dict = Depends(auth.get_current_user)):
    from fastapi.responses import HTMLResponse

    _ensure_project(project_id)
    row = db.query_one(
        "SELECT * FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,),
    )
    if row is None or not row.get("report_html"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="报告尚未生成"
        )

    project = db.query_one("SELECT project_name FROM projects WHERE id = ?", (project_id,))
    filename = f"report_{project_id}.html"
    return HTMLResponse(
        content=row["report_html"],
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{filename}\"; "
                f"filename*=UTF-8''{_quote(project['project_name'])}_report.html"
            )
        },
    )


def _quote(text: str) -> str:
    from urllib.parse import quote

    return quote(text, safe="")


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/logs —— 运行日志
# ---------------------------------------------------------------------------
@router.get("/{project_id}/logs", summary="查询运行日志")
def get_logs(
    project_id: int,
    log_level: str | None = Query(default=None, description="按日志级别筛选"),
    limit: int = Query(default=500, ge=1, le=5000),
    since_id: int = Query(default=0, ge=0, description="只返回 id 大于该值的日志"),
    user: dict = Depends(auth.get_current_user),
):
    _ensure_project(project_id)
    sql = "SELECT * FROM runtime_logs WHERE project_id = ? AND id > ?"
    params: list = [project_id, since_id]
    if log_level:
        sql += " AND log_level = ?"
        params.append(log_level)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = db.query_all(sql, tuple(params))
    rows.reverse()
    return rows


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/resources —— 资源消耗
# ---------------------------------------------------------------------------
@router.get("/{project_id}/resources", summary="查询资源消耗")
def get_resources(
    project_id: int,
    limit: int = Query(default=300, ge=1, le=5000),
    user: dict = Depends(auth.get_current_user),
):
    _ensure_project(project_id)
    rows = db.query_all(
        "SELECT * FROM resource_usages WHERE project_id = ? ORDER BY id DESC LIMIT ?",
        (project_id, limit),
    )
    rows.reverse()
    return rows


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/messages —— 聊天消息
# ---------------------------------------------------------------------------
@router.get("/{project_id}/messages", summary="查询角色聊天消息")
def get_messages(
    project_id: int,
    limit: int = Query(default=300, ge=1, le=2000),
    user: dict = Depends(auth.get_current_user),
):
    _ensure_project(project_id)
    rows = db.query_all(
        "SELECT * FROM chat_messages WHERE project_id = ? ORDER BY id DESC LIMIT ?",
        (project_id, limit),
    )
    rows.reverse()
    for row in rows:
        row["role_label"] = scheduler.ROLE_LABELS.get(row["worker_role"], row["worker_role"])
    return rows


# ---------------------------------------------------------------------------
# GET /api/projects/{project_id}/snapshot —— 监控页首屏快照
# ---------------------------------------------------------------------------
@router.get("/{project_id}/snapshot", summary="实时监控页首屏数据快照")
def get_snapshot(project_id: int, user: dict = Depends(auth.get_current_user)):
    """一次性返回监控页所需的全部初始数据，避免首屏发起多次请求。"""
    project = _ensure_project(project_id)
    sandbox_row = sandbox.get_sandbox(project_id)

    return {
        "project": {
            "id": project["id"],
            "project_name": project["project_name"],
            "project_status": project["project_status"],
            "source_type": project["source_type"],
            "source_path": project["source_path"],
            "task_content": project.get("task_content"),
        },
        "sandbox": sandbox_row,
        "current_stage": db.query_one(
            "SELECT stage_name, stage_status, started_at FROM runtime_stages "
            "WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        ),
        "stages": get_stages(project_id, user),
        "roles": get_role_states(project_id, user),
        "logs": get_logs(project_id, None, 200, 0, user),
        "messages": get_messages(project_id, 100, user),
        "resources": get_resources(project_id, 120, user),
        "vulnerability_count": db.count("vulnerabilities", "project_id = ?", (project_id,)),
        "attack_path_count": db.count("attack_paths", "project_id = ?", (project_id,)),
        "report_id": db.query_scalar(
            "SELECT id FROM reports WHERE project_id = ? ORDER BY id DESC LIMIT 1",
            (project_id,),
        ),
    }


# ---------------------------------------------------------------------------
# WS /api/projects/{project_id}/stream —— 实时订阅
# ---------------------------------------------------------------------------
@router.websocket("/{project_id}/stream")
async def project_stream(websocket: WebSocket, project_id: int):
    """实时推送项目状态、阶段、角色、日志、消息、资源与漏洞事件。

    鉴权：通过查询参数 `?token=<登录令牌>` 传递（浏览器 WebSocket 无法自定义请求头）。
    """
    token = websocket.query_params.get("token")
    user = auth.resolve_token(token)
    if user is None:
        # 必须先 accept 才能下发应用层关闭码；直接 close 会被降级为 HTTP 403，
        # 前端也就无法区分「登录态失效」与普通网络错误。
        await websocket.accept()
        await websocket.close(code=4401, reason="未登录或登录态已过期")
        return

    if db.query_one("SELECT id FROM projects WHERE id = ?", (project_id,)) is None:
        await websocket.accept()
        await websocket.close(code=4404, reason="项目不存在")
        return

    await manager.connect(project_id, websocket)
    try:
        await websocket.send_json(
            {
                "type": "connected",
                "data": {
                    "project_id": project_id,
                    "message": "实时通道已建立",
                    "subscribers": manager.connection_count(project_id),
                },
                "ts": None,
            }
        )
        while True:
            # 客户端心跳；同时保持连接存活
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await manager.disconnect(project_id, websocket)
