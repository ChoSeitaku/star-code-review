"""认证模块与系统配置模块路由（§1.4.7 / §1.4.10）。"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status

from .. import auth, config, db, security
from ..schemas import ConfigUpdateRequest, LoginRequest, SystemInitRequest
from ..utils import now_str

router = APIRouter(prefix="/api/system", tags=["系统与认证"])


# ---------------------------------------------------------------------------
# POST /api/system/init —— 初始化管理员账户
# ---------------------------------------------------------------------------
@router.post("/init", summary="初始化系统管理员账户")
def system_init(payload: SystemInitRequest = Body(default=SystemInitRequest())):
    """初始化管理员账户（幂等：已初始化时返回现有账户信息，不覆盖密码）。"""
    config.ensure_default_configs()

    existing_admin = db.query_one("SELECT * FROM users WHERE role = 'admin' LIMIT 1")
    if existing_admin:
        return {
            "initialized": False,
            "message": "系统已初始化，管理员账户已存在",
            "username": existing_admin["username"],
            "created_at": existing_admin["created_at"],
        }

    user_id = db.insert(
        "users",
        {
            "username": payload.username,
            "password_hash": security.hash_password(payload.password),
            "role": "admin",
            "status": "active",
            "created_at": now_str(),
        },
    )
    return {
        "initialized": True,
        "message": "系统初始化完成，管理员账户已创建",
        "user_id": user_id,
        "username": payload.username,
    }


# ---------------------------------------------------------------------------
# POST /api/system/login —— 登录
# ---------------------------------------------------------------------------
@router.post("/login", summary="用户登录")
def login(payload: LoginRequest):
    user = db.query_one("SELECT * FROM users WHERE username = ?", (payload.username,))
    if user is None or not security.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )
    if user["status"] != "active":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="该账户已被停用"
        )

    auth.purge_expired_sessions()
    token = auth.create_session(user["id"])
    return {
        "token": token,
        "username": user["username"],
        "role": user["role"],
        "expires_in": security.TOKEN_TTL_SECONDS,
    }


# ---------------------------------------------------------------------------
# POST /api/system/logout —— 退出登录
# ---------------------------------------------------------------------------
@router.post("/logout", summary="退出登录")
def logout(
    user: dict = Depends(auth.get_current_user),
    authorization: str | None = Header(default=None),
):
    if authorization and authorization.lower().startswith("bearer "):
        auth.destroy_session(authorization[7:].strip())
    return {"message": "已退出登录"}


# ---------------------------------------------------------------------------
# GET /api/system/me —— 当前登录用户
# ---------------------------------------------------------------------------
@router.get("/me", summary="获取当前登录用户信息")
def current_user(user: dict = Depends(auth.get_current_user)):
    return user


# ---------------------------------------------------------------------------
# GET /api/system/config —— 读取系统配置
# ---------------------------------------------------------------------------
@router.get("/config", summary="查询系统配置")
def read_config(user: dict = Depends(auth.get_current_user)):
    return {"items": config.get_all_configs()}


# ---------------------------------------------------------------------------
# PUT /api/system/config —— 更新系统配置
# ---------------------------------------------------------------------------
@router.put("/config", summary="更新系统配置")
def update_config(
    payload: ConfigUpdateRequest,
    user: dict = Depends(auth.require_admin),
):
    updated: list[dict] = []
    for item in payload.items:
        config.set_config(item.config_key, item.config_value)
        updated.append(
            {"config_key": item.config_key, "config_value": item.config_value}
        )
    return {"message": f"已更新 {len(updated)} 项配置", "items": updated}


# ---------------------------------------------------------------------------
# GET /api/system/overview —— 管理员总览（资源消耗与系统日志）
# ---------------------------------------------------------------------------
@router.get("/overview", summary="系统总览：资源消耗与运行统计")
def overview(user: dict = Depends(auth.get_current_user)):
    stats = {
        "project_total": db.count("projects"),
        "project_running": db.count("projects", "project_status = 'running'"),
        "project_completed": db.count("projects", "project_status = 'completed'"),
        "vulnerability_total": db.count("vulnerabilities"),
        "attack_path_total": db.count("attack_paths"),
        "worker_task_total": db.count("worker_tasks"),
        "log_total": db.count("runtime_logs"),
        "report_total": db.count("reports"),
    }

    active_sandboxes = db.query_all(
        "SELECT sandbox_code, project_id, isolation_type, sandbox_status, created_at "
        "FROM sandboxes WHERE sandbox_status != 'destroyed' ORDER BY id DESC LIMIT 20"
    )

    recent_logs = db.query_all(
        "SELECT id, project_id, log_level, log_content, created_at "
        "FROM runtime_logs ORDER BY id DESC LIMIT 30"
    )

    resource_summary = db.query_one(
        "SELECT ROUND(AVG(cpu_usage), 2) AS avg_cpu, "
        "       ROUND(MAX(memory_usage), 2) AS peak_memory, "
        "       SUM(token_count) AS total_tokens, "
        "       COUNT(*) AS sample_count "
        "FROM resource_usages"
    ) or {}

    return {
        "stats": stats,
        "active_sandboxes": active_sandboxes,
        "recent_logs": recent_logs,
        "resource_summary": resource_summary,
    }
