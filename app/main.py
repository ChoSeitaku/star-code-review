"""FastAPI 应用入口。

- 启动时自动执行 scripts/init_db.sql 建库建表
- 注册认证、项目、结果查询三组路由
- 托管前端构建产物（frontend/dist），实现单端口访问
"""

from __future__ import annotations

import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import config, db
from .engine.scheduler import registry
from .routers import projects, results, system

API_DESCRIPTION = """
面向源码项目的自动化安全评估系统后端接口。

**执行链路**：项目接入 → 隔离环境准备 → 源码静态分析 → 漏洞验证 → 攻击路径编排 → 报告生成

所有评估均在只读隔离环境内完成，验证过程不产生真实破坏。
"""


@asynccontextmanager
async def lifespan(_: FastAPI):
    """启动时建库建表并写入默认配置；退出时停止所有后台评估任务。"""
    db.init_db()
    config.ensure_default_configs()
    print("[star-review] 数据库初始化完成")
    print(f"[star-review] 数据目录: {config.DATA_DIR}")
    print("[star-review] 服务已启动，接口文档: http://127.0.0.1:8002/api/docs")

    yield

    for project_id in registry.active_projects():
        registry.request_stop(project_id)
        task = registry.get_task(project_id)
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(Exception):
                await task


app = FastAPI(
    title="自动化安全评估系统",
    description=API_DESCRIPTION,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router)
app.include_router(projects.router)
app.include_router(results.router)


# ---------------------------------------------------------------------------
# 健康检查
# ---------------------------------------------------------------------------
@app.get("/api/health", tags=["系统与认证"], summary="健康检查")
def health():
    return {
        "status": "ok",
        "service": "star-review",
        "version": app.version,
        "database": str(config.DB_PATH),
    }


@app.get("/api/rules", tags=["系统与认证"], summary="查询内置规则库清单")
def list_rules():
    from .engine import rules

    return rules.rule_doc()


# ---------------------------------------------------------------------------
# 前端静态资源托管（单端口部署）
# ---------------------------------------------------------------------------
_DIST_DIR = config.FRONTEND_DIST
_ASSETS_DIR = _DIST_DIR / "assets"

if _ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")


@app.get("/", include_in_schema=False)
def serve_index():
    index_file = _DIST_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))
    return JSONResponse(
        status_code=200,
        content={
            "service": "自动化安全评估系统",
            "message": "后端服务运行中，但尚未构建前端。请执行：cd frontend && npm install && npm run build",
            "api_docs": "/api/docs",
        },
    )


@app.get("/{full_path:path}", include_in_schema=False)
def serve_spa(full_path: str):
    """SPA 前端路由回退：非 /api 前缀的路径统一交给 index.html。"""
    if full_path.startswith("api/"):
        return JSONResponse(status_code=404, content={"detail": "接口不存在"})

    candidate = _DIST_DIR / full_path
    if candidate.is_file():
        return FileResponse(str(candidate))

    index_file = _DIST_DIR / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))

    return JSONResponse(
        status_code=404,
        content={"detail": "前端未构建，请先运行 cd frontend && npm run build"},
    )


def run() -> None:
    """命令行入口：python -m app.main"""
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8002,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    run()
