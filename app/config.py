"""全局配置：目录布局、运行参数、系统配置项读写。

系统配置（§1.4.3 系统配置页）持久化在 system_configs 表，此处提供默认值兜底。
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# 目录布局（§1.4.9 隔离环境与文件存储要求）
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "star_review.db"
SCHEMA_PATH = BASE_DIR / "scripts" / "init_db.sql"

RUNTIME_LOG_DIR = BASE_DIR / "runtime_logs"   # 日志文件 runtime_logs/{project_id}/
REPORT_DIR = BASE_DIR / "reports"             # 报告文件 reports/{project_id}/
WORKSPACE_DIR = BASE_DIR / "workspace"        # 临时执行文件 workspace/{project_id}/

FRONTEND_DIST = BASE_DIR / "frontend" / "dist"
EXAMPLES_DIR = BASE_DIR / "examples"

# 每次任务启动时清理这些目录下超过保留天数的项目目录
MANAGED_DIRS = (RUNTIME_LOG_DIR, REPORT_DIR, WORKSPACE_DIR)


def project_log_dir(project_id: int) -> Path:
    return RUNTIME_LOG_DIR / str(project_id)


def project_report_dir(project_id: int) -> Path:
    return REPORT_DIR / str(project_id)


def project_workspace_dir(project_id: int) -> Path:
    return WORKSPACE_DIR / str(project_id)


# ---------------------------------------------------------------------------
# 系统配置默认值（§1.4.3 系统配置页展示：隔离环境配置、默认超时时间、并发数、保留天数）
# ---------------------------------------------------------------------------
DEFAULT_CONFIGS: dict[str, tuple[str, str]] = {
    "isolation_type": (
        "simulated",
        "隔离环境类型：simulated（模拟隔离）/ docker（容器隔离）",
    ),
    "isolation_readonly_mount": (
        "true",
        "源码目录是否以只读形式挂载到隔离环境",
    ),
    "isolation_network": (
        "none",
        "隔离环境网络策略：none（禁网）/ limited（受限）/ full（放开）",
    ),
    "default_timeout_seconds": (
        "600",
        "单个评估任务的默认超时时间（秒）",
    ),
    "max_concurrency": (
        "3",
        "同时运行的评估任务并发数上限",
    ),
    "retention_days": (
        "30",
        "日志、报告、临时文件的保留天数",
    ),
    "command_whitelist": (
        "ls,cat,find,grep,wc,head,tail,file,stat,python",
        "隔离环境内允许执行的命令白名单（逗号分隔）",
    ),
    "max_scan_files": (
        "2000",
        "单次代码分析最多扫描的文件数",
    ),
}

# 源码目录扫描时跳过的目录与后缀
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".idea", ".vscode", "site-packages", ".tox",
    ".mypy_cache", ".pytest_cache", "target", "vendor",
}

SCANNABLE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".php", ".rb", ".go",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".sql", ".sh", ".bash", ".yml",
    ".yaml", ".json", ".xml", ".jsp", ".asp", ".aspx", ".vue", ".html",
}

MAX_FILE_BYTES = 512 * 1024   # 超过 512KB 的文件跳过，避免拖慢演示链路


# ---------------------------------------------------------------------------
# 系统配置读写（DB 支持，带默认值兜底）
# ---------------------------------------------------------------------------
def get_config(key: str, default: str | None = None) -> str | None:
    from . import db  # 延迟导入避免循环依赖

    row = db.query_one(
        "SELECT config_value FROM system_configs WHERE config_key = ?", (key,)
    )
    if row is not None and row["config_value"] is not None:
        return row["config_value"]
    if default is not None:
        return default
    fallback = DEFAULT_CONFIGS.get(key)
    return fallback[0] if fallback else None


def get_int_config(key: str, default: int) -> int:
    raw = get_config(key)
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


def get_bool_config(key: str, default: bool = False) -> bool:
    raw = get_config(key)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def get_command_whitelist() -> set[str]:
    raw = get_config("command_whitelist") or ""
    return {item.strip() for item in raw.split(",") if item.strip()}


def get_all_configs() -> list[dict]:
    """返回全部配置项，补齐默认值，供系统配置页展示。"""
    from . import db

    rows = db.query_all("SELECT config_key, config_value, description, updated_at FROM system_configs")
    stored = {row["config_key"]: row for row in rows}

    result = []
    for key, (default_value, description) in DEFAULT_CONFIGS.items():
        row = stored.pop(key, None)
        result.append(
            {
                "config_key": key,
                "config_value": row["config_value"] if row else default_value,
                "description": row["description"] if row and row["description"] else description,
                "updated_at": row["updated_at"] if row else None,
            }
        )
    # 追加数据库中额外存在的自定义配置项
    for row in stored.values():
        result.append(row)
    return result


def set_config(key: str, value: str) -> None:
    from . import db
    from .utils import now_str

    description = DEFAULT_CONFIGS.get(key, (None, None))[1]
    existing = db.query_one("SELECT id FROM system_configs WHERE config_key = ?", (key,))
    if existing:
        db.execute(
            "UPDATE system_configs SET config_value = ?, updated_at = ? WHERE config_key = ?",
            (value, now_str(), key),
        )
    else:
        db.execute(
            "INSERT INTO system_configs (config_key, config_value, description, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (key, value, description, now_str()),
        )


def ensure_default_configs() -> None:
    """初始化时写入默认配置项（不覆盖已有值）。"""
    from . import db

    for key, (value, description) in DEFAULT_CONFIGS.items():
        if not db.query_one("SELECT id FROM system_configs WHERE config_key = ?", (key,)):
            db.execute(
                "INSERT INTO system_configs (config_key, config_value, description, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (key, value, description, _now()),
            )


def _now() -> str:
    from .utils import now_str

    return now_str()
