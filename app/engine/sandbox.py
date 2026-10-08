"""隔离环境模块（§1.4.7 / §1.4.9）。

本系统默认使用 **模拟隔离环境（simulated）**：
- 每个项目分配唯一隔离环境编号 `SA-{project_id}-{随机串}`；
- 源码目录以「只读挂载」方式接入：引擎只通过只读句柄读取源码，
  任何写操作都被限制在 `workspace/{project_id}/` 内；
- 命令执行受白名单 + 路径围栏双重限制，且不经过 shell。

同时提供五种执行能力（§1.4.1）：
隔离环境管理 / 源码读取 / 目录遍历 / 关键字搜索 / 命令执行。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .. import config, db, security
from ..utils import now_str

# 命令执行超时与输出上限，防止演示链路被异常命令卡死
COMMAND_TIMEOUT_SECONDS = 20
MAX_OUTPUT_CHARS = 8000


class SandboxError(RuntimeError):
    """隔离环境相关错误。"""


# ---------------------------------------------------------------------------
# 隔离环境管理
# ---------------------------------------------------------------------------
def get_sandbox(project_id: int) -> dict | None:
    return db.query_one(
        "SELECT * FROM sandboxes WHERE project_id = ? ORDER BY id DESC LIMIT 1",
        (project_id,),
    )


def create_sandbox(
    project_id: int,
    source_path: str,
    source_type: str = "local",
    isolation_type: str = "simulated",
) -> dict:
    """创建并启动隔离环境，返回沙箱记录。"""
    workspace = config.project_workspace_dir(project_id)
    # 每次启动任务重建临时目录，保证环境干净
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=True)

    source_root = _prepare_source(project_id, source_path, source_type, workspace)

    existing = get_sandbox(project_id)
    code = security.sandbox_code(project_id)
    mount_path = _readonly_mount(source_root, workspace)

    if existing:
        db.update(
            "sandboxes",
            {
                "sandbox_code": code,
                "isolation_type": isolation_type,
                "source_mount_path": str(mount_path),
                "workspace_path": str(workspace),
                "sandbox_status": "running",
                "created_at": now_str(),
                "destroyed_at": None,
            },
            "id = ?",
            (existing["id"],),
        )
        sandbox_id = existing["id"]
    else:
        sandbox_id = db.insert(
            "sandboxes",
            {
                "sandbox_code": code,
                "project_id": project_id,
                "isolation_type": isolation_type,
                "source_mount_path": str(mount_path),
                "workspace_path": str(workspace),
                "sandbox_status": "running",
                "created_at": now_str(),
                "destroyed_at": None,
            },
        )

    return {
        "id": sandbox_id,
        "sandbox_code": code,
        "project_id": project_id,
        "isolation_type": isolation_type,
        "source_mount_path": str(mount_path),
        "source_root": str(source_root),
        "workspace_path": str(workspace),
        "sandbox_status": "running",
    }


def start_sandbox(project_id: int) -> dict | None:
    sandbox = get_sandbox(project_id)
    if sandbox:
        db.update(
            "sandboxes",
            {"sandbox_status": "running"},
            "id = ?",
            (sandbox["id"],),
        )
        sandbox["sandbox_status"] = "running"
    return sandbox


def stop_sandbox(project_id: int) -> None:
    sandbox = get_sandbox(project_id)
    if sandbox:
        db.update(
            "sandboxes",
            {"sandbox_status": "stopped"},
            "id = ?",
            (sandbox["id"],),
        )


def destroy_sandbox(project_id: int) -> None:
    """销毁隔离环境并清理临时执行目录。"""
    sandbox = get_sandbox(project_id)
    if sandbox:
        db.update(
            "sandboxes",
            {"sandbox_status": "destroyed", "destroyed_at": now_str()},
            "id = ?",
            (sandbox["id"],),
        )
    shutil.rmtree(config.project_workspace_dir(project_id), ignore_errors=True)


# ---------------------------------------------------------------------------
# 源码接入与只读挂载
# ---------------------------------------------------------------------------
def _prepare_source(
    project_id: int, source_path: str, source_type: str, workspace: Path
) -> Path:
    """把源码接入隔离环境，返回只读挂载源目录。"""
    if source_type == "git":
        clone_dir = workspace / "source"
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", source_path, str(clone_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise SandboxError("未检测到 git 命令，无法接入仓库地址") from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxError("克隆仓库超时（超过 120 秒）") from exc

        if result.returncode != 0:
            raise SandboxError(f"克隆仓库失败：{result.stderr.strip()[:300]}")
        return clone_dir

    # 本地目录接入
    candidate = Path(source_path)
    if not candidate.is_absolute():
        candidate = (config.BASE_DIR / candidate).resolve()

    if not candidate.exists():
        raise SandboxError(f"源码路径不存在：{candidate}")
    if not candidate.is_dir():
        raise SandboxError(f"源码路径不是目录：{candidate}")

    return candidate


def _readonly_mount(source_root: Path, workspace: Path) -> Path:
    """建立只读挂载视图。

    模拟隔离环境下不创建真实内核挂载点（Windows 上需要特权），
    而是在工作区登记挂载描述，并由本模块的读取/执行接口强制只读语义：
    源码目录只允许读取，一切写入被重定向到 workspace 内。
    """
    mount_dir = workspace / "mnt"
    mount_dir.mkdir(parents=True, exist_ok=True)
    descriptor = mount_dir / "source.mount"
    descriptor.write_text(
        f"type=readonly\nsource={source_root}\nmode=ro\n",
        encoding="utf-8",
    )
    return source_root


def resolve_source_root(project_id: int) -> Path:
    """取得项目的源码根目录。"""
    sandbox = get_sandbox(project_id)
    if sandbox and sandbox.get("source_mount_path"):
        return Path(sandbox["source_mount_path"])

    project = db.query_one("SELECT * FROM projects WHERE id = ?", (project_id,))
    if not project:
        raise SandboxError(f"项目不存在：{project_id}")

    candidate = Path(project["source_path"])
    if not candidate.is_absolute():
        candidate = (config.BASE_DIR / candidate).resolve()
    return candidate


# ---------------------------------------------------------------------------
# 执行能力 1：源码读取（只读）
# ---------------------------------------------------------------------------
def read_source_file(project_id: int, relative_path: str, max_bytes: int = 200_000) -> str:
    """只读读取源码文件内容。"""
    target = _safe_source_path(project_id, relative_path)
    if not target.is_file():
        raise SandboxError(f"文件不存在：{relative_path}")
    if target.stat().st_size > max_bytes:
        raise SandboxError(f"文件过大（超过 {max_bytes} 字节）：{relative_path}")
    return target.read_text(encoding="utf-8", errors="replace")


def _safe_source_path(project_id: int, relative_path: str) -> Path:
    """把相对路径解析到源码根内，阻断路径穿越。"""
    root = resolve_source_root(project_id).resolve()
    target = (root / relative_path).resolve()
    if target != root and root not in target.parents:
        raise SandboxError(f"路径越界，已阻断：{relative_path}")
    return target


# ---------------------------------------------------------------------------
# 执行能力 2：目录遍历
# ---------------------------------------------------------------------------
def walk_source(project_id: int, max_files: int | None = None) -> list[dict]:
    """遍历源码目录，返回可扫描文件清单。"""
    root = resolve_source_root(project_id).resolve()
    if not root.is_dir():
        raise SandboxError(f"源码目录不存在：{root}")

    limit = max_files if max_files is not None else config.get_int_config("max_scan_files", 2000)
    entries: list[dict] = []

    for current_dir, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name for name in dirnames
            if name not in config.SKIP_DIRS and not name.startswith(".")
        ]
        for filename in filenames:
            path = Path(current_dir) / filename
            if path.suffix.lower() not in config.SCANNABLE_SUFFIXES:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > config.MAX_FILE_BYTES or size == 0:
                continue

            entries.append(
                {
                    "relative_path": path.relative_to(root).as_posix(),
                    "size": size,
                    "suffix": path.suffix.lower(),
                }
            )
            if len(entries) >= limit:
                return entries

    return entries


# ---------------------------------------------------------------------------
# 执行能力 3：关键字搜索
# ---------------------------------------------------------------------------
def search_source(project_id: int, keyword: str, max_hits: int = 200) -> list[dict]:
    """在源码中搜索关键字，返回命中位置。"""
    if not keyword:
        return []

    root = resolve_source_root(project_id).resolve()
    hits: list[dict] = []
    needle = keyword.lower()

    for entry in walk_source(project_id):
        try:
            content = (root / entry["relative_path"]).read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            continue
        for line_no, line in enumerate(content.splitlines(), start=1):
            if needle in line.lower():
                hits.append(
                    {
                        "file_path": entry["relative_path"],
                        "line_no": line_no,
                        "line_text": line.strip()[:300],
                    }
                )
                if len(hits) >= max_hits:
                    return hits
    return hits


# ---------------------------------------------------------------------------
# 执行能力 4：命令执行（白名单 + 路径围栏，不经过 shell）
# ---------------------------------------------------------------------------
def run_command(project_id: int, argv: list[str], cwd: str | None = None) -> dict:
    """在隔离环境内执行白名单命令。

    安全约束：
    1. 必须显式传入参数数组，不经过 shell，杜绝 `;` `|` `&&` 注入；
    2. 命令名必须命中 system_configs.command_whitelist；
    3. 工作目录固定限制在 workspace/{project_id} 内；
    4. 参数中的绝对路径必须落在源码根或工作区内。
    """
    if not argv:
        raise SandboxError("命令为空")

    command = Path(argv[0]).name
    whitelist = config.get_command_whitelist()
    if command not in whitelist:
        raise SandboxError(
            f"命令 `{command}` 不在白名单内，允许的命令：{', '.join(sorted(whitelist))}"
        )

    workspace = config.project_workspace_dir(project_id).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    work_dir = (workspace / cwd).resolve() if cwd else workspace
    if work_dir != workspace and workspace not in work_dir.parents:
        raise SandboxError(f"工作目录越界，已阻断：{cwd}")

    source_root = resolve_source_root(project_id).resolve()
    for arg in argv[1:]:
        candidate = Path(arg)
        if not candidate.is_absolute():
            continue
        resolved = candidate.resolve()
        if resolved != source_root and source_root not in resolved.parents \
                and resolved != workspace and workspace not in resolved.parents:
            raise SandboxError(f"参数路径越界，已阻断：{arg}")

    try:
        completed = subprocess.run(
            argv,
            cwd=str(work_dir),
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise SandboxError(f"命令不可用：{command}") from exc
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"命令执行超时（超过 {COMMAND_TIMEOUT_SECONDS} 秒）") from exc

    return {
        "command": " ".join(argv),
        "returncode": completed.returncode,
        "stdout": (completed.stdout or "")[:MAX_OUTPUT_CHARS],
        "stderr": (completed.stderr or "")[:MAX_OUTPUT_CHARS],
    }


# ---------------------------------------------------------------------------
# 执行能力 5：隔离环境自检
# ---------------------------------------------------------------------------
def inspect_environment(project_id: int) -> dict:
    """环境检查角色使用：检查隔离环境是否满足分析前置条件。"""
    root = resolve_source_root(project_id)
    files = walk_source(project_id) if root.is_dir() else []

    suffix_stats: dict[str, int] = {}
    total_bytes = 0
    for entry in files:
        suffix_stats[entry["suffix"]] = suffix_stats.get(entry["suffix"], 0) + 1
        total_bytes += entry["size"]

    return {
        "source_root": str(root),
        "source_exists": root.is_dir(),
        "readonly": config.get_bool_config("isolation_readonly_mount", True),
        "network": config.get_config("isolation_network", "none"),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "suffix_stats": dict(sorted(suffix_stats.items(), key=lambda kv: -kv[1])[:10]),
        "python_available": shutil.which("python") is not None,
    }
