"""端到端演示脚本（无头模式）。

覆盖 §1.4.13 验收标准中的完整链路：
    初始化系统 → 登录 → 创建项目接入示例源码 → 启动任务
    → 观察阶段推进 → 拉取漏洞 / 攻击路径 / 报告

用法：
    # 先启动后端服务
    .venv/Scripts/python.exe -m app.main

    # 另开一个终端运行本脚本
    .venv/Scripts/python.exe demo/run_demo.py

    # 演示「停止任务」：启动后在中途停止，确认已保存数据保留
    .venv/Scripts/python.exe demo/run_demo.py --demo-stop
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import httpx

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = "examples/vuln-demo"

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
BLUE = "\033[36m"


def color(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def banner(title: str) -> None:
    print()
    print(color("─" * 72, DIM))
    print(color(f"  {title}", BOLD))
    print(color("─" * 72, DIM))


def step(text: str) -> None:
    print(f"  {color('▸', BLUE)} {text}")


def ok(text: str) -> None:
    print(f"  {color('✓', GREEN)} {text}")


def warn(text: str) -> None:
    print(f"  {color('!', YELLOW)} {text}")


def fail(text: str) -> None:
    print(f"  {color('✗', RED)} {text}")


class DemoClient:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token: str | None = None
        self.client = httpx.Client(base_url=self.base_url, timeout=30.0)

    def close(self) -> None:
        self.client.close()

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def request(self, method: str, path: str, **kwargs):
        response = self.client.request(method, path, headers=self._headers(), **kwargs)
        if response.status_code >= 400:
            detail = ""
            try:
                payload = response.json()
                detail = payload.get("detail") or payload.get("message") or ""
            except Exception:
                detail = response.text[:200]
            raise RuntimeError(f"{method} {path} 返回 {response.status_code}：{detail}")
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    # -- 接口封装 ---------------------------------------------------------
    def init_system(self):
        return self.request("POST", "/api/system/init", json={
            "username": self.username, "password": self.password,
        })

    def login(self):
        data = self.request("POST", "/api/system/login", json={
            "username": self.username, "password": self.password,
        })
        self.token = data["token"]
        return data

    def create_project(self, name: str, source_path: str):
        return self.request("POST", "/api/projects", json={
            "project_name": name,
            "source_type": "local",
            "source_path": source_path,
            "task_content": "对示例业务服务进行源码安全评估，重点关注注入类缺陷与凭据泄露。",
            "isolation_type": "simulated",
        })

    def start(self, project_id: int):
        return self.request("POST", f"/api/projects/{project_id}/start")

    def stop(self, project_id: int):
        return self.request("POST", f"/api/projects/{project_id}/stop")

    def detail(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}")

    def stages(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/stages")

    def workers(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/workers")

    def logs(self, project_id: int, limit: int = 400):
        return self.request("GET", f"/api/projects/{project_id}/logs", params={"limit": limit})

    def resources(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/resources")

    def vulnerabilities(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/vulnerabilities")

    def attack_paths(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/attack-paths")

    def report(self, project_id: int):
        return self.request("GET", f"/api/projects/{project_id}/report")

    def delete(self, project_id: int):
        return self.request("DELETE", f"/api/projects/{project_id}")


def wait_for_completion(client: DemoClient, project_id: int, timeout: int = 180) -> str:
    """轮询项目状态，实时打印阶段推进过程。"""
    deadline = time.time() + timeout
    last_stage = None
    last_status = None

    while time.time() < deadline:
        detail = client.detail(project_id)
        status_value = detail["project_status"]

        stages = client.stages(project_id)
        if stages:
            latest = stages[-1]
            key = (latest["stage_name"], latest["stage_status"])
            if key != last_stage:
                last_stage = key
                label = latest.get("stage_label") or latest["stage_name"]
                mark = {
                    "running": color("执行中", BLUE),
                    "success": color("完成", GREEN),
                    "failed": color("失败", RED),
                    "stopped": color("已停止", YELLOW),
                }.get(latest["stage_status"], latest["stage_status"])
                print(f"      [{label}] {mark}")

        if status_value != last_status:
            last_status = status_value

        if status_value in {"completed", "failed", "stopped"}:
            return status_value

        time.sleep(0.7)

    raise TimeoutError(f"等待任务完成超时（{timeout} 秒）")


def main() -> int:
    parser = argparse.ArgumentParser(description="自动化安全评估系统 - 端到端演示")
    parser.add_argument("--base-url", default="http://127.0.0.1:8002", help="后端服务地址")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="源码路径或仓库地址")
    parser.add_argument("--project-name", default=None, help="项目名称")
    parser.add_argument("--keep", action="store_true", help="演示结束后保留项目，不执行删除")
    parser.add_argument(
        "--demo-stop", action="store_true",
        help="演示「停止任务」：启动后中途停止，验证已保存数据保留",
    )
    args = parser.parse_args()

    project_name = args.project_name or f"示例评估-{time.strftime('%m%d-%H%M%S')}"

    print()
    print(color("╔" + "═" * 70 + "╗", BOLD))
    print(color("║", BOLD) + "  自动化安全评估系统 · 端到端演示".ljust(62) + color("║", BOLD))
    print(color("╚" + "═" * 70 + "╝", BOLD))

    client = DemoClient(args.base_url, args.username, args.password)

    try:
        # ------------------------------------------------------------------
        banner("步骤 1 / 6  初始化系统并登录")
        try:
            init_result = client.init_system()
            if init_result.get("initialized"):
                ok(f"系统初始化完成，管理员账户：{init_result['username']}")
            else:
                step(f"系统已初始化，使用现有管理员账户：{init_result['username']}")
        except Exception as exc:
            warn(f"初始化跳过：{exc}")

        session = client.login()
        ok(f"登录成功：{session['username']}（角色 {session['role']}）")

        # ------------------------------------------------------------------
        banner("步骤 2 / 6  创建项目并接入源码")
        step(f"源码路径：{args.source}")
        project = client.create_project(project_name, args.source)
        project_id = project["id"]
        ok(f"项目已创建：#{project_id} {project['project_name']}")
        ok(f"项目状态：{project['project_status']}")
        if not (BASE_DIR / args.source).exists():
            warn(f"提示：本地路径 {args.source} 不存在，启动任务时可能失败")

        # ------------------------------------------------------------------
        banner("步骤 3 / 6  启动评估任务")
        client.start(project_id)
        ok("任务已启动，系统正在准备隔离环境")
        print()
        print(color("      阶段推进：", DIM))

        if args.demo_stop:
            # 中途停止，验证「当前阶段不再继续执行，已保存数据保留」
            time.sleep(6)
            client.stop(project_id)
            status_value = client.detail(project_id)["project_status"]
            ok(f"已在任务执行中途停止，项目状态：{status_value}")

            stages = client.stages(project_id)
            vulns = client.vulnerabilities(project_id)
            logs = client.logs(project_id, limit=1000)
            workers = client.workers(project_id)

            print()
            step("停止后数据保留情况：")
            ok(f"阶段记录 {len(stages)} 条（保留）")
            ok(f"角色任务记录 {len(workers)} 条（保留）")
            ok(f"已保存漏洞 {len(vulns)} 条（保留）")
            ok(f"已保存日志 {len(logs)} 条（保留）")

            if not args.keep:
                print()
                result = client.delete(project_id)
                ok(f"项目已删除：#{project_id}")
                step(f"清理记录：{result['deleted_records']}")
                step(f"清理目录：{result['removed_directories']}")
            return 0

        status_value = wait_for_completion(client, project_id)
        if status_value == "completed":
            ok("评估任务执行完成")
        else:
            fail(f"评估任务结束，最终状态：{status_value}")
            return 1

        # ------------------------------------------------------------------
        banner("步骤 4 / 6  阶段与角色执行结果")
        stages = client.stages(project_id)
        print(f"      {'阶段':<22}{'状态':<10}{'耗时':>8}")
        for stage in stages:
            duration = stage.get("duration_seconds")
            print(
                f"      {stage.get('stage_label', stage['stage_name']):<20}"
                f"{stage['stage_status']:<12}"
                f"{(str(duration) + 's') if duration is not None else '--':>8}"
            )

        print()
        workers = client.workers(project_id)
        role_counts: dict[str, int] = {}
        for worker in workers:
            role_counts[worker["worker_role"]] = role_counts.get(worker["worker_role"], 0) + 1
        ok(f"角色任务记录 {len(workers)} 条，覆盖 {len(role_counts)} 类角色")
        for role, count in role_counts.items():
            step(f"{role:<20} 执行 {count} 次")

        # ------------------------------------------------------------------
        banner("步骤 5 / 6  漏洞与攻击路径")
        vulnerabilities = client.vulnerabilities(project_id)
        verified = [v for v in vulnerabilities if v["verify_status"] == "verified"]
        by_risk = {"high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            by_risk[vuln["risk_level"]] = by_risk.get(vuln["risk_level"], 0) + 1

        ok(
            f"发现漏洞 {len(vulnerabilities)} 条"
            f"（高危 {by_risk['high']} / 中危 {by_risk['medium']} / 低危 {by_risk['low']}），"
            f"已验证 {len(verified)} 条"
        )
        print()
        print(f"      {'编号':<12}{'风险':<8}{'漏洞标题':<24}{'文件位置'}")
        for vuln in vulnerabilities[:12]:
            risk = {"high": "高危", "medium": "中危", "low": "低危"}.get(vuln["risk_level"], "?")
            mark = color("✓", GREEN) if vuln["verify_status"] == "verified" else color("·", DIM)
            print(
                f"      {vuln['vuln_code']:<12}{risk:<8}{vuln['vuln_title']:<22}"
                f"{vuln['file_path']} {mark}"
            )
        if len(vulnerabilities) > 12:
            print(color(f"      … 其余 {len(vulnerabilities) - 12} 条见漏洞列表页", DIM))

        print()
        paths = client.attack_paths(project_id)
        ok(f"编排攻击路径 {len(paths)} 条")
        for path in paths:
            print()
            print(f"      {color(path['path_code'], BLUE)} {path['path_title']}")
            for item in path["items"]:
                print(
                    f"        {item['step_order']}. {color(item['vuln_code'], BLUE)} "
                    f"{item['vuln_title']}  ({item['file_path']})"
                )
            print(color(f"        最终影响：{path['final_impact_text'][:64]}…", DIM))

        # ------------------------------------------------------------------
        banner("步骤 6 / 6  报告与运行数据")
        report = client.report(project_id)
        report_path = Path(report["report_file_path"])
        ok(f"报告已生成：编号 {report['id']}")
        step(f"报告文件：{report_path}")
        step(f"文件存在：{'是' if report_path.exists() else '否'}")
        ok(f"Markdown 长度 {len(report['report_markdown'])} 字符")

        sections = [
            line.strip("# ").strip()
            for line in report["report_markdown"].splitlines()
            if line.startswith("## ")
        ]
        step(f"报告章节：{'、'.join(sections)}")

        resources = client.resources(project_id)
        logs = client.logs(project_id, limit=2000)
        if resources:
            peak_memory = max(r["memory_usage"] for r in resources)
            tokens = resources[-1]["token_count"]
            ok(f"资源采样 {len(resources)} 个点，峰值内存 {peak_memory} MB，Token 估算 {tokens}")
        ok(f"运行日志 {len(logs)} 条")

        # ------------------------------------------------------------------
        banner("演示完成")
        print(f"  项目 #{project_id}「{project_name}」评估链路已全部跑通。")
        print()
        print("  在浏览器中查看完整界面：")
        print(color(f"    {args.base_url}/#/login", BLUE))
        print()
        print("  登录后依次查看：")
        print("    项目详情 → 实时监控 → 漏洞列表 → 攻击路径 → 评估报告")
        print()

        if not args.keep:
            answer = input(color("  是否删除本次演示项目及其全部数据？(y/N) ", BOLD)).strip().lower()
            if answer == "y":
                result = client.delete(project_id)
                ok(f"项目已删除：#{project_id}")
                step(f"清理记录：{result['deleted_records']}")
                step(f"清理目录：{result['removed_directories']}")
            else:
                step(f"已保留项目 #{project_id}，可在浏览器中继续查看")

        return 0

    except httpx.ConnectError:
        print()
        fail(f"无法连接后端服务：{args.base_url}")
        print()
        print("  请先启动后端服务：")
        print(color("    .venv/Scripts/python.exe -m app.main", BLUE))
        print()
        return 2
    except KeyboardInterrupt:
        print()
        warn("演示被中断")
        return 130
    except Exception as exc:
        print()
        fail(f"演示失败：{exc}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    if sys.platform == "win32":
        # 保证中文在 Windows 控制台正常输出
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    sys.exit(main())
