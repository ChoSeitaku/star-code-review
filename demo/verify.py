"""验收自检脚本。

逐项核对需求文档中的可验证条目：
  §1.4.10  16 个接口全部可用且返回结构符合预期
  §1.4.11  实时通道能收到全部 8 种消息类型
  §1.4.12  输出结果格式（漏洞列表/详情、攻击路径、最终报告）
  §1.4.13  验收标准（初始化、登录、建项目、启动、阶段变化、停止、删除）

用法（需先启动后端服务）：
    .venv/Scripts/python.exe demo/verify.py
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

import httpx

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [\033[32mPASS\033[0m] {name}")
    else:
        FAIL += 1
        FAILURES.append(name)
        print(f"  [\033[31mFAIL\033[0m] {name}" + (f" —— {detail}" if detail else ""))


def section(title: str) -> None:
    print()
    print(f"\033[1m{title}\033[0m")
    print("─" * 70)


# ---------------------------------------------------------------------------
# §1.4.10 接口验证
# ---------------------------------------------------------------------------
def verify_api(base_url: str, source: str) -> int | None:
    client = httpx.Client(base_url=base_url, timeout=30.0)
    token: str | None = None
    project_id: int | None = None

    def req(method: str, path: str, auth: bool = True, **kwargs):
        headers = {"Authorization": f"Bearer {token}"} if (auth and token) else {}
        return client.request(method, path, headers=headers, **kwargs)

    try:
        section("§1.4.10 接口验证")

        # POST /api/system/init
        response = req("POST", "/api/system/init",
                       auth=False, json={"username": "admin", "password": "admin123"})
        check("POST /api/system/init 初始化管理员账户", response.status_code == 200,
              f"状态码 {response.status_code}")

        # POST /api/system/login
        response = req("POST", "/api/system/login",
                       auth=False, json={"username": "admin", "password": "admin123"})
        check("POST /api/system/login 登录校验", response.status_code == 200,
              f"状态码 {response.status_code}")
        if response.status_code != 200:
            return None
        token = response.json()["token"]

        # 错误密码应被拒绝
        bad = req("POST", "/api/system/login",
                  auth=False, json={"username": "admin", "password": "wrong-password"})
        check("登录态识别：错误密码返回 401", bad.status_code == 401,
              f"状态码 {bad.status_code}")

        # 未携带令牌应被拒绝
        unauth = client.get("/api/projects")
        check("登录态识别：未登录访问受保护接口返回 401", unauth.status_code == 401,
              f"状态码 {unauth.status_code}")

        # POST /api/projects
        response = req("POST", "/api/projects", json={
            "project_name": f"验收自检-{int(time.time())}",
            "source_type": "local",
            "source_path": source,
            "task_content": "验收自检任务",
            "isolation_type": "simulated",
        })
        check("POST /api/projects 创建项目", response.status_code in (200, 201),
              f"状态码 {response.status_code}")
        if response.status_code not in (200, 201):
            return None
        project = response.json()
        project_id = project["id"]

        required_project_fields = {
            "id", "project_name", "source_type", "source_path", "task_content",
            "project_status", "created_by", "created_at", "updated_at",
        }
        check("projects 表字段完整（§1.4.8）",
              required_project_fields.issubset(project.keys()),
              f"缺失 {required_project_fields - set(project.keys())}")

        # GET /api/projects
        response = req("GET", "/api/projects")
        check("GET /api/projects 查询项目列表",
              response.status_code == 200 and isinstance(response.json(), list),
              f"状态码 {response.status_code}")

        # GET /api/projects/{id}
        response = req("GET", f"/api/projects/{project_id}")
        check("GET /api/projects/{project_id} 查询项目详情",
              response.status_code == 200 and response.json()["id"] == project_id)

        # POST /api/projects/{id}/start
        response = req("POST", f"/api/projects/{project_id}/start")
        check("POST /api/projects/{id}/start 启动评估任务", response.status_code == 200,
              response.text[:160])

        # 等待执行完成，期间观察阶段变化与临时目录的建立
        base_dir = Path(__file__).resolve().parent.parent
        observed_stages: set[str] = set()
        workspace_seen = False
        deadline = time.time() + 180
        final_status = None
        while time.time() < deadline:
            stages = req("GET", f"/api/projects/{project_id}/stages").json()
            observed_stages.update(stage["stage_name"] for stage in stages)
            final_status = req("GET", f"/api/projects/{project_id}").json()["project_status"]

            if (base_dir / "workspace" / str(project_id)).is_dir():
                workspace_seen = True

            if final_status in {"completed", "failed", "stopped"}:
                break
            time.sleep(0.6)

        check("启动后项目状态变为 running 并最终 completed",
              final_status == "completed", f"最终状态 {final_status}")

        expected_stages = {
            "environment_scan", "code_analysis", "vulnerability_verify",
            "report_generate", "done",
        }
        check("§1.4.4 五个执行阶段全部出现",
              expected_stages.issubset(observed_stages),
              f"缺失 {expected_stages - observed_stages}")

        # GET stages
        response = req("GET", f"/api/projects/{project_id}/stages")
        stages = response.json()
        check("GET /api/projects/{id}/stages 查询阶段状态",
              response.status_code == 200 and len(stages) >= 5)
        if stages:
            stage_fields = {"id", "project_id", "stage_name", "stage_status",
                            "started_at", "finished_at", "error_message"}
            check("runtime_stages 表字段完整（§1.4.8）",
                  stage_fields.issubset(stages[0].keys()),
                  f"缺失 {stage_fields - set(stages[0].keys())}")

        # GET workers
        response = req("GET", f"/api/projects/{project_id}/workers")
        workers = response.json()
        check("GET /api/projects/{id}/workers 查询角色执行状态",
              response.status_code == 200 and len(workers) > 0)
        if workers:
            worker_fields = {"id", "project_id", "stage_id", "worker_role", "task_content",
                             "task_status", "result_summary", "started_at", "finished_at"}
            check("worker_tasks 表字段完整（§1.4.8）",
                  worker_fields.issubset(workers[0].keys()),
                  f"缺失 {worker_fields - set(workers[0].keys())}")

            roles = {worker["worker_role"] for worker in workers}
            expected_roles = {
                "general_processor", "env_checker", "code_analyzer",
                "vuln_verifier", "report_writer", "ops_helper",
            }
            check("§1.4.5 至少 6 类执行角色均有独立任务记录",
                  expected_roles.issubset(roles), f"缺失 {expected_roles - roles}")

            traceable = all(
                worker.get("project_id") == project_id and worker.get("stage_id")
                for worker in workers
            )
            check("§1.4.5 角色执行结果可回溯到项目与阶段", traceable)

        # GET vulnerabilities
        response = req("GET", f"/api/projects/{project_id}/vulnerabilities")
        vulns = response.json()
        check("GET /api/projects/{id}/vulnerabilities 查询漏洞列表",
              response.status_code == 200 and isinstance(vulns, list) and len(vulns) > 0,
              f"返回 {len(vulns) if isinstance(vulns, list) else '?'} 条")

        if vulns:
            required = {"vuln_code", "vuln_title", "risk_level", "file_path", "verify_status"}
            check("§1.4.12 漏洞列表字段（编号/标题/风险/位置/验证状态）",
                  required.issubset(vulns[0].keys()),
                  f"缺失 {required - set(vulns[0].keys())}")

            detail_fields = {
                "impact_text", "condition_text", "evidence_text",
                "reproduce_steps_text", "verify_code_text",
            }
            check("§1.4.12 漏洞详情字段（影响/条件/证据/复现/验证代码）",
                  detail_fields.issubset(vulns[0].keys()),
                  f"缺失 {detail_fields - set(vulns[0].keys())}")

            verified = [v for v in vulns if v["verify_status"] == "verified"]
            check("漏洞验证阶段产出已验证漏洞", len(verified) > 0,
                  f"已验证 {len(verified)}/{len(vulns)}")

        # GET attack-paths
        response = req("GET", f"/api/projects/{project_id}/attack-paths")
        paths = response.json()
        check("GET /api/projects/{id}/attack-paths 查询攻击路径列表",
              response.status_code == 200 and isinstance(paths, list) and len(paths) > 0,
              f"返回 {len(paths) if isinstance(paths, list) else '?'} 条")

        if paths:
            path = paths[0]
            required = {"path_code", "path_title", "path_summary", "final_impact_text", "items"}
            check("§1.4.12 攻击路径字段（编号/关联漏洞/利用顺序/最终影响）",
                  required.issubset(path.keys()),
                  f"缺失 {required - set(path.keys())}")
            orders = [item["step_order"] for item in path["items"]]
            check("攻击路径利用顺序连续递增", orders == sorted(orders) and len(orders) >= 2,
                  f"顺序 {orders}")

        # GET report
        response = req("GET", f"/api/projects/{project_id}/report")
        check("GET /api/projects/{id}/report 查询最终报告", response.status_code == 200)
        if response.status_code == 200:
            report = response.json()
            markdown = report.get("report_markdown") or ""
            sections = {
                "项目概述": "一、项目概述" in markdown,
                "执行过程": "二、执行过程" in markdown,
                "漏洞汇总": "三、漏洞汇总" in markdown,
                "攻击路径": "四、攻击路径" in markdown,
                "风险结论": "五、风险结论" in markdown,
                "修复建议": "六、修复建议" in markdown,
            }
            for name, present in sections.items():
                check(f"§1.4.12 报告包含「{name}」章节", present)

            check("报告 HTML 与文件均已生成",
                  bool(report.get("report_html")) and Path(report["report_file_path"]).exists(),
                  report.get("report_file_path", ""))

        # GET logs
        response = req("GET", f"/api/projects/{project_id}/logs")
        logs = response.json()
        check("GET /api/projects/{id}/logs 查询运行日志",
              response.status_code == 200 and isinstance(logs, list) and len(logs) > 0,
              f"返回 {len(logs) if isinstance(logs, list) else '?'} 条")

        # GET resources
        response = req("GET", f"/api/projects/{project_id}/resources")
        resources = response.json()
        check("GET /api/projects/{id}/resources 查询资源消耗",
              response.status_code == 200 and isinstance(resources, list) and len(resources) > 0,
              f"返回 {len(resources) if isinstance(resources, list) else '?'} 条")
        if resources:
            fields = {"cpu_usage", "memory_usage", "token_count"}
            check("resource_usages 表字段完整（§1.4.8）",
                  fields.issubset(resources[0].keys()),
                  f"缺失 {fields - set(resources[0].keys())}")

        # §1.4.9 文件存储
        section("§1.4.9 隔离环境与文件存储")
        base = base_dir
        check("日志文件按 runtime_logs/{project_id}/ 存储",
              (base / "runtime_logs" / str(project_id)).is_dir())
        check("报告文件按 reports/{project_id}/ 存储",
              (base / "reports" / str(project_id)).is_dir())
        # 临时执行目录在任务执行期间存在，任务结束后随隔离环境一并销毁
        check("任务执行期间临时执行文件按 workspace/{project_id}/ 存储", workspace_seen)
        check("任务结束后临时目录已随隔离环境销毁",
              not (base / "workspace" / str(project_id)).exists())

        sandbox = req("GET", f"/api/projects/{project_id}/sandbox").json()
        check("§1.4.9 每个项目绑定独立隔离环境编号",
              bool(sandbox.get("sandbox_code")), json.dumps(sandbox, ensure_ascii=False)[:120])

        # §1.4.4 删除项目
        section("§1.4.4 删除项目及其关联数据")
        response = req("DELETE", f"/api/projects/{project_id}")
        check("DELETE /api/projects/{id} 删除项目", response.status_code == 200,
              response.text[:160])

        gone = req("GET", f"/api/projects/{project_id}")
        check("删除后项目详情返回 404", gone.status_code == 404, f"状态码 {gone.status_code}")

        check("删除后日志目录已清理",
              not (base / "runtime_logs" / str(project_id)).exists())
        check("删除后报告目录已清理",
              not (base / "reports" / str(project_id)).exists())
        check("删除后临时目录已清理",
              not (base / "workspace" / str(project_id)).exists())

        return None

    finally:
        client.close()


# ---------------------------------------------------------------------------
# §1.4.11 实时消息验证
# ---------------------------------------------------------------------------
async def verify_ws(base_url: str, source: str) -> None:
    import websockets

    section("§1.4.11 实时消息类型验证")

    ws_base = base_url.replace("http://", "ws://").replace("https://", "wss://")
    client = httpx.Client(base_url=base_url, timeout=30.0)

    response = client.post("/api/system/login", json={"username": "admin", "password": "admin123"})
    if response.status_code != 200:
        check("WebSocket 验证前置：登录成功", False, f"状态码 {response.status_code}")
        client.close()
        return
    token = response.json()["token"]

    project = client.post(
        "/api/projects",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "project_name": f"WS验收-{int(time.time())}",
            "source_type": "local",
            "source_path": source,
            "task_content": "实时消息验证",
            "isolation_type": "simulated",
        },
    ).json()
    project_id = project["id"]

    # 未授权连接应被拒绝
    try:
        async with websockets.connect(f"{ws_base}/api/projects/{project_id}/stream") as sock:
            await asyncio.wait_for(sock.recv(), timeout=5)
        check("未携带令牌的 WebSocket 连接被拒绝", False, "连接未被关闭")
    except websockets.exceptions.ConnectionClosed as exc:
        check("未携带令牌的 WebSocket 连接被拒绝", exc.code == 4401, f"关闭码 {exc.code}")
    except Exception as exc:
        check("未携带令牌的 WebSocket 连接被拒绝", False, str(exc)[:100])

    received: dict[str, int] = {}

    async def listen(stop_event: asyncio.Event) -> None:
        url = f"{ws_base}/api/projects/{project_id}/stream?token={token}"
        async with websockets.connect(url, ping_interval=20) as sock:
            while not stop_event.is_set():
                try:
                    raw = await asyncio.wait_for(sock.recv(), timeout=1.5)
                except asyncio.TimeoutError:
                    continue
                except websockets.exceptions.ConnectionClosed:
                    break
                try:
                    message = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                message_type = message.get("type")
                received[message_type] = received.get(message_type, 0) + 1

    stop_event = asyncio.Event()
    listener = asyncio.create_task(listen(stop_event))
    await asyncio.sleep(1.0)

    client.post(
        f"/api/projects/{project_id}/start",
        headers={"Authorization": f"Bearer {token}"},
    )

    deadline = time.time() + 120
    expected = [
        "project_status", "stage_status", "worker_status", "chat_message",
        "runtime_log", "resource_usage", "vulnerability_found", "report_ready",
    ]
    while time.time() < deadline:
        if all(received.get(name, 0) > 0 for name in expected):
            break
        await asyncio.sleep(0.5)

    stop_event.set()
    listener.cancel()
    try:
        await listener
    except (asyncio.CancelledError, Exception):
        pass

    for name in expected:
        count = received.get(name, 0)
        check(f"收到实时消息类型 {name}", count > 0, f"收到 {count} 条")

    # 清理
    client.delete(
        f"/api/projects/{project_id}", headers={"Authorization": f"Bearer {token}"}
    )
    client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="自动化安全评估系统 - 验收自检")
    parser.add_argument("--base-url", default="http://127.0.0.1:8002")
    parser.add_argument("--source", default="examples/vuln-demo")
    parser.add_argument("--skip-ws", action="store_true", help="跳过 WebSocket 实时消息验证")
    args = parser.parse_args()

    print()
    print("\033[1m╔" + "═" * 68 + "╗\033[0m")
    print("\033[1m║\033[0m  自动化安全评估系统 · 验收自检".ljust(60) + "\033[1m║\033[0m")
    print("\033[1m╚" + "═" * 68 + "╝\033[0m")

    try:
        httpx.get(f"{args.base_url}/api/health", timeout=5.0)
    except Exception as exc:
        print(f"\n\033[31m无法连接后端服务 {args.base_url}：{exc}\033[0m")
        print("请先启动：.venv/Scripts/python.exe -m app.main\n")
        return 2

    try:
        verify_api(args.base_url, args.source)
        if not args.skip_ws:
            asyncio.run(verify_ws(args.base_url, args.source))
    except KeyboardInterrupt:
        print("\n\033[33m自检被中断\033[0m")
        return 130
    except Exception as exc:
        print(f"\n\033[31m自检异常终止：{type(exc).__name__}: {exc}\033[0m")
        return 1

    section("自检结果汇总")
    total = PASS + FAIL
    print(f"  通过 \033[32m{PASS}\033[0m / {total}")
    if FAIL:
        print(f"  失败 \033[31m{FAIL}\033[0m")
        for name in FAILURES:
            print(f"    · {name}")
        print()
        return 1
    print("  \033[32m全部验收项通过\033[0m")
    print()
    return 0


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    sys.exit(main())
