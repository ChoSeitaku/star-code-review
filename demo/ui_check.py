"""前端界面自动化检查（可选，用于交付前的 UI 冒烟测试）。

使用 Playwright 驱动本机已安装的 Edge / Chrome，逐页访问并截图，
同时收集控制台错误，确认 9 个页面均可正常渲染、实时监控页能收到 WebSocket 推送。

前置条件：
    uv pip install playwright          # 复用本机已安装的 Edge，无需下载浏览器

用法（需先启动后端服务）：
    .venv/Scripts/python.exe demo/ui_check.py
    .venv/Scripts/python.exe demo/ui_check.py --channel chrome --headed
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import httpx

SHOT_DIR = Path(__file__).resolve().parent / "screenshots"

PASS = 0
FAIL = 0
FAILURES: list[str] = []
CONSOLE_ERRORS: list[str] = []


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


def main() -> int:
    parser = argparse.ArgumentParser(description="前端界面自动化检查")
    parser.add_argument("--base-url", default="http://127.0.0.1:8002")
    parser.add_argument("--channel", default="msedge", help="浏览器通道：msedge / chrome")
    parser.add_argument("--headed", action="store_true", help="显示浏览器窗口")
    parser.add_argument("--keep", action="store_true", help="检查结束后保留演示项目")
    args = parser.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("\033[31m未安装 Playwright，请执行：uv pip install playwright\033[0m")
        return 2

    # 确认后端可用
    try:
        httpx.get(f"{args.base_url}/api/health", timeout=5.0)
    except Exception as exc:
        print(f"\033[31m无法连接后端服务 {args.base_url}：{exc}\033[0m")
        print("请先启动：.venv/Scripts/python.exe -m app.main\n")
        return 2

    SHOT_DIR.mkdir(parents=True, exist_ok=True)

    # 预置一个跑完的项目，供各结果页面展示真实数据
    client = httpx.Client(base_url=args.base_url, timeout=60.0)
    client.post("/api/system/init", json={"username": "admin", "password": "admin123"})
    token = client.post(
        "/api/system/login", json={"username": "admin", "password": "admin123"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    project = client.post(
        "/api/projects",
        headers=headers,
        json={
            "project_name": "界面检查-示例业务服务",
            "source_type": "local",
            "source_path": "examples/vuln-demo",
            "task_content": "界面自动化检查任务",
            "isolation_type": "simulated",
        },
    ).json()
    project_id = project["id"]

    print()
    print("\033[1m╔" + "═" * 68 + "╗\033[0m")
    print("\033[1m║\033[0m  自动化安全评估系统 · 前端界面检查".ljust(60) + "\033[1m║\033[0m")
    print("\033[1m╚" + "═" * 68 + "╝\033[0m")

    exit_code = 0
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                channel=args.channel, headless=not args.headed
            )
            page = browser.new_page(viewport={"width": 1560, "height": 950})

            page.on(
                "console",
                lambda message: CONSOLE_ERRORS.append(f"{message.type}: {message.text}")
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: CONSOLE_ERRORS.append(f"pageerror: {error}"))

            base = args.base_url.rstrip("/")

            # ---------------------------------------------------------------
            section("1. 登录页")
            page.goto(f"{base}/#/login", wait_until="networkidle")
            check("登录页渲染成功", page.locator(".login-card").count() == 1)
            check("标题显示正确", "自动化安全评估系统" in page.inner_text(".login-title"))
            check("初始化按钮存在", page.locator("text=初始化系统").count() >= 1)

            page.click("text=初始化系统")
            page.wait_for_timeout(1200)
            check(
                "初始化系统返回提示",
                page.locator(".alert").count() >= 1,
                page.inner_text("body")[:120],
            )

            page.fill("#username", "admin")
            page.fill("#password", "admin123")
            page.click("button[type=submit]")
            page.wait_for_timeout(1800)
            check("登录成功并跳转到项目列表", "#/projects" in page.url, page.url)
            page.screenshot(path=str(SHOT_DIR / "01-登录页.png"))
            page.goto(f"{base}/#/login", wait_until="networkidle")
            page.screenshot(path=str(SHOT_DIR / "01b-登录页.png"))

            # ---------------------------------------------------------------
            section("2. 项目列表页")
            page.goto(f"{base}/#/projects", wait_until="networkidle")
            page.wait_for_timeout(900)
            check("项目列表渲染成功", page.locator(".table-wrap").count() >= 1)
            headers_text = page.inner_text("table.data thead")
            for column in ["项目名称", "源码来源", "项目状态", "最近启动时间", "最近完成时间"]:
                check(f"列表包含「{column}」列", column in headers_text)
            # 无项目上下文时导航只展示「项目」「系统」两组
            check("侧边导航渲染成功", page.locator(".nav-item").count() >= 3,
                  f"{page.locator('.nav-item').count()} 项")
            page.screenshot(path=str(SHOT_DIR / "02-项目列表页.png"))

            # ---------------------------------------------------------------
            section("3. 项目创建页")
            page.goto(f"{base}/#/projects/new", wait_until="networkidle")
            page.wait_for_timeout(900)
            check("创建表单渲染成功", page.locator("#project_name").count() == 1)
            for field_id in ["project_name", "source_type", "source_path", "task_content", "isolation_type"]:
                check(f"表单包含字段 {field_id}", page.locator(f"#{field_id}").count() == 1)
            check("规则库清单已加载", page.locator(".badge").count() >= 12)
            page.screenshot(path=str(SHOT_DIR / "03-项目创建页.png"))

            # ---------------------------------------------------------------
            section("4. 启动任务并观察实时监控页")
            client.post(f"/api/projects/{project_id}/start", headers=headers)

            page.goto(f"{base}/#/projects/{project_id}/monitor", wait_until="networkidle")
            page.wait_for_timeout(2500)

            check("监控页渲染成功", page.locator(".stat").count() >= 4)
            check("阶段步进器渲染成功", page.locator(".step").count() == 5)
            check("6 类角色卡片全部渲染", page.locator(".role-card").count() == 6)

            ws_text = page.inner_text("body")
            check(
                "WebSocket 实时通道已连接",
                "实时通道已连接" in ws_text,
                ws_text[:160].replace("\n", " "),
            )

            # 等待任务推进，确认日志 / 消息 / 资源曲线有实时数据
            page.wait_for_timeout(9000)
            check("运行日志实时滚动", page.locator(".log-line").count() > 0,
                  f"日志 {page.locator('.log-line').count()} 行")
            check("角色消息实时推送", page.locator(".chat-item").count() > 0,
                  f"消息 {page.locator('.chat-item').count()} 条")
            check("角色卡片出现执行状态", page.locator(".role-card.is-running, .role-card.is-success").count() > 0)
            page.screenshot(path=str(SHOT_DIR / "04-实时监控页.png"))

            # 等待任务完成
            deadline = time.time() + 120
            while time.time() < deadline:
                status_value = client.get(
                    f"/api/projects/{project_id}", headers=headers
                ).json()["project_status"]
                if status_value in {"completed", "failed", "stopped"}:
                    break
                time.sleep(1)
            page.wait_for_timeout(2500)
            check("资源曲线已绘制数据点", page.locator(".chart-legend").count() >= 1)
            page.screenshot(path=str(SHOT_DIR / "04b-实时监控页-完成.png"))

            # ---------------------------------------------------------------
            section("5. 项目详情页")
            page.goto(f"{base}/#/projects/{project_id}", wait_until="networkidle")
            page.wait_for_timeout(1400)
            check("详情页渲染成功", page.locator(".kv").count() >= 1)
            check("统计卡片渲染成功", page.locator(".stat").count() >= 4)
            check("阶段记录表格渲染成功", page.locator("table.data").count() >= 1)
            body_text = page.inner_text("body")
            check("展示隔离环境编号", "SA-" in body_text)
            page.screenshot(path=str(SHOT_DIR / "05-项目详情页.png"))

            # ---------------------------------------------------------------
            section("6. 漏洞列表页")
            page.goto(f"{base}/#/projects/{project_id}/vulnerabilities", wait_until="networkidle")
            page.wait_for_timeout(1400)
            rows = page.locator("table.data tbody tr").count()
            check("漏洞列表渲染成功", rows > 0, f"{rows} 行")
            vuln_text = page.inner_text("table.data")
            for column in ["漏洞编号", "漏洞标题", "风险等级", "验证状态", "文件位置"]:
                check(f"漏洞表包含「{column}」列", column in page.inner_text("table.data thead"))

            check("漏洞详情面板渲染成功", page.locator(".code.evidence").count() >= 1)
            check("筛选下拉可用", page.locator("select").count() >= 2)
            page.screenshot(path=str(SHOT_DIR / "06-漏洞列表页.png"))

            # 筛选高危
            page.select_option("select >> nth=0", "high")
            page.wait_for_timeout(1200)
            filtered = page.locator("table.data tbody tr").count()
            check("按风险等级筛选生效", 0 < filtered <= rows, f"筛选后 {filtered} / 全部 {rows}")

            # ---------------------------------------------------------------
            section("7. 攻击路径页")
            page.goto(f"{base}/#/projects/{project_id}/attack-paths", wait_until="networkidle")
            page.wait_for_timeout(1400)
            path_cards = page.locator(".card").count()
            check("攻击路径渲染成功", path_cards > 0, f"{path_cards} 张卡片")
            check("利用顺序时间线渲染成功", page.locator(".timeline-item").count() > 0,
                  f"{page.locator('.timeline-item').count()} 个步骤")
            path_text = page.inner_text("body")
            check("展示最终影响", "最终影响" in path_text)
            check("展示关联漏洞编号", "VULN-" in path_text)
            page.screenshot(path=str(SHOT_DIR / "07-攻击路径页.png"))

            # ---------------------------------------------------------------
            section("8. 报告页")
            page.goto(f"{base}/#/projects/{project_id}/report", wait_until="networkidle")
            page.wait_for_timeout(2200)
            check("报告页渲染成功", page.locator("iframe.report-frame").count() == 1)
            frame = page.frame_locator("iframe.report-frame")
            frame_body = frame.locator("body")
            check("报告 iframe 内容已渲染", frame_body.count() == 1)
            report_text = frame_body.inner_text() if frame_body.count() else ""
            for section_name in ["项目概述", "执行过程", "漏洞汇总", "攻击路径", "风险结论", "修复建议"]:
                check(f"报告含「{section_name}」章节", section_name in report_text)
            check("下载按钮可用", page.locator("text=下载报告").count() >= 1)
            page.screenshot(path=str(SHOT_DIR / "08-报告页.png"))

            # ---------------------------------------------------------------
            section("9. 系统配置页")
            page.goto(f"{base}/#/config", wait_until="networkidle")
            page.wait_for_timeout(1400)
            check("系统配置页渲染成功", page.locator(".field").count() >= 6,
                  f"{page.locator('.field').count()} 个配置项")
            config_text = page.inner_text("body")
            for key in ["isolation_type", "default_timeout_seconds", "max_concurrency", "retention_days"]:
                check(f"展示配置项 {key}", key in config_text)
            page.screenshot(path=str(SHOT_DIR / "09-系统配置页.png"))

            # ---------------------------------------------------------------
            section("10. 控制台错误检查")
            real_errors = [
                error for error in CONSOLE_ERRORS
                if "favicon" not in error.lower()
                and "403" not in error
                and "net::ERR" not in error
            ]
            check("浏览器控制台无错误", len(real_errors) == 0)
            for error in real_errors[:8]:
                print(f"       \033[31m{error[:150]}\033[0m")

            browser.close()

    except Exception as exc:
        print(f"\n\033[31m界面检查异常终止：{type(exc).__name__}: {exc}\033[0m")
        exit_code = 1
    finally:
        if not args.keep:
            try:
                client.delete(f"/api/projects/{project_id}", headers=headers)
            except Exception:
                pass
        client.close()

    section("检查结果汇总")
    total = PASS + FAIL
    print(f"  通过 \033[32m{PASS}\033[0m / {total}")
    if FAIL:
        print(f"  失败 \033[31m{FAIL}\033[0m")
        for name in FAILURES:
            print(f"    · {name}")
        exit_code = 1
    else:
        print("  \033[32m全部界面检查项通过\033[0m")
    print(f"\n  截图已保存至：{SHOT_DIR}")
    print()
    return exit_code


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    sys.exit(main())
