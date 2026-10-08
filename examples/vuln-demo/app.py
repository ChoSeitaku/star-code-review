"""示例业务服务的主应用（演示用）。

注意：本文件包含故意植入的安全缺陷，仅用于演示自动化安全评估系统的
分析、验证与攻击路径编排能力。请勿部署运行。

覆盖的缺陷类型：命令注入、XSS、路径遍历、动态代码执行、
服务端请求伪造、不安全反序列化、异常吞错、生产环境调试模式。
"""

import os
import pickle
import base64

from urllib.request import urlopen

from flask import Flask, request, render_template_string

import db
from config import API_BASE, UPLOAD_DIR

app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string("<h1>示例业务服务</h1><p>Portal Demo</p>")


@app.route("/login", methods=["POST"])
def login():
    """登录接口：查询条件直接来自请求参数。"""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    user = db.find_user_by_name(username)
    if user and db.check_password(username, password):
        return {"code": 0, "message": "登录成功", "user": user["username"]}
    return {"code": 1, "message": "用户名或密码错误"}


@app.route("/greet")
def greet():
    """欢迎页：把用户名直接拼接进 HTML，未做实体转义。"""
    username = request.args.get("username", "访客")
    return render_template_string(f"<h1>欢迎回来，{username}！</h1>")


@app.route("/ping")
def ping():
    """网络诊断接口：把用户输入拼接进系统命令。"""
    host = request.args.get("host", "127.0.0.1")
    result = os.system("ping -c 1 " + host)
    return {"code": 0, "message": f"诊断已执行，返回码 {result}"}


@app.route("/download")
def download():
    """文件下载接口：路径由用户输入拼接，未校验目录边界。"""
    filename = request.args.get("file", "readme.txt")
    with open(f"{UPLOAD_DIR}/{filename}", "r", encoding="utf-8") as handle:
        return {"code": 0, "content": handle.read()}


@app.route("/calc")
def calc():
    """计算器接口：使用 eval 执行用户提交的表达式。"""
    expression = request.args.get("expr", "1+1")
    return {"code": 0, "result": eval(f"({expression})")}


@app.route("/preview")
def preview():
    """链接预览接口：请求目标由用户输入控制，可被诱导访问内网。"""
    target_url = request.args.get("url", "")
    with urlopen(API_BASE + target_url, timeout=5) as response:
        return {"code": 0, "body": response.read(2048).decode("utf-8", "replace")}


@app.route("/session/restore", methods=["POST"])
def restore_session():
    """会话恢复接口：直接反序列化外部数据。"""
    raw = request.form.get("state", "")
    try:
        state = pickle.loads(base64.b64decode(raw))
        return {"code": 0, "state": str(state)}
    except:
        pass
    return {"code": 1, "message": "会话恢复失败"}


@app.route("/report/export")
def export_report():
    """报表导出接口：异常被静默吞掉，失败原因不留痕。"""
    try:
        with open(f"{UPLOAD_DIR}/report.csv", "r", encoding="utf-8") as handle:
            content = handle.read()
    except:
        pass
    return {"code": 0, "content": content}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
