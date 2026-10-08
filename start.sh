#!/usr/bin/env bash
# ==========================================================================
#  自动化安全评估系统 - 一键启动（Linux / macOS / Git Bash）
#  首次运行会自动安装后端依赖并构建前端
# ==========================================================================
set -e

cd "$(dirname "$0")"

PY=".venv/Scripts/python.exe"
[ -x "$PY" ] || PY=".venv/bin/python"
[ -x "$PY" ] || { echo "[错误] 未找到虚拟环境，请先执行: python -m venv .venv"; exit 1; }

echo
echo "============================================================"
echo "  自动化安全评估系统"
echo "============================================================"
echo

# ---- 1. 后端依赖 ----
echo "[1/3] 检查后端依赖..."
if ! "$PY" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "      正在安装后端依赖..."
    if command -v uv >/dev/null 2>&1; then
        uv pip install --python "$PY" -e .
    else
        "$PY" -m pip install -e .
    fi
fi
echo "      后端依赖就绪"

# ---- 2. 前端构建 ----
echo "[2/3] 检查前端构建产物..."
if [ ! -f "frontend/dist/index.html" ]; then
    echo "      未找到 frontend/dist，正在构建前端..."
    if ! command -v npm >/dev/null 2>&1; then
        echo "[错误] 未检测到 npm，请先安装 Node.js"
        exit 1
    fi
    cd frontend
    [ -d node_modules ] || npm install --no-audit --no-fund
    npm run build
    cd ..
else
    echo "      前端产物已存在"
fi

# ---- 3. 启动服务 ----
echo "[3/3] 启动后端服务..."
echo
echo "      访问地址: http://127.0.0.1:8002"
echo "      接口文档: http://127.0.0.1:8002/api/docs"
echo "      默认账户: admin / admin123 （首次使用请在登录页点击「初始化系统」）"
echo
echo "      按 Ctrl+C 停止服务"
echo

export PYTHONIOENCODING=utf-8
exec "$PY" -m app.main
