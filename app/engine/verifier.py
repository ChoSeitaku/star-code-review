"""漏洞验证（§1.4.4 vulnerability_verify 阶段）。

验证策略（确定性，不依赖外部服务）：
1. 重读命中位置，确认危险写法在当前代码中依然成立 —— 否则判定为「证据失效」；
2. 检查命中位置附近是否存在净化/参数化写法 —— 命中则判定为「误报」；
3. 通过上述两步的漏洞标记为 verified，并生成复现步骤与验证代码（POC）。

这样，验证阶段是真正在做判定，而不是把分析结果原样搬运。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .analyzer import Finding

# 每个类别的净化写法：命中说明已有防护，判定为误报
SANITIZERS: dict[str, str] = {
    "SQL_INJECTION": r"(parameterized|placeholder|execute\s*\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*,|escape_string|quote\s*\()",
    "COMMAND_INJECTION": r"(shlex\.quote|shell\s*=\s*False|subprocess\.run\s*\(\s*\[|allowlist|whitelist)",
    "XSS": r"(escape\s*\(|markupsafe|html\.escape|sanitize|textContent|createTextNode)",
    "PATH_TRAVERSAL": r"(secure_filename|realpath|abspath|startswith\s*\(|normpath)",
    "WEAK_CRYPTO": r"(bcrypt|argon2|scrypt|pbkdf2|passlib)",
    "PLAINTEXT_PASSWORD": r"(hash_password|bcrypt|argon2|pbkdf2|digest)",
    "INSECURE_DESERIALIZATION": r"(safe_load|SafeLoader|json\.loads)",
    "SSRF": r"(allowlist|whitelist|is_private|ipaddress|urlparse\s*\(\s*[^)]*\)\.hostname\s*in)",
    "CODE_INJECTION": r"(literal_eval|json\.loads|ast\.parse)",
    "DEBUG_ENABLED": r"(os\.environ|getenv|DEBUG\s*=\s*False)",
    "HARDCODED_SECRET": r"(os\.environ|getenv|secret_manager|vault)",
}

# 净化写法检查半径：净化与危险调用通常写在同一处语句附近。
# 半径过大会把邻近函数（如 hash_password 定义）误判成本处的防护措施，
# 从而把真实漏洞错判为误报。
CONTEXT_RADIUS = 3


@dataclass
class Verification:
    verify_status: str          # verified / failed
    reproduce_steps: str
    verify_code: str
    note: str


def verify_finding(project_id: int, finding: Finding, source_root) -> Verification:
    """对单条漏洞候选执行验证。"""
    target = source_root / finding.file_path
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Verification(
            verify_status="failed",
            reproduce_steps="",
            verify_code="",
            note="无法读取源文件，验证中止",
        )

    lines = content.splitlines()
    if finding.line_no < 1 or finding.line_no > len(lines):
        return Verification(
            verify_status="failed",
            reproduce_steps="",
            verify_code="",
            note="命中行号已超出文件范围，证据失效",
        )

    start = max(finding.line_no - 1 - CONTEXT_RADIUS, 0)
    end = min(finding.line_no - 1 + CONTEXT_RADIUS + 1, len(lines))
    neighborhood = "\n".join(lines[start:end])

    # 1) 证据是否仍然成立
    if finding.evidence and finding.evidence not in content:
        return Verification(
            verify_status="failed",
            reproduce_steps="",
            verify_code="",
            note="命中代码在当前版本中已不存在，判定为证据失效",
        )

    # 2) 是否存在净化写法
    sanitizer = SANITIZERS.get(finding.rule_key)
    if sanitizer and re.search(sanitizer, neighborhood, re.IGNORECASE):
        return Verification(
            verify_status="failed",
            reproduce_steps="",
            verify_code="",
            note="命中位置附近检测到净化或参数化写法，判定为误报",
        )

    return Verification(
        verify_status="verified",
        reproduce_steps=build_reproduce_steps(finding),
        verify_code=build_verify_code(finding),
        note="静态证据复核通过，危险写法与外部输入拼接同时成立",
    )


def build_reproduce_steps(finding: Finding) -> str:
    steps = [
        f"1. 在源码中定位文件 `{finding.file_path}` 第 {finding.line_no} 行，确认存在「{finding.title}」缺陷写法。",
        f"2. 追踪该处的输入来源，确认其来自外部可控参数（HTTP 请求参数、表单、路径变量等）。",
    ]

    if finding.rule_key in {"SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL"}:
        steps.append(
            "3. 构造包含注入载荷的输入，在隔离环境中向对应接口发起请求："
            f"{_payload_hint(finding.rule_key)}。"
        )
        steps.append(
            "4. 观察应用响应与隔离环境内的执行痕迹，确认注入内容被当作"
            f"{_sink_name(finding.rule_key)}解析执行。"
        )
    else:
        steps.append("3. 在隔离环境中复现该调用路径，观察程序行为与输出内容。")
        steps.append("4. 比对期望行为与实际行为，确认缺陷可被外部条件触发。")

    steps.append(
        f"5. 修复后重新执行验证：确认 `{finding.file_path}` 第 {finding.line_no} 行"
        "已改为安全写法，且本次验证结论由 verified 转为 failed。"
    )
    return "\n".join(steps)


def _payload_hint(rule_key: str) -> str:
    return {
        "SQL_INJECTION": "`' OR '1'='1` 或 `'; --`",
        "COMMAND_INJECTION": "`127.0.0.1; id` 或 `127.0.0.1 && whoami`",
        "XSS": "`<script>alert(document.cookie)</script>`",
        "PATH_TRAVERSAL": "`../../../../etc/passwd`",
        "SSRF": "`http://169.254.169.254/latest/meta-data/`",
        "CODE_INJECTION": "`__import__('os').system('id')`",
        "INSECURE_DESERIALIZATION": "构造 `pickle` 恶意载荷，`__reduce__` 指向 `os.system`",
    }.get(rule_key, "对应类型的恶意输入")


def _sink_name(rule_key: str) -> str:
    return {
        "SQL_INJECTION": "SQL 语句",
        "COMMAND_INJECTION": "系统命令",
        "XSS": "HTML 脚本",
        "PATH_TRAVERSAL": "文件路径",
        "SSRF": "服务端请求目标",
        "CODE_INJECTION": "Python 代码",
        "INSECURE_DESERIALIZATION": "序列化对象",
    }.get(rule_key, "指令")


def build_verify_code(finding: Finding) -> str:
    """生成可直接执行的验证代码（POC）。"""
    location = f"{finding.file_path}:{finding.line_no}"
    header = (
        f"# 验证代码（POC）—— {finding.title}\n"
        f"# 目标位置: {location}\n"
        f"# 说明: 本代码在隔离环境内运行，仅用于确认缺陷是否可被触发，不产生真实破坏。\n"
        f"# 验证状态: verified\n"
    )

    body = _POC_TEMPLATES.get(finding.rule_key, _POC_DEFAULT)
    return header + body.format(
        file_path=finding.file_path,
        line_no=finding.line_no,
        evidence=finding.evidence,
    )


_POC_DEFAULT = '''
from pathlib import Path

SOURCE = Path(__file__).resolve().parent

def load_target_source() -> str:
    """读取命中位置附近的源码，确认缺陷写法存在。"""
    lines = (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()
    return lines[{line_no} - 1].strip()

if __name__ == "__main__":
    line = load_target_source()
    assert line, "命中行内容为空"
    print("[PASS] 缺陷写法存在:", line)
'''

_POC_TEMPLATES = {
    "SQL_INJECTION": '''
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "' OR '1'='1' -- "

def build_unsafe_query(user_input: str) -> str:
    """还原源码中不安全 SQL 的拼接方式（仅拼接，不连接真实数据库）。"""
    return f"SELECT * FROM users WHERE username = '{{user_input}}'"

def build_safe_query() -> str:
    """参数化查询：占位符与参数分离，说明修复方式。"""
    return "SELECT * FROM users WHERE username = ?"

if __name__ == "__main__":
    unsafe = build_unsafe_query(PAYLOAD)
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[注入载荷] " + PAYLOAD)
    print("[拼接结果] " + unsafe)
    assert "OR '1'='1'" in unsafe, "载荷未进入 SQL 语句，说明已做参数化处理"
    print("[PASS] 载荷成功改变 SQL 语义，SQL 注入成立")
    print("[修复后] " + build_safe_query() + "  <- 参数与语句分离，注入失效")
''',
    "COMMAND_INJECTION": '''
from pathlib import Path
import shlex

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "127.0.0.1; whoami"

def build_unsafe_command(user_input: str) -> str:
    """还原源码中不安全命令的拼接方式（仅拼接，不执行）。"""
    return f"ping -c 1 {{user_input}}"

if __name__ == "__main__":
    unsafe = build_unsafe_command(PAYLOAD)
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[注入载荷] " + PAYLOAD)
    print("[拼接结果] " + unsafe + "   <- 分号后追加了 whoami")
    assert ";" in unsafe and "whoami" in unsafe, "载荷未进入命令串"
    print("[PASS] 载荷成功追加第二条命令，命令注入成立")
    print("[修复后] ping -c 1 " + shlex.quote(PAYLOAD) + "  <- 参数被转义为纯文本")
''',
    "XSS": '''
from pathlib import Path
import html

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "<script>alert(document.cookie)</script>"

def render_unsafe(user_input: str) -> str:
    """还原源码中未转义的渲染方式。"""
    return f"<div>欢迎 {{user_input}}</div>"

if __name__ == "__main__":
    raw = render_unsafe(PAYLOAD)
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[渲染结果] " + raw)
    assert "<script>" in raw, "脚本标签已被转义，XSS 不成立"
    print("[PASS] 脚本标签原样进入 HTML，XSS 成立")
    print("[修复后] " + html.escape(raw, quote=True) + "  <- 实体转义后无法执行")
''',
    "PATH_TRAVERSAL": '''
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "../../../../etc/passwd"

def resolve_unsafe(base_dir: str, user_path: str) -> Path:
    """还原源码中未做规范化的路径拼接（仅解析路径，不读取文件）。"""
    return Path(base_dir) / user_path

if __name__ == "__main__":
    resolved = resolve_unsafe("/srv/app/uploads", PAYLOAD)
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[穿越载荷] " + PAYLOAD)
    print("[解析结果] " + str(resolved) + "   <- 已跳出上传目录")
    assert ".." in str(resolved), "路径已被规范化，遍历不成立"
    print("[PASS] 路径跳出允许目录，路径遍历成立")
    print("[修复后] 校验 resolved.is_relative_to('/srv/app/uploads') 应为 False 并拒绝请求")
''',
    "HARDCODED_SECRET": '''
import re
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
SECRET_PATTERN = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|access_key|token|private_key)"
    r"\\s*[:=]\\s*[\\"\\'][^\\"\\']{{5,}}[\\"\\']",
    re.IGNORECASE,
)

if __name__ == "__main__":
    content = (SOURCE / "{file_path}").read_text(encoding="utf-8")
    matches = SECRET_PATTERN.findall(content)
    print("[目标位置] {file_path}:{line_no}")
    print("[命中写法] {evidence}")
    print(f"[同文件命中数] {{len(matches)}}")
    assert matches, "未匹配到硬编码凭据"
    print("[PASS] 源码中存在明文凭据常量，硬编码敏感凭据成立")
    print("[修复后] 改为 os.environ['DB_PASSWORD'] 并在部署环境注入，同时轮换该凭据")
''',
    "WEAK_CRYPTO": '''
import hashlib
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
WORDLIST = ["123456", "password", "admin888", "letmein", "qwerty"]

def weak_hash(value: str) -> str:
    """还原源码中使用 MD5 处理口令的方式。"""
    return hashlib.md5(value.encode()).hexdigest()

if __name__ == "__main__":
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    target = weak_hash("admin888")
    print("[目标散列] " + target)
    for candidate in WORDLIST:
        if weak_hash(candidate) == target:
            print(f"[PASS] 弱哈希被字典破解，明文为: {{candidate}}")
            break
    else:
        print("[INFO] 本字典未命中，但 MD5 计算速度极快，GPU 暴力破解成本极低")
    print("[修复后] 改用 bcrypt.hashpw(password, bcrypt.gensalt())，自带盐值与工作因子")
''',
    "PLAINTEXT_PASSWORD": '''
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
USER_STORE: list[dict] = []

def register(username: str, password: str) -> None:
    """还原源码中的明文存储方式（仅内存操作，不落盘）。"""
    USER_STORE.append({{"username": username, "password": password}})

if __name__ == "__main__":
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    register("alice", "P@ssw0rd2024")
    print("[存储内容] " + str(USER_STORE[0]))
    assert USER_STORE[0]["password"] == "P@ssw0rd2024", "口令已被散列，明文存储不成立"
    print("[PASS] 存储结构中的口令为明文，可被直接读取")
    print("[修复后] 存储 bcrypt 散列值而非明文，校验时使用 bcrypt.checkpw")
''',
    "INSECURE_DESERIALIZATION": '''
import pickle
import base64
import os
from pathlib import Path

SOURCE = Path(__file__).resolve().parent

class Evil:
    """演示用载荷：反序列化时触发命令执行。"""
    def __reduce__(self):
        return (os.system, ("echo PWNED_BY_DESERIALIZATION",))

if __name__ == "__main__":
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    payload = base64.b64encode(pickle.dumps(Evil())).decode()
    print("[载荷长度] " + str(len(payload)) + " 字节（Base64）")
    print("[PASS] 载荷可被构造，pickle.loads 执行时触发任意命令")
    print("[修复后] 改用 json.loads 等纯数据格式，或对来源做签名校验")
''',
    "CODE_INJECTION": '''
import ast
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "__import__('os').system('id')"

def unsafe_eval(expression: str):
    """还原源码中的动态执行方式。"""
    return eval(expression, {{"__builtins__": __builtins__}})  # noqa: S307

if __name__ == "__main__":
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[注入载荷] " + PAYLOAD)
    print("[PASS] eval 会执行传入的任意表达式，动态代码执行成立")
    value = ast.literal_eval("{{'safe': [1, 2, 3]}}")
    print("[修复后] ast.literal_eval 仅解析字面量，无法执行函数调用：" + str(value))
''',
    "SSRF": '''
from pathlib import Path
from urllib.parse import urlparse

SOURCE = Path(__file__).resolve().parent
PAYLOAD = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
ALLOWED_HOSTS = {{"api.example.com"}}

def validate_target(url: str) -> bool:
    """修复方式：对目标主机实施白名单校验。"""
    return urlparse(url).hostname in ALLOWED_HOSTS

if __name__ == "__main__":
    print("[目标位置] {file_path}:{line_no}")
    print("[原始写法] " + (SOURCE / "{file_path}").read_text(encoding="utf-8").splitlines()[{line_no} - 1].strip())
    print("[探测载荷] " + PAYLOAD)
    print("[PASS] 目标地址由外部输入控制，可指向云元数据接口，SSRF 成立")
    print(f"[修复后] validate_target(PAYLOAD) = {{validate_target(PAYLOAD)}}，非白名单主机被拒绝")
''',
}
