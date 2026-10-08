"""内置规则引擎：源码安全缺陷模式库。

设计说明
--------
每条规则由「触发模式 trigger」+「可选污点模式 taint」组成：
- trigger 命中表示出现了危险调用/危险写法；
- taint   命中表示该调用确实拼接了变量（用户可控输入），而非固定常量。

两者都命中才判定为漏洞，可显著降低纯关键字匹配的误报率。
匹配在「当前行 + 后 2 行」的滑动窗口上进行，以覆盖跨行的函数调用。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    rule_key: str
    title: str
    risk_level: str          # high / medium / low
    category: str            # 用于攻击路径编排
    trigger: str             # 触发正则
    condition: str           # 触发条件说明
    impact: str              # 影响说明
    remediation: str         # 修复建议
    taint: str = ""          # 污点正则（为空表示无需污点确认）
    exclude: str = ""        # 命中该正则则跳过（白名单/已修复写法）
    suffixes: tuple[str, ...] = ()   # 适用文件后缀，空表示全部

    _trigger_re: re.Pattern = field(init=False, repr=False, compare=False)
    _taint_re: re.Pattern | None = field(init=False, repr=False, compare=False)
    _exclude_re: re.Pattern | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # MULTILINE：匹配在「当前行 + 后 2 行」的滑动窗口上进行，
        # 需要让 ^ / $ 按行生效，否则行尾断言（如 `except:`）永远无法命中。
        flags = re.IGNORECASE | re.MULTILINE
        object.__setattr__(self, "_trigger_re", re.compile(self.trigger, flags))
        object.__setattr__(
            self, "_taint_re", re.compile(self.taint, flags) if self.taint else None
        )
        object.__setattr__(
            self, "_exclude_re", re.compile(self.exclude, flags) if self.exclude else None
        )

    def applies_to(self, suffix: str) -> bool:
        return not self.suffixes or suffix.lower() in self.suffixes

    def match_window(self, window: str) -> re.Match | None:
        """在滑动窗口文本上执行匹配，未命中返回 None。"""
        if self._exclude_re and self._exclude_re.search(window):
            return None
        match = self._trigger_re.search(window)
        if match is None:
            return None
        if self._taint_re and not self._taint_re.search(window):
            return None
        return match


# ---------------------------------------------------------------------------
# 污点模式：变量拼接 / 格式化插值的通用写法
# ---------------------------------------------------------------------------
TAINT_CONCAT = (
    r"(f[\"'])"                       # f-string
    r"|(\+\s*[A-Za-z_$])"             # "..." + var
    r"|([A-Za-z_$0-9_\)\]]\s*\+)"     # var + "..."
    r"|(\.format\s*\()"               # "...".format(
    r"|(%\s*[\(\w])"                  # "..." % var
    r"|(\$\{)"                        # JS 模板串
)
TAINT_USER_INPUT = r"(request|req\.|input\(|params|args|form|query|body|user_|getParameter)"

# ---------------------------------------------------------------------------
# 规则库
# ---------------------------------------------------------------------------
RULES: tuple[Rule, ...] = (
    Rule(
        rule_key="SQL_INJECTION",
        title="SQL 注入",
        risk_level="high",
        category="injection",
        trigger=r"\.(execute|executemany)\s*\(|cursor\.execute",
        taint=TAINT_CONCAT,
        exclude=r"(execute\s*\(\s*[\"'][^\"']*[\"']\s*,\s*\(|%s[\"']\s*,\s*\()",
        condition="将外部输入直接拼接进 SQL 语句后交给数据库执行，未使用参数化查询。",
        impact="攻击者可构造恶意 SQL 片段绕过认证、读取任意数据表，甚至通过堆叠注入写入文件或执行系统命令，导致全库数据泄露。",
        remediation="改用参数化查询（占位符 + 参数元组），禁止使用字符串拼接、f-string 或 % 格式化构造 SQL；对数据库账户遵循最小权限原则。",
    ),
    Rule(
        rule_key="COMMAND_INJECTION",
        title="命令注入",
        risk_level="high",
        category="injection",
        trigger=r"os\.(system|popen)\s*\(|subprocess\.(run|call|check_output|check_call|Popen)\s*\(",
        taint=TAINT_CONCAT,
        exclude=r"shell\s*=\s*False|shlex\.quote|\[[\"']",
        condition="将外部输入拼接进操作系统命令并执行，且未做转义或白名单校验。",
        impact="攻击者可在服务器上以应用进程权限执行任意系统命令，读取敏感文件、反弹 shell、横向渗透，最终完全接管主机。",
        remediation="避免拼接命令字符串；使用参数数组形式调用（如 subprocess.run([...], shell=False)）；确需拼接时使用 shlex.quote 并配合命令白名单。",
    ),
    Rule(
        rule_key="HARDCODED_SECRET",
        title="硬编码敏感凭据",
        risk_level="high",
        category="credential",
        trigger=r"(password|passwd|pwd|secret|api_key|apikey|access_key|token|private_key)\s*[:=]\s*[\"'][^\"']{5,}[\"']",
        exclude=r"(os\.environ|getenv|environ\.get|input\(|None\s*$|[\"']{2}|YOUR_|PLACEHOLDER|xxxx)",
        condition="源码中以明文常量形式写入了口令、密钥或访问令牌。",
        impact="任何可读取源码或反编译产物的人员（含通过其他漏洞读取文件的攻击者）均可直接获得凭据，用于访问数据库、第三方接口或云资源。",
        remediation="将敏感配置迁移至环境变量或密钥管理服务；立即轮换已泄露的凭据；在 CI 中加入密钥扫描，防止再次提交。",
    ),
    Rule(
        rule_key="XSS",
        title="跨站脚本（XSS）",
        risk_level="high",
        category="injection",
        trigger=r"render_template_string\s*\(|innerHTML\s*=|document\.write\s*\(|\.html\s*\(\s*[A-Za-z_$]",
        taint=TAINT_CONCAT + r"|" + TAINT_USER_INPUT,
        condition="将外部输入未经 HTML 转义直接渲染到页面中。",
        impact="攻击者可注入恶意脚本，在受害者浏览器中窃取会话 Cookie、劫持页面操作、实施钓鱼或蠕虫式传播。",
        remediation="输出到 HTML 上下文时统一进行实体转义（如 Jinja2 自动转义、escapeHtml）；避免使用 innerHTML，改用 textContent；配置 CSP 响应头作为纵深防御。",
    ),
    Rule(
        rule_key="PATH_TRAVERSAL",
        title="路径遍历",
        risk_level="high",
        category="file_access",
        trigger=r"\bopen\s*\(|send_file\s*\(|send_from_directory\s*\(",
        taint=TAINT_CONCAT,
        exclude=r"os\.path\.abspath|realpath|secure_filename|startswith",
        condition="文件路径由外部输入拼接而成，未对 ../ 等穿越序列做规范化与白名单校验。",
        impact="攻击者可读取或覆盖隔离环境外的任意文件，例如配置文件、密钥文件、系统账户文件，为后续提权提供支撑。",
        remediation="使用 os.path.realpath 规范化后校验是否位于允许的根目录内；优先使用文件名白名单映射，拒绝包含路径分隔符的输入。",
    ),
    Rule(
        rule_key="WEAK_CRYPTO",
        title="使用弱哈希算法保护口令",
        risk_level="medium",
        category="crypto",
        trigger=r"hashlib\.(md5|sha1)\s*\(|\b(md5|sha1)\s*\(",
        taint=r"(password|passwd|pwd|secret|credential|login)",
        condition="使用 MD5/SHA1 等快速哈希算法存储或校验口令，且未加盐、未使用慢哈希。",
        impact="MD5/SHA1 抗碰撞性已被攻破，且计算速度极快，攻击者可通过彩虹表或 GPU 暴力破解在短时间内还原明文口令。",
        remediation="改用 bcrypt、scrypt 或 Argon2 等自适应慢哈希算法，并为每个用户生成独立随机盐。",
    ),
    Rule(
        rule_key="PLAINTEXT_PASSWORD",
        title="口令明文存储",
        risk_level="high",
        category="credential",
        trigger=r"[\"']password[\"']\s*:\s*[A-Za-z_][\w\.]*\b|password\s*=\s*[a-z_]*password\b",
        exclude=r"(hash|digest|bcrypt|argon|pbkdf2|encrypted)",
        condition="用户口令以明文形式写入存储结构，未经过任何散列或加密处理。",
        impact="一旦数据库或存储文件泄露，全部用户口令将直接暴露；由于口令复用普遍，还会导致用户在其它系统的账户被撞库攻击。",
        remediation="存储口令的不可逆哈希（bcrypt/Argon2）而非明文；同时排查历史数据，对存量明文口令强制重置。",
    ),
    Rule(
        rule_key="INSECURE_DESERIALIZATION",
        title="不安全的反序列化",
        risk_level="high",
        category="injection",
        trigger=r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\(|marshal\.loads?\s*\(",
        exclude=r"yaml\.safe_load|SafeLoader",
        condition="对象经反序列化直接还原，数据来源不可信时会在反序列化过程中触发任意代码执行。",
        impact="攻击者可构造恶意序列化载荷，在反序列化阶段直接执行任意代码，等同于获取服务器控制权。",
        remediation="禁止对不可信数据使用 pickle/marshal；YAML 使用 yaml.safe_load；跨进程数据交换改用 JSON 等纯数据格式。",
    ),
    Rule(
        rule_key="CODE_INJECTION",
        title="动态代码执行",
        risk_level="high",
        category="injection",
        trigger=r"\beval\s*\(|\bexec\s*\(",
        taint=TAINT_CONCAT,
        exclude=r"ast\.literal_eval",
        condition="使用 eval/exec 执行由外部输入拼接而成的代码字符串。",
        impact="攻击者可注入并执行任意 Python 代码，直接获得服务器权限，是危害最高的漏洞类型之一。",
        remediation="彻底移除 eval/exec 的动态执行逻辑；确有解析需求时使用 ast.literal_eval 或专用解析器（如 json.loads）。",
    ),
    Rule(
        rule_key="SSRF",
        title="服务端请求伪造（SSRF）",
        risk_level="medium",
        category="injection",
        trigger=r"requests\.(get|post|put|head)\s*\(|urlopen\s*\(|httpx\.(get|post)\s*\(",
        taint=TAINT_CONCAT,
        exclude=r"[\"']https?://[a-z0-9\.\-]+[\"']\s*\)\s*$",
        condition="请求目标 URL 由外部输入控制，未校验目标地址是否属于允许范围。",
        impact="攻击者可以应用服务器为跳板探测并访问内网服务、读取云厂商元数据接口获取临时凭据，突破网络边界。",
        remediation="对目标地址实施协议与域名白名单；解析 DNS 后校验目标 IP 不属于内网网段与环回地址；禁止跟随重定向。",
    ),
    Rule(
        rule_key="DEBUG_ENABLED",
        title="生产环境开启调试模式",
        risk_level="medium",
        category="config",
        trigger=r"debug\s*=\s*True|DEBUG\s*=\s*True",
        condition="应用以调试模式启动，异常时会向客户端返回完整堆栈与源码片段。",
        impact="错误页面会泄露框架版本、文件绝对路径、源码上下文甚至环境变量，为攻击者提供精准的利用情报。",
        remediation="生产环境关闭 debug；通过环境变量控制该开关并在部署流水线中强制校验；使用统一错误页。",
    ),
    Rule(
        rule_key="BROAD_EXCEPTION",
        title="异常处理吞掉错误",
        risk_level="low",
        category="config",
        trigger=r"except\s*(Exception)?\s*:\s*$|except\s*:\s*pass",
        exclude=r"(logger|logging|log\.|raise|print)",
        condition="捕获异常后既不记录日志也不向上抛出，错误被静默吞掉。",
        impact="安全事件（如鉴权失败、注入尝试）不会留下任何痕迹，攻击行为难以被及时发现，同时增加故障排查难度。",
        remediation="捕获异常后至少记录日志；明确捕获具体异常类型；对安全相关失败路径进行告警。",
    ),
)

RULES_BY_KEY: dict[str, Rule] = {rule.rule_key: rule for rule in RULES}


def rules_for_suffix(suffix: str) -> list[Rule]:
    return [rule for rule in RULES if rule.applies_to(suffix)]


def rule_doc() -> list[dict]:
    """返回规则清单，供 README / 接口说明展示。"""
    return [
        {
            "rule_key": rule.rule_key,
            "title": rule.title,
            "risk_level": rule.risk_level,
            "category": rule.category,
        }
        for rule in RULES
    ]
