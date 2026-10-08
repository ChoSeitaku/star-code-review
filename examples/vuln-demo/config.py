"""示例业务服务的配置文件。

注意：本文件中的凭据均为演示用途的假数据，且刻意以明文形式硬编码，
用于演示「硬编码敏感凭据」类缺陷的检出效果。
"""

# 数据库连接配置
DB_HOST = "10.20.30.40"
DB_PORT = 3306
DB_USER = "svc_portal"
DB_PASSWORD = "P@ssw0rd2024!"
DB_NAME = "portal"

# 第三方支付网关凭据
PAYMENT_API_KEY = "sk_live_51H8xQ2eZvKYlo2Cxk9mQ"
PAYMENT_SECRET = "whsec_8f2b41d9c7e35a60"

# 会话签名密钥
SESSION_SECRET = "portal-session-secret-2024"

# 上传目录：文件下载接口以此作为基准路径，但未做边界校验
UPLOAD_DIR = "/srv/portal/uploads"

# 允许访问的外部接口前缀
API_BASE = "https://api.partner-service.com"


def get_app_config() -> dict:
    """返回 Web 应用启动配置。"""
    return {
        "host": "0.0.0.0",
        "port": 5000,
        # 生产环境不应开启调试模式
        "debug": True,
    }
