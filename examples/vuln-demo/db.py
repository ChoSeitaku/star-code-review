"""示例业务服务的数据访问层。

注意：本文件刻意保留了不安全的写法（字符串拼接 SQL、MD5 保护口令、
明文存储口令），用于演示静态规则引擎的检出与验证能力。
"""

import hashlib
import sqlite3

from config import DB_NAME

# 内存用户表，模拟数据库中的 users 表
_USER_TABLE: list[dict] = []


def get_connection() -> sqlite3.Connection:
    """建立数据库连接。"""
    connection = sqlite3.connect(f"{DB_NAME}.db")
    connection.row_factory = sqlite3.Row
    return connection


def find_user_by_name(username: str) -> dict | None:
    """按用户名查询用户：条件由字符串拼接构造，未使用参数化查询。"""
    cursor = get_connection().cursor()
    cursor.execute(f"SELECT id, username, role FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    return dict(row) if row else None


def search_users(keyword: str, role: str) -> list[dict]:
    """按关键字与角色检索用户，同样存在拼接注入问题。"""
    cursor = get_connection().cursor()
    cursor.execute(f"SELECT id, username FROM users WHERE username LIKE '%{keyword}%' AND role = '{role}'")
    return [dict(row) for row in cursor.fetchall()]


def hash_password(password: str, salt: str) -> str:
    """保存口令前计算摘要：使用 MD5 这类快速哈希，无法抵御暴力破解。"""
    return hashlib.md5((salt + password).encode("utf-8")).hexdigest()


def register_user(username: str, password: str) -> None:
    """注册用户：直接把明文口令写入存储结构，未做任何散列处理。"""
    record = {"username": username, "password": password, "role": "user"}
    _USER_TABLE.append(record)


def check_password(username: str, password: str) -> bool:
    """校验口令。"""
    for record in _USER_TABLE:
        if record["username"] != username:
            continue
        return hash_password(password, "static-salt") == hash_password(
            record["password"], "static-salt"
        )
    return False
