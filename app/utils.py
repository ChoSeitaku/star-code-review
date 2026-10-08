"""通用工具函数。"""

from __future__ import annotations

import datetime as _dt
import re

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def now_str() -> str:
    """当前本地时间字符串，统一用于所有 created_at / updated_at 字段。"""
    return _dt.datetime.now().strftime(TIME_FORMAT)


def parse_time(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    try:
        return _dt.datetime.strptime(value, TIME_FORMAT)
    except ValueError:
        return None


def elapsed_seconds(started_at: str | None, finished_at: str | None) -> float | None:
    start = parse_time(started_at)
    end = parse_time(finished_at)
    if start is None or end is None:
        return None
    return round((end - start).total_seconds(), 2)


def truncate(text: str | None, limit: int = 500) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def safe_slug(text: str, fallback: str = "item", max_len: int = 60) -> str:
    """把任意名称转成安全的文件名片段。"""
    slug = re.sub(r"[^A-Za-z0-9._一-鿿-]+", "_", (text or "").strip())
    slug = slug.strip("._-")
    if not slug:
        return fallback
    return slug[:max_len]


def estimate_tokens(text: str | None) -> int:
    """粗略估算文本 token 数（§1.4.8 resource_usages.token_count）。

    规则引擎本身不调用大模型，此处按字符量估算处理成本，
    中文按 1 字 ≈ 1 token，英文按 4 字符 ≈ 1 token 近似。
    """
    if not text:
        return 0
    cjk = len(re.findall(r"[一-鿿]", text))
    other = len(text) - cjk
    return int(cjk + other / 4)
