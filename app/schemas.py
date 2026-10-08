"""请求/响应数据模型（Pydantic）。

字段命名严格对应需求文档 §1.4.10 接口要求。
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

SourceType = Literal["local", "git"]
IsolationType = Literal["simulated", "docker"]


# ---------------------------------------------------------------------------
# 认证模块
# ---------------------------------------------------------------------------
class SystemInitRequest(BaseModel):
    username: str = Field(default="admin", min_length=3, max_length=50)
    password: str = Field(default="admin123", min_length=6, max_length=128)

    @field_validator("username", "password")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


# ---------------------------------------------------------------------------
# 项目模块
# ---------------------------------------------------------------------------
class ProjectCreateRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    source_type: SourceType = "local"
    source_path: str = Field(min_length=1, max_length=1000)
    task_content: str = Field(default="", max_length=4000)
    isolation_type: IsolationType = "simulated"

    @field_validator("project_name", "source_path", "task_content")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


# ---------------------------------------------------------------------------
# 系统配置模块
# ---------------------------------------------------------------------------
class ConfigUpdateItem(BaseModel):
    config_key: str = Field(min_length=1, max_length=80)
    config_value: str = Field(max_length=2000)


class ConfigUpdateRequest(BaseModel):
    items: list[ConfigUpdateItem] = Field(min_length=1, max_length=50)
