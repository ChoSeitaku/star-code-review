-- ============================================================================
-- 自动化安全评估系统 - 数据库初始化脚本
-- 数据库: SQLite 3
-- 说明: 本脚本幂等，可重复执行（全部使用 CREATE TABLE IF NOT EXISTS）
-- 表结构严格对应需求文档 §1.4.8 数据表要求
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. users 用户表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',      -- admin / user
    status        TEXT    NOT NULL DEFAULT 'active',    -- active / disabled
    created_at    TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- 2. projects 项目表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_name   TEXT    NOT NULL,
    source_type    TEXT    NOT NULL DEFAULT 'local',    -- local / git
    source_path    TEXT    NOT NULL,
    task_content   TEXT,
    project_status TEXT    NOT NULL DEFAULT 'created',  -- created/running/completed/failed/stopped
    created_by     INTEGER,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL,
    FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------------------
-- 3. runtime_stages 运行阶段表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runtime_stages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id    INTEGER NOT NULL,
    stage_name    TEXT    NOT NULL,                     -- environment_scan/code_analysis/
                                                        -- vulnerability_verify/report_generate/done
    stage_status  TEXT    NOT NULL DEFAULT 'idle',      -- idle/running/success/failed/stopped
    started_at    TEXT,
    finished_at   TEXT,
    error_message TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 4. worker_tasks 角色任务表（§1.4.5：需含任务内容/开始/结束/结果/错误信息）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS worker_tasks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL,
    stage_id       INTEGER,
    worker_role    TEXT    NOT NULL,                    -- general_processor/env_checker/code_analyzer/
                                                        -- vuln_verifier/report_writer/ops_helper
    task_content   TEXT,
    task_status    TEXT    NOT NULL DEFAULT 'idle',     -- idle/running/success/failed
    result_summary TEXT,
    error_message  TEXT,
    started_at     TEXT,
    finished_at    TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    FOREIGN KEY (stage_id)   REFERENCES runtime_stages (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 5. vulnerabilities 漏洞表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id           INTEGER NOT NULL,
    vuln_code            TEXT    NOT NULL,              -- VULN-001
    vuln_title           TEXT    NOT NULL,
    risk_level           TEXT    NOT NULL DEFAULT 'low',-- high/medium/low
    file_path            TEXT,
    condition_text       TEXT,                          -- 触发条件
    impact_text          TEXT,                          -- 影响说明（§1.4.12 漏洞详情要求）
    evidence_text        TEXT,                          -- 证据内容（命中代码）
    verify_status        TEXT    NOT NULL DEFAULT 'unverified', -- unverified/verified/failed
    reproduce_steps_text TEXT,                          -- 复现步骤
    verify_code_text     TEXT,                          -- 验证代码（POC）
    remediation_text     TEXT,                          -- 修复建议
    created_at           TEXT    NOT NULL,
    -- 以下为引擎内部定位字段（规则标识 / 命中行号 / 命中分类），
    -- 用于攻击路径编排与规则命中回溯，不影响 §1.4.8 规定字段
    rule_key             TEXT,
    line_no              INTEGER,
    category             TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 6. attack_paths 攻击路径表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_paths (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id        INTEGER NOT NULL,
    path_code         TEXT    NOT NULL,                 -- PATH-001
    path_title        TEXT    NOT NULL,
    path_summary      TEXT,
    final_impact_text TEXT,                             -- 最终影响
    created_at        TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 7. attack_path_items 攻击路径步骤表（关联漏洞）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_path_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path_id    INTEGER NOT NULL,
    vuln_id    INTEGER NOT NULL,
    step_order INTEGER NOT NULL,                        -- 利用顺序
    step_text  TEXT,
    FOREIGN KEY (path_id) REFERENCES attack_paths (id) ON DELETE CASCADE,
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 8. chat_messages 实时聊天消息表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS chat_messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL,
    worker_role  TEXT,
    message_type TEXT    NOT NULL DEFAULT 'info',       -- info/thinking/result/warning
    message_text TEXT,
    created_at   TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 9. runtime_logs 运行日志表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS runtime_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL,
    stage_id       INTEGER,
    worker_task_id INTEGER,
    log_level      TEXT    NOT NULL DEFAULT 'INFO',     -- DEBUG/INFO/WARN/ERROR
    log_content    TEXT,
    created_at     TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 10. resource_usages 资源消耗表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS resource_usages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL,
    cpu_usage    REAL    NOT NULL DEFAULT 0,            -- CPU 占用百分比
    memory_usage REAL    NOT NULL DEFAULT 0,            -- 内存占用 MB
    token_count  INTEGER NOT NULL DEFAULT 0,            -- 消耗 token 估算
    recorded_at  TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 11. reports 报告表
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id       INTEGER NOT NULL,
    report_markdown  TEXT,
    report_html      TEXT,
    report_file_path TEXT,
    created_at       TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ============================================================================
-- 以下为支撑表（非 §1.4.8 强制要求，为满足 §1.4.3 配置页与 §1.4.7 认证模块）
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 12. sessions 登录态表（认证模块）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- 13. system_configs 系统配置表（配置模块）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS system_configs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key   TEXT    NOT NULL UNIQUE,
    config_value TEXT,
    description  TEXT,
    updated_at   TEXT    NOT NULL
);

-- ---------------------------------------------------------------------------
-- 14. sandboxes 隔离环境表（§1.4.9 每个项目绑定独立隔离环境编号）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sandboxes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sandbox_code      TEXT    NOT NULL UNIQUE,          -- SA-{project_id}-{random}
    project_id        INTEGER NOT NULL,
    isolation_type    TEXT    NOT NULL DEFAULT 'simulated',
    source_mount_path TEXT,                             -- 只读挂载的源码路径
    workspace_path    TEXT,                             -- 临时执行目录
    sandbox_status    TEXT    NOT NULL DEFAULT 'created', -- created/running/stopped/destroyed
    created_at        TEXT    NOT NULL,
    destroyed_at      TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE
);

-- ============================================================================
-- 索引
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_projects_status        ON projects (project_status);
CREATE INDEX IF NOT EXISTS idx_stages_project         ON runtime_stages (project_id);
CREATE INDEX IF NOT EXISTS idx_workers_project        ON worker_tasks (project_id);
CREATE INDEX IF NOT EXISTS idx_workers_stage          ON worker_tasks (stage_id);
CREATE INDEX IF NOT EXISTS idx_vulns_project          ON vulnerabilities (project_id);
CREATE INDEX IF NOT EXISTS idx_paths_project          ON attack_paths (project_id);
CREATE INDEX IF NOT EXISTS idx_path_items_path        ON attack_path_items (path_id);
CREATE INDEX IF NOT EXISTS idx_chat_project           ON chat_messages (project_id);
CREATE INDEX IF NOT EXISTS idx_logs_project           ON runtime_logs (project_id);
CREATE INDEX IF NOT EXISTS idx_resources_project      ON resource_usages (project_id);
CREATE INDEX IF NOT EXISTS idx_reports_project        ON reports (project_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token         ON sessions (token);
CREATE INDEX IF NOT EXISTS idx_sandboxes_project      ON sandboxes (project_id);
