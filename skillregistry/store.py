"""SQLite 持久层。

设计要点：

- 所有写操作使用 ``BEGIN IMMEDIATE``，配合唯一约束把并发上传与
  并发审批串行化，避免产生两个正式版本。
- 所有事实（包、版本、签署、安装、任务、批次、事件）都立即落盘，
  进程重启后审查可以继续签署、回滚批次可以继续执行。
- 事件日志只追加不修改，正式事实通过新版本追加，不覆盖历史。
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
create table if not exists meta(
    key text primary key,
    value text not null
);

create table if not exists packages(
    package_id text primary key,
    name text not null unique,
    created_at text not null
);

create table if not exists versions(
    version_id text primary key,
    package_id text not null references packages(package_id),
    state text not null,
    content_digest text not null,
    manifest_digest text not null,
    deps_digest text not null,
    entrypoint_digest text not null,
    capability_digest text not null,
    fingerprint text not null,
    entrypoint_json text not null,
    formal_version_no integer,
    created_at text not null,
    published_at text,
    frozen_at text,
    isolated_at text,
    isolate_reason text,
    predecessor_version_id text,
    unique(package_id, fingerprint),
    unique(package_id, formal_version_no)
);

create table if not exists version_files(
    version_id text not null references versions(version_id),
    path text not null,
    size integer not null,
    sha256 text not null,
    primary key(version_id, path)
);

create table if not exists version_dependencies(
    version_id text not null references versions(version_id),
    name text not null,
    constraint_text text not null,
    digest text not null,
    primary key(version_id, name)
);

create table if not exists version_capabilities(
    version_id text not null references versions(version_id),
    capability text not null,
    primary key(version_id, capability)
);

create table if not exists reviews(
    review_id text primary key,
    version_id text not null references versions(version_id),
    predecessor_version_id text,
    risk_level text not null,
    required_approvers text not null,
    reasons text not null,
    policy_version text not null,
    status text not null,
    created_at text not null,
    closed_at text
);

create table if not exists signatures(
    review_id text not null references reviews(review_id),
    approver_role text not null,
    approver_id text not null,
    payload_digest text not null,
    signature text not null,
    signed_at text not null,
    primary key(review_id, approver_role)
);

create table if not exists tenants(
    tenant_id text primary key,
    plan text not null,
    region text not null,
    created_at text not null
);

create table if not exists assignments(
    assignment_id text primary key,
    tenant_id text not null references tenants(tenant_id),
    package_id text not null references packages(package_id),
    version_id text not null references versions(version_id),
    state text not null,
    source text not null,
    rollout_batch_id text,
    group_name text,
    enabled_at text not null,
    disabled_at text,
    unique(tenant_id, package_id)
);

create table if not exists installs(
    install_id text primary key,
    tenant_id text not null,
    package_id text not null,
    version_id text not null,
    assignment_id text references assignments(assignment_id),
    rollout_batch_id text references rollout_batches(batch_id),
    manifest_digest text not null,
    deps_digest text not null,
    status text not null,
    installed_at text not null,
    replaced_at text,
    replaced_by_install_id text
);

create table if not exists tasks(
    task_id text primary key,
    tenant_id text not null,
    package_id text not null,
    version_id text not null,
    install_id text references installs(install_id),
    state text not null,
    total_count integer not null default 0,
    error_count integer not null default 0,
    previous_version_id text,
    affected_at text,
    created_at text not null,
    updated_at text not null
);

create table if not exists rollout_batches(
    batch_id text primary key,
    package_id text not null,
    version_id text not null,
    status text not null,
    salt text not null,
    groups_json text not null,
    threshold real not null,
    min_samples integer not null,
    total_count integer not null default 0,
    error_count integer not null default 0,
    rules_locked integer not null default 1,
    created_at text not null,
    started_at text,
    frozen_at text,
    freeze_reason text,
    rollback_target_version_id text,
    rollback_started_at text,
    rollback_completed_at text
);

create table if not exists rollout_members(
    batch_id text not null references rollout_batches(batch_id),
    tenant_id text not null,
    group_name text not null,
    bucket integer not null,
    assigned_at text not null,
    primary key(batch_id, tenant_id)
);

create table if not exists event_log(
    seq integer primary key autoincrement,
    event_id text not null unique,
    event_type text not null,
    aggregate_type text not null,
    aggregate_id text not null,
    occurred_at text not null,
    actor_id text not null,
    payload_json text not null
);

create index if not exists idx_versions_package on versions(package_id);
create index if not exists idx_installs_version on installs(version_id);
create index if not exists idx_installs_batch on installs(rollout_batch_id);
create index if not exists idx_tasks_version on tasks(version_id);
create index if not exists idx_events_aggregate on event_log(aggregate_type, aggregate_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


class Store:
    """SQLite 封装。"""

    def __init__(self, path: str = ":memory:", *, busy_retries: int = 20, busy_wait: float = 0.02):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("pragma journal_mode=wal")
        self.connection.execute("pragma foreign_keys=on")
        self.connection.execute("pragma busy_timeout=30000")
        self.connection.executescript(SCHEMA)
        self._busy_retries = busy_retries
        self._busy_wait = busy_wait

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """即时事务：拿到事务即持有写锁，遇锁竞争重试。"""
        connection = self.connection
        last_error: sqlite3.OperationalError | None = None
        for attempt in range(self._busy_retries):
            try:
                connection.execute("begin immediate")
                break
            except sqlite3.OperationalError as error:  # database is locked
                last_error = error
                time.sleep(self._busy_wait * (attempt + 1))
        else:  # pragma: no cover - 重试上限只在极端压力下出现
            raise last_error  # type: ignore[misc]
        try:
            yield connection
        except Exception:
            connection.execute("rollback")
            raise
        else:
            connection.execute("commit")

    # -- 通用辅助 -------------------------------------------------------

    def get(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row:
        row = self.connection.execute(sql, params).fetchone()
        return row

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(self.connection.execute(sql, params).fetchall())

    def append_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        actor_id: str,
        payload: dict[str, Any],
    ) -> str:
        event_id = new_id("evt")
        connection.execute(
            "insert into event_log(event_id, event_type, aggregate_type, aggregate_id, "
            "occurred_at, actor_id, payload_json) values (?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                event_type,
                aggregate_type,
                aggregate_id,
                now_iso(),
                actor_id,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        return event_id

    def list_events(self, aggregate_type: str | None = None, aggregate_id: str | None = None) -> list[dict[str, Any]]:
        sql = "select * from event_log"
        clauses: list[str] = []
        params: list[Any] = []
        if aggregate_type:
            clauses.append("aggregate_type = ?")
            params.append(aggregate_type)
        if aggregate_id:
            clauses.append("aggregate_id = ?")
            params.append(aggregate_id)
        if clauses:
            sql += " where " + " and ".join(clauses)
        sql += " order by seq"
        rows = self.all(sql, tuple(params))
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result
