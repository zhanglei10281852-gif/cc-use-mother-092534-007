"""SQLite 仅追加事件日志与聚合投影。

事实源只有 event_log；其余对象（版本状态、分配、批次、任务）全部由事件折叠得到。
每次命令在单个 ``BEGIN IMMEDIATE`` 事务内重读、校验、追加事件，
SQLite 对写事务串行化，配合唯一约束，保证重复上传与并发审批不会产生两个正式版本。
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA_VERSION = 1

SCHEMA = """
create table if not exists event_log (
    event_id       text primary key,
    aggregate_type text not null,
    aggregate_id   text not null,
    sequence       integer not null,
    occurred_at    text not null,
    actor_id       text not null,
    event_type     text not null,
    payload        text not null,
    unique(aggregate_id, sequence)
);
create index if not exists idx_event_aggregate on event_log(aggregate_type, aggregate_id);

create table if not exists commands (
    idempotency_key text primary key,
    result          text not null
);

-- 正式版本的硬约束：包内序号单调、内容指纹唯一。
create table if not exists official_versions (
    package_id  text not null,
    version_no  integer not null,
    version_id  text not null,
    fingerprint text not null,
    primary key (package_id, version_no),
    unique (package_id, fingerprint)
);

-- 上传即登记：同一包下同一内容指纹只能有一个版本聚合。
create table if not exists version_uploads (
    version_id  text primary key,
    package_id  text not null,
    fingerprint text not null,
    unique (package_id, fingerprint)
);
"""


class Conflict(Exception):
    """违反唯一性或并发不变量。"""


class StaleCommand(Exception):
    """幂等键被重复用于不同请求。"""


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventStore:
    def __init__(self, path: str | Path = ":memory:", clock: Callable[[], str] = utcnow_iso) -> None:
        self.path = str(path)
        self.clock = clock
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("pragma journal_mode=wal")
        self.connection.execute("pragma foreign_keys=on")
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "EventStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- 读取 ----------------------------------------------------------

    def all_events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select * from event_log order by rowid"
        ).fetchall()
        return [self._decode(row) for row in rows]

    def events_for(self, aggregate_type: str, aggregate_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "select * from event_log where aggregate_type=? and aggregate_id=? order by sequence",
            (aggregate_type, aggregate_id),
        ).fetchall()
        return [self._decode(row) for row in rows]

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        event = {
            "event_id": row["event_id"],
            "aggregate_type": row["aggregate_type"],
            "aggregate_id": row["aggregate_id"],
            "sequence": row["sequence"],
            "occurred_at": row["occurred_at"],
            "actor_id": row["actor_id"],
            "event_type": row["event_type"],
            "payload": json.loads(row["payload"]),
        }
        return event

    # ---- 写入 ----------------------------------------------------------

    def transaction(self) -> "Transaction":
        return Transaction(self)


class Transaction:
    """一次命令的一致性边界。"""

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.conn = store.connection
        self._closed = False

    def __enter__(self) -> "Transaction":
        # IMMEDIATE 立即取得写锁：并发命令在此串行，避免“读后写”竞态。
        self.conn.execute("begin immediate")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._closed:
            return
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self._closed = True

    def commit(self) -> None:
        self.conn.commit()
        self._closed = True

    def rollback(self) -> None:
        self.conn.rollback()
        self._closed = True

    # ---- 幂等 ----------------------------------------------------------

    def cached_result(self, key: str | None) -> dict[str, Any] | None:
        if key is None:
            return None
        row = self.conn.execute(
            "select result from commands where idempotency_key=?", (key,)
        ).fetchone()
        return json.loads(row["result"]) if row else None

    def remember(self, key: str | None, result: dict[str, Any]) -> None:
        if key is None:
            return
        try:
            self.conn.execute(
                "insert into commands(idempotency_key, result) values(?, ?)",
                (key, json.dumps(result, ensure_ascii=False, sort_keys=True)),
            )
        except sqlite3.IntegrityError:
            raise StaleCommand(f"幂等键已被使用：{key}") from None

    # ---- 追加事件 ------------------------------------------------------

    def next_sequence(self, aggregate_type: str, aggregate_id: str) -> int:
        row = self.conn.execute(
            "select coalesce(max(sequence), 0) as s from event_log "
            "where aggregate_type=? and aggregate_id=?",
            (aggregate_type, aggregate_id),
        ).fetchone()
        return int(row["s"]) + 1

    def append(
        self,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: dict[str, Any],
        actor_id: str,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        sequence = self.next_sequence(aggregate_type, aggregate_id)
        event = {
            "event_id": uuid.uuid4().hex,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "sequence": sequence,
            "occurred_at": occurred_at or self.store.clock(),
            "actor_id": actor_id,
            "event_type": event_type,
            "payload": payload,
        }
        self.conn.execute(
            "insert into event_log(event_id, aggregate_type, aggregate_id, sequence, "
            "occurred_at, actor_id, event_type, payload) values(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event["event_id"],
                aggregate_type,
                aggregate_id,
                sequence,
                event["occurred_at"],
                actor_id,
                event_type,
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
            ),
        )
        return event

    def append_many(
        self,
        aggregate_type: str,
        aggregate_id: str,
        items: Iterable[tuple[str, dict[str, Any]]],
        actor_id: str,
    ) -> list[dict[str, Any]]:
        return [
            self.append(aggregate_type, aggregate_id, event_type, payload, actor_id)
            for event_type, payload in items
        ]

    # ---- 正式版本/上传唯一约束 ----------------------------------------

    def register_upload(self, version_id: str, package_id: str, fingerprint: str) -> None:
        try:
            self.conn.execute(
                "insert into version_uploads(version_id, package_id, fingerprint) values(?, ?, ?)",
                (version_id, package_id, fingerprint),
            )
        except sqlite3.IntegrityError:
            raise Conflict("相同内容摘要的版本已存在") from None

    def existing_upload(self, package_id: str, fingerprint: str) -> str | None:
        row = self.conn.execute(
            "select version_id from version_uploads where package_id=? and fingerprint=?",
            (package_id, fingerprint),
        ).fetchone()
        return row["version_id"] if row else None

    def next_official_no(self, package_id: str) -> int:
        row = self.conn.execute(
            "select coalesce(max(version_no), 0) as n from official_versions where package_id=?",
            (package_id,),
        ).fetchone()
        return int(row["n"]) + 1

    def register_official(self, package_id: str, version_no: int, version_id: str, fingerprint: str) -> None:
        try:
            self.conn.execute(
                "insert into official_versions(package_id, version_no, version_id, fingerprint) "
                "values(?, ?, ?, ?)",
                (package_id, version_no, version_id, fingerprint),
            )
        except sqlite3.IntegrityError:
            raise Conflict("正式版本冲突（序号或内容摘要重复）") from None

    def official_versions(self, package_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "select * from official_versions where package_id=? order by version_no",
            (package_id,),
        ).fetchall()
