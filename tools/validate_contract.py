"""校验领域合同与样例事件，不实现完整业务服务。"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_json(relative_path: str):
    return json.loads((ROOT / relative_path).read_text(encoding="utf-8"))


def validate() -> tuple[int, int, int]:
    contract = load_json("domain/contract.json")
    events = load_json("examples/events.json")
    policy_book = load_json("domain/policies.json")
    policies = policy_book.get("policies", policy_book if isinstance(policy_book, list) else [])
    required = {"project", "entities", "states", "event_types", "time_policy", "rules"}
    missing = sorted(required - set(contract))
    if missing:
        raise ValueError("领域合同缺少字段：" + "、".join(missing))
    if contract["time_policy"] != "ISO 8601 with timezone":
        raise ValueError("time_policy 必须明确包含时区")
    allowed = set(contract["event_types"])
    if not isinstance(policies, list) or len(policies) < 3:
        raise ValueError("策略资料至少需要三项")
    risk_levels = policy_book.get("risk_levels", [])
    if not risk_levels:
        raise ValueError("策略资料缺少风险等级路由")
    for level in risk_levels:
        if not level.get("approvers"):
            raise ValueError(f"风险等级 {level.get('code')} 缺少审批角色")
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "create table event_log(event_id text primary key, event_type text not null, "
        "aggregate_id text not null, occurred_at text not null, actor_id text not null)"
    )
    previous = None
    for event in events:
        if event["event_type"] not in allowed:
            raise ValueError(f"未知事件类型：{event['event_type']}")
        occurred_at = datetime.fromisoformat(event["occurred_at"])
        if occurred_at.tzinfo is None:
            raise ValueError("样例事件必须包含时区")
        if previous is not None and occurred_at < previous:
            raise ValueError("样例事件必须按发生时间排序")
        previous = occurred_at
        connection.execute(
            "insert into event_log values (?, ?, ?, ?, ?)",
            (event["event_id"], event["event_type"], event["aggregate_id"], event["occurred_at"], event["actor_id"]),
        )
    connection.commit()
    stored = connection.execute("select count(*) from event_log").fetchone()[0]
    connection.close()
    return len(contract["entities"]), stored, len(policies)

if __name__ == "__main__":
    entity_count, event_count, policy_count = validate()
    print(f"合同校验通过：{entity_count} 类实体，{event_count} 条样例事件，{policy_count} 项策略")
