"""风险路由、租户准入与灰度规则的策略模型。

策略全部以数据表达，可从 JSON 载入；默认策略覆盖三类高风险能力域：
邮件读写、支付、家庭设备。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

# 审查环节
STAGE_CODE_REVIEW = "code_review"
STAGE_DATA_OWNER = "data_owner"
STAGE_FINANCE = "finance"
KNOWN_STAGES = (STAGE_CODE_REVIEW, STAGE_DATA_OWNER, STAGE_FINANCE)


@dataclass(frozen=True)
class CapabilityRule:
    """单项能力的风险要求。"""

    capability: str
    stages: tuple[str, ...]
    min_plan: str = "free"
    conflict_group: str | None = None
    allowed_regions: tuple[str, ...] | None = None  # None 表示不限制地区


@dataclass(frozen=True)
class RiskPolicy:
    rules: Mapping[str, CapabilityRule] = field(default_factory=dict)
    plan_order: tuple[str, ...] = ("free", "pro", "enterprise")

    def stages_for(self, capabilities: Sequence[str]) -> set[str]:
        stages: set[str] = set()
        for capability in capabilities:
            rule = self.rules.get(capability)
            if rule is not None:
                stages.update(rule.stages)
        return stages

    def required_plan(self, capabilities: Sequence[str]) -> str:
        required = "free"
        order = self.plan_order
        for capability in capabilities:
            rule = self.rules.get(capability)
            if rule is not None and order.index(rule.min_plan) > order.index(required):
                required = rule.min_plan
        return required

    def conflict_groups(self, capabilities: Sequence[str]) -> set[str]:
        return {
            rule.conflict_group
            for capability in capabilities
            if (rule := self.rules.get(capability)) is not None and rule.conflict_group
        }

    def plan_allows(self, tenant_plan: str, capabilities: Sequence[str]) -> bool:
        order = self.plan_order
        if tenant_plan not in order:
            return False
        return order.index(tenant_plan) >= order.index(self.required_plan(capabilities))

    @classmethod
    def default(cls) -> "RiskPolicy":
        return cls(
            rules={
                "mail.read": CapabilityRule("mail.read", (STAGE_CODE_REVIEW,)),
                "mail.write": CapabilityRule(
                    "mail.write", (STAGE_CODE_REVIEW, STAGE_DATA_OWNER), "pro", "mailbox"
                ),
                "payment": CapabilityRule(
                    "payment", (STAGE_CODE_REVIEW, STAGE_DATA_OWNER, STAGE_FINANCE),
                    "enterprise", "payment-provider", ("CN", "SG", "US"),
                ),
                "payment.read": CapabilityRule(
                    "payment.read", (STAGE_CODE_REVIEW, STAGE_FINANCE), "pro"
                ),
                "home.device": CapabilityRule(
                    "home.device", (STAGE_CODE_REVIEW, STAGE_DATA_OWNER), "pro", "home-control"
                ),
            }
        )

    @classmethod
    def load(cls, path: str | Path) -> "RiskPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        rules = {
            item["capability"]: CapabilityRule(
                capability=item["capability"],
                stages=tuple(item["stages"]),
                min_plan=item.get("min_plan", "free"),
                conflict_group=item.get("conflict_group"),
                allowed_regions=tuple(item["allowed_regions"]) if item.get("allowed_regions") else None,
            )
            for item in raw.get("rules", [])
        }
        return cls(rules=rules, plan_order=tuple(raw.get("plan_order", cls.default().plan_order)))


def canary_bucket(version_id: str, tenant_id: str, salt: str) -> int:
    """把租户确定性地映射到 [0, 100) 灰度桶。

    同一 (版本, 租户, 盐) 永远落入同一桶；盐在批次开始时固定，
    因此批次期间分组不可变化。
    """
    digest = hashlib.sha256(f"{version_id}|{tenant_id}|{salt}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


def tenant_in_percent(version_id: str, tenant_id: str, salt: str, percent: int) -> bool:
    return canary_bucket(version_id, tenant_id, salt) < percent
