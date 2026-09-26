"""风险路由、套餐、地区与能力冲突策略。

策略资料来自 ``domain/policies.json``，也可以在代码里直接构造。
策略按版本生效（``version`` 字段），历史路由决策记录当时使用的
策略版本，保证规则演进不改变历史结论的可解释性。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

DEFAULT_POLICY_VERSION = "2026-09-01"


@dataclass(frozen=True)
class RouteDecision:
    """一次风险路由的结论。"""

    risk_level: str
    required_approvers: tuple[str, ...]
    added_capabilities: frozenset[str]
    policy_version: str
    reasons: tuple[str, ...]


@dataclass
class PolicyBook:
    """可程序化读取的策略册。"""

    risk_levels: list[dict[str, Any]]
    conflicting_groups: list[frozenset[str]] = field(default_factory=list)
    capability_regions: dict[str, set[str]] = field(default_factory=dict)
    plans: dict[str, set[str]] = field(default_factory=dict)
    default_groups: tuple[dict[str, Any], ...] = (
        {"name": "canary", "size": 10},
        {"name": "early", "size": 40},
        {"name": "general", "size": 50},
    )
    anomaly_threshold: float = 0.05
    min_samples: int = 20
    salt: str = "registry-default-salt"
    version: str = DEFAULT_POLICY_VERSION

    @classmethod
    def default(cls) -> "PolicyBook":
        path = Path(__file__).resolve().parents[1] / "domain" / "policies.json"
        if path.exists():
            return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
        return cls(risk_levels=[])

    @classmethod
    def from_file(cls, path: str | Path) -> "PolicyBook":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyBook":
        risk = data.get("risk_levels", [])
        conflicts = [frozenset(group) for group in data.get("conflicting_capability_groups", [])]
        scopes = data.get("capability_scopes", {})
        region_limits = data.get("capability_regions", {})
        regions: dict[str, set[str]] = {}
        for capability, scope in scopes.items():
            if scope in ("global", "tenant"):
                # 全局/租户作用域不受地区限制。
                regions[capability] = {"*"}
            else:
                # region 作用域：必须显式配置地区白名单，缺省不放行任何地区。
                regions[capability] = set(region_limits.get(capability, ()))
        for capability, allowed in region_limits.items():
            regions[capability] = set(allowed)
        plans: dict[str, set[str]] = {}
        for plan_name, spec in data.get("plans", {}).items():
            plans[plan_name] = set(spec.get("allowed_capabilities", []))
        rollout = data.get("rollout", {})
        groups = tuple(rollout.get("default_groups", cls.default_groups))
        return cls(
            risk_levels=risk,
            conflicting_groups=conflicts,
            capability_regions=regions,
            plans=plans,
            default_groups=groups,
            anomaly_threshold=float(rollout.get("default_anomaly_rate_threshold", 0.05)),
            min_samples=int(rollout.get("default_min_samples", 20)),
            salt=rollout.get("salt", cls.salt),
            version=str(data.get("policy_version", DEFAULT_POLICY_VERSION)),
        )

    # -- 风险路由 -------------------------------------------------------

    def route(
        self,
        capabilities: Iterable[str],
        previous_capabilities: Iterable[str] = (),
    ) -> RouteDecision:
        """比较版本能力差异，按最高风险等级决定必需审批角色。

        首个版本把全部能力视为「新增」；后续版本只对净增的能力
        触发重新审批（能力扩大必须重新审批）。
        """
        current = frozenset(capabilities)
        previous = frozenset(previous_capabilities)
        added = current - previous
        scan_targets = current if not previous else added
        # 能力集合首次出现或扩大时，所有新能力都要过路由；
        # 纯收窄不需要新审批，但仍由调用方决定是否允许直接放行。
        rank = 0
        required: set[str] = set()
        reasons: list[str] = []
        capability_level: dict[str, str] = {}
        for level in self.risk_levels:
            for capability in level.get("capabilities", []):
                capability_level[capability] = level["code"]
        levels = {level["code"]: index for index, level in enumerate(self.risk_levels)}
        for capability in sorted(scan_targets):
            level_code = capability_level.get(capability, "low")
            level = next((item for item in self.risk_levels if item["code"] == level_code), None)
            if level is None:
                reasons.append(f"能力 {capability} 未登记风险等级，按低风险处理")
                continue
            if levels[level_code] > rank:
                rank = levels[level_code]
            required.update(level.get("approvers", []))
            reasons.append(f"能力 {capability} 属于 {level_code}，需要 {','.join(level.get('approvers', []))}")
        chosen = self.risk_levels[rank]["code"] if self.risk_levels else "low"
        if not required:
            required.add("code_review")
        return RouteDecision(
            risk_level=chosen,
            required_approvers=tuple(sorted(required)),
            added_capabilities=added,
            policy_version=self.version,
            reasons=tuple(reasons),
        )

    # -- 租户放行校验 ---------------------------------------------------

    def check_plan(self, plan: str, capabilities: Iterable[str]) -> str | None:
        allowed = self.plans.get(plan)
        if allowed is None:
            return f"未知套餐：{plan}"
        if "*" in allowed:
            return None
        blocked = sorted(set(capabilities) - allowed)
        if blocked:
            return f"套餐 {plan} 不允许能力：{','.join(blocked)}"
        return None

    def check_region(self, region: str, capabilities: Iterable[str]) -> str | None:
        for capability in sorted(capabilities):
            allowed = self.capability_regions.get(capability, {"*"})
            if "*" not in allowed and region not in allowed:
                return f"地区 {region} 不允许能力 {capability}"
        return None

    def find_conflicts(self, desired: Iterable[str], existing: Iterable[str]) -> list[tuple[str, str]]:
        """返回 (冲突能力 A, 冲突能力 B) 列表。"""
        desired_set = frozenset(desired)
        existing_set = frozenset(existing)
        conflicts: list[tuple[str, str]] = []
        for group in self.conflicting_groups:
            hit_desired = group & desired_set
            hit_existing = group & existing_set
            if hit_desired and hit_existing:
                for a in sorted(hit_desired):
                    for b in sorted(hit_existing):
                        if a != b:
                            conflicts.append((a, b))
        return sorted(set(conflicts))
