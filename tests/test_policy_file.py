"""领域策略文件与代码默认策略的一致性。"""
from __future__ import annotations

from pathlib import Path

from registry.policy import RiskPolicy

from .support import ServiceTestCase

ROOT = Path(__file__).resolve().parents[1]


class PolicyFileTest(ServiceTestCase):
    def test_policy_file_loads_and_matches_default_routing(self):
        loaded = RiskPolicy.load(ROOT / "domain" / "risk_policy.json")
        default = RiskPolicy.default()
        for capability in ("mail.read", "mail.write", "payment.read", "payment", "home.device"):
            self.assertEqual(
                loaded.stages_for([capability]), default.stages_for([capability])
            )
            self.assertEqual(
                loaded.required_plan([capability]), default.required_plan([capability])
            )
            self.assertEqual(
                loaded.conflict_groups([capability]), default.conflict_groups([capability])
            )

    def test_payment_region_restriction_loaded_from_file(self):
        loaded = RiskPolicy.load(ROOT / "domain" / "risk_policy.json")
        self.assertEqual(
            loaded.rules["payment"].allowed_regions, ("CN", "SG", "US")
        )
        self.assertTrue(loaded.plan_allows("enterprise", ["payment"]))
        self.assertFalse(loaded.plan_allows("pro", ["payment"]))
