"""服务集成测试的公共夹具。"""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from registry import EventStore, KeyStore, RegistryService, RiskPolicy

KEYS = {
    "reviewer-code": "code-secret",
    "reviewer-data": "data-secret",
    "reviewer-finance": "finance-secret",
}


def make_files(seed: str = "a"):
    """同 seed 同摘要（用于重复上传）；不同 seed 产生新版本内容。"""
    return [
        {"path": "main.py", "sha256": seed[0] * 64, "size": 100},
        {"path": "lib/util.py", "sha256": "c" * 64, "size": 50},
    ]


class ServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / "registry.db")
        self.store = EventStore(self.path)
        self.keys = KeyStore(KEYS)
        self.service = RegistryService(self.store, RiskPolicy.default(), self.keys)

    def tearDown(self) -> None:
        self.store.close()
        self.tmp.cleanup()

    # ---- 端到端辅助 ----------------------------------------------------

    def publish_version(
        self,
        package_id: str,
        files,
        capabilities,
        *,
        dependencies=None,
        entry_points=("main:run",),
        actor="operator-01",
    ):
        uploaded = self.service.upload_version(
            package_id, files, dependencies=dependencies or {"requests": "2.31.0"},
            entry_points=list(entry_points), capabilities=list(capabilities),
            actor_id=actor,
        )
        version_id = uploaded["version_id"]
        self.service.verify_manifest(version_id, actor_id="scanner")
        self.service.open_review(version_id, actor_id=actor)
        view = self.service.view()
        stages = list(view.version(version_id).reviews)
        signer_for = {
            "code_review": "reviewer-code",
            "data_owner": "reviewer-data",
            "finance": "reviewer-finance",
        }
        for stage in stages:
            self.service.sign_review(version_id, stage, signer_for[stage])
        approved = self.service.approve_version(version_id, actor_id=actor)
        return approved["version_id"]

    def register_tenant(self, tenant_id="t1", region="CN", plan="enterprise"):
        self.service.register_tenant(tenant_id, region, plan, actor_id="admin")
        return tenant_id
