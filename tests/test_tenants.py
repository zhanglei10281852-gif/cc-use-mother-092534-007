"""租户启用闸门（地区、套餐、能力冲突）与历史安装核验测试。"""
from __future__ import annotations

import unittest

from skillregistry.errors import (
    CapabilityConflict,
    DriftDetected,
    PlanDenied,
    RegionDenied,
)
from skillregistry.service import RegistryService
from tests.helpers import approve_version, make_deps, make_files, make_submission, required_roles, sha


class TenantGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")
        self.service.tenants.register_tenant("free-cn", "free", "cn-north")
        self.service.tenants.register_tenant("pro-unsupported", "pro", "us-west")
        self.service.tenants.register_tenant("ent-cn", "enterprise", "cn-north")
        self.service.tenants.register_tenant("ent-us", "enterprise", "us-west")

    def approve(self, package: str, capabilities):
        result = self.service.submit_package(package, make_submission(capabilities=capabilities))
        version_id = result["version_id"]
        approve_version(self.service, version_id, required_roles(self.service, version_id))
        return version_id

    def test_plan_blocks_capability_not_in_plan(self) -> None:
        version_id = self.approve("mailer", ("mail.read",))
        with self.assertRaises(PlanDenied):
            self.service.tenants.enable_skill("free-cn", "mailer", version_id)

    def test_region_blocks_home_device_outside_whitelist(self) -> None:
        version_id = self.approve("home", ("device.home.control",))
        with self.assertRaises(RegionDenied):
            self.service.tenants.enable_skill("ent-us", "home", version_id)

    def test_region_allows_whitelisted_region(self) -> None:
        version_id = self.approve("home", ("device.home.control",))
        install_id = self.service.tenants.enable_skill("ent-cn", "home", version_id)
        self.assertTrue(install_id)

    def test_conflicting_capabilities_across_skills_are_rejected(self) -> None:
        reader = self.approve("mail-reader", ("mail.read",))
        sender = self.approve("mail-sender", ("mail.send",))
        self.service.tenants.enable_skill("ent-cn", "mail-reader", reader)
        with self.assertRaises(CapabilityConflict):
            self.service.tenants.enable_skill("ent-cn", "mail-sender", sender)

    def test_conflict_does_not_block_other_tenants(self) -> None:
        reader = self.approve("mail-reader", ("mail.read",))
        sender = self.approve("mail-sender", ("mail.send",))
        self.service.tenants.enable_skill("ent-cn", "mail-reader", reader)
        self.assertTrue(self.service.tenants.enable_skill("ent-us", "mail-sender", sender))

    def test_payment_allowed_for_enterprise_any_region(self) -> None:
        version_id = self.approve("pay", ("payment.execute",))
        self.assertTrue(self.service.tenants.enable_skill("ent-us", "pay", version_id))


class InstallVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")
        self.service.tenants.register_tenant("ent-cn", "enterprise", "cn-north")
        result = self.service.submit_package("mailer", make_submission(
            files=("main.py", "util.py"), deps=("requests", "httpx"), capabilities=("mail.read",)))
        version_id = result["version_id"]
        approve_version(self.service, version_id, required_roles(self.service, version_id))
        self.install_id = self.service.tenants.enable_skill("ent-cn", "mailer", version_id)
        self.files = make_files("main.py", "util.py")
        self.deps = make_deps("requests", "httpx")

    def test_exact_manifest_verifies(self) -> None:
        self.assertTrue(self.service.tenants.verify_install(self.install_id, self.files, self.deps))

    def test_added_file_fails_verification(self) -> None:
        drifted = self.files + make_files("extra.py")
        with self.assertRaises(DriftDetected):
            self.service.tenants.verify_install(self.install_id, drifted, self.deps)
        install = self.service.store.get(
            "select status from installs where install_id = ?", (self.install_id,)
        )
        self.assertEqual(install["status"], "drifted")

    def test_dependency_digest_drift_fails_verification(self) -> None:
        drifted_deps = [
            {"name": "requests", "constraint": "^2.0", "digest": "f" * 64},
            {"name": "httpx", "constraint": "^1.0", "digest": sha("dep:httpx")},
        ]
        with self.assertRaises(DriftDetected):
            self.service.tenants.verify_install(self.install_id, self.files, drifted_deps)

    def test_history_install_records_exact_manifests(self) -> None:
        installs = self.service.tenants.list_installs(
            self.service.tenants.list_enabled("ent-cn")[0]["version_id"]
        )
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0]["status"], "active")
        self.assertIsNotNone(installs[0]["manifest_digest"])
        self.assertIsNotNone(installs[0]["deps_digest"])


if __name__ == "__main__":
    unittest.main()
