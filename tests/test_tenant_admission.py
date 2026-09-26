"""租户准入：地区、套餐、冲突能力；隔离与受影响任务。"""
from __future__ import annotations

from registry import ServiceError

from .support import ServiceTestCase, make_files


class AdmissionTest(ServiceTestCase):
    def test_region_blocks_payment_outside_allowed_regions(self):
        self.publish_version("pay", make_files("a"), ["payment"])
        self.service.register_tenant("t-eu", "EU", "enterprise", actor_id="admin")
        with self.assertRaises(ServiceError) as ctx:
            self.service.enable_for_tenant("pay", "t-eu", actor_id="admin")
        self.assertIn("地区", str(ctx.exception))

    def test_plan_must_meet_capability_requirement(self):
        self.publish_version("pay", make_files("a"), ["payment.read"])  # 要求 pro
        self.service.register_tenant("t-free", "CN", "free", actor_id="admin")
        with self.assertRaises(ServiceError) as ctx:
            self.service.enable_for_tenant("pay", "t-free", actor_id="admin")
        self.assertIn("套餐", str(ctx.exception))

        self.service.register_tenant("t-pro", "CN", "pro", actor_id="admin")
        result = self.service.enable_for_tenant("pay", "t-pro", actor_id="admin")
        self.assertEqual(result["tenant_id"], "t-pro")

    def test_conflicting_capabilities_rejected(self):
        # 两个支付类技能属于同一冲突组 payment-provider。
        self.publish_version("wallet", make_files("a"), ["payment"])
        self.publish_version("wallet2", make_files("b"), ["payment"])
        self.service.register_tenant("t1", "CN", "enterprise", actor_id="admin")
        self.service.enable_for_tenant("wallet", "t1", actor_id="admin")
        with self.assertRaises(ServiceError) as ctx:
            self.service.enable_for_tenant("wallet2", "t1", actor_id="admin")
        self.assertIn("冲突能力组", str(ctx.exception))

    def test_no_conflict_between_different_groups(self):
        self.publish_version("mailer", make_files("a"), ["mail.write"])
        self.publish_version("home", make_files("b"), ["home.device"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mailer", "t1", actor_id="admin")
        result = self.service.enable_for_tenant("home", "t1", actor_id="admin")
        self.assertEqual(result["version_id"], self.service.view().latest_safe_version("home").version_id)


class QuarantineTest(ServiceTestCase):
    def test_quarantine_lists_affected_tasks_and_blocks_new_assignment(self):
        vid = self.publish_version("mail", make_files("a"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", actor_id="admin")
        self.service.register_task("task-1", "t1", "mail", actor_id="scheduler")
        self.service.register_task("task-2", "t1", "mail", actor_id="scheduler")

        result = self.service.quarantine_version(vid, "发现可疑外联", actor_id="secops")
        affected = {item["task_id"] for item in result["affected_tasks"]}
        self.assertEqual(affected, {"task-1", "task-2"})

        self.service.register_tenant("t2", "CN", "pro", actor_id="admin")
        with self.assertRaises(ServiceError):
            self.service.enable_for_tenant("mail", "t2", version_id=vid, actor_id="admin")

    def test_quarantine_isolates_single_version_only(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        v2 = self.publish_version("mail", make_files("b"), ["mail.read"])
        self.service.quarantine_version(v1, "旧版本问题", actor_id="secops")
        # v2 仍可分配。
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        result = self.service.enable_for_tenant("mail", "t1", actor_id="admin")
        self.assertEqual(result["version_id"], v2)
