"""灰度分组、异常冻结、回滚、隔离与重启恢复测试。"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from skillregistry.canonical import stable_bucket
from skillregistry.errors import RulesLocked, VersionStateError
from skillregistry.service import RegistryService
from tests.helpers import approve_version, make_submission, required_roles


def approved_version(service, package="mailer", capabilities=("fs.read",), **kwargs):
    result = service.submit_package(package, make_submission(capabilities=capabilities, **kwargs))
    version_id = result["version_id"]
    formal_no = approve_version(service, version_id, required_roles(service, version_id))
    return version_id, formal_no


class DeterministicGroupingTest(unittest.TestCase):
    def test_bucket_is_stable_across_processes(self) -> None:
        first = stable_bucket("fixed-salt", "tenant-42", 100)
        second = stable_bucket("fixed-salt", "tenant-42", 100)
        self.assertEqual(first, second)
        self.assertNotEqual(
            stable_bucket("fixed-salt", "tenant-42", 100),
            stable_bucket("other-salt", "tenant-42", 100),
        )

    def test_group_assignment_is_persistent_and_rule_independent(self) -> None:
        service = RegistryService(":memory:")
        version_id, _ = approved_version(service)
        batch_id = service.rollout.start_rollout(
            version_id,
            groups=[{"name": "canary", "size": 10}, {"name": "rest", "size": 90}],
            salt="salt-1",
        )
        placement_a = service.rollout.group_of(batch_id, "tenant-a")
        placement_b = service.rollout.group_of(batch_id, "tenant-b")
        # 确定性：重复调用结果不变。
        self.assertEqual(placement_a, service.rollout.group_of(batch_id, "tenant-a"))
        self.assertIn(placement_a["group"], {"canary", "rest"})
        self.assertIn(placement_b["group"], {"canary", "rest"})

    def test_rules_cannot_change_after_batch_starts(self) -> None:
        service = RegistryService(":memory:")
        version_id, _ = approved_version(service)
        batch_id = service.rollout.start_rollout(version_id)
        with self.assertRaises(RulesLocked):
            service.rollout.update_rules(batch_id, salt="new-salt")

    def test_group_sizes_must_sum_to_100(self) -> None:
        service = RegistryService(":memory:")
        version_id, _ = approved_version(service)
        with self.assertRaises(ValueError):
            service.rollout.start_rollout(
                version_id, groups=[{"name": "a", "size": 30}, {"name": "b", "size": 30}]
            )


class RolloutFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")
        for tenant_id, region in [("t-cn-1", "cn-north"), ("t-cn-2", "cn-north"), ("t-cn-3", "cn-north")]:
            self.service.tenants.register_tenant(tenant_id, "pro", region)
        self.v1, self.no1 = approved_version(self.service, files=("v1.py",))
        for tenant_id in ("t-cn-1", "t-cn-2", "t-cn-3"):
            self.service.tenants.enable_skill(tenant_id, "mailer", self.v1)

    def release_v2(self):
        result = self.service.submit_package(
            "mailer", make_submission(files=("v1.py", "v2.py"), capabilities=("fs.read",))
        )
        v2 = result["version_id"]
        approve_version(self.service, v2, required_roles(self.service, v2))
        return v2

    def test_frozen_batch_rejects_new_assignments(self) -> None:
        v2 = self.release_v2()
        batch_id = self.service.rollout.start_rollout(v2, min_samples=10, threshold=0.05)
        self.service.rollout.assign(batch_id, "t-cn-1", open_groups={"canary", "early", "general"})
        # 10 个样本中 1 个异常即达到 10%，越过 5% 阈值。
        outcome = self.service.rollout.report_result(batch_id, errors=1, total=10)
        self.assertEqual(outcome["status"], "frozen")
        with self.assertRaises(VersionStateError):
            self.service.rollout.assign(
                batch_id, "t-cn-2", open_groups={"canary", "early", "general"}
            )
        self.assertEqual(self.service.catalog.get_version(v2)["state"], "rolled_back")

    def test_rollback_returns_to_latest_safe_version(self) -> None:
        v2 = self.release_v2()
        batch_id = self.service.rollout.start_rollout(v2)
        install_v2 = self.service.rollout.assign(
            batch_id, "t-cn-1", open_groups={"canary", "early", "general"}
        )
        self.service.rollout.freeze(batch_id, "手动冻结")
        target = self.service.rollout.rollback(batch_id)
        self.assertEqual(target, self.v1)
        old = self.service.store.get("select * from installs where install_id = ?", (install_v2,))
        self.assertEqual(old["status"], "rolled_back")
        self.assertIsNotNone(old["replaced_by_install_id"])
        new = self.service.store.get(
            "select * from installs where install_id = ?", (old["replaced_by_install_id"],)
        )
        self.assertEqual(new["version_id"], self.v1)
        self.assertEqual(new["status"], "active")
        assignment = self.service.tenants.list_enabled("t-cn-1")[0]
        self.assertEqual(assignment["version_id"], self.v1)

    def test_rollback_lists_affected_tasks(self) -> None:
        v2 = self.release_v2()
        batch_id = self.service.rollout.start_rollout(v2)
        install_id = self.service.rollout.assign(
            batch_id, "t-cn-1", open_groups={"canary", "early", "general"}
        )
        self.service.rollout.register_task("task-1", "t-cn-1", install_id)
        self.service.rollout.freeze(batch_id, "异常")
        self.service.rollout.rollback(batch_id)
        tasks = self.service.rollout.affected_tasks(v2)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["task_id"], "task-1")
        self.assertEqual(tasks[0]["state"], "affected")
        self.assertEqual(tasks[0]["previous_version_id"], v2)

    def test_below_threshold_does_not_freeze(self) -> None:
        v2 = self.release_v2()
        batch_id = self.service.rollout.start_rollout(v2, min_samples=100, threshold=0.05)
        outcome = self.service.rollout.report_result(batch_id, errors=1, total=10)
        self.assertEqual(outcome["status"], "rolling_out")
        outcome = self.service.rollout.report_result(batch_id, errors=3, total=90)
        self.assertEqual(outcome["status"], "rolling_out")

    def test_isolate_single_version_stops_rollout_and_lists_impact(self) -> None:
        v2 = self.release_v2()
        batch_id = self.service.rollout.start_rollout(v2)
        install_id = self.service.rollout.assign(
            batch_id, "t-cn-1", open_groups={"canary", "early", "general"}
        )
        self.service.rollout.register_task("task-x", "t-cn-1", install_id)
        impact = self.service.rollout.isolate_version(v2, "发现未授权外联")
        self.assertEqual(len(impact["tasks"]), 1)
        self.assertEqual(len(impact["installs"]), 1)
        self.assertEqual(self.service.catalog.get_version(v2)["state"], "isolated")
        self.assertEqual(self.service.rollout.get_batch(batch_id)["status"], "frozen")
        # v1 不受影响，仍可给新租户正常启用。
        self.service.tenants.register_tenant("t-cn-4", "pro", "cn-north")
        self.assertTrue(self.service.tenants.enable_skill("t-cn-4", "mailer", self.v1))
        # 同版本同租户的既有分配保持不变。
        self.assertEqual(self.service.tenants.list_enabled("t-cn-2")[0]["version_id"], self.v1)

    def test_rollback_version_covers_manual_install_without_batch(self) -> None:
        v2 = self.release_v2()
        # 直接手动启用 v2，没有灰度批次。
        install_v2 = self.service.tenants.enable_skill("t-cn-3", "mailer", v2)
        self.service.rollout.isolate_version(v2, "应急隔离")
        target = self.service.rollout.rollback_version(v2)
        self.assertEqual(target, self.v1)
        self.assertEqual(
            self.service.store.get(
                "select status from installs where install_id = ?", (install_v2,)
            )["status"],
            "rolled_back",
        )
        self.assertEqual(self.service.tenants.list_enabled("t-cn-3")[0]["version_id"], self.v1)
        self.assertEqual(self.service.catalog.get_version(v2)["state"], "rolled_back")


class RestartRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "registry.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _service(self, recover: bool = True) -> RegistryService:
        return RegistryService(self.db_path, recover=recover)

    def test_in_progress_review_continues_after_restart(self) -> None:
        service = self._service()
        result = service.submit_package("pay", make_submission(capabilities=("payment.execute",)))
        version_id = result["version_id"]
        roles = required_roles(service, version_id)
        service.reviews.sign_review(version_id, roles[0], "user-a")
        service.close()

        reopened = self._service()
        status = reopened.reviews.review_status(version_id)
        self.assertEqual(status["status"], "open")
        self.assertEqual([s["approver_role"] for s in status["signatures"]], [roles[0]])
        for role in roles[1:]:
            reopened.reviews.sign_review(version_id, role, f"user-{role}")
        formal_no = reopened.reviews.approve(version_id)
        self.assertEqual(formal_no, 1)
        reopened.close()

    def test_interrupted_rollback_batch_resumes_after_restart(self) -> None:
        service = self._service()
        for tenant_id in ("t1", "t2", "t3"):
            service.tenants.register_tenant(tenant_id, "pro", "cn-north")
        v1, _ = approved_version(service, files=("old.py",))
        for tenant_id in ("t1", "t2", "t3"):
            service.tenants.enable_skill(tenant_id, "mailer", v1)
        result = service.submit_package(
            "mailer", make_submission(files=("old.py", "new.py"), capabilities=("fs.read",))
        )
        v2 = result["version_id"]
        approve_version(service, v2, required_roles(service, v2))
        batch_id = service.rollout.start_rollout(v2)
        for tenant_id in ("t1", "t2", "t3"):
            service.rollout.assign(batch_id, tenant_id, open_groups={"canary", "early", "general"})
        # 模拟回滚进行到一半时进程崩溃：批次停留在 rolling_back。
        with service.store.transaction() as conn:
            conn.execute(
                "update rollout_batches set status = 'rolling_back', "
                "rollback_target_version_id = ?, rollback_started_at = ? "
                "where batch_id = ?",
                (v1, "2026-09-25T00:00:00+00:00", batch_id),
            )
        service.close()

        reopened = self._service()  # 构造时自动恢复
        batch = reopened.rollout.get_batch(batch_id)
        self.assertEqual(batch["status"], "rolled_back")
        active_v2 = reopened.store.all(
            "select * from installs where version_id = ? and status = 'active'", (v2,)
        )
        self.assertEqual(active_v2, [])
        active_v1 = reopened.store.all(
            "select * from installs where version_id = ? and status = 'active'", (v1,)
        )
        self.assertEqual(len(active_v1), 3)
        reopened.close()


class ConcurrentApprovalTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "registry.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_concurrent_approvals_produce_single_formal_version(self) -> None:
        service = RegistryService(self.db_path)
        result = service.submit_package("pay", make_submission(capabilities=("payment.execute",)))
        version_id = result["version_id"]
        roles = required_roles(service, version_id)
        for role in roles:
            service.reviews.sign_review(version_id, role, f"user-{role}")
        service.close()

        results: list[int] = []
        errors: list[Exception] = []

        def worker() -> None:
            worker_service = RegistryService(self.db_path, recover=False)
            try:
                results.append(worker_service.reviews.approve(version_id))
            except Exception as error:  # noqa: BLE001 - 记录并断言
                errors.append(error)
            finally:
                worker_service.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(results, [1] * 8)
        check = RegistryService(self.db_path, recover=False)
        formal = check.store.all(
            "select * from versions where package_id = "
            "(select package_id from packages where name = 'pay') and formal_version_no is not null"
        )
        self.assertEqual(len(formal), 1)
        self.assertEqual(formal[0]["formal_version_no"], 1)
        check.close()


if __name__ == "__main__":
    unittest.main()
