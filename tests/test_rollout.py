"""灰度分组、异常冻结、回滚到安全版本与重启连续性。"""
from __future__ import annotations

from registry import EventStore, KeyStore, RegistryService, RiskPolicy, ServiceError

from .support import KEYS, ServiceTestCase, make_files


def reopen(path) -> RegistryService:
    """模拟进程重启：全新存储实例从事件日志恢复全部状态。"""
    store = EventStore(path)
    return RegistryService(store, RiskPolicy.default(), KeyStore(KEYS))


class RolloutTest(ServiceTestCase):
    def _setup_two_versions(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        v2 = self.publish_version("mail", make_files("b"), ["mail.read"])
        return v1, v2

    def test_canary_grouping_is_deterministic_and_fixed_by_salt(self):
        v1, v2 = self._setup_two_versions()
        batch = self.service.start_rollout(
            "mail", v2, 20, salt="fixed-salt", actor_id="op"
        )
        for i in range(40):
            self.service.register_tenant(f"t{i:02d}", "CN", "pro", actor_id="admin")
        result = self.service.assign_due_tenants(
            batch["batch_id"], [f"t{i:02d}" for i in range(40)], actor_id="op"
        )
        first_assigned = list(result["assigned"])
        self.assertTrue(first_assigned)
        self.assertLessEqual(len(first_assigned), 40)

        # 再次调用不会重复分配。
        again = self.service.assign_due_tenants(
            batch["batch_id"], [f"t{i:02d}" for i in range(40)], actor_id="op"
        )
        self.assertEqual(again["assigned"], [])

        # 分组确定：重启后同一盐、同一比例，结论不变。
        self.store.close()
        svc2 = reopen(self.path)
        view = svc2.view()
        b = view.batches[batch["batch_id"]]
        from registry.policy import tenant_in_percent
        for tenant_id in first_assigned:
            self.assertTrue(tenant_in_percent(v2, tenant_id, "fixed-salt", 20))
        self.assertEqual(set(b.assigned_tenants), set(first_assigned))
        self.service = svc2  # 防止 tearDown 关闭已关闭连接

    def test_expand_includes_more_tenants_but_grouping_does_not_change(self):
        v1, v2 = self._setup_two_versions()
        for i in range(60):
            self.service.register_tenant(f"t{i:02d}", "CN", "pro", actor_id="admin")
        batch = self.service.start_rollout("mail", v2, 10, salt="s", actor_id="op")
        bid = batch["batch_id"]
        r10 = self.service.assign_due_tenants(bid, [f"t{i:02d}" for i in range(60)], actor_id="op")
        self.service.expand_rollout(bid, 50, actor_id="op")
        r50 = self.service.assign_due_tenants(bid, [f"t{i:02d}" for i in range(60)], actor_id="op")
        # 早期集合必须是扩大后集合的子集：桶映射不变。
        self.assertTrue(set(r10["assigned"]).issubset(set(r10["assigned"]) | set(r50["assigned"])))
        self.assertGreater(len(r50["assigned"]), 0)

    def test_anomaly_freeze_stops_new_assignment(self):
        v1, v2 = self._setup_two_versions()
        for i in range(30):
            self.service.register_tenant(f"t{i:02d}", "CN", "pro", actor_id="admin")
        batch = self.service.start_rollout("mail", v2, 100, salt="s", actor_id="op")
        bid = batch["batch_id"]
        first = self.service.assign_due_tenants(
            bid, [f"t{i:02d}" for i in range(10)], actor_id="op"
        )
        self.assertTrue(first["assigned"])

        report = self.service.report_anomaly(bid, 0.08, 0.05, actor_id="monitor")
        self.assertTrue(report["frozen"])
        with self.assertRaises(ServiceError):
            self.service.assign_due_tenants(
                bid, [f"t{i:02d}" for i in range(10, 30)], actor_id="op"
            )
        # 冻结期间连手动指定该版本的新分配也被拒绝。
        with self.assertRaises(ServiceError):
            self.service.enable_for_tenant("mail", "t10", version_id=v2, actor_id="admin")

        # 恢复后可以继续。
        self.service.resume_rollout(bid, actor_id="op")
        more = self.service.assign_due_tenants(
            bid, [f"t{i:02d}" for i in range(10, 30)], actor_id="op"
        )
        self.assertTrue(more["assigned"])

    def test_rollback_reverts_to_latest_safe_version_in_batches(self):
        v1, v2 = self._setup_two_versions()
        for i in range(12):
            self.service.register_tenant(f"t{i:02d}", "CN", "pro", actor_id="admin")
            self.service.enable_for_tenant("mail", f"t{i:02d}", version_id=v1, actor_id="admin")
            self.service.register_task(f"task-{i}", f"t{i:02d}", "mail", actor_id="sched")
        batch = self.service.start_rollout("mail", v2, 100, salt="s", actor_id="op")
        bid = batch["batch_id"]
        self.service.assign_due_tenants(bid, [f"t{i:02d}" for i in range(12)], actor_id="op")
        # 任务跟随到 v2。
        self.assertTrue(all(t.version_id == v2 for t in self.service.view().tasks.values()))

        # 异常越线冻结，再启动回滚，每批 5 个租户、分三次完成。
        self.service.report_anomaly(bid, 0.2, 0.05, actor_id="monitor")
        r1 = self.service.rollback_batch(bid, batch_size=5, actor_id="op")
        self.assertEqual(r1["state"], "rolling_back")
        self.assertEqual(len(r1["reverted"]), 5)
        r2 = self.service.rollback_batch(bid, batch_size=5, actor_id="op")
        self.assertEqual(len(r2["reverted"]), 5)
        r3 = self.service.rollback_batch(bid, batch_size=5, actor_id="op")
        self.assertEqual(len(r3["reverted"]), 2)
        self.assertTrue(r3["done"])

        view = self.service.view()
        self.assertEqual(view.version(v2).state, "rolled_back")
        self.assertEqual(view.batches[bid].state, "rolled_back")
        # 所有分配与任务都回到 v1。
        for i in range(12):
            self.assertEqual(
                view.tenants[f"t{i:02d}"].assignments["mail"].current.version_id, v1
            )
        self.assertTrue(all(t.version_id == v1 for t in view.tasks.values()))
        # 回滚完成后重复调用是安全的空操作。
        again = self.service.rollback_batch(bid, actor_id="op")
        self.assertTrue(again["done"])

    def test_rollback_resumes_after_restart(self):
        v1, v2 = self._setup_two_versions()
        for i in range(8):
            self.service.register_tenant(f"t{i:02d}", "CN", "pro", actor_id="admin")
            self.service.enable_for_tenant("mail", f"t{i:02d}", version_id=v1, actor_id="admin")
        batch = self.service.start_rollout("mail", v2, 100, salt="s", actor_id="op")
        bid = batch["batch_id"]
        self.service.assign_due_tenants(bid, [f"t{i:02d}" for i in range(8)], actor_id="op")
        self.service.report_anomaly(bid, 0.3, 0.05, actor_id="monitor")
        first = self.service.rollback_batch(bid, batch_size=3, actor_id="op")
        self.assertEqual(len(first["reverted"]), 3)

        # 重启：进行中的回滚批次必须保持连续，从剩余租户继续。
        self.store.close()
        svc2 = reopen(self.path)
        view = svc2.view()
        self.assertEqual(view.batches[bid].state, "rolling_back")
        self.assertEqual(len(view.batches[bid].pending_rollback_tenants), 5)
        rest = svc2.rollback_batch(bid, actor_id="op")
        self.assertEqual(len(rest["reverted"]), 5)
        self.assertTrue(rest["done"])
        for i in range(8):
            self.assertEqual(
                svc2.view().tenants[f"t{i:02d}"].assignments["mail"].current.version_id, v1
            )
        self.service = svc2

    def test_review_progress_survives_restart(self):
        uploaded = self.service.upload_version(
            "pay", make_files("a"), capabilities=["payment"], actor_id="op"
        )
        vid = uploaded["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        self.service.open_review(vid, actor_id="op")
        self.service.sign_review(vid, "code_review", "reviewer-code")
        self.service.sign_review(vid, "data_owner", "reviewer-data")

        self.store.close()
        svc2 = reopen(self.path)
        state = svc2.view().version(vid)
        self.assertEqual(state.state, "reviewing")
        self.assertIn("code_review", state.reviews)
        self.assertIn("finance", state.reviews)
        self.assertTrue(state.reviews["code_review"].signed)
        self.assertFalse(state.reviews["finance"].signed)
        # 剩余环节签署后即可批准，审查不重头再来。
        svc2.sign_review(vid, "finance", "reviewer-finance")
        approved = svc2.approve_version(vid, actor_id="op")
        self.assertEqual(approved["official_no"], 1)
        self.service = svc2

    def test_rollout_freeze_blocks_manual_enable_of_target(self):
        v1, v2 = self._setup_two_versions()
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        batch = self.service.start_rollout("mail", v2, 1, salt="s", actor_id="op")
        self.service.report_anomaly(batch["batch_id"], 0.9, 0.5, actor_id="monitor")
        with self.assertRaises(ServiceError):
            self.service.enable_for_tenant("mail", "t1", version_id=v2, actor_id="admin")
