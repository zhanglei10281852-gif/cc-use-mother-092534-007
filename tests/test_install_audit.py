"""历史安装轨迹与运行内容的确切清单验证。"""
from __future__ import annotations

from registry import ServiceError

from .support import ServiceTestCase, make_files


class InstallHistoryTest(ServiceTestCase):
    def test_history_records_every_version_with_exact_manifests(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        v2 = self.publish_version("mail", make_files("b"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v1, actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v2, actor_id="admin")

        history = self.service.install_history("t1", "mail")
        self.assertEqual([item["version_id"] for item in history], [v1, v2])
        self.assertIsNotNone(history[0]["removed_at"])
        self.assertIsNone(history[1]["removed_at"])
        # 历史记录保留了安装当时的确切文件摘要，而不是当前版本的摘要。
        self.assertEqual(history[0]["digests"]["main.py"], "a" * 64)
        self.assertEqual(history[1]["digests"]["main.py"], "b" * 64)

    def test_verify_installed_content_matches_record(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v1, actor_id="admin")

        result = self.service.verify_installed_content("t1", "mail", make_files("a"))
        self.assertTrue(result["verified"])
        self.assertEqual(result["version_id"], v1)

    def test_verify_detects_changed_file_digest(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v1, actor_id="admin")

        tampered = [
            {"path": "main.py", "sha256": "9" * 64, "size": 100},
            {"path": "lib/util.py", "sha256": "c" * 64, "size": 50},
        ]
        with self.assertRaises(ServiceError) as ctx:
            self.service.verify_installed_content("t1", "mail", tampered)
        self.assertIn("漂移", str(ctx.exception))

    def test_verify_detects_added_or_removed_file(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v1, actor_id="admin")

        with self.assertRaises(ServiceError):
            self.service.verify_installed_content(
                "t1", "mail", [{"path": "main.py", "sha256": "a" * 64, "size": 100}]
            )
        extra = make_files("a") + [{"path": "evil.py", "sha256": "e" * 64, "size": 1}]
        with self.assertRaises(ServiceError):
            self.service.verify_installed_content("t1", "mail", extra)

    def test_rollback_preserves_full_history_chain(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        v2 = self.publish_version("mail", make_files("b"), ["mail.read"])
        self.service.register_tenant("t1", "CN", "pro", actor_id="admin")
        self.service.enable_for_tenant("mail", "t1", version_id=v1, actor_id="admin")
        batch = self.service.start_rollout("mail", v2, 100, salt="s", actor_id="op")
        self.service.assign_due_tenants(batch["batch_id"], ["t1"], actor_id="op")
        self.service.report_anomaly(batch["batch_id"], 0.5, 0.1, actor_id="monitor")
        self.service.rollback_batch(batch["batch_id"], actor_id="op")

        history = self.service.install_history("t1", "mail")
        self.assertEqual(
            [item["version_id"] for item in history], [v1, v2, v1]
        )
        self.assertIsNone(history[-1]["removed_at"])
        # 当前运行内容仍可用 v1 的确切清单验证通过。
        self.assertTrue(
            self.service.verify_installed_content("t1", "mail", make_files("a"))["verified"]
        )
