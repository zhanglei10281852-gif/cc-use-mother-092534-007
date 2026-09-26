"""风险路由、多环节签署、能力扩大重审与漂移失效。"""
from __future__ import annotations

from registry import ServiceError
from registry.canonical import content_fingerprint

from .support import ServiceTestCase, make_files


class RoutingTest(ServiceTestCase):
    def test_payment_routes_to_all_three_stages(self):
        vid = self.service.upload_version(
            "pay", make_files("a"), capabilities=["payment"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        opened = self.service.open_review(vid, actor_id="op")
        self.assertEqual(
            set(opened["stages"]), {"code_review", "data_owner", "finance"}
        )

    def test_mail_write_routes_to_code_and_data_owner(self):
        vid = self.service.upload_version(
            "mail", make_files("a"), capabilities=["mail.write"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        opened = self.service.open_review(vid, actor_id="op")
        self.assertEqual(set(opened["stages"]), {"code_review", "data_owner"})

    def test_approval_requires_every_stage_signed(self):
        vid = self.service.upload_version(
            "pay", make_files("a"), capabilities=["payment"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        self.service.open_review(vid, actor_id="op")
        self.service.sign_review(vid, "code_review", "reviewer-code")
        self.service.sign_review(vid, "data_owner", "reviewer-data")
        with self.assertRaises(ServiceError):
            self.service.approve_version(vid, actor_id="op")

    def test_full_approval_succeeds_and_assigns_official_number(self):
        vid = self.publish_version("pay", make_files("a"), ["payment.read"])
        state = self.service.view().version(vid)
        self.assertEqual(state.state, "approved")
        self.assertEqual(state.official_no, 1)

    def test_capability_widening_requires_new_review(self):
        v1 = self.publish_version("mail", make_files("a"), ["mail.read"])
        v2 = self.service.upload_version(
            "mail", make_files("b"), capabilities=["mail.write"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(v2, actor_id="scanner")
        opened = self.service.open_review(v2, actor_id="op")
        # mail.write 相对上一个正式版本是新增能力，且需要数据所有者环节。
        self.assertIn("mail.write", opened["widened_capabilities"])
        self.assertIn("data_owner", opened["stages"])
        self.assertNotEqual(v1, v2)

    def test_concurrent_approval_creates_single_official_version(self):
        import threading
        from registry import EventStore, KeyStore, RegistryService, RiskPolicy
        from .support import KEYS

        vid = self.service.upload_version(
            "pkg", make_files("a"), capabilities=["mail.read"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        self.service.open_review(vid, actor_id="op")
        self.service.sign_review(vid, "code_review", "reviewer-code")

        outcomes: list[str | Exception] = []

        def approve() -> None:
            store = EventStore(self.path)
            try:
                svc = RegistryService(store, RiskPolicy.default(), KeyStore(KEYS))
                svc.approve_version(vid, actor_id="op")
                outcomes.append("ok")
            except Exception as exc:  # noqa: BLE001
                outcomes.append(exc)
            finally:
                store.close()

        threads = [threading.Thread(target=approve) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(outcomes.count("ok"), 1, outcomes)
        officials = self.service.view().official_versions("pkg")
        self.assertEqual(len(officials), 1)
        self.assertEqual(officials[0].version_id, vid)


class DriftSignatureTest(ServiceTestCase):
    def test_signature_covers_fingerprint_and_capabilities(self):
        vid = self.service.upload_version(
            "pkg", make_files("a"), capabilities=["mail.read"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        self.service.open_review(vid, actor_id="op")
        signed = self.service.sign_review(vid, "code_review", "reviewer-code")
        # 直接用不同指纹/能力验签必然失败。
        self.assertFalse(
            self.keys.verify_signature(
                "reviewer-code", "f" * 64, ["mail.read"], "code_review", signed["signature"]
            )
        )
        self.assertFalse(
            self.keys.verify_signature(
                "reviewer-code", self.service.view().version(vid).fingerprint,
                ["payment"], "code_review", signed["signature"],
            )
        )

    def test_approval_fails_when_content_drifted_after_signing(self):
        vid = self.service.upload_version(
            "pkg", make_files("a"), capabilities=["mail.read"], actor_id="op"
        )["version_id"]
        self.service.verify_manifest(vid, actor_id="scanner")
        self.service.open_review(vid, actor_id="op")
        self.service.sign_review(vid, "code_review", "reviewer-code")

        # 模拟漂移：直接改写事件日志中已签署版本的清单（依赖被替换），
        # 内容指纹随之改变，审批时验签必须失败。
        import json
        conn = self.store.connection
        row = conn.execute(
            "select event_id, payload from event_log where event_type='package.uploaded'"
        ).fetchone()
        payload = json.loads(row["payload"])
        payload["manifest"]["dependencies"] = {"evil": "9.9.9"}
        conn.execute(
            "update event_log set payload=? where event_id=?",
            (json.dumps(payload, ensure_ascii=False, sort_keys=True), row["event_id"]),
        )
        conn.commit()
        with self.assertRaises(ServiceError):
            self.service.approve_version(vid, actor_id="op")

    def test_manifest_recompute_detects_tampering(self):
        vid = self.service.upload_version(
            "pkg", make_files("a"), capabilities=["mail.read"], actor_id="op"
        )["version_id"]
        # 正常验证通过。
        self.service.verify_manifest(vid, actor_id="scanner")
        # 指纹与清单不一致时拒绝。
        import json
        conn = self.store.connection
        row = conn.execute(
            "select event_id, payload from event_log where event_type='package.uploaded'"
        ).fetchone()
        payload = json.loads(row["payload"])
        payload["fingerprint"] = content_fingerprint(payload["manifest"])[:-1] + "0"
        conn.execute(
            "update event_log set payload=? where event_id=?",
            (json.dumps(payload, ensure_ascii=False, sort_keys=True), row["event_id"]),
        )
        conn.commit()
        # 已 verified 标志为 True；新上传版本若指纹不匹配则在 verify 阶段拦截。
        vid2 = self.service.upload_version(
            "pkg2", make_files("z"), capabilities=["mail.read"], actor_id="op"
        )["version_id"]
        conn.execute(
            "update event_log set payload=json_set(payload, '$.fingerprint', ?) "
            "where aggregate_id=? and event_type='package.uploaded'",
            ("0" * 64, vid2),
        )
        conn.commit()
        with self.assertRaises(ServiceError):
            self.service.verify_manifest(vid2, actor_id="scanner")
