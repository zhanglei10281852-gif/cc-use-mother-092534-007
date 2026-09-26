"""上传、内容指纹与去重。"""
from __future__ import annotations

import threading

from registry import EventStore, KeyStore, RegistryService, RiskPolicy
from registry.canonical import content_fingerprint, normalize_manifest

from .support import KEYS, ServiceTestCase, make_files


class FingerprintTest(ServiceTestCase):
    def test_fingerprint_is_order_insensitive_but_content_sensitive(self):
        m1 = normalize_manifest(
            [make_files("a")[1], make_files("a")[0]],
            {"b": "1", "a": "2"}, ["z", "a"], ["mail.read", "payment"],
        )
        m2 = normalize_manifest(
            make_files("a"), {"a": "2", "b": "1"}, ["a", "z"], ["payment", "mail.read"],
        )
        self.assertEqual(content_fingerprint(m1), content_fingerprint(m2))

        m3 = normalize_manifest(make_files("d"), {}, [], ["mail.read"])
        self.assertNotEqual(content_fingerprint(m2), content_fingerprint(m3))

    def test_duplicate_upload_returns_same_version(self):
        first = self.service.upload_version(
            "pkg", make_files("a"), dependencies={"x": "1"},
            entry_points=["m:r"], capabilities=["mail.read"], actor_id="op",
            idempotency_key="up-1",
        )
        again = self.service.upload_version(
            "pkg", make_files("a"), dependencies={"x": "1"},
            entry_points=["m:r"], capabilities=["mail.read"], actor_id="op",
        )
        self.assertEqual(first["version_id"], again["version_id"])
        self.assertTrue(again["deduplicated"])
        self.assertEqual(len(self.service.view().package_versions["pkg"]), 1)

    def test_dependency_drift_is_a_different_version(self):
        first = self.service.upload_version(
            "pkg", make_files("a"), dependencies={"x": "1.0"},
            entry_points=["m:r"], capabilities=[], actor_id="op",
        )
        drifted = self.service.upload_version(
            "pkg", make_files("a"), dependencies={"x": "2.0"},
            entry_points=["m:r"], capabilities=[], actor_id="op",
        )
        self.assertNotEqual(first["version_id"], drifted["version_id"])

    def test_idempotent_retry_does_not_duplicate(self):
        kwargs = dict(
            dependencies={}, entry_points=[], capabilities=[], actor_id="op",
            idempotency_key="idem-upload",
        )
        first = self.service.upload_version("pkg", make_files("a"), **kwargs)
        second = self.service.upload_version("pkg", make_files("a"), **kwargs)
        self.assertEqual(first["version_id"], second["version_id"])

    def test_concurrent_identical_uploads_create_one_version(self):
        # 每个线程独立连接同一数据库文件：写事务在 SQLite 层串行，
        # version_uploads 唯一约束保证只登记一个版本，其余请求去重。
        errors: list[Exception] = []
        results: list[str] = []
        lock = threading.Lock()

        def upload() -> None:
            store = EventStore(self.path)
            try:
                svc = RegistryService(store, RiskPolicy.default(), KeyStore(KEYS))
                out = svc.upload_version(
                    "pkg", make_files("a"), dependencies={},
                    entry_points=["m:r"], capabilities=["mail.read"], actor_id="op",
                )
                with lock:
                    results.append(out["version_id"])
            except Exception as exc:  # noqa: BLE001 - 记录到列表断言
                with lock:
                    errors.append(exc)
            finally:
                store.close()

        threads = [threading.Thread(target=upload) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors)
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(len(self.service.view().package_versions["pkg"]), 1)
