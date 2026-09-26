"""并发上传去重的线程测试。"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from skillregistry.service import RegistryService
from tests.helpers import make_submission


class ConcurrentUploadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "registry.db")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_concurrent_identical_uploads_create_single_version(self) -> None:
        setup = RegistryService(self.db_path)
        package_id = setup.catalog.register_package("mailer")
        setup.close()
        submission = make_submission(capabilities=("mail.read",))

        version_ids: list[str] = []
        created_flags: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            service = RegistryService(self.db_path, recover=False)
            version_id, created = service.catalog.upload(package_id, submission)
            with lock:
                version_ids.append(version_id)
                created_flags.append(created)
            service.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(set(version_ids)), 1)
        self.assertEqual(created_flags.count(True), 1)
        self.assertEqual(created_flags.count(False), 7)
        check = RegistryService(self.db_path, recover=False)
        versions = check.catalog.list_versions(package_id)
        self.assertEqual(len(versions), 1)
        check.close()


if __name__ == "__main__":
    unittest.main()
