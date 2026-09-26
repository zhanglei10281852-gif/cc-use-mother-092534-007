"""上传去重、版本差异与版本编号测试。"""
from __future__ import annotations

import unittest

from skillregistry.catalog import PackageSubmission
from skillregistry.service import RegistryService
from tests.helpers import make_submission, sha


class CatalogTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")
        self.catalog = self.service.catalog

    def test_duplicate_upload_reuses_candidate_version(self) -> None:
        package_id = self.catalog.register_package("mailer")
        submission = make_submission(capabilities=("mail.read",))
        version_id_1, created_1 = self.catalog.upload(package_id, submission)
        version_id_2, created_2 = self.catalog.upload(package_id, submission)
        self.assertTrue(created_1)
        self.assertFalse(created_2)
        self.assertEqual(version_id_1, version_id_2)
        self.assertEqual(len(self.catalog.list_versions(package_id)), 1)

    def test_field_order_does_not_create_new_version(self) -> None:
        package_id = self.catalog.register_package("mailer")
        first = make_submission(files=("a.py", "b.py"), capabilities=("mail.read", "fs.read"))
        reordered = PackageSubmission.from_dict({
            "capabilities": ["fs.read", "mail.read"],
            "files": [
                {"sha256": sha("content:b.py"), "size": 40, "path": "b.py"},
                {"sha256": sha("content:a.py"), "size": 40, "path": "a.py"},
            ],
            "dependencies": [{"name": "requests", "constraint": "^1.0", "digest": sha("dep:requests")}],
            "entrypoints": [{"command": "./bin/run", "name": "run"}],
        })
        v1, c1 = self.catalog.upload(package_id, first)
        v2, c2 = self.catalog.upload(package_id, reordered)
        self.assertEqual(v1, v2)
        self.assertFalse(c2)

    def test_content_or_dependency_change_creates_new_candidate(self) -> None:
        package_id = self.catalog.register_package("mailer")
        v1, _ = self.catalog.upload(package_id, make_submission(files=("a.py",)))
        v2, created = self.catalog.upload(package_id, make_submission(files=("a.py", "b.py")))
        self.assertTrue(created)
        self.assertNotEqual(v1, v2)
        v3, created = self.catalog.upload(package_id, make_submission(files=("a.py",), deps=("requests", "httpx")))
        self.assertTrue(created)
        self.assertNotEqual(v2, v3)

    def test_diff_reports_files_deps_and_capability_changes(self) -> None:
        package_id = self.catalog.register_package("mailer")
        v1, _ = self.catalog.upload(package_id, make_submission(
            files=("a.py", "old.py"), deps=("requests",), capabilities=("fs.read",)))
        v2, _ = self.catalog.upload(package_id, make_submission(
            files=("a.py", "new.py"), deps=("requests", "httpx"),
            capabilities=("fs.read", "mail.read")))
        diff = self.catalog.diff(v1, v2)
        self.assertEqual(diff.files_added, ("new.py",))
        self.assertEqual(diff.files_removed, ("old.py",))
        self.assertEqual(diff.deps_added, ("httpx",))
        self.assertEqual(diff.capabilities_added, ("mail.read",))
        self.assertTrue(diff.capability_expanded)
        self.assertFalse(diff.is_identical)

    def test_changed_file_content_with_same_path_is_detected(self) -> None:
        package_id = self.catalog.register_package("mailer")
        v1, _ = self.catalog.upload(package_id, make_submission(files=("a.py",)))
        changed = PackageSubmission.from_dict({
            "files": [{"path": "a.py", "size": 99, "sha256": sha("different-content")}],
            "dependencies": [{"name": "requests", "constraint": "^1.0", "digest": sha("dep:requests")}],
            "entrypoints": [{"name": "run", "command": "./bin/run"}],
            "capabilities": ["fs.read"],
        })
        v2, _ = self.catalog.upload(package_id, changed)
        diff = self.catalog.diff(v1, v2)
        self.assertEqual(diff.files_changed, ("a.py",))


if __name__ == "__main__":
    unittest.main()
