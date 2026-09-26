"""风险路由、签署、漂移失效与并发放行测试。"""
from __future__ import annotations

import json
import unittest

from skillregistry.errors import (
    DriftDetected,
    MissingApproval,
    ReviewClosed,
    VersionStateError,
)
from skillregistry.service import RegistryService
from tests.helpers import approve_version, make_submission, required_roles


class ReviewRoutingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")

    def submit(self, name, capabilities, *, package="mailer"):
        result = self.service.submit_package(package, make_submission(capabilities=capabilities))
        return result["version_id"]

    def test_low_risk_requires_only_code_review(self) -> None:
        version_id = self.submit("v1", ("fs.read", "calendar.read"))
        status = self.service.reviews.review_status(version_id)
        self.assertEqual(status["risk_level"], "low")
        self.assertEqual(status["required_approvers"], ["code_review"])

    def test_mail_capability_routes_to_code_review_and_data_owner(self) -> None:
        version_id = self.submit("v1", ("mail.read", "mail.send"))
        status = self.service.reviews.review_status(version_id)
        self.assertEqual(status["risk_level"], "elevated")
        self.assertEqual(set(status["required_approvers"]), {"code_review", "data_owner"})

    def test_payment_capability_routes_to_finance_as_well(self) -> None:
        version_id = self.submit("v1", ("payment.execute",))
        status = self.service.reviews.review_status(version_id)
        self.assertEqual(status["risk_level"], "critical")
        self.assertEqual(
            set(status["required_approvers"]),
            {"code_review", "data_owner", "finance"},
        )

    def test_capability_expansion_re_routes_new_capability(self) -> None:
        v1 = self.submit("v1", ("fs.read",))
        approve_version(self.service, v1, required_roles(self.service, v1))
        v2 = self.submit("v2", ("fs.read", "payment.execute"))
        status = self.service.reviews.review_status(v2)
        # 新版本扩大到支付：三角色全部要签。
        self.assertEqual(
            set(status["required_approvers"]),
            {"code_review", "data_owner", "finance"},
        )

    def test_pure_capability_narrowing_does_not_require_extra_approvals(self) -> None:
        v1 = self.submit("v1", ("mail.read", "mail.send"))
        approve_version(self.service, v1, required_roles(self.service, v1))
        v2 = self.submit("v2", ("mail.read",))
        status = self.service.reviews.review_status(v2)
        # 没有新增能力：默认仅需代码审查确认。
        self.assertEqual(status["required_approvers"], ["code_review"])


class SignatureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.service = RegistryService(":memory:")

    def _approved_payment_version(self):
        result = self.service.submit_package("pay", make_submission(capabilities=("payment.execute",)))
        version_id = result["version_id"]
        roles = required_roles(self.service, version_id)
        formal_no = approve_version(self.service, version_id, roles)
        return version_id, formal_no

    def test_approve_fails_without_all_required_signatures(self) -> None:
        result = self.service.submit_package("pay", make_submission(capabilities=("payment.execute",)))
        version_id = result["version_id"]
        self.service.reviews.sign_review(version_id, "code_review", "cr-1")
        with self.assertRaises(MissingApproval):
            self.service.reviews.approve(version_id)

    def test_full_approval_assigns_formal_version_number(self) -> None:
        version_id, formal_no = self._approved_payment_version()
        self.assertEqual(formal_no, 1)
        version = self.service.catalog.get_version(version_id)
        self.assertEqual(version["state"], "approved")

    def test_signing_after_review_closed_is_rejected(self) -> None:
        version_id, _ = self._approved_payment_version()
        with self.assertRaises(ReviewClosed):
            self.service.reviews.sign_review(version_id, "code_review", "late")

    def test_duplicate_approval_is_idempotent(self) -> None:
        version_id, first = self._approved_payment_version()
        second = self.service.reviews.approve(version_id)
        self.assertEqual(first, second)
        self.assertEqual(
            self.service.store.get(
                "select count(*) as c from versions where formal_version_no = 1"
            )["c"],
            1,
        )

    def test_signatures_verify_against_fresh_digests(self) -> None:
        version_id, _ = self._approved_payment_version()
        self.assertTrue(self.service.reviews.verify_version_signatures(version_id))

    def test_signature_does_not_carry_to_new_version(self) -> None:
        v1, _ = self._approved_payment_version()
        result = self.service.submit_package(
            "pay", make_submission(files=("main.py", "extra.py"), capabilities=("payment.execute",))
        )
        v2 = result["version_id"]
        # 新版本即使能力相同，内容摘要不同，没有继承任何签署。
        status = self.service.reviews.review_status(v2)
        self.assertEqual(status["signatures"], [])
        self.assertEqual(status["status"], "open")

    def test_tampered_version_digest_invalidates_signatures(self) -> None:
        version_id, _ = self._approved_payment_version()
        # 直接篡改底层版本摘要，模拟内容漂移：签名核验必须失败。
        with self.service.store.transaction() as conn:
            conn.execute(
                "update versions set deps_digest = ? where version_id = ?",
                ("0" * 64, version_id),
            )
        with self.assertRaises(DriftDetected):
            self.service.reviews.verify_version_signatures(version_id)
        self.service.tenants.register_tenant("t1", "enterprise", "cn-north")
        with self.assertRaises(DriftDetected):
            self.service.tenants.enable_skill("t1", "pay", version_id)

    def test_rejected_version_cannot_be_approved(self) -> None:
        result = self.service.submit_package("pay", make_submission(capabilities=("payment.execute",)))
        version_id = result["version_id"]
        self.service.reviews.reject(version_id, "security", "发现高危问题")
        with self.assertRaises(ReviewClosed):
            self.service.reviews.sign_review(version_id, "finance", "fin-1")
        self.assertEqual(self.service.catalog.get_version(version_id)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
