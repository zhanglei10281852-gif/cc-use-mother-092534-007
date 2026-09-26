"""审查路由、绑定摘要的签署、漂移核验与并发放行。

签署的载荷只包含候选版本标识、确定的内容/依赖/入口点/能力摘要、
必需审批角色集合与策略版本。版本行不可变，签署不会随新版本携带；
安装或放行前重新核验载荷摘要与签名，任何漂移都会使签署失效。
"""
from __future__ import annotations

import json
from typing import Any

from .canonical import sign, verify_signature
from .errors import (
    DriftDetected,
    DuplicateFormalVersion,
    MissingApproval,
    ReviewClosed,
    UnknownObject,
    VersionStateError,
)
from .policy import PolicyBook
from .store import Store, new_id, now_iso

# 签署载荷的固定结构，字段名也是签名边界的一部分。
SIGNATURE_PAYLOAD_VERSION = 1


class ReviewService:
    def __init__(self, store: Store, policy: PolicyBook, secret: str = "registry-signing-secret"):
        self.store = store
        self.policy = policy
        self.secret = secret

    # -- 路由 -----------------------------------------------------------

    def start_review(self, version_id: str, *, actor_id: str = "system") -> str:
        """比较与上一版本的能力差异并建立审查，返回 review_id。"""
        with self.store.transaction() as conn:
            version = conn.execute(
                "select * from versions where version_id = ?", (version_id,)
            ).fetchone()
            if version is None:
                raise UnknownObject(f"未知版本：{version_id}")
            if version["state"] != "reviewing":
                raise VersionStateError(f"版本状态 {version['state']} 不允许开始审查")
            existing = conn.execute(
                "select review_id from reviews where version_id = ? and status = 'open'",
                (version_id,),
            ).fetchone()
            if existing:
                return existing["review_id"]

            previous_caps: set[str] = set()
            predecessor_id = version["predecessor_version_id"]
            if predecessor_id:
                previous_caps = {
                    row["capability"]
                    for row in conn.execute(
                        "select capability from version_capabilities where version_id = ?",
                        (predecessor_id,),
                    )
                }
            current_caps = [
                row["capability"]
                for row in conn.execute(
                    "select capability from version_capabilities where version_id = ? order by capability",
                    (version_id,),
                )
            ]
            decision = self.policy.route(current_caps, previous_caps)
            review_id = new_id("rev")
            conn.execute(
                "insert into reviews(review_id, version_id, predecessor_version_id, risk_level, "
                "required_approvers, reasons, policy_version, status, created_at) "
                "values (?, ?, ?, ?, ?, ?, ?, 'open', ?)",
                (
                    review_id, version_id, predecessor_id, decision.risk_level,
                    json.dumps(decision.required_approvers, ensure_ascii=False),
                    json.dumps(decision.reasons, ensure_ascii=False),
                    decision.policy_version, now_iso(),
                ),
            )
            self.store.append_event(
                conn, "review.routed", "review", review_id, actor_id,
                {
                    "version_id": version_id,
                    "risk_level": decision.risk_level,
                    "required_approvers": list(decision.required_approvers),
                    "added_capabilities": sorted(decision.added_capabilities),
                    "policy_version": decision.policy_version,
                    "reasons": list(decision.reasons),
                },
            )
            return review_id

    # -- 签署 -----------------------------------------------------------

    def sign_review(self, version_id: str, approver_role: str, approver_id: str) -> dict[str, Any]:
        """一个必需审批角色对当前版本摘要签署。

        审查行与签署行立即落盘：进程重启后未完成的审查仍可继续签署，
        已完成的签署不会丢失。
        """
        with self.store.transaction() as conn:
            review = self._open_review_conn(conn, version_id)
            required = set(json.loads(review["required_approvers"]))
            if approver_role not in required:
                raise VersionStateError(f"该审查不需要审批角色：{approver_role}")
            payload = self._payload(conn, review)
            payload_digest, signature = sign(self.secret, payload)
            conn.execute(
                "insert or replace into signatures(review_id, approver_role, approver_id, "
                "payload_digest, signature, signed_at) values (?, ?, ?, ?, ?, ?)",
                (review["review_id"], approver_role, approver_id, payload_digest, signature, now_iso()),
            )
            self.store.append_event(
                conn, "review.signed", "review", review["review_id"], approver_id,
                {"version_id": version_id, "approver_role": approver_role, "payload_digest": payload_digest},
            )
            return {"review_id": review["review_id"], "payload_digest": payload_digest, "signature": signature}

    def reject(self, version_id: str, approver_id: str, reason: str) -> None:
        with self.store.transaction() as conn:
            review = self._open_review_conn(conn, version_id)
            conn.execute(
                "update reviews set status = 'rejected', closed_at = ? where review_id = ?",
                (now_iso(), review["review_id"]),
            )
            conn.execute("update versions set state = 'rejected' where version_id = ?", (version_id,))
            self.store.append_event(
                conn, "review.rejected", "review", review["review_id"], approver_id,
                {"version_id": version_id, "reason": reason},
            )

    # -- 放行（并发安全） -----------------------------------------------

    def approve(self, version_id: str, *, actor_id: str = "system") -> int:
        """全部必需角色签署后放行，分配正式版本号，返回版本号。

        使用即时事务串行化并发审批；正式版本号在事务内取 max+1，
        并有唯一约束兜底，重复/并发调用只会产生一个正式版本。
        """
        for attempt in range(2):
            try:
                with self.store.transaction() as conn:
                    review = conn.execute(
                        "select * from reviews where version_id = ? order by rowid desc limit 1",
                        (version_id,),
                    ).fetchone()
                    if review is None:
                        raise UnknownObject(f"版本没有审查记录：{version_id}")
                    if review["status"] == "approved":
                        # 并发审批已胜出：幂等返回同一正式版本号。
                        published = conn.execute(
                            "select formal_version_no from versions where version_id = ?",
                            (version_id,),
                        ).fetchone()
                        return int(published["formal_version_no"])
                    if review["status"] != "open":
                        raise ReviewClosed(f"审查已结束：{review['status']}")
                    version = conn.execute(
                        "select * from versions where version_id = ?", (version_id,)
                    ).fetchone()
                    if version["state"] not in ("reviewing",):
                        raise VersionStateError(f"版本状态 {version['state']} 不允许放行")

                    required = set(json.loads(review["required_approvers"]))
                    signed_rows = conn.execute(
                        "select * from signatures where review_id = ?", (review["review_id"],)
                    ).fetchall()
                    signed_roles = {row["approver_role"] for row in signed_rows}
                    missing = required - signed_roles
                    if missing:
                        raise MissingApproval(f"缺少审批角色签署：{','.join(sorted(missing))}")

                    # 漂移核验：重算载荷摘要并逐角色验证 HMAC。
                    payload = self._payload(conn, review)
                    from .canonical import digest as canonical_digest
                    fresh_digest = canonical_digest(payload)
                    for row in signed_rows:
                        if row["payload_digest"] != fresh_digest:
                            raise DriftDetected(
                                f"签署载荷与当前版本摘要不一致（{row['approver_role']}），签署失效"
                            )
                        if not verify_signature(self.secret, row["payload_digest"], row["signature"]):
                            raise DriftDetected(f"签名核验失败（{row['approver_role']}）")

                    max_no = conn.execute(
                        "select max(formal_version_no) from versions where package_id = ?",
                        (version["package_id"],),
                    ).fetchone()[0]
                    next_no = (max_no or 0) + 1
                    try:
                        cursor = conn.execute(
                            "update versions set state = 'approved', formal_version_no = ?, "
                            "published_at = ? where version_id = ? and state = 'reviewing'",
                            (next_no, now_iso(), version_id),
                        )
                    except Exception:
                        # 唯一约束冲突意味着并发审批已经分配了版本号。
                        raise DuplicateFormalVersion("正式版本号冲突，可能存在并发审批")
                    if cursor.rowcount == 0:
                        raise DuplicateFormalVersion("版本已被并发审批处理")
                    conn.execute(
                        "update reviews set status = 'approved', closed_at = ? where review_id = ?",
                        (now_iso(), review["review_id"]),
                    )
                    self.store.append_event(
                        conn, "version.approved", "version", version_id, actor_id,
                        {"formal_version_no": next_no, "review_id": review["review_id"]},
                    )
                    return next_no
            except DuplicateFormalVersion:
                if attempt == 0:
                    # 并发审批胜出：重读状态，若已成为正式版本则幂等返回其版本号。
                    current = self.store.get(
                        "select state, formal_version_no from versions where version_id = ?",
                        (version_id,),
                    )
                    if current["state"] == "approved" and current["formal_version_no"] is not None:
                        return int(current["formal_version_no"])
                raise

    # -- 漂移核验 -------------------------------------------------------

    def verify_version_signatures(self, version_id: str) -> bool:
        """核验某版本全部签署仍然有效（供安装/启用前调用）。"""
        with self.store.transaction() as conn:
            review = conn.execute(
                "select * from reviews where version_id = ? and status = 'approved' "
                "order by rowid desc limit 1", (version_id,)
            ).fetchone()
            if review is None:
                raise UnknownObject(f"版本没有已通过审查：{version_id}")
            from .canonical import digest as canonical_digest
            payload = self._payload(conn, review)
            fresh_digest = canonical_digest(payload)
            rows = conn.execute(
                "select * from signatures where review_id = ?", (review["review_id"],)
            ).fetchall()
            for row in rows:
                if row["payload_digest"] != fresh_digest:
                    raise DriftDetected(f"签署载荷漂移（{row['approver_role']}）")
                if not verify_signature(self.secret, row["payload_digest"], row["signature"]):
                    raise DriftDetected(f"签名无效（{row['approver_role']}）")
            return True

    def review_status(self, version_id: str) -> dict[str, Any]:
        row = self.store.get(
            "select * from reviews where version_id = ? order by rowid desc limit 1",
            (version_id,),
        )
        if row is None:
            raise UnknownObject(f"版本没有审查记录：{version_id}")
        result = dict(row)
        result["required_approvers"] = json.loads(result["required_approvers"])
        result["reasons"] = json.loads(result["reasons"])
        result["signatures"] = [
            dict(item) for item in self.store.all(
                "select approver_role, approver_id, payload_digest, signed_at "
                "from signatures where review_id = ? order by approver_role",
                (row["review_id"],),
            )
        ]
        return result

    # -- 内部 -----------------------------------------------------------

    def _open_review_conn(self, conn, version_id: str):
        review = conn.execute(
            "select * from reviews where version_id = ? and status = 'open' order by rowid desc limit 1",
            (version_id,),
        ).fetchone()
        if review is None:
            closed = conn.execute(
                "select status from reviews where version_id = ? order by rowid desc limit 1",
                (version_id,),
            ).fetchone()
            if closed is None:
                raise UnknownObject(f"版本没有审查记录：{version_id}")
            raise ReviewClosed(f"审查已结束：{closed['status']}")
        return review

    def _payload(self, conn, review) -> dict[str, Any]:
        version = conn.execute(
            "select * from versions where version_id = ?", (review["version_id"],)
        ).fetchone()
        return {
            "payload_version": SIGNATURE_PAYLOAD_VERSION,
            "review_id": review["review_id"],
            "version_id": review["version_id"],
            "content_digest": version["content_digest"],
            "deps_digest": version["deps_digest"],
            "entrypoint_digest": version["entrypoint_digest"],
            "capability_digest": version["capability_digest"],
            "required_approvers": sorted(json.loads(review["required_approvers"])),
            "policy_version": review["policy_version"],
        }
