"""技能包登记与放行服务。

每个公共方法对应一条命令，统一在一个 ``BEGIN IMMEDIATE`` 事务内：
折叠事件 -> 校验 -> 追加事件 -> 登记结果。重启后只需重新折叠事件日志，
审查停留环节与回滚批次进度天然连续。
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping, Sequence

from .canonical import (
    content_fingerprint,
    file_digest_table,
    normalize_manifest,
)
from .policy import (
    KNOWN_STAGES,
    RiskPolicy,
    tenant_in_percent,
)
from .projections import (
    BATCH_FROZEN,
    BATCH_ROLLED_BACK,
    BATCH_ROLLING_BACK,
    BATCH_RUNNING,
    VERSION_STATE_APPROVED,
    VERSION_STATE_QUARANTINED,
    VERSION_STATE_REVIEWING,
    VERSION_STATE_ROLLED_BACK,
    RegistryView,
    UnknownAggregate,
    fold,
)
from .signing import KeyStore
from .store import Conflict, EventStore

PLANS = ("free", "pro", "enterprise")


class ServiceError(Exception):
    """业务规则拒绝。"""


class RegistryService:
    def __init__(
        self,
        store: EventStore,
        policy: RiskPolicy | None = None,
        keys: KeyStore | None = None,
    ) -> None:
        self.store = store
        self.policy = policy or RiskPolicy.default()
        self.keys = keys or KeyStore()

    # ------------------------------------------------------------------
    # 内部基础
    # ------------------------------------------------------------------

    def _view(self, tx) -> RegistryView:
        return fold(self.store.all_events())

    def _version(self, view: RegistryView, version_id: str):
        try:
            return view.version(version_id)
        except UnknownAggregate:
            raise ServiceError(f"未知版本：{version_id}") from None

    def _audit(self, view: RegistryView) -> list[dict[str, Any]]:
        return self.store.all_events()

    # ------------------------------------------------------------------
    # 租户
    # ------------------------------------------------------------------

    def register_tenant(
        self, tenant_id: str, region: str, plan: str, *, actor_id: str, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        if plan not in self.policy.plan_order:
            raise ServiceError(f"未知套餐：{plan}")
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            if tenant_id in view.tenants:
                raise ServiceError("租户已存在")
            tx.append(
                "tenant", tenant_id, "tenant.registered",
                {"region": region, "plan": plan}, actor_id,
            )
            result = {"tenant_id": tenant_id, "region": region, "plan": plan}
            tx.remember(idempotency_key, result)
            return result

    # ------------------------------------------------------------------
    # 上传 / 清单 / 内容指纹
    # ------------------------------------------------------------------

    def upload_version(
        self,
        package_id: str,
        files: Sequence[Mapping[str, Any]],
        *,
        dependencies: Mapping[str, str] | None = None,
        entry_points: Sequence[str] | None = None,
        capabilities: Sequence[str] | None = None,
        name: str | None = None,
        actor_id: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        manifest = normalize_manifest(files, dependencies or {}, entry_points or [], capabilities or [])
        fingerprint = content_fingerprint(manifest)
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            # 重复上传：相同内容摘要直接返回既有版本，绝不产生第二个版本。
            existing = tx.existing_upload(package_id, fingerprint)
            if existing is not None:
                result = {
                    "package_id": package_id,
                    "version_id": existing,
                    "fingerprint": fingerprint,
                    "deduplicated": True,
                }
                tx.remember(idempotency_key, result)
                return result
            version_id = f"ver-{uuid.uuid4().hex[:12]}"
            tx.register_upload(version_id, package_id, fingerprint)
            tx.append(
                "version", version_id, "package.uploaded",
                {
                    "package_id": package_id,
                    "name": name or package_id,
                    "fingerprint": fingerprint,
                    "manifest": manifest,
                },
                actor_id,
            )
            result = {
                "package_id": package_id,
                "version_id": version_id,
                "fingerprint": fingerprint,
                "deduplicated": False,
            }
            tx.remember(idempotency_key, result)
            return result

    def verify_manifest(self, version_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            view = self._view(tx)
            version = self._version(view, version_id)
            if version.manifest_verified:
                return {"version_id": version_id, "already_verified": True}
            # 用存储的规范清单重算摘要：任何字节/依赖漂移都会让摘要对不上。
            recomputed = content_fingerprint(version.manifest)
            if recomputed != version.fingerprint:
                raise ServiceError("清单摘要不一致，疑似内容漂移")
            for item in version.manifest["files"]:
                if len(item["sha256"]) != 64:
                    raise ServiceError(f"文件摘要格式非法：{item['path']}")
            tx.append("version", version_id, "manifest.verified", {}, actor_id)
            return {"version_id": version_id, "fingerprint": version.fingerprint}

    # ------------------------------------------------------------------
    # 风险路由与审查签署
    # ------------------------------------------------------------------

    def open_review(self, version_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            view = self._view(tx)
            version = self._version(view, version_id)
            if not version.manifest_verified:
                raise ServiceError("清单尚未验证，不能进入审查")
            if version.state in (VERSION_STATE_REVIEWING, VERSION_STATE_APPROVED,
                                 VERSION_STATE_QUARANTINED, VERSION_STATE_ROLLED_BACK):
                raise ServiceError(f"版本当前状态 {version.state}，不能开启审查")
            stages = sorted(self.policy.stages_for(version.capabilities))
            previous_caps: set[str] = set()
            officials = view.official_versions(version.package_id)
            if officials:
                previous_caps = set(officials[-1].capabilities)
            widened = sorted(set(version.capabilities) - previous_caps)
            tx.append(
                "version", version_id, "review.opened",
                {"stages": stages, "widened_capabilities": widened}, actor_id,
            )
            return {"version_id": version_id, "stages": stages, "widened_capabilities": widened}

    def sign_review(
        self, version_id: str, stage: str, signer: str, *, idempotency_key: str | None = None
    ) -> dict[str, Any]:
        if stage not in KNOWN_STAGES:
            raise ServiceError(f"未知审查环节：{stage}")
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            version = self._version(view, version_id)
            review = version.reviews.get(stage)
            if review is None:
                raise ServiceError(f"该版本不需要 {stage} 审批，或审查未开启")
            if signer in review.signatures:
                raise Conflict("该环节已由同一签署人签署")
            # 签名只覆盖内容摘要 + 能力集合 + 环节。
            signature = self.keys.sign(signer, version.fingerprint, version.capabilities, stage)
            tx.append(
                "version", version_id, "review.signed",
                {"stage": stage, "signer": signer, "signature": signature}, signer,
            )
            result = {"version_id": version_id, "stage": stage, "signer": signer, "signature": signature}
            tx.remember(idempotency_key, result)
            return result

    def approve_version(self, version_id: str, *, actor_id: str, idempotency_key: str | None = None) -> dict[str, Any]:
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            version = self._version(view, version_id)
            if version.state == VERSION_STATE_APPROVED:
                raise Conflict("版本已批准")
            if not version.manifest_verified:
                raise ServiceError("清单未验证")
            required = self.policy.stages_for(version.capabilities)
            if not required:
                raise ServiceError("能力集合未路由到任何审批环节")
            if set(version.reviews) != required:
                raise ServiceError("审查环节与风险路由不一致，请重新开启审查")
            for stage in required:
                review = version.reviews[stage]
                if not review.signatures:
                    raise ServiceError(f"{stage} 尚未签署")
                # 从当前清单重算摘要：签署后任何文件/依赖/能力漂移都会让指纹改变。
                current_fingerprint = content_fingerprint(version.manifest)
                if current_fingerprint != version.fingerprint:
                    raise ServiceError("当前内容摘要与登记不一致（内容或依赖已漂移）")
                for signer, record in review.signatures.items():
                    # 按当前内容与能力验签：漂移内容的指纹改变，旧签名自动失效。
                    if not self.keys.verify_signature(
                        signer, current_fingerprint, version.capabilities, stage, record["signature"]
                    ):
                        raise ServiceError(f"{stage} 的签名对当前内容失效（内容或能力已漂移）")
            # 并发审批在此串行：第二个事务读到的已是 approved，且唯一约束兜底。
            version_no = tx.next_official_no(version.package_id)
            tx.register_official(version.package_id, version_no, version_id, version.fingerprint)
            tx.append(
                "version", version_id, "version.approved",
                {"official_no": version_no, "fingerprint": version.fingerprint}, actor_id,
            )
            result = {
                "package_id": version.package_id,
                "version_id": version_id,
                "official_no": version_no,
            }
            tx.remember(idempotency_key, result)
            return result

    def reject_version(self, version_id: str, reason: str, *, actor_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            view = self._view(tx)
            version = self._version(view, version_id)
            if version.state == VERSION_STATE_APPROVED:
                raise ServiceError("已批准版本不能驳回，如需停用请隔离")
            tx.append("version", version_id, "version.rejected", {"reason": reason}, actor_id)
            return {"version_id": version_id, "state": "rejected"}

    def quarantine_version(self, version_id: str, reason: str, *, actor_id: str) -> dict[str, Any]:
        """隔离单个版本：立即停止新分配，并列出受影响任务。"""
        with self.store.transaction() as tx:
            view = self._view(tx)
            version = self._version(view, version_id)
            tx.append("version", version_id, "version.quarantined", {"reason": reason}, actor_id)
            affected = [
                {"task_id": task.task_id, "tenant_id": task.tenant_id}
                for task in view.tasks_on_version(version_id)
            ]
            return {"version_id": version_id, "state": "quarantined", "affected_tasks": affected}

    # ------------------------------------------------------------------
    # 租户准入：地区 / 套餐 / 冲突能力 / 冻结与隔离
    # ------------------------------------------------------------------

    def _entitlement_violation(
        self, view: RegistryView, tenant, package_id: str, capabilities: Sequence[str], version_id: str
    ) -> str | None:
        # 地区：各能力允许地区取交集。
        for capability in capabilities:
            rule = self.policy.rules.get(capability)
            if rule is not None and rule.allowed_regions and tenant.region not in rule.allowed_regions:
                return f"地区 {tenant.region} 不允许能力 {capability}"
        # 套餐。
        if not self.policy.plan_allows(tenant.plan, capabilities):
            return f"套餐 {tenant.plan} 低于能力要求的 {self.policy.required_plan(capabilities)}"
        # 冲突能力：与该租户其他在用技能比较冲突组。
        new_groups = self.policy.conflict_groups(capabilities)
        if new_groups:
            for other_pkg, assignment in tenant.assignments.items():
                if other_pkg == package_id or assignment.current is None:
                    continue
                other_groups = self.policy.conflict_groups(assignment.current.capabilities)
                clash = new_groups & other_groups
                if clash:
                    return f"与已启用技能 {other_pkg} 存在冲突能力组：{sorted(clash)}"
        # 隔离 / 回滚 / 冻结中的版本不接受新分配。
        version = view.versions.get(version_id)
        if version is not None:
            if version.state in (VERSION_STATE_QUARANTINED, VERSION_STATE_ROLLED_BACK):
                return f"版本处于 {version.state}，已停止分配"
            for batch in view.package_batches.get(package_id, []):
                state = view.batches[batch]
                if state.target_version_id == version_id and state.state == BATCH_FROZEN:
                    return "该版本灰度已冻结，停止新分配"
        return None

    def enable_for_tenant(
        self,
        package_id: str,
        tenant_id: str,
        *,
        version_id: str | None = None,
        actor_id: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            if tenant_id not in view.tenants:
                raise ServiceError(f"未知租户：{tenant_id}")
            tenant = view.tenants[tenant_id]
            target = self._resolve_target(view, package_id, version_id)
            violation = self._entitlement_violation(
                view, tenant, package_id, target.capabilities, target.version_id
            )
            if violation:
                raise ServiceError(violation)
            current = tenant.assignments.get(package_id)
            if current is not None and current.current is not None:
                if current.current.version_id == target.version_id:
                    return {"package_id": package_id, "tenant_id": tenant_id,
                            "version_id": target.version_id, "already_enabled": True}
                event_type = "assignment.migrated"
            else:
                event_type = "assignment.activated"
            tx.append(
                "tenant", tenant_id, event_type,
                self._assignment_payload(package_id, target), actor_id,
            )
            self._bind_tasks(tx, view, tenant_id, package_id, target, actor_id)
            result = {"package_id": package_id, "tenant_id": tenant_id,
                      "version_id": target.version_id, "fingerprint": target.fingerprint}
            tx.remember(idempotency_key, result)
            return result

    def _resolve_target(self, view: RegistryView, package_id: str, version_id: str | None):
        if version_id is None:
            target = view.latest_safe_version(package_id)
            if target is None:
                raise ServiceError(f"包 {package_id} 没有可启用的安全正式版本")
            return target
        target = view.versions.get(version_id)
        if target is None or target.package_id != package_id:
            raise ServiceError(f"未知版本：{version_id}")
        if target.state != VERSION_STATE_APPROVED or target.official_no is None:
            raise ServiceError("只能启用已批准的正式版本")
        return target

    @staticmethod
    def _assignment_payload(package_id: str, version) -> dict[str, Any]:
        return {
            "package_id": package_id,
            "version_id": version.version_id,
            "fingerprint": version.fingerprint,
            "digests": file_digest_table(version.manifest["files"]),
            "capabilities": list(version.capabilities),
        }

    def _bind_tasks(self, tx, view, tenant_id, package_id, version, actor_id) -> None:
        for task in view.tasks.values():
            if task.tenant_id == tenant_id and task.package_id == package_id and task.active:
                tx.append(
                    "task", task.task_id, "task.version_bound",
                    {"version_id": version.version_id, "fingerprint": version.fingerprint}, actor_id,
                )

    def register_task(self, task_id: str, tenant_id: str, package_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            view = self._view(tx)
            if task_id in view.tasks:
                raise Conflict("任务已存在")
            tenant = view.tenants.get(tenant_id)
            if tenant is None:
                raise ServiceError(f"未知租户：{tenant_id}")
            assignment = tenant.assignments.get(package_id)
            if assignment is None or assignment.current is None:
                raise ServiceError("租户尚未启用该技能包")
            record = assignment.current
            tx.append(
                "task", task_id, "task.registered",
                {"tenant_id": tenant_id, "package_id": package_id,
                 "version_id": record.version_id, "fingerprint": record.fingerprint},
                actor_id,
            )
            return {"task_id": task_id, "version_id": record.version_id}

    # ------------------------------------------------------------------
    # 灰度发布
    # ------------------------------------------------------------------

    def start_rollout(
        self,
        package_id: str,
        version_id: str,
        percent: int,
        *,
        salt: str | None = None,
        safe_version_id: str | None = None,
        actor_id: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if not 0 < percent <= 100:
            raise ServiceError("灰度比例必须在 1..100 之间")
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            target = self._version(view, version_id)
            if target.package_id != package_id or target.state != VERSION_STATE_APPROVED:
                raise ServiceError("灰度目标必须是已批准版本")
            if safe_version_id is None:
                safe = self._previous_safe(view, package_id, version_id)
                safe_version_id = safe.version_id if safe else None
            salt = salt or uuid.uuid4().hex
            batch_id = f"batch-{uuid.uuid4().hex[:12]}"
            tx.append(
                "batch", batch_id, "rollout.started",
                {"package_id": package_id, "target_version_id": version_id,
                 "safe_version_id": safe_version_id, "salt": salt, "percent": percent},
                actor_id,
            )
            result = {"batch_id": batch_id, "salt": salt, "percent": percent,
                      "safe_version_id": safe_version_id}
            tx.remember(idempotency_key, result)
            return result

    @staticmethod
    def _previous_safe(view: RegistryView, package_id: str, version_id: str):
        candidates = [
            version for version in view.official_versions(package_id)
            if version.version_id != version_id and version.state == VERSION_STATE_APPROVED
        ]
        return candidates[-1] if candidates else None

    def expand_rollout(self, batch_id: str, percent: int, *, actor_id: str) -> dict[str, Any]:
        """扩大灰度比例。盐与桶函数不变，只是纳入更多桶；冻结期间禁止。"""
        with self.store.transaction() as tx:
            view = self._view(tx)
            batch = self._batch(view, batch_id)
            if batch.state == BATCH_FROZEN:
                raise ServiceError("批次已冻结，不能扩大灰度")
            if batch.state != BATCH_RUNNING:
                raise ServiceError(f"批次状态 {batch.state}，不能扩大灰度")
            if percent <= batch.percent or percent > 100:
                raise ServiceError("新比例必须大于当前比例且不超过 100")
            tx.append("batch", batch_id, "rollout.percent_expanded", {"percent": percent}, actor_id)
            return {"batch_id": batch_id, "percent": percent}

    def assign_due_tenants(self, batch_id: str, candidate_tenant_ids: Sequence[str], *, actor_id: str) -> dict[str, Any]:
        """按批次开始时固定的盐和比例做确定性分组，为到期租户分配目标版本。"""
        assigned: list[str] = []
        skipped: dict[str, str] = {}
        with self.store.transaction() as tx:
            view = self._view(tx)
            batch = self._batch(view, batch_id)
            if batch.state == BATCH_FROZEN:
                raise ServiceError("批次已冻结，停止新分配")
            if batch.state != BATCH_RUNNING:
                raise ServiceError(f"批次状态 {batch.state}，不能分配")
            target = self._version(view, batch.target_version_id)
            in_batch = set(batch.assigned_tenants)
            for tenant_id in candidate_tenant_ids:
                if tenant_id in in_batch:
                    continue
                if not tenant_in_percent(target.version_id, tenant_id, batch.salt, batch.percent):
                    skipped[tenant_id] = "not_in_canary_bucket"
                    continue
                tenant = view.tenants.get(tenant_id)
                if tenant is None:
                    skipped[tenant_id] = "unknown_tenant"
                    continue
                violation = self._entitlement_violation(
                    view, tenant, batch.package_id, target.capabilities, target.version_id
                )
                if violation:
                    skipped[tenant_id] = violation
                    continue
                current = tenant.assignments.get(batch.package_id)
                if current is not None and current.current is not None:
                    if current.current.version_id == target.version_id:
                        # 已在目标版本上：登记进批次即可，不重复产生安装记录。
                        tx.append("batch", batch_id, "rollout.tenant_assigned",
                                  {"tenant_id": tenant_id}, actor_id)
                        assigned.append(tenant_id)
                        continue
                    event_type = "assignment.migrated"
                else:
                    event_type = "assignment.activated"
                tx.append("tenant", tenant_id, event_type,
                          self._assignment_payload(batch.package_id, target), actor_id)
                self._bind_tasks(tx, view, tenant_id, batch.package_id, target, actor_id)
                tx.append("batch", batch_id, "rollout.tenant_assigned",
                          {"tenant_id": tenant_id}, actor_id)
                assigned.append(tenant_id)
            return {"batch_id": batch_id, "assigned": assigned, "skipped": skipped}

    def report_anomaly(self, batch_id: str, anomaly_rate: float, threshold: float, *, actor_id: str) -> dict[str, Any]:
        """上报异常率；越线立即冻结新分配。回滚由 rollback_batch 显式执行。"""
        with self.store.transaction() as tx:
            view = self._view(tx)
            batch = self._batch(view, batch_id)
            if batch.state != BATCH_RUNNING:
                return {"batch_id": batch_id, "state": batch.state, "frozen": False}
            breached = anomaly_rate > threshold
            if breached:
                tx.append(
                    "batch", batch_id, "rollout.frozen",
                    {"anomaly_rate": anomaly_rate, "threshold": threshold,
                     "reason": f"异常率 {anomaly_rate:.2%} 超过阈值 {threshold:.2%}"},
                    actor_id,
                )
            return {"batch_id": batch_id, "anomaly_rate": anomaly_rate,
                    "threshold": threshold, "frozen": breached}

    def resume_rollout(self, batch_id: str, *, actor_id: str) -> dict[str, Any]:
        with self.store.transaction() as tx:
            view = self._view(tx)
            batch = self._batch(view, batch_id)
            if batch.state != BATCH_FROZEN:
                raise ServiceError("只有冻结中的批次可以恢复")
            tx.append("batch", batch_id, "rollout.resumed", {}, actor_id)
            return {"batch_id": batch_id, "state": BATCH_RUNNING}

    def rollback_batch(
        self, batch_id: str, *, batch_size: int | None = None, actor_id: str,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """把批次内已分配租户回滚到最近安全版本。

        分批推进、可重复调用：每批处理 ``batch_size`` 个租户，全部完成后批次关闭。
        状态全部在事件里，进程重启后再次调用即从中断处继续。
        """
        with self.store.transaction() as tx:
            if (cached := tx.cached_result(idempotency_key)) is not None:
                return cached
            view = self._view(tx)
            batch = self._batch(view, batch_id)
            if batch.state in (BATCH_ROLLED_BACK,):
                return {"batch_id": batch_id, "state": BATCH_ROLLED_BACK, "reverted": [], "done": True}
            if batch.state not in (BATCH_FROZEN, BATCH_ROLLING_BACK, BATCH_RUNNING):
                raise ServiceError(f"批次状态 {batch.state}，不能回滚")

            safe = None
            if batch.state != BATCH_ROLLING_BACK:
                safe_version_id = batch.safe_version_id
                if safe_version_id is not None:
                    safe = view.versions.get(safe_version_id)
                    if safe is None or safe.state != VERSION_STATE_APPROVED:
                        raise ServiceError("回滚目标安全版本不可用")
                tx.append(
                    "batch", batch_id, "rollout.rollback_started",
                    {"safe_version_id": batch.safe_version_id}, actor_id,
                )
                # 目标版本标记为已回滚：持久事实，阻止再分配。
                tx.append("version", batch.target_version_id, "version.rolled_back",
                          {"batch_id": batch_id}, actor_id)
                view = self._view(tx)
                batch = view.batches[batch_id]
            # 续跑批次（含重启后）也要解析回滚目标：始终以批次固定的安全版本为准。
            if safe is None and batch.safe_version_id is not None:
                safe = view.versions.get(batch.safe_version_id)
                if safe is None or safe.state != VERSION_STATE_APPROVED:
                    raise ServiceError("回滚目标安全版本不可用")

            pending = batch.pending_rollback_tenants
            due = pending if batch_size is None else pending[:batch_size]
            reverted: list[str] = []
            for tenant_id in due:
                tenant = view.tenants[tenant_id]
                assignment = tenant.assignments[batch.package_id]
                if safe is None:
                    # 没有安全版本可退回：停用分配并关闭任务。
                    tx.append("tenant", tenant_id, "assignment.deactivated",
                              {"package_id": batch.package_id}, actor_id)
                    for task in view.tasks.values():
                        if task.tenant_id == tenant_id and task.package_id == batch.package_id and task.active:
                            tx.append("task", task.task_id, "task.closed",
                                      {"reason": "rollback_without_safe_version"}, actor_id)
                else:
                    tx.append("tenant", tenant_id, "assignment.migrated",
                              self._assignment_payload(batch.package_id, safe), actor_id)
                    self._bind_tasks(tx, view, tenant_id, batch.package_id, safe, actor_id)
                tx.append("batch", batch_id, "rollout.tenant_reverted",
                          {"tenant_id": tenant_id}, actor_id)
                reverted.append(tenant_id)

            remaining = len(pending) - len(due)
            done = remaining == 0
            if done:
                tx.append("batch", batch_id, "rollout.completed",
                          {"state": BATCH_ROLLED_BACK}, actor_id)
            result = {
                "batch_id": batch_id,
                "state": BATCH_ROLLED_BACK if done else BATCH_ROLLING_BACK,
                "reverted": reverted,
                "remaining": remaining,
                "done": done,
            }
            tx.remember(idempotency_key, {"state": result["state"], "done": done})
            return result

    def _batch(self, view: RegistryView, batch_id: str):
        try:
            return view.batch(batch_id)
        except UnknownAggregate:
            raise ServiceError(f"未知批次：{batch_id}") from None

    # ------------------------------------------------------------------
    # 查询 / 审计 / 历史安装验证
    # ------------------------------------------------------------------

    def view(self) -> RegistryView:
        return fold(self.store.all_events())

    def affected_tasks(self, version_id: str) -> list[dict[str, Any]]:
        view = self.view()
        return [
            {"task_id": task.task_id, "tenant_id": task.tenant_id,
             "package_id": task.package_id, "version_id": task.version_id}
            for task in view.tasks_on_version(version_id)
        ]

    def install_history(self, tenant_id: str, package_id: str) -> list[dict[str, Any]]:
        """该租户该技能包的完整安装轨迹（含被替换/移除的版本）。"""
        view = self.view()
        tenant = view.tenants.get(tenant_id)
        if tenant is None:
            raise ServiceError(f"未知租户：{tenant_id}")
        assignment = tenant.assignments.get(package_id)
        if assignment is None:
            return []
        return [
            {
                "version_id": record.version_id,
                "fingerprint": record.fingerprint,
                "digests": record.digests,
                "capabilities": record.capabilities,
                "installed_at": record.installed_at,
                "removed_at": record.removed_at,
            }
            for record in assignment.history
        ]

    def verify_installed_content(
        self, tenant_id: str, package_id: str, delivered_files: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """校验当前安装运行的确切内容：交付摘要必须与历史安装记录逐文件一致。"""
        view = self.view()
        tenant = view.tenants.get(tenant_id)
        if tenant is None:
            raise ServiceError(f"未知租户：{tenant_id}")
        assignment = tenant.assignments.get(package_id)
        if assignment is None or assignment.current is None:
            raise ServiceError("租户未安装该技能包")
        record = assignment.current
        delivered = file_digest_table(delivered_files)
        if set(delivered) != set(record.digests):
            drift = sorted(set(delivered) ^ set(record.digests))
            raise ServiceError(f"文件清单漂移：{drift}")
        changed = {
            path: {"expected": expected, "actual": delivered[path]}
            for path, expected in record.digests.items()
            if delivered[path] != expected
        }
        if changed:
            raise ServiceError(f"文件摘要漂移：{changed}")
        return {
            "tenant_id": tenant_id,
            "package_id": package_id,
            "version_id": record.version_id,
            "fingerprint": record.fingerprint,
            "verified": True,
        }

    def event_log(self) -> list[dict[str, Any]]:
        return self.store.all_events()
