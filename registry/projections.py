"""把事件日志折叠成读模型。

所有状态都由事件派生，进程重启后重新折叠即可恢复——进行中的审查停留的环节、
回滚批次尚未处理的租户，都会原样再现。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

VERSION_STATE_UPLOADED = "uploaded"
VERSION_STATE_REVIEWING = "reviewing"
VERSION_STATE_APPROVED = "approved"
VERSION_STATE_REJECTED = "rejected"
VERSION_STATE_QUARANTINED = "quarantined"
VERSION_STATE_ROLLED_BACK = "rolled_back"
VERSION_STATE_RETIRED = "retired"

BATCH_RUNNING = "running"
BATCH_FROZEN = "frozen"
BATCH_ROLLING_BACK = "rolling_back"
BATCH_ROLLED_BACK = "rolled_back"
BATCH_COMPLETED = "completed"


@dataclass
class ReviewState:
    stage: str
    signatures: dict[str, dict[str, Any]] = field(default_factory=dict)  # signer -> {signature, at}

    @property
    def signed(self) -> bool:
        return bool(self.signatures)


@dataclass
class VersionState:
    version_id: str
    package_id: str
    fingerprint: str = ""
    manifest: dict[str, Any] = field(default_factory=dict)
    state: str = VERSION_STATE_UPLOADED
    manifest_verified: bool = False
    reviews: dict[str, ReviewState] = field(default_factory=dict)
    official_no: int | None = None
    quarantine_reason: str | None = None
    created_at: str | None = None

    @property
    def capabilities(self) -> list[str]:
        return list(self.manifest.get("capabilities", []))

    @property
    def required_stages(self) -> set[str]:
        return set(self.reviews)

    def all_stages_signed(self) -> bool:
        return bool(self.reviews) and all(review.signed for review in self.reviews.values())

    def stage_signed_by(self, stage: str) -> set[str]:
        review = self.reviews.get(stage)
        return set(review.signatures) if review else set()


@dataclass
class InstallRecord:
    version_id: str
    fingerprint: str
    digests: dict[str, str]
    capabilities: list[str]
    installed_at: str
    removed_at: str | None = None


@dataclass
class AssignmentState:
    package_id: str
    history: list[InstallRecord] = field(default_factory=list)

    @property
    def current(self) -> InstallRecord | None:
        for record in reversed(self.history):
            if record.removed_at is None:
                return record
        return None


@dataclass
class TenantState:
    tenant_id: str
    region: str = ""
    plan: str = ""
    assignments: dict[str, AssignmentState] = field(default_factory=dict)

    def active_capabilities(self) -> dict[str, list[str]]:
        return {
            package_id: list(record.capabilities)
            for package_id, assignment in self.assignments.items()
            if (record := assignment.current) is not None
        }


@dataclass
class TaskState:
    task_id: str
    tenant_id: str
    package_id: str
    version_id: str
    fingerprint: str
    active: bool = True


@dataclass
class BatchState:
    batch_id: str
    package_id: str = ""
    target_version_id: str = ""
    safe_version_id: str | None = None
    salt: str = ""
    percent: int = 0
    state: str = BATCH_RUNNING
    anomaly_rate: float = 0.0
    freeze_reason: str | None = None
    assigned_tenants: list[str] = field(default_factory=list)
    reverted_tenants: list[str] = field(default_factory=list)
    started_at: str | None = None

    @property
    def pending_rollback_tenants(self) -> list[str]:
        return [tenant for tenant in self.assigned_tenants if tenant not in self.reverted_tenants]


@dataclass
class RegistryView:
    packages: dict[str, dict[str, Any]] = field(default_factory=dict)
    versions: dict[str, VersionState] = field(default_factory=dict)
    package_versions: dict[str, list[str]] = field(default_factory=dict)
    tenants: dict[str, TenantState] = field(default_factory=dict)
    tasks: dict[str, TaskState] = field(default_factory=dict)
    batches: dict[str, BatchState] = field(default_factory=dict)
    package_batches: dict[str, list[str]] = field(default_factory=dict)

    # ---- 查询辅助 ------------------------------------------------------

    def version(self, version_id: str) -> VersionState:
        try:
            return self.versions[version_id]
        except KeyError:
            raise UnknownAggregate(f"未知版本：{version_id}") from None

    def tenant(self, tenant_id: str) -> TenantState:
        try:
            return self.tenants[tenant_id]
        except KeyError:
            raise UnknownAggregate(f"未知租户：{tenant_id}") from None

    def batch(self, batch_id: str) -> BatchState:
        try:
            return self.batches[batch_id]
        except KeyError:
            raise UnknownAggregate(f"未知批次：{batch_id}") from None

    def official_versions(self, package_id: str) -> list[VersionState]:
        return [
            self.versions[vid]
            for vid in self.package_versions.get(package_id, [])
            if self.versions[vid].official_no is not None
        ]

    def latest_safe_version(self, package_id: str) -> VersionState | None:
        """最近的、已批准且未隔离/回滚的正式版本。"""
        candidates = [
            version
            for version in self.official_versions(package_id)
            if version.state == VERSION_STATE_APPROVED
        ]
        return candidates[-1] if candidates else None

    def tasks_on_version(self, version_id: str) -> list[TaskState]:
        return [
            task for task in self.tasks.values()
            if task.version_id == version_id and task.active
        ]

    def tenants_on_version(self, version_id: str) -> set[str]:
        return {task.tenant_id for task in self.tasks_on_version(version_id)}


class UnknownAggregate(KeyError):
    pass


# ---------------------------------------------------------------------------
# 折叠
# ---------------------------------------------------------------------------

def _ensure_tenant(view: RegistryView, tenant_id: str) -> TenantState:
    tenant = view.tenants.get(tenant_id)
    if tenant is None:
        tenant = TenantState(tenant_id=tenant_id)
        view.tenants[tenant_id] = tenant
    return tenant


def _apply_version_event(view: RegistryView, event: Mapping[str, Any]) -> None:
    payload = event["payload"]
    version_id = event["aggregate_id"]
    version = view.versions.get(version_id)
    if version is None:
        version = VersionState(version_id=version_id, package_id=payload["package_id"])
        view.versions[version_id] = version
        view.package_versions.setdefault(payload["package_id"], []).append(version_id)
        version.created_at = event["occurred_at"]

    kind = event["event_type"]
    if kind == "package.uploaded":
        version.fingerprint = payload["fingerprint"]
        version.manifest = payload["manifest"]
        version.state = VERSION_STATE_UPLOADED
        view.packages.setdefault(
            payload["package_id"], {"package_id": payload["package_id"], "name": payload.get("name", payload["package_id"])}
        )
    elif kind == "manifest.verified":
        version.manifest_verified = True
    elif kind == "review.opened":
        version.state = VERSION_STATE_REVIEWING
        for stage in payload["stages"]:
            version.reviews.setdefault(stage, ReviewState(stage=stage))
    elif kind == "review.signed":
        review = version.reviews.setdefault(payload["stage"], ReviewState(stage=payload["stage"]))
        review.signatures[payload["signer"]] = {
            "signature": payload["signature"],
            "at": event["occurred_at"],
        }
    elif kind == "version.rejected":
        version.state = VERSION_STATE_REJECTED
    elif kind == "version.approved":
        version.state = VERSION_STATE_APPROVED
        version.official_no = payload["official_no"]
    elif kind == "version.quarantined":
        version.state = VERSION_STATE_QUARANTINED
        version.quarantine_reason = payload.get("reason")
    elif kind == "version.rolled_back":
        version.state = VERSION_STATE_ROLLED_BACK
    elif kind == "version.retired":
        version.state = VERSION_STATE_RETIRED


def _apply_tenant_event(view: RegistryView, event: Mapping[str, Any]) -> None:
    payload = event["payload"]
    tenant = _ensure_tenant(view, event["aggregate_id"])
    kind = event["event_type"]
    if kind == "tenant.registered":
        tenant.region = payload["region"]
        tenant.plan = payload["plan"]
    elif kind in ("assignment.activated", "assignment.migrated"):
        if kind == "assignment.migrated":
            previous = tenant.assignments.get(payload["package_id"])
            if previous is not None and previous.current is not None:
                previous.current.removed_at = event["occurred_at"]
        assignment = tenant.assignments.setdefault(
            payload["package_id"], AssignmentState(package_id=payload["package_id"])
        )
        assignment.history.append(
            InstallRecord(
                version_id=payload["version_id"],
                fingerprint=payload["fingerprint"],
                digests=dict(payload["digests"]),
                capabilities=list(payload["capabilities"]),
                installed_at=event["occurred_at"],
            )
        )
    elif kind == "assignment.deactivated":
        assignment = tenant.assignments.get(payload["package_id"])
        if assignment is not None and assignment.current is not None:
            assignment.current.removed_at = event["occurred_at"]


def _apply_task_event(view: RegistryView, event: Mapping[str, Any]) -> None:
    payload = event["payload"]
    kind = event["event_type"]
    if kind == "task.registered":
        view.tasks[event["aggregate_id"]] = TaskState(
            task_id=event["aggregate_id"],
            tenant_id=payload["tenant_id"],
            package_id=payload["package_id"],
            version_id=payload["version_id"],
            fingerprint=payload["fingerprint"],
        )
    elif kind == "task.version_bound":
        task = view.tasks[event["aggregate_id"]]
        task.version_id = payload["version_id"]
        task.fingerprint = payload["fingerprint"]
        task.active = True
    elif kind == "task.closed":
        view.tasks[event["aggregate_id"]].active = False


def _apply_batch_event(view: RegistryView, event: Mapping[str, Any]) -> None:
    payload = event["payload"]
    batch_id = event["aggregate_id"]
    batch = view.batches.get(batch_id)
    if batch is None:
        batch = BatchState(batch_id=batch_id)
        view.batches[batch_id] = batch
        view.package_batches.setdefault(payload["package_id"], []).append(batch_id)
    kind = event["event_type"]
    if kind == "rollout.started":
        batch.package_id = payload["package_id"]
        batch.target_version_id = payload["target_version_id"]
        batch.safe_version_id = payload.get("safe_version_id")
        batch.salt = payload["salt"]
        batch.percent = payload["percent"]
        batch.state = BATCH_RUNNING
        batch.started_at = event["occurred_at"]
    elif kind == "rollout.tenant_assigned":
        if payload["tenant_id"] not in batch.assigned_tenants:
            batch.assigned_tenants.append(payload["tenant_id"])
    elif kind == "rollout.frozen":
        batch.state = BATCH_FROZEN
        batch.freeze_reason = payload.get("reason")
        batch.anomaly_rate = float(payload.get("anomaly_rate", batch.anomaly_rate))
    elif kind == "rollout.resumed":
        batch.state = BATCH_RUNNING
        batch.freeze_reason = None
    elif kind == "rollout.percent_expanded":
        batch.percent = int(payload["percent"])
    elif kind == "rollout.rollback_started":
        batch.state = BATCH_ROLLING_BACK
        batch.safe_version_id = payload["safe_version_id"]
    elif kind == "rollout.tenant_reverted":
        if payload["tenant_id"] not in batch.reverted_tenants:
            batch.reverted_tenants.append(payload["tenant_id"])
    elif kind == "rollout.completed":
        batch.state = payload.get("state", BATCH_COMPLETED)


_DISPATCH = {
    "version": _apply_version_event,
    "tenant": _apply_tenant_event,
    "task": _apply_task_event,
    "batch": _apply_batch_event,
}


def fold(events: Sequence[Mapping[str, Any]]) -> RegistryView:
    view = RegistryView()
    for event in events:
        handler = _DISPATCH.get(event["aggregate_type"])
        if handler is not None:
            handler(view, event)
    return view
