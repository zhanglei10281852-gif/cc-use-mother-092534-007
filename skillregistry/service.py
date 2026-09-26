"""组合全部模块的门面，并在启动时恢复中断流程。"""
from __future__ import annotations

from typing import Any

from .catalog import Catalog, PackageSubmission
from .policy import PolicyBook
from .reviews import ReviewService
from .rollout import RolloutService
from .store import Store
from .tenants import TenantDirectory


class RegistryService:
    """技能包登记与放行服务的统一入口。"""

    def __init__(
        self,
        store: Store | str = ":memory:",
        *,
        policy: PolicyBook | None = None,
        signing_secret: str = "registry-signing-secret",
        recover: bool = True,
    ):
        self.store = store if isinstance(store, Store) else Store(store)
        self.policy = policy or PolicyBook.default()
        self.catalog = Catalog(self.store)
        self.reviews = ReviewService(self.store, self.policy, secret=signing_secret)
        self.tenants = TenantDirectory(self.store, self.reviews)
        self.rollout = RolloutService(self.store, self.tenants, self.policy)
        if recover:
            self.recover()

    # -- 恢复 -----------------------------------------------------------

    def recover(self) -> dict[str, list[str]]:
        """重启后恢复：继续未完成的回滚批次。

        审查本来就是开放状态、签署逐行持久化，无需额外修补；
        回滚是多步流程，这里接续所有 ``rolling_back`` 批次。
        """
        resumed_rollbacks = self.rollout.resume_interrupted()
        return {"resumed_rollbacks": resumed_rollbacks}

    def close(self) -> None:
        self.store.close()

    # -- 便捷包装 -------------------------------------------------------

    def submit_package(
        self,
        package_name: str,
        submission: dict[str, Any] | PackageSubmission,
        *,
        actor_id: str = "operator",
    ) -> dict[str, Any]:
        """登记包、接收上传、核验清单并建立审查的一步式入口。"""
        package_id = self.catalog.register_package(package_name, actor_id=actor_id)
        payload = submission if isinstance(submission, PackageSubmission) else PackageSubmission.from_dict(submission)
        version_id, created = self.catalog.upload(package_id, payload, actor_id=actor_id)
        if created:
            self.catalog.verify_manifest(version_id, actor_id=actor_id)
            self.reviews.start_review(version_id, actor_id=actor_id)
        return {"package_id": package_id, "version_id": version_id, "created": created}
