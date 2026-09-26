"""技能包供应链登记处服务。

仅依赖 Python 标准库，持久化使用 SQLite。模块划分：

- ``canonical``：规范化编码、摘要、确定性分桶与签名。
- ``errors``：领域错误。
- ``policy``：风险路由、套餐、地区与能力冲突策略。
- ``store``：SQLite 表结构、即时事务与事件日志。
- ``catalog``：包登记、上传去重、版本编号与差异比较。
- ``reviews``：审查路由、绑定摘要的签署、漂移核验与并发放行。
- ``tenants``：租户启用校验（地区、套餐、冲突能力）。
- ``rollout``：灰度批次、确定性分组、异常冻结、回滚与隔离。
- ``service``：组合以上模块的门面，并在启动时恢复中断流程。
"""
from __future__ import annotations

from .errors import (
    CapabilityConflict,
    DriftDetected,
    DuplicateFormalVersion,
    GateDenied,
    MissingApproval,
    PlanDenied,
    RegionDenied,
    RegistryError,
    ReviewClosed,
    RulesLocked,
    UnknownObject,
    VersionStateError,
)
from .policy import PolicyBook
from .service import RegistryService
from .store import Store

__all__ = [
    "RegistryService",
    "Store",
    "PolicyBook",
    "RegistryError",
    "UnknownObject",
    "VersionStateError",
    "ReviewClosed",
    "MissingApproval",
    "DuplicateFormalVersion",
    "RulesLocked",
    "GateDenied",
    "PlanDenied",
    "RegionDenied",
    "CapabilityConflict",
    "DriftDetected",
]
