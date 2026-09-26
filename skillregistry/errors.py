"""领域错误类型。"""
from __future__ import annotations


class RegistryError(Exception):
    """所有登记处错误的基类。"""


class UnknownObject(RegistryError):
    """引用的包、版本、租户或批次不存在。"""


class VersionStateError(RegistryError):
    """对象当前状态不允许该操作。"""


class ReviewClosed(VersionStateError):
    """审查已经结束（批准或驳回），不能再签署。"""


class MissingApproval(RegistryError):
    """放行时必需的审批角色尚未全部签署。"""


class DuplicateFormalVersion(RegistryError):
    """并发放行检测到正式版本号冲突。"""


class RulesLocked(VersionStateError):
    """灰度批次开始后分组规则不可变化。"""


class GateDenied(RegistryError):
    """租户放行校验未通过的基类。"""


class PlanDenied(GateDenied):
    """租户套餐不允许请求的能力。"""


class RegionDenied(GateDenied):
    """租户地区不允许请求的能力。"""


class CapabilityConflict(GateDenied):
    """与租户已启用技能的能力互斥。"""


class DriftDetected(RegistryError):
    """核验发现内容、依赖或能力摘要与签署时不一致。"""
