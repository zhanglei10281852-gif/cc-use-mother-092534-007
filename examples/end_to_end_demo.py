"""端到端流程演示：上传 → 去重 → 差异与路由 → 签署 → 租户闸门 →
灰度 → 异常冻结 → 回滚 → 隔离 → 重启恢复。

运行：python3 examples/end_to_end_demo.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skillregistry.errors import CapabilityConflict, PlanDenied, RegionDenied  # noqa: E402
from skillregistry.service import RegistryService  # noqa: E402
from tests.helpers import approve_version, make_files, make_deps, make_submission, required_roles  # noqa: E402


def main() -> None:
    tmp = tempfile.TemporaryDirectory()
    db_path = str(Path(tmp.name) / "demo.db")
    service = RegistryService(db_path)

    # 1. 首个版本：只读取文件，低风险，仅需代码审查。
    first = service.submit_package("家庭助手", make_submission(
        files=("main.py",), capabilities=("fs.read",)))
    v1 = first["version_id"]
    approve_version(service, v1, required_roles(service, v1))
    print(f"v1 放行：{service.catalog.get_version(v1)['formal_version_no']}")

    # 2. 重复上传不产生新版本。
    duplicate = service.submit_package("家庭助手", make_submission(
        files=("main.py",), capabilities=("fs.read",)))
    assert duplicate["version_id"] == v1
    print("重复上传复用同一候选版本")

    # 3. 新版本增加邮件与家庭设备控制：能力扩大，路由到代码审查 + 数据所有者。
    second = service.submit_package("家庭助手", make_submission(
        files=("main.py", "home.py"),
        capabilities=("fs.read", "mail.read", "device.home.control"),
    ))
    v2 = second["version_id"]
    diff = service.catalog.diff(v1, v2)
    print(f"版本差异：新增文件 {diff.files_added}，新增能力 {diff.capabilities_added}")
    status = service.reviews.review_status(v2)
    print(f"风险等级 {status['risk_level']}，需要 {status['required_approvers']} 签署")

    # 4. 缺签不能放行；签齐后成为正式版本 2。
    service.reviews.sign_review(v2, "code_review", "reviewer-1")
    try:
        service.reviews.approve(v2)
    except Exception as error:
        print(f"未签齐时放行被拒：{type(error).__name__}")
    service.reviews.sign_review(v2, "data_owner", "owner-1")
    no2 = service.reviews.approve(v2)
    print(f"v2 放行：正式版本 {no2}")

    # 5. 租户闸门：套餐、地区、能力冲突。
    service.tenants.register_tenant("free-cn", "free", "cn-north")
    service.tenants.register_tenant("ent-us", "enterprise", "us-west")
    service.tenants.register_tenant("ent-cn", "enterprise", "cn-north")
    for tenant, error_type in [("free-cn", PlanDenied), ("ent-us", RegionDenied)]:
        try:
            service.tenants.enable_skill(tenant, "家庭助手", v2)
        except error_type as error:
            print(f"{tenant} 被闸门拦截：{error}")
    service.tenants.enable_skill("ent-cn", "家庭助手", v2)
    print("ent-cn 通过全部闸门并安装")

    # 互斥能力：已启用 mail.read 的租户不能再启用 mail.send 技能。
    other = service.submit_package("发信器", make_submission(capabilities=("mail.send",)))
    approve_version(service, other["version_id"], required_roles(service, other["version_id"]))
    try:
        service.tenants.enable_skill("ent-cn", "发信器", other["version_id"])
    except CapabilityConflict as error:
        print(f"互斥能力拦截：{error}")

    # 6. 灰度发布：确定性分组，规则开批后锁定。
    for index in range(20):
        service.tenants.register_tenant(f"canary-{index:02d}", "pro", "cn-north")
    batch_id = service.rollout.start_rollout(v2, min_samples=20, threshold=0.05)
    for index in range(5):
        service.rollout.assign(
            batch_id, f"canary-{index:02d}", open_groups={"canary", "early", "general"}
        )
    print(f"5 个租户进入灰度，分组例如：{service.rollout.group_of(batch_id, 'canary-00')}")

    # 7. 异常率越线：冻结新分配并自动回滚到最近安全版本 v1。
    outcome = service.rollout.report_result(batch_id, errors=2, total=20)
    print(f"上报后批次状态：{outcome['status']}，异常率 {outcome['error_rate']:.0%}")
    print(f"当前正式安全版本仍是 v1：{service.catalog.latest_safe('家庭助手')['version_id'] == v1}")
    active_in_batch = service.store.all(
        "select count(*) as c from installs where rollout_batch_id = ? and version_id = ? "
        "and status = 'active'",
        (batch_id, v2),
    )[0]["c"]
    print(f"批次内 v2 活跃安装数（应为 0，已全部回滚到 v1）：{active_in_batch}")

    # 8. 隔离单个版本并列出受影响任务与安装。
    impact = service.rollout.isolate_version(v2, "发现未授权外联")
    print(f"隔离 v2：受影响安装 {len(impact['installs'])} 个")

    # 9. 历史安装清单核验：内容漂移即失效。
    install_id = service.tenants.list_installs(v1)[0]["install_id"]
    exact_files = make_files("main.py")
    exact_deps = make_deps("requests")
    assert service.tenants.verify_install(install_id, exact_files, exact_deps)
    print("历史安装确切清单核验通过")

    # 10. 重启后审查与批次连续：重新打开库，自动恢复中断流程。
    service.close()
    reopened = RegistryService(db_path)
    print(f"重启恢复结果：{reopened.recover()}")
    events = reopened.store.list_events(aggregate_type="rollout", aggregate_id=batch_id)
    print(f"批次审计事件链：{[event['event_type'] for event in events]}")
    reopened.close()
    tmp.cleanup()


if __name__ == "__main__":
    main()
