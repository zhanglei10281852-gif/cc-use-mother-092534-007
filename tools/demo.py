"""端到端演示：上传 -> 风险路由 -> 签署放行 -> 租户准入 -> 灰度 -> 异常冻结 -> 回滚。

内存库运行，不写磁盘：

    python3 tools/demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from registry import EventStore, KeyStore, RegistryService, RiskPolicy  # noqa: E402

SIGNERS = {
    "reviewer-code": "code-secret",
    "reviewer-data": "data-secret",
    "reviewer-finance": "finance-secret",
}
SIGNER_FOR_STAGE = {
    "code_review": "reviewer-code",
    "data_owner": "reviewer-data",
    "finance": "reviewer-finance",
}


def files(seed: str):
    return [
        {"path": "main.py", "sha256": seed * 64, "size": 120},
        {"path": "skills/pay.py", "sha256": "0" * 64, "size": 340},
    ]


def publish(svc: RegistryService, package_id: str, seed: str, capabilities: list[str]) -> str:
    uploaded = svc.upload_version(
        package_id, files(seed),
        dependencies={"ledger-sdk": "3.1.0"},
        entry_points=["main:run"],
        capabilities=capabilities,
        actor_id="operator-01",
    )
    vid = uploaded["version_id"]
    print(f"上传 {package_id} -> {vid}，内容摘要 {uploaded['fingerprint'][:16]}…")
    svc.verify_manifest(vid, actor_id="scanner")
    opened = svc.open_review(vid, actor_id="operator-01")
    print(f"风险路由环节：{opened['stages']}，新增能力：{opened['widened_capabilities']}")
    for stage in opened["stages"]:
        svc.sign_review(vid, stage, SIGNER_FOR_STAGE[stage])
    approved = svc.approve_version(vid, actor_id="operator-01")
    print(f"放行：正式版本号 v{approved['official_no']}")
    return vid


def main() -> None:
    svc = RegistryService(EventStore(":memory:"), RiskPolicy.default(), KeyStore(SIGNERS))

    v1 = publish(svc, "pay-assistant", "a", ["payment.read"])
    v2 = publish(svc, "pay-assistant", "b", ["payment"])  # 能力扩大：新增财务环节

    for tid, region, plan in [("t-cn", "CN", "enterprise"), ("t-eu", "EU", "enterprise"),
                              ("t-free", "CN", "free")]:
        svc.register_tenant(tid, region, plan, actor_id="admin")

    svc.enable_for_tenant("pay-assistant", "t-cn", version_id=v1, actor_id="admin")
    svc.register_task("task-1", "t-cn", "pay-assistant", actor_id="scheduler")
    for tid, reason in [("t-eu", "地区"), ("t-free", "套餐")]:
        try:
            svc.enable_for_tenant("pay-assistant", tid, actor_id="admin")
        except Exception as exc:  # noqa: BLE001 - 演示打印
            print(f"租户 {tid} 被拒（{reason}约束）：{exc}")

    batch = svc.start_rollout("pay-assistant", v2, 100, salt="demo-salt", actor_id="operator-01")
    bid = batch["batch_id"]
    svc.assign_due_tenants(bid, ["t-cn"], actor_id="operator-01")
    print(f"灰度批次 {bid} 已把 t-cn 切到 {v2}")

    report = svc.report_anomaly(bid, 0.12, 0.05, actor_id="monitor")
    print(f"异常率上报：冻结={report['frozen']}，新分配已停止")

    result = svc.affected_tasks(v2)
    print(f"受影响任务：{[t['task_id'] for t in result]}")

    rolled = svc.rollback_batch(bid, actor_id="operator-01")
    print(f"回滚完成：{rolled['state']}，退回 {batch['safe_version_id']}")

    verified = svc.verify_installed_content("t-cn", "pay-assistant", files("a"))
    print(f"运行内容校验：verified={verified['verified']}，版本 {verified['version_id']}")
    print(f"安装轨迹：{[h['version_id'] for h in svc.install_history('t-cn', 'pay-assistant')]}")


if __name__ == "__main__":
    main()
