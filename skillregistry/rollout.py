"""灰度批次、确定性分组、异常冻结、回滚与版本隔离。

- 分组规则（分组大小、盐值、阈值）在批次开始时固化，之后任何修改
  都会抛出 :class:`RulesLocked`。
- 租户分到哪一组只由 (盐值, 租户ID) 的确定性哈希决定，与分配顺序
  无关，重启或换进程结果一致。
- 异常率越过阈值：批次冻结（停止新分配），版本回到最近安全版本；
  回滚按安装逐条推进并持久化进度，进程重启后继续完成。
"""
from __future__ import annotations

import json
from typing import Any

from .canonical import stable_bucket
from .errors import RulesLocked, UnknownObject, VersionStateError
from .store import Store, new_id, now_iso


class RolloutService:
    def __init__(self, store: Store, tenant_directory, policy):
        self.store = store
        self.tenants = tenant_directory
        self.policy = policy

    # -- 批次生命周期 ---------------------------------------------------

    def start_rollout(
        self,
        version_id: str,
        *,
        groups: list[dict[str, Any]] | None = None,
        salt: str | None = None,
        threshold: float | None = None,
        min_samples: int | None = None,
        actor_id: str = "operator",
    ) -> str:
        groups = list(groups or self.policy.default_groups)
        self._validate_groups(groups)
        salt = salt or self.policy.salt
        threshold = self.policy.anomaly_threshold if threshold is None else threshold
        min_samples = self.policy.min_samples if min_samples is None else min_samples

        with self.store.transaction() as conn:
            version = conn.execute("select * from versions where version_id = ?", (version_id,)).fetchone()
            if version is None:
                raise UnknownObject(f"未知版本：{version_id}")
            if version["state"] != "approved":
                raise VersionStateError(f"版本状态 {version['state']} 不允许开始灰度")
            batch_id = new_id("bat")
            conn.execute(
                "insert into rollout_batches(batch_id, package_id, version_id, status, salt, "
                "groups_json, threshold, min_samples, rules_locked, created_at, started_at) "
                "values (?,?,?,?,?,?,?,?,1,?,?)",
                (
                    batch_id, version["package_id"], version_id, "rolling_out", salt,
                    json.dumps(groups, ensure_ascii=False, sort_keys=True),
                    threshold, min_samples, now_iso(), now_iso(),
                ),
            )
            conn.execute("update versions set state = 'rolling_out' where version_id = ?", (version_id,))
            self.store.append_event(
                conn, "rollout.started", "rollout", batch_id, actor_id,
                {"version_id": version_id, "groups": groups, "salt": salt,
                 "threshold": threshold, "min_samples": min_samples},
            )
            return batch_id

    def update_rules(self, batch_id: str, **changes: Any) -> None:
        """批次开始后修改分组规则一律拒绝。"""
        with self.store.transaction() as conn:
            batch = conn.execute("select * from rollout_batches where batch_id = ?", (batch_id,)).fetchone()
            if batch is None:
                raise UnknownObject(f"未知批次：{batch_id}")
            if batch["started_at"] is not None or batch["rules_locked"]:
                raise RulesLocked("灰度分组规则在批次开始后不可变化")

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.store.get("select * from rollout_batches where batch_id = ?", (batch_id,))
        if row is None:
            raise UnknownObject(f"未知批次：{batch_id}")
        result = dict(row)
        result["groups"] = json.loads(result.pop("groups_json"))
        return result

    # -- 确定性分组 -----------------------------------------------------

    def group_of(self, batch_id: str, tenant_id: str) -> dict[str, Any]:
        """返回租户在该批次中的确定性分组，结果会被持久化。"""
        batch = self.get_batch(batch_id)
        bucket = stable_bucket(batch["salt"], tenant_id, 100)
        groups: list[dict[str, Any]] = batch["groups"]
        cumulative = 0
        chosen = groups[-1]["name"]
        for group in groups:
            cumulative += group["size"]
            if bucket < cumulative:
                chosen = group["name"]
                break
        return {"group": chosen, "bucket": bucket}

    def assign(self, batch_id: str, tenant_id: str, *, open_groups: set[str] | None = None) -> str:
        """把批次版本分配给租户（经过全部租户闸门），返回 install_id。

        ``open_groups`` 为当前放开的灰度组；只有租户所在组已放开才分配。
        批次冻结或版本被隔离/回滚后，新分配一律拒绝。
        """
        placement = self.group_of(batch_id, tenant_id)
        if open_groups is not None and placement["group"] not in open_groups:
            raise VersionStateError(
                f"租户所在灰度组 {placement['group']} 尚未放开"
            )
        with self.store.transaction() as conn:
            batch = conn.execute("select * from rollout_batches where batch_id = ?", (batch_id,)).fetchone()
            if batch["status"] != "rolling_out":
                raise VersionStateError(f"批次状态 {batch['status']}，不能新分配")
            version = conn.execute(
                "select * from versions where version_id = ?", (batch["version_id"],)
            ).fetchone()
            if version["state"] not in ("approved", "rolling_out"):
                raise VersionStateError(f"版本状态 {version['state']}，不能新分配")
            existing = conn.execute(
                "select i.install_id from rollout_members m "
                "join installs i on i.rollout_batch_id = m.batch_id and i.tenant_id = m.tenant_id "
                "where m.batch_id = ? and m.tenant_id = ? and i.status = 'active'",
                (batch_id, tenant_id),
            ).fetchone()
            if existing:
                return existing["install_id"]

            tenant = conn.execute("select * from tenants where tenant_id = ?", (tenant_id,)).fetchone()
            if tenant is None:
                raise UnknownObject(f"未知租户：{tenant_id}")
            capabilities = [
                row["capability"] for row in conn.execute(
                    "select capability from version_capabilities where version_id = ? order by capability",
                    (version["version_id"],),
                )
            ]
            region_message = self.policy.check_region(tenant["region"], capabilities)
            if region_message:
                raise VersionStateError(region_message)
            plan_message = self.policy.check_plan(tenant["plan"], capabilities)
            if plan_message:
                raise VersionStateError(plan_message)
            existing_caps = self.tenants._tenant_capabilities_conn(
                conn, tenant_id, exclude_package=version["package_id"]
            )
            conflicts = self.policy.find_conflicts(capabilities, existing_caps)
            if conflicts:
                raise VersionStateError("; ".join(f"{a} 与 {b} 互斥" for a, b in conflicts))
            self.tenants._assert_signatures_fresh_conn(conn, version["version_id"])

            # 复用或新建分配（同一租户同一包只有一条分配）。
            assignment = conn.execute(
                "select * from assignments where tenant_id = ? and package_id = ?",
                (tenant_id, version["package_id"]),
            ).fetchone()
            assignment_id = assignment["assignment_id"] if assignment else new_id("asn")
            if assignment:
                conn.execute(
                    "update assignments set version_id = ?, state = 'active', source = 'rollout', "
                    "rollout_batch_id = ?, group_name = ?, enabled_at = ?, disabled_at = null "
                    "where assignment_id = ?",
                    (version["version_id"], batch_id, placement["group"], now_iso(), assignment_id),
                )
            else:
                conn.execute(
                    "insert into assignments(assignment_id, tenant_id, package_id, version_id, state, "
                    "source, rollout_batch_id, group_name, enabled_at) values (?,?,?,?,?,?,?,?,?)",
                    (
                        assignment_id, tenant_id, version["package_id"], version["version_id"], "active",
                        "rollout", batch_id, placement["group"], now_iso(),
                    ),
                )
            install_id = self.tenants._insert_install_conn(
                conn, tenant_id, version, assignment_id=assignment_id, rollout_batch_id=batch_id,
            )
            # 该租户同一包的旧活跃安装被新版本取代。
            conn.execute(
                "update installs set status = 'superseded', replaced_at = ?, "
                "replaced_by_install_id = ? where tenant_id = ? and package_id = ? "
                "and install_id <> ? and status = 'active'",
                (now_iso(), install_id, tenant_id, version["package_id"], install_id),
            )
            conn.execute(
                "insert into rollout_members(batch_id, tenant_id, group_name, bucket, assigned_at) "
                "values (?, ?, ?, ?, ?)",
                (batch_id, tenant_id, placement["group"], placement["bucket"], now_iso()),
            )
            self.store.append_event(
                conn, "skill.enabled", "rollout", batch_id, "rollout",
                {"tenant_id": tenant_id, "version_id": version["version_id"],
                 "install_id": install_id, "group": placement["group"]},
            )
            return install_id

    # -- 异常率与冻结 ---------------------------------------------------

    def register_task(self, task_id: str, tenant_id: str, install_id: str) -> None:
        with self.store.transaction() as conn:
            install = conn.execute("select * from installs where install_id = ?", (install_id,)).fetchone()
            if install is None:
                raise UnknownObject(f"未知安装：{install_id}")
            conn.execute(
                "insert or ignore into tasks(task_id, tenant_id, package_id, version_id, install_id, "
                "state, created_at, updated_at) values (?,?,?,?,?,'running',?,?)",
                (
                    task_id, tenant_id, install["package_id"], install["version_id"], install_id,
                    now_iso(), now_iso(),
                ),
            )

    def report_result(self, batch_id: str, errors: int, total: int) -> dict[str, Any]:
        """累计批次异常样本，越线则冻结并触发回滚。"""
        with self.store.transaction() as conn:
            batch = conn.execute("select * from rollout_batches where batch_id = ?", (batch_id,)).fetchone()
            if batch is None:
                raise UnknownObject(f"未知批次：{batch_id}")
            conn.execute(
                "update rollout_batches set total_count = total_count + ?, error_count = error_count + ? "
                "where batch_id = ?",
                (total, errors, batch_id),
            )
            refreshed = conn.execute(
                "select * from rollout_batches where batch_id = ?", (batch_id,)
            ).fetchone()
            rate = refreshed["error_count"] / refreshed["total_count"] if refreshed["total_count"] else 0.0
            crossed = (
                refreshed["status"] == "rolling_out"
                and refreshed["total_count"] >= refreshed["min_samples"]
                and rate >= refreshed["threshold"]
            )
            if crossed:
                self._freeze_conn(
                    conn, batch_id,
                    f"异常率 {rate:.2%} 达到阈值 {refreshed['threshold']:.2%}",
                )
        if crossed:
            self.rollback(batch_id)
        return {"status": "frozen" if crossed else "rolling_out", "error_rate": rate}

    def freeze(self, batch_id: str, reason: str) -> None:
        with self.store.transaction() as conn:
            self._freeze_conn(conn, batch_id, reason)

    def _freeze_conn(self, conn, batch_id: str, reason: str) -> None:
        batch = conn.execute("select * from rollout_batches where batch_id = ?", (batch_id,)).fetchone()
        if batch is None:
            raise UnknownObject(f"未知批次：{batch_id}")
        if batch["status"] != "rolling_out":
            return
        conn.execute(
            "update rollout_batches set status = 'frozen', frozen_at = ?, freeze_reason = ? "
            "where batch_id = ?",
            (now_iso(), reason, batch_id),
        )
        conn.execute(
            "update versions set state = 'frozen', frozen_at = ? where version_id = ? and state = 'rolling_out'",
            (now_iso(), batch["version_id"]),
        )
        self.store.append_event(
            conn, "rollout.frozen", "rollout", batch_id, "monitor",
            {"version_id": batch["version_id"], "reason": reason},
        )
        self.store.append_event(
            conn, "version.frozen", "version", batch["version_id"], "monitor",
            {"batch_id": batch_id, "reason": reason},
        )

    # -- 隔离 -----------------------------------------------------------

    def isolate_version(self, version_id: str, reason: str, *, actor_id: str = "operator") -> dict[str, Any]:
        """隔离单个版本：停止其灰度新分配，列出受影响任务与安装。"""
        with self.store.transaction() as conn:
            version = conn.execute("select * from versions where version_id = ?", (version_id,)).fetchone()
            if version is None:
                raise UnknownObject(f"未知版本：{version_id}")
            conn.execute(
                "update versions set state = 'isolated', isolated_at = ?, isolate_reason = ? "
                "where version_id = ?",
                (now_iso(), reason, version_id),
            )
            conn.execute(
                "update rollout_batches set status = 'frozen', frozen_at = coalesce(frozen_at, ?), "
                "freeze_reason = ? where version_id = ? and status = 'rolling_out'",
                (now_iso(), f"版本隔离：{reason}", version_id),
            )
            affected_tasks = [
                dict(row) for row in conn.execute(
                    "select task_id, tenant_id, state, total_count, error_count from tasks "
                    "where version_id = ? and state in ('running','affected') order by tenant_id, task_id",
                    (version_id,),
                )
            ]
            affected_installs = [
                dict(row) for row in conn.execute(
                    "select install_id, tenant_id, status, installed_at from installs "
                    "where version_id = ? order by installed_at", (version_id,),
                )
            ]
            self.store.append_event(
                conn, "version.isolated", "version", version_id, actor_id,
                {"reason": reason, "task_count": len(affected_tasks),
                 "install_count": len(affected_installs)},
            )
            return {"tasks": affected_tasks, "installs": affected_installs}

    def affected_tasks(self, version_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.all(
            "select * from tasks where version_id = ? order by affected_at, tenant_id", (version_id,)
        )]

    # -- 回滚（可续跑） -------------------------------------------------

    def rollback(self, batch_id: str, *, target_version_id: str | None = None) -> str:
        """把批次内全部活跃安装回滚到最近安全版本，返回目标版本ID。

        每次调用都从事务中读取尚未替换的安装继续推进，因此回滚批次
        在进程重启后调用同一方法即可接续完成。
        """
        with self.store.transaction() as conn:
            batch = conn.execute("select * from rollout_batches where batch_id = ?", (batch_id,)).fetchone()
            if batch is None:
                raise UnknownObject(f"未知批次：{batch_id}")
            target_id = target_version_id or batch["rollback_target_version_id"]
            if not target_id:
                target = self._latest_safe_conn(conn, batch["package_id"], exclude=batch["version_id"])
                if target is None:
                    raise VersionStateError("没有可回滚的安全版本")
                target_id = target["version_id"]
            target = conn.execute("select * from versions where version_id = ?", (target_id,)).fetchone()
            if target is None or target["state"] != "approved":
                raise VersionStateError(f"回滚目标 {target_id} 不是可用的安全版本")
            if not batch["rollback_started_at"]:
                conn.execute(
                    "update rollout_batches set status = 'rolling_back', rollback_target_version_id = ?, "
                    "rollback_started_at = ? where batch_id = ?",
                    (target_id, now_iso(), batch_id),
                )
                self.store.append_event(
                    conn, "rollback.started", "rollout", batch_id, "system",
                    {"from_version_id": batch["version_id"], "to_version_id": target_id},
                )

        # 逐条推进，每条一个事务，保证中断后可续。
        source_version_id = self.store.get(
            "select version_id from rollout_batches where batch_id = ?", (batch_id,)
        )["version_id"]
        while True:
            with self.store.transaction() as conn:
                pending = conn.execute(
                    "select * from installs where version_id = ? and status = 'active' "
                    "order by installed_at limit 1",
                    (source_version_id,),
                ).fetchall()
                if not pending:
                    conn.execute(
                        "update rollout_batches set status = 'rolled_back', rollback_completed_at = ? "
                        "where batch_id = ? and status = 'rolling_back'",
                        (now_iso(), batch_id),
                    )
                    frozen_version = conn.execute(
                        "select version_id from rollout_batches where batch_id = ?", (batch_id,)
                    ).fetchone()["version_id"]
                    conn.execute(
                        "update versions set state = 'rolled_back' where version_id = ? "
                        "and state in ('frozen','isolated','rolling_out')",
                        (frozen_version,),
                    )
                    self.store.append_event(
                        conn, "rollback.completed", "rollout", batch_id, "system",
                        {"target_version_id": target_id},
                    )
                    self.store.append_event(
                        conn, "version.rolled_back", "version", frozen_version, "system",
                        {"batch_id": batch_id, "target_version_id": target_id},
                    )
                    return target_id
                old = pending[0]
                target_row = conn.execute(
                    "select * from versions where version_id = ?", (target_id,)
                ).fetchone()
                new_install_id = self.tenants._insert_install_conn(
                    conn, old["tenant_id"], target_row,
                    assignment_id=old["assignment_id"], rollout_batch_id=batch_id,
                )
                conn.execute(
                    "update installs set status = 'rolled_back', replaced_at = ?, "
                    "replaced_by_install_id = ? where install_id = ?",
                    (now_iso(), new_install_id, old["install_id"]),
                )
                conn.execute(
                    "update assignments set version_id = ?, group_name = 'rollback' "
                    "where assignment_id = ?",
                    (target_id, old["assignment_id"]),
                )
                conn.execute(
                    "update tasks set state = 'affected', affected_at = ?, updated_at = ?, "
                    "previous_version_id = version_id where install_id = ? and state = 'running'",
                    (now_iso(), now_iso(), old["install_id"]),
                )
                self.store.append_event(
                    conn, "version.rolled_back", "install", old["install_id"], "system",
                    {"tenant_id": old["tenant_id"], "replaced_by": new_install_id},
                )

    def rollback_version(self, version_id: str, *, target_version_id: str | None = None) -> str:
        """版本级回滚：覆盖该版本全部活跃安装（含手动启用、无批次的）。

        若该版本没有进行中的回滚批次，建立一个应急批次承载审计与恢复，
        然后复用批次回滚逻辑。返回目标版本ID。
        """
        with self.store.transaction() as conn:
            version = conn.execute("select * from versions where version_id = ?", (version_id,)).fetchone()
            if version is None:
                raise UnknownObject(f"未知版本：{version_id}")
            batch = conn.execute(
                "select * from rollout_batches where version_id = ? and status in "
                "('rolling_back','rolled_back') order by rowid desc limit 1",
                (version_id,),
            ).fetchone()
            if batch is None:
                target_id = target_version_id
                if not target_id:
                    target = self._latest_safe_conn(conn, version["package_id"], exclude=version_id)
                    if target is None:
                        raise VersionStateError("没有可回滚的安全版本")
                    target_id = target["version_id"]
                batch_id = new_id("bat")
                conn.execute(
                    "insert into rollout_batches(batch_id, package_id, version_id, status, salt, "
                    "groups_json, threshold, min_samples, rules_locked, created_at, "
                    "rollback_target_version_id, rollback_started_at) "
                    "values (?,?,?,?,?,?,?,?,1,?,?,?)",
                    (
                        batch_id, version["package_id"], version_id, "rolling_back",
                        "emergency-rollback", "[]", 1.0, 0, now_iso(), target_id, now_iso(),
                    ),
                )
                self.store.append_event(
                    conn, "rollback.started", "rollout", batch_id, "system",
                    {"from_version_id": version_id, "to_version_id": target_id, "emergency": True},
                )
            else:
                batch_id = batch["batch_id"]
        return self.rollback(batch_id, target_version_id=target_version_id)

    def resume_interrupted(self) -> list[str]:
        """启动恢复：继续所有已开始但未完成的回滚批次。"""
        batches = self.store.all(
            "select batch_id from rollout_batches where status = 'rolling_back'"
        )
        resumed = [row["batch_id"] for row in batches]
        for batch_id in resumed:
            self.rollback(batch_id)
        return resumed

    # -- 内部 -----------------------------------------------------------

    def _latest_safe_conn(self, conn, package_id: str, *, exclude: str | None):
        sql = ("select * from versions where package_id = ? and formal_version_no is not null "
               "and state = 'approved'")
        params: list[Any] = [package_id]
        if exclude:
            sql += " and version_id <> ?"
            params.append(exclude)
        sql += " order by formal_version_no desc limit 1"
        return conn.execute(sql, params).fetchone()

    def _validate_groups(self, groups: list[dict[str, Any]]) -> None:
        if not groups:
            raise ValueError("至少需要一个灰度组")
        total = sum(int(group["size"]) for group in groups)
        if total != 100:
            raise ValueError(f"灰度组占比之和必须为 100，当前 {total}")
        names = [group["name"] for group in groups]
        if len(set(names)) != len(names):
            raise ValueError("灰度组名称不能重复")
