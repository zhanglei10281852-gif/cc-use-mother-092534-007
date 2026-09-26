"""租户资料、技能启用校验与历史安装清单核验。

启用技能时依次检查：

1. 版本处于可分配状态（已批准，未冻结/隔离/回滚），且签署仍然有效；
2. 租户地区允许全部能力；
3. 租户套餐允许全部能力；
4. 与该租户已启用的其他技能不存在互斥能力。

安装记录保存签署版本的确切清单摘要与依赖摘要；任何时候都可以
重新核验历史安装使用的确切清单，漂移会使该安装上的签署失效。
"""
from __future__ import annotations

from typing import Any

from .canonical import digest
from .errors import (
    CapabilityConflict,
    DriftDetected,
    PlanDenied,
    RegionDenied,
    UnknownObject,
    VersionStateError,
)
from .reviews import ReviewService
from .store import Store, new_id, now_iso

# 可以被分配/启用的版本状态。
ASSIGNABLE_STATES = {"approved"}


class TenantDirectory:
    def __init__(self, store: Store, reviews: ReviewService):
        self.store = store
        self.reviews = reviews
        self.policy = reviews.policy

    # -- 租户 -----------------------------------------------------------

    def register_tenant(self, tenant_id: str, plan: str, region: str) -> None:
        with self.store.transaction() as conn:
            conn.execute(
                "insert or ignore into tenants(tenant_id, plan, region, created_at) values (?, ?, ?, ?)",
                (tenant_id, plan, region, now_iso()),
            )

    def get_tenant(self, tenant_id: str) -> dict[str, Any]:
        row = self.store.get("select * from tenants where tenant_id = ?", (tenant_id,))
        if row is None:
            raise UnknownObject(f"未知租户：{tenant_id}")
        return dict(row)

    # -- 启用 -----------------------------------------------------------

    def enable_skill(
        self,
        tenant_id: str,
        package_ref: str,
        version_id: str,
        *,
        source: str = "manual",
        rollout_batch_id: str | None = None,
        group_name: str | None = None,
        actor_id: str = "operator",
    ) -> str:
        """启用技能并生成确切清单的安装记录，返回 install_id。"""
        with self.store.transaction() as conn:
            tenant = conn.execute("select * from tenants where tenant_id = ?", (tenant_id,)).fetchone()
            if tenant is None:
                raise UnknownObject(f"未知租户：{tenant_id}")
            version = conn.execute("select * from versions where version_id = ?", (version_id,)).fetchone()
            if version is None:
                raise UnknownObject(f"未知版本：{version_id}")
            if version["state"] not in ASSIGNABLE_STATES:
                raise VersionStateError(f"版本状态 {version['state']} 不可启用")

            capabilities = [
                row["capability"]
                for row in conn.execute(
                    "select capability from version_capabilities where version_id = ? order by capability",
                    (version_id,),
                )
            ]

            # 地区、套餐、能力冲突三道闸门。
            region_message = self.policy.check_region(tenant["region"], capabilities)
            if region_message:
                raise RegionDenied(region_message)
            plan_message = self.policy.check_plan(tenant["plan"], capabilities)
            if plan_message:
                raise PlanDenied(plan_message)
            existing_caps = self._tenant_capabilities_conn(conn, tenant_id, exclude_package=version["package_id"])
            conflicts = self.policy.find_conflicts(capabilities, existing_caps)
            if conflicts:
                detail = "; ".join(f"{a} 与 {b} 互斥" for a, b in conflicts)
                raise CapabilityConflict(f"租户 {tenant_id} 能力冲突：{detail}")

            # 签署必须仍然有效（内容/依赖/能力漂移时这里抛 DriftDetected）。
            self._assert_signatures_fresh_conn(conn, version_id)

            assignment = conn.execute(
                "select * from assignments where tenant_id = ? and package_id = ?",
                (tenant_id, version["package_id"]),
            ).fetchone()
            timestamp = now_iso()
            if assignment is None:
                assignment_id = new_id("asn")
                conn.execute(
                    "insert into assignments(assignment_id, tenant_id, package_id, version_id, state, "
                    "source, rollout_batch_id, group_name, enabled_at) values (?,?,?,?,?,?,?,?,?)",
                    (
                        assignment_id, tenant_id, version["package_id"], version_id, "active",
                        source, rollout_batch_id, group_name, timestamp,
                    ),
                )
            else:
                assignment_id = assignment["assignment_id"]
                conn.execute(
                    "update assignments set version_id = ?, state = 'active', source = ?, "
                    "rollout_batch_id = ?, group_name = ?, enabled_at = ?, disabled_at = null "
                    "where assignment_id = ?",
                    (version_id, source, rollout_batch_id, group_name, timestamp, assignment_id),
                )
            install_id = self._insert_install_conn(
                conn, tenant_id, version, assignment_id=assignment_id,
                rollout_batch_id=rollout_batch_id,
            )
            # 该租户同一包的旧活跃安装被本次启用的版本取代。
            conn.execute(
                "update installs set status = 'superseded', replaced_at = ?, "
                "replaced_by_install_id = ? where tenant_id = ? and package_id = ? "
                "and install_id <> ? and status = 'active'",
                (timestamp, install_id, tenant_id, version["package_id"], install_id),
            )
            self.store.append_event(
                conn, "skill.enabled", "tenant", tenant_id, actor_id,
                {
                    "package_id": version["package_id"],
                    "version_id": version_id,
                    "install_id": install_id,
                    "source": source,
                    "group_name": group_name,
                },
            )
            return install_id

    def disable_skill(self, tenant_id: str, package_ref: str, *, actor_id: str = "operator") -> None:
        package = self._package_conn(self.store.connection, package_ref)
        with self.store.transaction() as conn:
            row = conn.execute(
                "select * from assignments where tenant_id = ? and package_id = ? and state = 'active'",
                (tenant_id, package["package_id"]),
            ).fetchone()
            if row is None:
                raise UnknownObject(f"租户未启用该包：{tenant_id}/{package_ref}")
            conn.execute(
                "update assignments set state = 'disabled', disabled_at = ? where assignment_id = ?",
                (now_iso(), row["assignment_id"]),
            )
            conn.execute(
                "update installs set status = 'removed', replaced_at = ? where install_id = "
                "(select install_id from installs where assignment_id = ? and status = 'active')",
                (now_iso(), row["assignment_id"]),
            )
            self.store.append_event(
                conn, "skill.disabled", "tenant", tenant_id, actor_id,
                {"package_id": package["package_id"]},
            )

    def list_enabled(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.all(
            "select a.*, p.name as package_name from assignments a "
            "join packages p on p.package_id = a.package_id "
            "where a.tenant_id = ? and a.state = 'active' order by a.enabled_at",
            (tenant_id,),
        )]

    # -- 历史安装与漂移核验 ---------------------------------------------

    def verify_install(self, install_id: str, files: list[dict[str, Any]], dependencies: list[dict[str, Any]]) -> bool:
        """核验一次安装现场的文件清单与依赖是否与签署时完全一致。

        任何差异（文件增删改、尺寸或摘要变化、依赖版本/摘要漂移）都会
        导致核验失败，并把安装标记为漂移。
        """
        manifest_ok = False
        deps_ok = False
        drifted_version_id: str | None = None
        with self.store.transaction() as conn:
            install = conn.execute("select * from installs where install_id = ?", (install_id,)).fetchone()
            if install is None:
                raise UnknownObject(f"未知安装：{install_id}")
            manifest = [
                {"path": f["path"], "size": f["size"], "sha256": f["sha256"]}
                for f in sorted(files, key=lambda x: x["path"])
            ]
            deps = [
                {"name": d["name"], "constraint": d["constraint"], "digest": d["digest"]}
                for d in sorted(dependencies, key=lambda x: x["name"])
            ]
            manifest_ok = digest(manifest) == install["manifest_digest"]
            deps_ok = digest(deps) == install["deps_digest"]
            if not (manifest_ok and deps_ok):
                conn.execute(
                    "update installs set status = 'drifted' where install_id = ? and status = 'active'",
                    (install_id,),
                )
                self.store.append_event(
                    conn, "install.drift_detected", "install", install_id, "verifier",
                    {
                        "version_id": install["version_id"],
                        "manifest_match": manifest_ok,
                        "dependencies_match": deps_ok,
                    },
                )
                drifted_version_id = install["version_id"]
        # 事务已提交漂移标记，再向调用方报错。
        if drifted_version_id is not None:
            raise DriftDetected(
                f"安装 {install_id} 的清单/依赖与签署版本 {drifted_version_id} 不一致"
                f"（清单一致：{manifest_ok}，依赖一致：{deps_ok}）"
            )
        return True

    def list_installs(self, version_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.store.all(
            "select * from installs where version_id = ? order by installed_at", (version_id,)
        )]

    # -- 内部 -----------------------------------------------------------

    def _assert_signatures_fresh_conn(self, conn, version_id: str) -> None:
        """事务内复用 ReviewService 的核验逻辑，避免自开事务导致嵌套。"""
        review = conn.execute(
            "select * from reviews where version_id = ? and status = 'approved' "
            "order by rowid desc limit 1", (version_id,)
        ).fetchone()
        if review is None:
            raise VersionStateError(f"版本 {version_id} 没有已通过的审查")
        from .canonical import digest as canonical_digest, verify_signature
        payload = self.reviews._payload(conn, review)
        fresh = canonical_digest(payload)
        rows = conn.execute(
            "select * from signatures where review_id = ?", (review["review_id"],)
        ).fetchall()
        for row in rows:
            if row["payload_digest"] != fresh or not verify_signature(
                self.reviews.secret, row["payload_digest"], row["signature"]
            ):
                raise DriftDetected(f"版本 {version_id} 签署失效")

    def _tenant_capabilities_conn(self, conn, tenant_id: str, *, exclude_package: str | None) -> set[str]:
        sql = ("select vc.capability from assignments a "
               "join version_capabilities vc on vc.version_id = a.version_id "
               "where a.tenant_id = ? and a.state = 'active'")
        params: list[Any] = [tenant_id]
        if exclude_package:
            sql += " and a.package_id <> ?"
            params.append(exclude_package)
        return {row["capability"] for row in conn.execute(sql, params)}

    def _package_conn(self, conn, package_ref: str):
        row = conn.execute(
            "select * from packages where package_id = ? or name = ?", (package_ref, package_ref)
        ).fetchone()
        if row is None:
            raise UnknownObject(f"未知包：{package_ref}")
        return row

    def _insert_install_conn(self, conn, tenant_id: str, version, *, assignment_id=None,
                             rollout_batch_id=None) -> str:
        install_id = new_id("ist")
        conn.execute(
            "insert into installs(install_id, tenant_id, package_id, version_id, assignment_id, "
            "rollout_batch_id, manifest_digest, deps_digest, status, installed_at) "
            "values (?,?,?,?,?,?,?,?,?,?)",
            (
                install_id, tenant_id, version["package_id"], version["version_id"], assignment_id,
                rollout_batch_id, version["manifest_digest"], version["deps_digest"],
                "active", now_iso(),
            ),
        )
        return install_id
