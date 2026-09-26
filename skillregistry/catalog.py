"""包登记、上传去重、版本编号与版本差异比较。"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .canonical import combined_digest, digest
from .errors import UnknownObject, VersionStateError
from .store import Store, new_id, now_iso


@dataclass(frozen=True)
class PackageSubmission:
    """一次上传的规范化内容。"""

    files: tuple[dict[str, Any], ...]          # [{path, size, sha256}]
    dependencies: tuple[dict[str, Any], ...]   # [{name, constraint, digest}]
    entrypoints: tuple[dict[str, Any], ...]    # [{name, command}]
    capabilities: frozenset[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PackageSubmission":
        files = tuple(sorted((dict(item) for item in data.get("files", [])), key=lambda x: x["path"]))
        deps = tuple(sorted((dict(item) for item in data.get("dependencies", [])), key=lambda x: x["name"]))
        entries = tuple(sorted((dict(item) for item in data.get("entrypoints", [])), key=lambda x: x["name"]))
        capabilities = frozenset(data.get("capabilities", ()))
        return cls(files=files, dependencies=deps, entrypoints=entries, capabilities=capabilities)


@dataclass(frozen=True)
class VersionDiff:
    """两个版本之间的差异。"""

    files_added: tuple[str, ...]
    files_removed: tuple[str, ...]
    files_changed: tuple[str, ...]
    deps_added: tuple[str, ...]
    deps_removed: tuple[str, ...]
    deps_changed: tuple[str, ...]
    entrypoints_changed: bool
    capabilities_added: tuple[str, ...]
    capabilities_removed: tuple[str, ...]

    @property
    def is_identical(self) -> bool:
        return not (
            self.files_added or self.files_removed or self.files_changed
            or self.deps_added or self.deps_removed or self.deps_changed
            or self.entrypoints_changed
            or self.capabilities_added or self.capabilities_removed
        )

    @property
    def capability_expanded(self) -> bool:
        return bool(self.capabilities_added)


class Catalog:
    def __init__(self, store: Store):
        self.store = store

    # -- 登记与上传 -----------------------------------------------------

    def register_package(self, name: str, *, actor_id: str = "system") -> str:
        try:
            with self.store.transaction() as conn:
                existing = conn.execute(
                    "select package_id from packages where name = ?", (name,)
                ).fetchone()
                if existing:
                    return existing["package_id"]
                package_id = new_id("pkg")
                conn.execute(
                    "insert into packages(package_id, name, created_at) values (?, ?, ?)",
                    (package_id, name, now_iso()),
                )
                self.store.append_event(conn, "package.registered", "package", package_id, actor_id, {"name": name})
                return package_id
        except sqlite3.IntegrityError:
            # 并发登记同名包：复用先提交者。
            row = self.store.get("select package_id from packages where name = ?", (name,))
            return row["package_id"]

    def upload(self, package_ref: str, submission: PackageSubmission, *, actor_id: str = "operator") -> tuple[str, bool]:
        """接收一次上传，返回 (version_id, created)。

        内容摘要、依赖、入口点与能力集合完全一致的重复上传复用同一个
        候选版本，绝不会产生第二个版本（唯一约束兜底）。
        """
        package_id = self._resolve_package(package_ref)
        material = self._materialize(submission)
        try:
            with self.store.transaction() as conn:
                row = conn.execute(
                    "select version_id from versions where package_id = ? and fingerprint = ?",
                    (package_id, material["fingerprint"]),
                ).fetchone()
                if row:
                    self.store.append_event(
                        conn, "package.uploaded", "version", row["version_id"], actor_id,
                        {"duplicate": True, "fingerprint": material["fingerprint"]},
                    )
                    return row["version_id"], False
                version_id = new_id("ver")
                predecessor = conn.execute(
                    "select version_id from versions where package_id = ? "
                    "order by rowid desc limit 1", (package_id,)
                ).fetchone()
                conn.execute(
                    "insert into versions(version_id, package_id, state, content_digest, manifest_digest, "
                    "deps_digest, entrypoint_digest, capability_digest, fingerprint, entrypoint_json, "
                    "created_at, predecessor_version_id) values (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        version_id, package_id, "uploaded", material["content_digest"],
                        material["manifest_digest"], material["deps_digest"],
                        material["entrypoint_digest"], material["capability_digest"],
                        material["fingerprint"], json.dumps(submission.entrypoints, ensure_ascii=False),
                        now_iso(), predecessor["version_id"] if predecessor else None,
                    ),
                )
                for item in submission.files:
                    conn.execute(
                        "insert into version_files(version_id, path, size, sha256) values (?, ?, ?, ?)",
                        (version_id, item["path"], item["size"], item["sha256"]),
                    )
                for item in submission.dependencies:
                    conn.execute(
                        "insert into version_dependencies(version_id, name, constraint_text, digest) "
                        "values (?, ?, ?, ?)",
                        (version_id, item["name"], item["constraint"], item["digest"]),
                    )
                for capability in sorted(submission.capabilities):
                    conn.execute(
                        "insert into version_capabilities(version_id, capability) values (?, ?)",
                        (version_id, capability),
                    )
                self.store.append_event(
                    conn, "package.uploaded", "version", version_id, actor_id,
                    {
                        "package_id": package_id,
                        "fingerprint": material["fingerprint"],
                        "content_digest": material["content_digest"],
                        "capabilities": sorted(submission.capabilities),
                        "predecessor_version_id": predecessor["version_id"] if predecessor else None,
                    },
                )
                return version_id, True
        except sqlite3.IntegrityError:
            # 并发上传相同指纹：唯一约束兜底，复用先提交者。
            row = self.store.get(
                "select version_id from versions where package_id = ? and fingerprint = ?",
                (package_id, material["fingerprint"]),
            )
            if row is not None:
                return row["version_id"], False
            raise

    def verify_manifest(self, version_id: str, *, actor_id: str = "operator") -> None:
        """记录文件摘要核验通过，并推进到 reviewing。"""
        with self.store.transaction() as conn:
            version = self._get_version_conn(conn, version_id)
            if version["state"] != "uploaded":
                raise VersionStateError(f"版本状态 {version['state']} 不允许核验清单")
            conn.execute("update versions set state = 'reviewing' where version_id = ?", (version_id,))
            self.store.append_event(
                conn, "manifest.verified", "version", version_id, actor_id,
                {"manifest_digest": version["manifest_digest"]},
            )

    # -- 读取与差异 -----------------------------------------------------

    def get_version(self, version_id: str) -> dict[str, Any]:
        row = self.store.get("select * from versions where version_id = ?", (version_id,))
        if row is None:
            raise UnknownObject(f"未知版本：{version_id}")
        return dict(row)

    def get_package(self, package_ref: str) -> dict[str, Any]:
        row = self.store.get(
            "select * from packages where package_id = ? or name = ?",
            (package_ref, package_ref),
        )
        if row is None:
            raise UnknownObject(f"未知包：{package_ref}")
        return dict(row)

    def list_versions(self, package_ref: str) -> list[dict[str, Any]]:
        package_id = self._resolve_package(package_ref)
        return [dict(row) for row in self.store.all(
            "select * from versions where package_id = ? order by rowid", (package_id,)
        )]

    def latest_published(self, package_ref: str) -> dict[str, Any] | None:
        package_id = self._resolve_package(package_ref)
        row = self.store.get(
            "select * from versions where package_id = ? and formal_version_no is not null "
            "and state in ('approved', 'rolling_out') order by formal_version_no desc limit 1",
            (package_id,),
        )
        return dict(row) if row else None

    def latest_safe(self, package_ref: str, *, before_version: str | None = None) -> dict[str, Any] | None:
        """最近的安全版本：已发布且未被冻结/隔离/回滚。"""
        package_id = self._resolve_package(package_ref)
        sql = ("select * from versions where package_id = ? and formal_version_no is not null "
               "and state = 'approved'")
        params: list[Any] = [package_id]
        if before_version:
            sql += " and version_id <> ?"
            params.append(before_version)
        sql += " order by formal_version_no desc limit 1"
        row = self.store.get(sql, tuple(params))
        return dict(row) if row else None

    def capabilities(self, version_id: str) -> frozenset[str]:
        return frozenset(row["capability"] for row in self.store.all(
            "select capability from version_capabilities where version_id = ? order by capability",
            (version_id,),
        ))

    def diff(self, left_version_id: str, right_version_id: str) -> VersionDiff:
        left_files = {row["path"]: row["sha256"] for row in self.store.all(
            "select path, sha256 from version_files where version_id = ?", (left_version_id,))}
        right_files = {row["path"]: row["sha256"] for row in self.store.all(
            "select path, sha256 from version_files where version_id = ?", (right_version_id,))}
        left_deps = {row["name"]: (row["constraint_text"], row["digest"]) for row in self.store.all(
            "select name, constraint_text, digest from version_dependencies where version_id = ?",
            (left_version_id,))}
        right_deps = {row["name"]: (row["constraint_text"], row["digest"]) for row in self.store.all(
            "select name, constraint_text, digest from version_dependencies where version_id = ?",
            (right_version_id,))}
        left_entries = json.loads(self.get_version(left_version_id)["entrypoint_json"])
        right_entries = json.loads(self.get_version(right_version_id)["entrypoint_json"])

        files_added = tuple(sorted(right_files.keys() - left_files.keys()))
        files_removed = tuple(sorted(left_files.keys() - right_files.keys()))
        files_changed = tuple(sorted(
            path for path in left_files.keys() & right_files.keys()
            if left_files[path] != right_files[path]
        ))
        deps_added = tuple(sorted(right_deps.keys() - left_deps.keys()))
        deps_removed = tuple(sorted(left_deps.keys() - right_deps.keys()))
        deps_changed = tuple(sorted(
            name for name in left_deps.keys() & right_deps.keys()
            if left_deps[name] != right_deps[name]
        ))
        left_caps = self.capabilities(left_version_id)
        right_caps = self.capabilities(right_version_id)
        return VersionDiff(
            files_added=files_added,
            files_removed=files_removed,
            files_changed=files_changed,
            deps_added=deps_added,
            deps_removed=deps_removed,
            deps_changed=deps_changed,
            entrypoints_changed=left_entries != right_entries,
            capabilities_added=tuple(sorted(right_caps - left_caps)),
            capabilities_removed=tuple(sorted(left_caps - right_caps)),
        )

    # -- 内部 -----------------------------------------------------------

    def _resolve_package(self, package_ref: str) -> str:
        return self.get_package(package_ref)["package_id"]

    def _get_version_conn(self, conn, version_id: str):
        row = conn.execute("select * from versions where version_id = ?", (version_id,)).fetchone()
        if row is None:
            raise UnknownObject(f"未知版本：{version_id}")
        return row

    def _materialize(self, submission: PackageSubmission) -> dict[str, str]:
        manifest = [{"path": f["path"], "size": f["size"], "sha256": f["sha256"]} for f in submission.files]
        manifest_digest = digest(manifest)
        content_digest = combined_digest(
            manifest=manifest_digest,
            entrypoints=list(submission.entrypoints),
        )
        deps_digest = digest([
            {"name": d["name"], "constraint": d["constraint"], "digest": d["digest"]}
            for d in submission.dependencies
        ])
        entrypoint_digest = digest(list(submission.entrypoints))
        capability_digest = digest(sorted(submission.capabilities))
        fingerprint = combined_digest(
            content=content_digest,
            dependencies=deps_digest,
            entrypoints=entrypoint_digest,
            capabilities=capability_digest,
        )
        return {
            "manifest_digest": manifest_digest,
            "content_digest": content_digest,
            "deps_digest": deps_digest,
            "entrypoint_digest": entrypoint_digest,
            "capability_digest": capability_digest,
            "fingerprint": fingerprint,
        }
