"""测试辅助：构造上传内容与走完整审批流程的便捷函数。"""
from __future__ import annotations

import hashlib

from skillregistry.catalog import PackageSubmission


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_files(*names: str) -> list[dict]:
    return [{"path": name, "size": len(name) * 10, "sha256": sha(f"content:{name}")} for name in names]


def make_deps(*names: str) -> list[dict]:
    return [{"name": name, "constraint": "^1.0", "digest": sha(f"dep:{name}")} for name in names]


def make_submission(
    *,
    files=("main.py",),
    deps=("requests",),
    entries=("run",),
    capabilities=("fs.read",),
) -> PackageSubmission:
    return PackageSubmission.from_dict(
        {
            "files": make_files(*files),
            "dependencies": make_deps(*deps),
            "entrypoints": [{"name": name, "command": f"./bin/{name}"} for name in entries],
            "capabilities": list(capabilities),
        }
    )


def approve_version(service, version_id, roles: list[str]) -> int:
    """以各角色依次签署后放行。"""
    for role in roles:
        service.reviews.sign_review(version_id, role, f"user-{role}")
    return service.reviews.approve(version_id)


def required_roles(service, version_id) -> list[str]:
    return service.reviews.review_status(version_id)["required_approvers"]
