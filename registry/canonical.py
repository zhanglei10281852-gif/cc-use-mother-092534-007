"""规范化编码与内容指纹。

正式版本由 *文件摘要 + 依赖 + 入口点 + 能力集合* 共同唯一确定。
指纹只覆盖确定的内容：键排序、去空白分隔、路径排序，保证同内容必然同摘要、
不同内容必然不同摘要。签署与历史安装校验都以该指纹为锚点。
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

CanonicalFiles = list[dict[str, Any]]
CanonicalDeps = dict[str, str]


def canonical_json(obj: Any) -> str:
    """稳定 JSON：键排序、无多余空白、不转义非 ASCII。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def normalize_manifest(
    files: Sequence[Mapping[str, Any]],
    dependencies: Mapping[str, str],
    entry_points: Sequence[str],
    capabilities: Sequence[str],
) -> dict[str, Any]:
    """把上传材料整理成确定顺序的规范清单。"""
    normalized_files: CanonicalFiles = sorted(
        (
            {
                "path": str(item["path"]),
                "sha256": str(item["sha256"]).lower(),
                "size": int(item.get("size", 0)),
            }
            for item in files
        ),
        key=lambda item: item["path"],
    )
    paths = [item["path"] for item in normalized_files]
    if len(paths) != len(set(paths)):
        raise ValueError("清单中存在重复路径")
    deps: CanonicalDeps = {
        str(name): str(version) for name, version in sorted(dependencies.items())
    }
    return {
        "files": normalized_files,
        "dependencies": deps,
        "entry_points": sorted(str(point) for point in entry_points),
        "capabilities": sorted(set(str(cap) for cap in capabilities)),
    }


def content_fingerprint(manifest: Mapping[str, Any]) -> str:
    """对规范清单取 SHA-256，作为版本唯一的内容摘要。"""
    blob = canonical_json(
        {
            "files": [
                [item["path"], item["sha256"], item["size"]]
                for item in manifest["files"]
            ],
            "dependencies": manifest["dependencies"],
            "entry_points": manifest["entry_points"],
            "capabilities": manifest["capabilities"],
        }
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def file_digest_table(files: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    return {str(item["path"]): str(item["sha256"]).lower() for item in files}
