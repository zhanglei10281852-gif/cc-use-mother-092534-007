"""规范化编码、摘要、确定性分桶与签名。

所有摘要都对规范化后的 JSON 计算 SHA-256，保证字段顺序不会影响结果；
签名使用 HMAC-SHA256，载荷只包含确定的摘要与能力集合。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical(value: Any) -> str:
    """生成跨进程稳定的规范 JSON 字符串。"""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value: Any) -> str:
    """对任意可 JSON 化对象计算规范摘要。"""
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def combined_digest(**parts: Any) -> str:
    """对多个命名字段计算组合摘要（字段名固定，避免拼接歧义）。"""
    return digest(parts)


def stable_bucket(salt: str, key: str, modulus: int) -> int:
    """根据盐值与稳定键把对象确定性地映射到 ``[0, modulus)``。

    同一 (salt, key, modulus) 在任何进程里结果相同，因此灰度分组
    不依赖分配顺序或内存状态。
    """
    if modulus <= 0:
        raise ValueError("模数必须为正整数")
    raw = hashlib.blake2b(f"{salt}:{key}".encode("utf-8")).digest()
    return int.from_bytes(raw[:8], "big") % modulus


def sign(secret: str, payload: Any) -> tuple[str, str]:
    """返回 (载荷摘要, HMAC 签名)。"""
    payload_digest = digest(payload)
    signature = hmac.new(secret.encode("utf-8"), payload_digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return payload_digest, signature


def verify_signature(secret: str, payload_digest: str, signature: str) -> bool:
    expected = hmac.new(secret.encode("utf-8"), payload_digest.encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
