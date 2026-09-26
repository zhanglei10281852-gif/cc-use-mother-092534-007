"""审查签署。

签名 *只* 覆盖确定的内容摘要与能力集合（外加审批环节标识），
不绑定可变元数据。包内容或依赖发生漂移时内容指纹改变，旧签名立即失效——
失效不是一条需要维护的状态，而是验签时的必然结果。

采用 HMAC-SHA256（对称密钥库按签署人发放）；生产环境可替换为非对称实现，
验签语义保持不变。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Mapping, Sequence

from .canonical import canonical_json


def signing_payload(
    fingerprint: str, capabilities: Sequence[str], stage: str
) -> dict[str, object]:
    return {
        "fingerprint": fingerprint,
        "capabilities": sorted(set(capabilities)),
        "stage": stage,
    }


def sign(key: str | bytes, fingerprint: str, capabilities: Sequence[str], stage: str) -> str:
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    blob = canonical_json(signing_payload(fingerprint, capabilities, stage)).encode("utf-8")
    return base64.b64encode(hmac.new(key_bytes, blob, hashlib.sha256).digest()).decode("ascii")


def verify(
    key: str | bytes,
    fingerprint: str,
    capabilities: Sequence[str],
    stage: str,
    signature: str,
) -> bool:
    expected = sign(key, fingerprint, capabilities, stage)
    return hmac.compare_digest(expected, signature)


class KeyStore:
    """签署人标识 -> 密钥。测试与离线工具使用固定密钥库。"""

    def __init__(self, keys: Mapping[str, str | bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = {}
        for signer, key in (keys or {}).items():
            self.register(signer, key)

    def register(self, signer: str, key: str | bytes) -> None:
        self._keys[signer] = key.encode("utf-8") if isinstance(key, str) else key

    def key_of(self, signer: str) -> bytes:
        try:
            return self._keys[signer]
        except KeyError:
            raise UnknownSigner(f"未知签署人：{signer}") from None

    def sign(self, signer: str, fingerprint: str, capabilities: Sequence[str], stage: str) -> str:
        return sign(self.key_of(signer), fingerprint, capabilities, stage)

    def verify_signature(
        self, signer: str, fingerprint: str, capabilities: Sequence[str], stage: str, signature: str
    ) -> bool:
        try:
            key = self.key_of(signer)
        except UnknownSigner:
            return False
        return verify(key, fingerprint, capabilities, stage, signature)


class UnknownSigner(KeyError):
    pass


class InvalidSignature(Exception):
    pass
