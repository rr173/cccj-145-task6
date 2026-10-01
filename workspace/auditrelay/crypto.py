"""Deterministic encoding, HMAC signatures and RFC 9162 Merkle math.

These routines are intentionally byte-for-byte compatible with the upstream
gateway's ``receipts.dumps_canon`` and ``transparency`` hashing:

    canonical JSON : sorted keys, ","/":" separators, ensure_ascii
    checkpoint sig : hex HMAC-SHA256(secret, canonical(checkpoint - "sig"))
    leaf hash      : SHA256(0x00 || leaf_envelope_canonical_bytes)
    inner hash     : SHA256(0x01 || left || right)
    empty root     : SHA256("")

The relay only holds the upstream's verification secret; it has no signing key
of the upstream's, so it can verify but can never forge a tree head.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Iterable

CHECKPOINT_VERSION = "tc1"

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


# --------------------------------------------------------------------------- #
# canonical JSON / signatures
# --------------------------------------------------------------------------- #

def dumps_canon(obj: Any) -> str:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False)


def canonical_bytes(obj: Any) -> bytes:
    return dumps_canon(obj).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def checkpoint_signing_body(checkpoint: dict) -> bytes:
    return canonical_bytes({k: v for k, v in checkpoint.items() if k != "sig"})


def hmac_sign(secret: bytes, body: bytes) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_checkpoint(checkpoint: Any, secret: bytes) -> tuple[dict | None, str | None]:
    """Validate a signed tree head document.

    Returns ``(clean_body, None)`` on success or ``(None, reason)``.
    """
    if not isinstance(checkpoint, dict):
        return None, "checkpoint must be an object"
    sig = checkpoint.get("sig")
    if not isinstance(sig, str):
        return None, "checkpoint missing sig"
    expect = hmac_sign(secret, checkpoint_signing_body(checkpoint))
    if not hmac.compare_digest(sig, expect):
        return None, "checkpoint signature invalid"
    if checkpoint.get("checkpoint_version") != CHECKPOINT_VERSION:
        return None, "unsupported checkpoint version"
    size = checkpoint.get("tree_size")
    root = checkpoint.get("root_hash")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return None, "malformed checkpoint: tree_size"
    if not isinstance(root, str):
        return None, "malformed checkpoint: root_hash"
    return dict(checkpoint), None


# --------------------------------------------------------------------------- #
# Merkle hashing (identical rules to the gateway)
# --------------------------------------------------------------------------- #

def leaf_hash_bytes(leaf_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def envelope_hash(envelope: dict) -> bytes:
    return leaf_hash_bytes(canonical_bytes(envelope))


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def fold_level(level: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for i in range(0, len(level) - 1, 2):
        out.append(node_hash(level[i], level[i + 1]))
    if len(level) % 2:
        out.append(level[-1])  # promoted odd node
    return out


def merkle_root(leaf_hashes: Iterable[bytes]) -> bytes:
    level = list(leaf_hashes)
    if not level:
        return bytes.fromhex(EMPTY_HASH)
    while len(level) > 1:
        level = fold_level(level)
    return level[0]


def frontier_root(frontier: list[bytes]) -> bytes:
    """Root from a canonical append-ordered frontier (descending widths).

    The components are folded right-to-left: ``h = node(frontier[-2], h)``.
    """
    if not frontier:
        return bytes.fromhex(EMPTY_HASH)
    h = frontier[-1]
    for nxt in reversed(frontier[:-1]):
        h = node_hash(nxt, h)
    return h


def append_frontier(frontier: list[bytes], leaf_h: bytes, size: int) -> list[bytes]:
    """Return the new frontier after appending one leaf at 0-based *size*.

    ``size`` is the size *before* the append; the trailing set-bit run of
    ``size+1`` tells us how many equal-width components merge.
    """
    nf = list(frontier)
    width = 1
    n = size + 1
    while n & 1 == 0 and nf:
        leaf_h = node_hash(nf.pop(), leaf_h)
        width *= 2
        n >>= 1
    nf.append(leaf_h)
    return nf


def inclusion_nodes(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    n = len(leaf_hashes)
    if not (0 <= index < n):
        raise IndexError("leaf index out of range")
    level = list(leaf_hashes)
    pos = index
    proof: list[bytes] = []
    while len(level) > 1:
        if pos % 2:
            proof.append(level[pos - 1])
        elif pos + 1 < len(level):
            proof.append(level[pos + 1])
        pos //= 2
        level = fold_level(level)
    return proof


def verify_inclusion(root: bytes, leaf: bytes, index: int, tree_size: int,
                     proof_hashes: list[bytes]) -> bool:
    if tree_size <= 0 or not (0 <= index < tree_size):
        return False
    pos = index
    size = tree_size
    h = leaf
    pi = 0
    while size > 1:
        if pos % 2 == 1:
            if pi >= len(proof_hashes):
                return False
            h = node_hash(proof_hashes[pi], h)
            pi += 1
        elif pos + 1 < size:
            if pi >= len(proof_hashes):
                return False
            h = node_hash(h, proof_hashes[pi])
            pi += 1
        pos //= 2
        size = (size + 1) // 2
    return pi == len(proof_hashes) and h == root
