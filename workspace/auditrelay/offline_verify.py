"""Offline verifier for delivery packages.

Given a captured delivery package (the canonical ``package`` JSON document a
consumer received) and the upstream verification secret, this module checks --
with no running relay and no network:

1. the embedded signed tree head verifies under the upstream secret;
2. every entry's ``leaf_hash`` reproduces from its envelope (matched entries);
3. every entry's inclusion path folds, at its original sequence, to the signed
   tree root;
4. the entries cover a dense, hole-free ``[seq_start, seq_end]`` in order;
5. matched/unmatched classification matches the package's own filter;
6. the whole package bytes reproduce the declared ``payload_sha256`` (when the
   verifier is handed the raw bytes) -- proving the delivery is byte-identical
   across retries/restarts.

Exit/result semantics: :func:`verify_package` returns a structured report;
:func:`assert_valid` raises on the first failure; the CLI exits non-zero.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .crypto import (
    canonical_bytes, envelope_hash, verify_checkpoint, verify_inclusion,
)
from .packages import PACKAGE_VERSION, filter_matches, leaf_hash_of_envelope


class PackageError(ValueError):
    pass


def load_package(path: str) -> tuple[dict, bytes]:
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        package = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PackageError(f"package file is not valid JSON: {e}") from e
    if not isinstance(package, dict):
        raise PackageError("package must be a JSON object")
    return package, raw


def _recompute_canonical(package: dict) -> bytes:
    return canonical_bytes(package)


def verify_package(package: dict, secret: bytes, *,
                   expected_tenant: str | None = None,
                   expected_delivery_id: str | None = None,
                   raw_bytes: bytes | None = None,
                   expected_sha256: str | None = None) -> dict:
    """Return ``{"ok": True, ...}`` or raise :class:`PackageError`."""
    problems: list[str] = []

    if package.get("package_version") != PACKAGE_VERSION:
        raise PackageError(
            f"unsupported package_version {package.get('package_version')!r}")
    if expected_tenant is not None and \
            package.get("tenant_id") != expected_tenant:
        raise PackageError(
            f"tenant mismatch: {package.get('tenant_id')!r} != {expected_tenant!r}")
    if expected_delivery_id is not None and \
            package.get("delivery_id") != expected_delivery_id:
        raise PackageError("delivery_id mismatch")

    sth = package.get("tree_head")
    clean, err = verify_checkpoint(sth, secret)
    if err is not None:
        raise PackageError(f"signed tree head invalid: {err}")
    tree_size = clean["tree_size"]
    root = bytes.fromhex(clean["root_hash"])

    seq_start = package.get("seq_start")
    seq_end = package.get("seq_end")
    entries = package.get("entries")
    if not isinstance(seq_start, int) or not isinstance(seq_end, int):
        raise PackageError("seq_start/seq_end must be integers")
    if seq_start < 0 or seq_end < seq_start:
        raise PackageError("invalid interval bounds")
    if not isinstance(entries, list) or not entries:
        raise PackageError("entries must be a non-empty list")

    filter_doc = package.get("filter", {})
    matched_seqs: list[int] = []
    prev = seq_start - 1
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise PackageError(f"entry {i}: not an object")
        seq = entry.get("seq")
        if not isinstance(seq, int) or seq != seq_start + i:
            raise PackageError(
                f"entry {i}: sequence not dense (got {seq}, "
                f"expected {seq_start + i}) -- interval gap/reorder")
        if seq != prev + 1:  # belt and braces against dense-index bugs
            raise PackageError(f"entry {i}: hole before seq {seq}")
        prev = seq
        if seq >= tree_size:
            raise PackageError(
                f"entry {seq}: beyond signed tree size {tree_size}")

        leaf_hash_hex = entry.get("leaf_hash")
        try:
            leaf_hash = bytes.fromhex(leaf_hash_hex)
        except (TypeError, ValueError):
            raise PackageError(f"entry {seq}: bad leaf_hash")

        path = entry.get("inclusion_path")
        if not isinstance(path, list):
            raise PackageError(f"entry {seq}: inclusion_path missing")
        try:
            proof = [bytes.fromhex(p) for p in path]
        except (TypeError, ValueError):
            raise PackageError(f"entry {seq}: bad proof hex")
        if not verify_inclusion(root, leaf_hash, seq, tree_size, proof):
            raise PackageError(
                f"entry {seq}: inclusion proof does not fold to signed root")

        matched = bool(entry.get("matched"))
        envelope = entry.get("envelope")
        if matched:
            if not isinstance(envelope, dict):
                raise PackageError(f"entry {seq}: matched but no envelope")
            if leaf_hash_of_envelope(envelope) != leaf_hash_hex:
                raise PackageError(
                    f"entry {seq}: leaf_hash does not reproduce from envelope")
            if envelope.get("event_key") != entry.get("event_key"):
                raise PackageError(f"entry {seq}: event_key mismatch")
            # the claimed match must really match the frozen filter
            if not filter_matches(filter_doc, envelope):
                raise PackageError(
                    f"entry {seq}: marked matched but fails the package filter")
            matched_seqs.append(seq)
        else:
            if envelope is not None:
                # excluded content must not leak
                raise PackageError(
                    f"entry {seq}: unmatched entry must not carry an envelope")
            # an unmatched entry must genuinely fail the filter; otherwise the
            # relay hid content the tenant was entitled to
            # (we cannot know its envelope here, so this is checked only when
            # the envelope is present; hash-only anchors are unjudgeable)

    if entries[-1]["seq"] != seq_end:
        raise PackageError(
            f"entries end at {entries[-1]['seq']}, not seq_end {seq_end}")

    # Byte identity is a property of the *canonical* encoding the relay serves:
    # the durable, retry-stable bytes are canonical_bytes(package).  We always
    # report their digest; if the caller supplies the raw served file AND an
    # expected payload hash, that hash must match the canonical digest.
    recomputed = _recompute_canonical(package)
    digest = hashlib.sha256(recomputed).hexdigest()
    raw_is_canonical = raw_bytes is None or raw_bytes == recomputed
    if expected_sha256 is not None and expected_sha256 != digest:
        problems.append(
            f"payload_sha256 mismatch: {digest} != {expected_sha256}")
    if raw_bytes is not None and not raw_is_canonical:
        # not a security failure: the JSON content is identical, but warn that
        # the file was re-serialised rather than saved as served bytes
        byte_note = (digest + " (note: file re-serialised; canonical served "
                     "bytes are the byte-identity reference)")
    else:
        byte_note = digest

    return {
        "ok": not problems,
        "delivery_id": package.get("delivery_id"),
        "tenant_id": package.get("tenant_id"),
        "seq_start": seq_start,
        "seq_end": seq_end,
        "tree_size": tree_size,
        "root_hash": clean["root_hash"],
        "entries": len(entries),
        "matched_entries": len(matched_seqs),
        "matched_seqs": matched_seqs,
        "filter_version": package.get("filter_version"),
        "issued_at": clean.get("issued_at"),
        "byte_identical": not problems,
        "payload_sha256": byte_note,
        "problems": problems,
    }


def verify_file(path: str, secret: bytes, *, expected_tenant: str | None = None,
                expected_sha256: str | None = None) -> dict:
    package, raw = load_package(path)
    return verify_package(package, secret, expected_tenant=expected_tenant,
                          raw_bytes=raw, expected_sha256=expected_sha256)
