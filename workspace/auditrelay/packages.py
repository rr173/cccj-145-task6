"""Tenant filter rules and the immutable delivery package document.

A filter selects which upstream event types a tenant sees and optionally
matches fields inside the event envelope (``payload`` / ``subject_id`` /
``created_at`` / ``event_key``).  Rules are isolated per tenant and versioned;
a delivery freezes the filter version it was cut from.

A delivery package covers a *contiguous original-sequence interval*
``[seq_start, seq_end]``.  Matching leaves carry the full envelope; non-matching
leaves appear as hash-only anchors so the consumer can verify the interval's
continuity without ever learning excluded content.  Every entry carries an
inclusion path against the tree head embedded in the package.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .crypto import (canonical_bytes, dumps_canon, envelope_hash,
                     leaf_hash_bytes)

PACKAGE_VERSION = "dp1"

MATCHABLE_ENVELOPE_FIELDS = ("subject_id", "created_at", "event_key")


@dataclass
class Rule:
    event_types: list[str] = field(default_factory=list)  # empty == all types
    subject_prefix: str | None = None
    payload_equals: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_dict(raw: Any) -> "Rule":
        if not isinstance(raw, dict):
            raise ValueError("rule must be an object")
        et = raw.get("event_types", [])
        if not isinstance(et, list) or not all(isinstance(x, str) for x in et):
            raise ValueError("rule.event_types must be a list of strings")
        sp = raw.get("subject_prefix")
        if sp is not None and not isinstance(sp, str):
            raise ValueError("rule.subject_prefix must be a string")
        pe = raw.get("payload_equals", {})
        if not isinstance(pe, dict):
            raise ValueError("rule.payload_equals must be an object")
        return Rule(event_types=sorted(set(et)), subject_prefix=sp or None,
                    payload_equals=pe)

    def to_dict(self) -> dict:
        return {
            "event_types": list(self.event_types),
            "subject_prefix": self.subject_prefix,
            "payload_equals": dict(self.payload_equals),
        }

    def matches_envelope(self, envelope: dict) -> bool:
        if self.event_types and envelope.get("event_type") not in self.event_types:
            return False
        if self.subject_prefix is not None:
            subj = str(envelope.get("subject_id", ""))
            if not subj.startswith(self.subject_prefix):
                return False
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            payload = {}
        for k, v in self.payload_equals.items():
            if payload.get(k) != v:
                return False
        return True


def normalize_filter(raw: Any) -> dict:
    """Validate a filter document and return its canonical stored form."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("filter must be an object")
    rules_raw = raw.get("rules", [])
    if not isinstance(rules_raw, list):
        raise ValueError("filter.rules must be a list")
    mode = raw.get("match", "any")
    if mode not in ("any", "all"):
        raise ValueError("filter.match must be 'any' or 'all'")
    rules = [Rule.from_dict(r) for r in rules_raw]
    return {
        "filter_version_base": 1,
        "match": mode,
        "rules": [r.to_dict() for r in rules],
    }


def _compile(filter_doc: dict) -> list[Rule]:
    return [Rule.from_dict(r) for r in filter_doc.get("rules", [])]


def filter_matches(filter_doc: dict, envelope: dict) -> bool:
    """An empty filter matches everything; 'all' intersects, 'any' unions."""
    rules = _compile(filter_doc)
    if not rules:
        return True
    mode = filter_doc.get("match", "any")
    if mode == "all":
        return all(r.matches_envelope(envelope) for r in rules)
    return any(r.matches_envelope(envelope) for r in rules)


# --------------------------------------------------------------------------- #
# package assembly / canonical bytes
# --------------------------------------------------------------------------- #

def _entry(envelope: dict | None, leaf_index: int, leaf_hash_hex: str,
           inclusion_path: list[str], matched: bool) -> dict:
    if matched:
        return {
            "seq": leaf_index,
            "matched": True,
            "event_type": envelope["event_type"],
            "event_key": envelope["event_key"],
            "envelope": envelope,
            "leaf_hash": leaf_hash_hex,
            "inclusion_path": inclusion_path,
        }
    # excluded records are exposed only as opaque, verifiable anchors
    return {
        "seq": leaf_index,
        "matched": False,
        "leaf_hash": leaf_hash_hex,
        "inclusion_path": inclusion_path,
    }


def build_package(*, delivery_id: str, tenant_id: str, seq_start: int,
                  seq_end: int, entries: list[dict], sth: dict,
                  filter_doc: dict, filter_version: int,
                  created_at: str) -> dict:
    """Assemble the anchored delivery document.

    ``entries`` is a list produced by :func:`_entry` covering *every* sequence
    in the closed interval without holes.  Retry bookkeeping (attempt number,
    lease holder) is deliberately absent: a timeout or a process restart must
    re-serve byte-identical content under the same delivery_id.
    """
    return {
        "package_version": PACKAGE_VERSION,
        "delivery_id": delivery_id,
        "tenant_id": tenant_id,
        "seq_start": seq_start,
        "seq_end": seq_end,
        "created_at": created_at,
        "filter_version": filter_version,
        "filter": {
            "match": filter_doc.get("match", "any"),
            "rules": filter_doc.get("rules", []),
        },
        "tree_head": sth,
        "entries": entries,
    }


def package_entry_from_mirror(*, envelope: dict | None, leaf_index: int,
                              leaf_hash_hex: str, inclusion_path: list[str],
                              matched: bool) -> dict:
    return _entry(envelope, leaf_index, leaf_hash_hex, inclusion_path, matched)


def canonical_package_bytes(package: dict) -> bytes:
    """Stable bytes of a package: identical forever for the same delivery."""
    return canonical_bytes(package)


def package_payload_hash(package: dict) -> str:
    return hashlib.sha256(canonical_package_bytes(package)).hexdigest()


def delivery_id_for(tenant_id: str, seq_start: int, seq_end: int,
                    filter_version: int) -> str:
    """Deterministic id: re-cutting the same interval gives the same delivery."""
    h = hashlib.sha256(dumps_canon({
        "t": tenant_id, "s": seq_start, "e": seq_end,
        "f": filter_version,
    }).encode("utf-8")).hexdigest()[:16]
    return f"dlv_{tenant_id}_{seq_start}_{seq_end}_{h}"


def leaf_hash_of_envelope(envelope: dict) -> str:
    return envelope_hash(envelope).hex()
