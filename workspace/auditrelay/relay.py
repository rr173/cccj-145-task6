"""The auditing feed relay service.

Trust model
-----------
The relay trusts only (a) the upstream verification secret configured out of
band, and (b) bytes it has itself verified against it.  Every synchronisation
round:

1. fetch the current signed tree head (STH) over a read-only endpoint;
2. verify its HMAC signature; reject a height lower than the trusted height;
3. for each not-yet-mirrored index fetch the leaf record + inclusion proof and
   verify leaf hash, proof against the STH, envelope self-consistency and
   dense sequencing -- never accept a hole;
4. append the whole verified batch in ONE transaction and advance the trusted
   height/frontier/STH together.

Any failure (transport, bad signature, fallback height, missing index) stops
the round before committing anything, so the relay retains its last trusted
position and resumes exactly there when the upstream recovers.  The relay
fabricates no records.
"""

from __future__ import annotations

import hashlib
import json
import secrets as pysecrets
import sqlite3
import threading
from typing import Any, Callable

from . import errors as E
from .crypto import (
    append_frontier, canonical_bytes, envelope_hash, frontier_root,
    inclusion_nodes, leaf_hash_bytes, merkle_root, verify_checkpoint,
    verify_inclusion,
)
from .packages import (
    build_package, canonical_package_bytes, delivery_id_for,
    filter_matches, leaf_hash_of_envelope, normalize_filter,
    package_entry_from_mirror, package_payload_hash,
)
from .store import (
    KV, META_FRONTIER, META_HEIGHT, META_STH, META_STH_AT, META_UPSTREAM,
    init_db, now_iso,
)
from .upstream import UpstreamClient, UpstreamGap, UpstreamUnavailable

DEFAULT_LEASE_SECONDS = 30
MAX_WINDOW = 200
DEFAULT_WINDOW = 50

# delivery lifecycle
OPEN = "open"
ACKED = "acked"

# event categories
EV_SYNC = "sync"
EV_DELIVERY = "delivery"
EV_REJECT = "reject"
EV_TENANT = "tenant"


class Relay:
    def __init__(self, conn: sqlite3.Connection, client: UpstreamClient,
                 upstream_secret: bytes, *, lease_seconds: int = DEFAULT_LEASE_SECONDS,
                 clock: Callable[[], str] = now_iso,
                 monotonic: Callable[[], float] | None = None):
        self.db = conn
        self.client = client
        self.secret = upstream_secret
        self.lease_seconds = int(lease_seconds)
        self.now = clock
        import time as _time
        self._monotonic = monotonic or _time.monotonic
        self._lock = threading.RLock()
        # a dedicated sync lock: slow upstream fetches never run under the
        # tenant serving lock, so a stalled upstream cannot block consumers
        self._synclock = threading.RLock()
        init_db(self.db)
        self.kv = KV(self.db)

    # ------------------------------------------------------------------ #
    # observability event log
    # ------------------------------------------------------------------ #

    def _event(self, category: str, kind: str, *, tenant_id: str | None = None,
               detail: dict | None = None) -> None:
        self.db.execute(
            "INSERT INTO events(at, category, kind, tenant_id, detail_json) "
            "VALUES(?,?,?,?,?)",
            (self.now(), category, kind, tenant_id,
             json.dumps(detail or {}, sort_keys=True, ensure_ascii=False)))

    def list_events(self, *, category: str | None = None,
                    tenant_id: str | None = None, limit: int = 100) -> list[dict]:
        with self._lock:
            sql = "SELECT * FROM events WHERE 1=1"
            params: list[Any] = []
            if category:
                sql += " AND category=?"
                params.append(category)
            if tenant_id:
                sql += " AND tenant_id=?"
                params.append(tenant_id)
            sql += " ORDER BY id DESC LIMIT ?"
            params.append(min(int(limit), 1000))
            rows = self.db.execute(sql, params).fetchall()
            return [{
                "id": r["id"], "at": r["at"], "category": r["category"],
                "kind": r["kind"], "tenant_id": r["tenant_id"],
                "detail": json.loads(r["detail_json"]),
            } for r in rows]

    # ------------------------------------------------------------------ #
    # mirror state
    # ------------------------------------------------------------------ #

    def _height(self) -> int:
        return int(self.kv.get(META_HEIGHT, 0))

    def _frontier(self) -> list[bytes]:
        return [bytes.fromhex(h) for h in self.kv.get(META_FRONTIER, [])]

    def _last_sth(self) -> dict | None:
        return self.kv.get(META_STH, None)

    def _leaf_hashes_upto(self, size: int) -> list[bytes]:
        rows = self.db.execute(
            "SELECT leaf_hash FROM leaves WHERE leaf_index < ? ORDER BY leaf_index",
            (size,)).fetchall()
        return [bytes.fromhex(r["leaf_hash"]) for r in rows]

    def mirror_status(self) -> dict:
        with self._lock:
            height = self._height()
            sth = self._last_sth()
            up = self.kv.get(META_UPSTREAM, {
                "state": "unknown", "last_error": None, "last_success_at": None,
                "advertised_height": None})
            n = self.db.execute("SELECT COUNT(*) c FROM leaves").fetchone()["c"]
            return {
                "mirror_height": height,
                "stored_leaves": n,
                "last_trusted_tree_size": sth["tree_size"] if sth else 0,
                "last_trusted_root": sth["root_hash"] if sth else None,
                "last_trusted_at": self.kv.get(META_STH_AT),
                "upstream": up,
            }

    # ------------------------------------------------------------------ #
    # synchronisation
    # ------------------------------------------------------------------ #

    def sync_once(self) -> dict:
        """Run one pull/verify/commit round; never raises for upstream faults.

        Returns a small summary dict.  On any upstream/verification failure the
        trusted position is left untouched and the failure is recorded.
        """
        if not self._synclock.acquire(blocking=False):
            return {"advanced": False, "skipped": True,
                    "reason": "sync_already_running"}
        try:
            with self._lock:
                trusted = self._height()
                frontier = self._frontier()
                last = self._last_sth()

            # slow network/verify work happens outside the tenant-serving lock
            try:
                state = self.client.state()
            except UpstreamUnavailable as e:
                return self._sync_fail("upstream_unavailable", str(e), trusted)

            sth_doc = state.get("checkpoint")
            clean, err = verify_checkpoint(sth_doc, self.secret)
            if err is not None:
                return self._sync_fail("bad_signature", err, trusted,
                                       advertised=self._safe_size(state))

            advertised = clean["tree_size"]
            upstream_frozen = bool(state.get("frozen"))
            if advertised < trusted:
                # a signed but shorter head: rollback / equivocation attempt
                return self._sync_fail(
                    "fallback_height",
                    f"upstream tree_size {advertised} < trusted {trusted}",
                    trusted, advertised=advertised)

            if advertised == trusted:
                self._upstream_note(advertised, upstream_frozen)
                return {"advanced": False, "from": trusted, "to": trusted,
                        "frozen": upstream_frozen, "added": 0}

            verified: list[tuple[int, dict, str, str]] = []
            new_frontier = list(frontier)
            for idx in range(trusted, advertised):
                try:
                    rec = self.client.inclusion(idx)
                except UpstreamGap as e:
                    return self._sync_fail("interval_gap", str(e),
                                           trusted, advertised=advertised,
                                           at_index=idx)
                except UpstreamUnavailable as e:
                    return self._sync_fail("upstream_unavailable", str(e),
                                           trusted, advertised=advertised,
                                           at_index=idx)
                ok, why, envelope, leaf_hash_hex, incorporated_at = \
                    self._verify_leaf_record(rec, idx, advertised, clean)
                if not ok:
                    kind, message = why if isinstance(why, tuple) \
                        else ("leaf_invalid", str(why))
                    return self._sync_fail(kind, message, trusted,
                                           advertised=advertised, at_index=idx)
                new_frontier = append_frontier(
                    new_frontier, bytes.fromhex(leaf_hash_hex), idx)
                verified.append((idx, envelope, leaf_hash_hex, incorporated_at))

            new_root = frontier_root(new_frontier).hex()
            if new_root != clean["root_hash"]:
                return self._sync_fail(
                    "root_mismatch",
                    f"recomputed root {new_root[:16]}… != signed "
                    f"{clean['root_hash'][:16]}…",
                    trusted, advertised=advertised)

            # append-only guard: the old trusted frontier must still fold to
            # the root we previously trusted (binds to one history)
            if last is not None and frontier_root(frontier).hex() \
                    != last["root_hash"]:
                return self._sync_fail(
                    "prefix_changed",
                    "stored frontier no longer reproduces the trusted root",
                    trusted, advertised=advertised)

            # all verified: commit the batch atomically under the serving lock
            with self._lock:
                if self._height() != trusted:
                    return {"advanced": False, "skipped": True,
                            "reason": "height_changed"}
                ts = self.now()
                self.db.execute("BEGIN IMMEDIATE")
                committed = False
                try:
                    for idx, envelope, leaf_hash_hex, incorporated_at in verified:
                        self.db.execute(
                            "INSERT INTO leaves(leaf_index, event_type, "
                            "event_key, leaf_hash, envelope_json, "
                            "incorporated_at, mirrored_at) "
                            "VALUES(?,?,?,?,?,?,?)",
                            (idx, envelope["event_type"], envelope["event_key"],
                             leaf_hash_hex,
                             json.dumps(envelope, sort_keys=True,
                                        ensure_ascii=False),
                             incorporated_at, ts))
                    self.kv.set(META_HEIGHT, advertised)
                    self.kv.set(META_FRONTIER, [h.hex() for h in new_frontier])
                    self.kv.set(META_STH, clean)
                    self.kv.set(META_STH_AT, ts)
                    self.db.execute("COMMIT")
                    committed = True
                except Exception:
                    if not committed:
                        self.db.execute("ROLLBACK")
                    raise

                self._upstream_note(advertised, upstream_frozen, success=True)
                self._event(EV_SYNC, "mirror_advanced", detail={
                    "from": trusted, "to": advertised,
                    "added": advertised - trusted, "frozen": upstream_frozen})
            return {"advanced": True, "from": trusted, "to": advertised,
                    "frozen": upstream_frozen, "added": advertised - trusted}
        finally:
            self._synclock.release()

    def _verify_leaf_record(self, rec: Any, idx: int, tree_size: int,
                            sth: dict
                            ) -> tuple[bool, Any, dict | None, str | None,
                                       str | None]:
        if not isinstance(rec, dict):
            return False, ("protocol_error", "leaf response is not an object"), \
                None, None, None
        if rec.get("tree_size") != tree_size:
            return False, ("gap_or_stale",
                           f"leaf {idx}: response tree_size "
                           f"{rec.get('tree_size')} != {tree_size}"), \
                None, None, None
        envelope = rec.get("envelope")
        if not isinstance(envelope, dict):
            return False, ("leaf_invalid", f"leaf {idx}: missing envelope"), \
                None, None, None
        if rec.get("leaf_index") != idx:
            return False, ("gap_or_stale",
                           f"expected index {idx}, got {rec.get('leaf_index')}"), \
                None, None, None
        try:
            lh = envelope_hash(envelope).hex()
        except Exception as e:  # pragma: no cover - defensive
            return False, ("leaf_invalid", f"leaf {idx}: {e}"), None, None, None
        if lh != rec.get("leaf_hash"):
            return False, ("leaf_hash_mismatch",
                           f"leaf {idx}: hash does not reproduce envelope"), \
                None, None, None
        if envelope.get("event_key") != rec.get("event_key"):
            return False, ("leaf_invalid",
                           f"leaf {idx}: event_key mismatch"), None, None, None
        path = rec.get("inclusion_path")
        if not isinstance(path, list):
            return False, ("proof_invalid",
                           f"leaf {idx}: inclusion_path missing"), None, None, None
        try:
            proof = [bytes.fromhex(p) for p in path]
        except (TypeError, ValueError):
            return False, ("proof_invalid",
                           f"leaf {idx}: bad proof hex"), None, None, None
        if not verify_inclusion(bytes.fromhex(sth["root_hash"]),
                                bytes.fromhex(lh), idx, tree_size, proof):
            return False, ("proof_invalid",
                           f"leaf {idx}: inclusion proof does not fold to the "
                           "signed root"), None, None, None
        envelope = json.loads(json.dumps(envelope))  # normalise copy
        incorporated = rec.get("envelope", {}).get("created_at") or ""
        return True, None, envelope, lh, incorporated

    def _sync_fail(self, kind: str, message: str, trusted: int, *,
                   advertised: int | None = None,
                   at_index: int | None = None) -> dict:
        detail = {"message": message, "trusted_height": trusted}
        if advertised is not None:
            detail["advertised_height"] = advertised
        if at_index is not None:
            detail["at_index"] = at_index
        self.kv.set(META_UPSTREAM, {
            "state": "halted", "halt_reason": kind, "last_error": message,
            "last_success_at": self.kv.get(META_UPSTREAM, {}).get(
                "last_success_at"),
            "trusted_height": trusted,
            "advertised_height": advertised,
            "halted_at": self.now()})
        self._event(EV_SYNC, "sync_halted:" + kind, detail=detail)
        return {"advanced": False, "from": trusted, "to": trusted,
                "halt_reason": kind, "message": message}

    def _upstream_note(self, advertised: int, frozen: bool, *,
                       success: bool = True) -> None:
        self.kv.set(META_UPSTREAM, {
            "state": "frozen" if frozen else "healthy",
            "halt_reason": None, "last_error": None,
            "last_success_at": self.now(),
            "advertised_height": advertised,
            "trusted_height": advertised})

    @staticmethod
    def _safe_size(state: dict) -> int | None:
        cp = state.get("checkpoint") if isinstance(state, dict) else None
        if isinstance(cp, dict) and isinstance(cp.get("tree_size"), int):
            return cp["tree_size"]
        return None

    # ------------------------------------------------------------------ #
    # tenants
    # ------------------------------------------------------------------ #

    @staticmethod
    def _hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def new_tenant_token(tenant_id: str) -> str:
        return f"artok.{tenant_id}." + pysecrets.token_urlsafe(18)

    def create_tenant(self, tenant_id: str, *, name: str = "",
                      filter_doc: dict | None = None) -> dict:
        with self._lock:
            if not tenant_id or not all(
                    c.isalnum() or c in "-_" for c in tenant_id):
                raise E.InvalidBody("tenant_id must be alnum/-/_")
            existing = self.db.execute(
                "SELECT 1 FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
            if existing:
                raise E.InvalidBody(f"tenant {tenant_id} already exists")
            try:
                norm = normalize_filter(filter_doc or {})
            except ValueError as e:
                raise E.InvalidBody(str(e))
            token = self.new_tenant_token(tenant_id)
            self.db.execute(
                "INSERT INTO tenants(tenant_id, name, token_hash, filter_json, "
                "filter_version, cursor, active, created_at) "
                "VALUES(?,?,?,?,1,0,1,?)",
                (tenant_id, name or tenant_id, self._hash_token(token),
                 json.dumps(norm, sort_keys=True), self.now()))
            self._event(EV_TENANT, "tenant_created", tenant_id=tenant_id,
                        detail={"name": name or tenant_id})
            return {"tenant_id": tenant_id, "name": name or tenant_id,
                    "token": token, "filter": norm, "filter_version": 1,
                    "active": True}

    def _tenant_row(self, tenant_id: str) -> sqlite3.Row:
        row = self.db.execute(
            "SELECT * FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
        if row is None:
            raise E.NotFound(f"unknown tenant {tenant_id}")
        return row

    def authenticate(self, tenant_id: str, token: str) -> sqlite3.Row:
        """Resolve a bearer token to its tenant, rejecting cross-tenant use.

        A token embeds its owner (``artok.<owner>.<secret>``); presenting a
        tenant-B token against tenant A is a cross-tenant rejection distinct
        from a wholly invalid token.
        """
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != "artok":
            raise E.InvalidToken("malformed token")
        owner = parts[1]
        if owner != tenant_id:
            self._event(EV_REJECT, "cross_tenant_token", tenant_id=tenant_id,
                        detail={"token_owner": owner})
            raise E.CrossTenant(
                f"token belongs to tenant '{owner}', not '{tenant_id}'")
        row = self._tenant_row(tenant_id)
        if not pysecrets_equals(self._hash_token(token), row["token_hash"]):
            self._event(EV_REJECT, "invalid_token", tenant_id=tenant_id)
            raise E.InvalidToken("token does not match tenant")
        return row

    def set_filter(self, tenant_id: str, token: str, raw_filter: dict) -> dict:
        with self._lock:
            row = self.authenticate(tenant_id, token)
            if not row["active"]:
                self._reject("tenant_inactive", tenant_id, {"op": "set_filter"})
                raise E.TenantInactive("tenant is deactivated")
            open_row = self.db.execute(
                "SELECT delivery_id FROM deliveries WHERE tenant_id=? "
                "AND status=?", (tenant_id, OPEN)).fetchone()
            if open_row is not None:
                self._reject("filter_locked", tenant_id,
                             {"op": "set_filter",
                              "delivery_id": open_row["delivery_id"]})
                raise E.FilterLocked(
                    "filter is frozen while a delivery is outstanding; "
                    "ack or let the lease expire first")
            try:
                norm = normalize_filter(raw_filter)
            except ValueError as e:
                raise E.InvalidBody(str(e))
            new_version = row["filter_version"] + 1
            self.db.execute(
                "UPDATE tenants SET filter_json=?, filter_version=? "
                "WHERE tenant_id=?",
                (json.dumps(norm, sort_keys=True), new_version, tenant_id))
            self._event(EV_TENANT, "filter_updated", tenant_id=tenant_id,
                        detail={"filter_version": new_version})
            return {"tenant_id": tenant_id, "filter": norm,
                    "filter_version": new_version}

    def set_active(self, tenant_id: str, active: bool, *,
                   reason: str = "") -> dict:
        """Admin operation: deactivate/re-enable a tenant.

        Deactivation keeps its state and last position; it only blocks new
        leases.  An outstanding open lease is left in place and can still be
        acked (idempotently), but no further delivery is cut.
        """
        with self._lock:
            row = self._tenant_row(tenant_id)
            self.db.execute(
                "UPDATE tenants SET active=?, disabled_at=? WHERE tenant_id=?",
                (1 if active else 0, None if active else self.now(), tenant_id))
            self._event(EV_TENANT,
                        "tenant_enabled" if active else "tenant_disabled",
                        tenant_id=tenant_id, detail={"reason": reason})
            return {"tenant_id": tenant_id, "active": active}

    def _reject(self, kind: str, tenant_id: str, detail: dict) -> None:
        self._event(EV_REJECT, kind, tenant_id=tenant_id, detail=detail)

    def get_tenant(self, tenant_id: str, token: str) -> dict:
        with self._lock:
            row = self.authenticate(tenant_id, token)
            return self._tenant_view(row)

    def _tenant_view(self, row: sqlite3.Row) -> dict:
        height = self._height()
        fdoc = json.loads(row["filter_json"])
        backlog_total = max(0, height - row["cursor"])
        backlog_match = self._count_matching(row["cursor"], height, fdoc)
        open_row = self.db.execute(
            "SELECT * FROM deliveries WHERE tenant_id=? AND status=?",
            (row["tenant_id"], OPEN)).fetchone()
        lease = None
        if open_row is not None:
            lease = {
                "delivery_id": open_row["delivery_id"],
                "lease_holder": open_row["lease_holder"],
                "lease_expires_at": open_row["lease_expires_at"],
                "attempt": open_row["attempt"],
                "seq_start": open_row["seq_start"],
                "seq_end": open_row["seq_end"],
                "expired": self._lease_expired(open_row),
            }
        return {
            "tenant_id": row["tenant_id"], "name": row["name"],
            "active": bool(row["active"]),
            "filter_version": row["filter_version"], "filter": fdoc,
            "cursor": row["cursor"],
            "mirror_height": height,
            "backlog": backlog_total,
            "backlog_matching": backlog_match,
            "open_lease": lease,
        }

    def _count_matching(self, start: int, end: int, fdoc: dict) -> int:
        rows = self.db.execute(
            "SELECT envelope_json FROM leaves WHERE leaf_index >= ? "
            "AND leaf_index < ? ORDER BY leaf_index", (start, end)).fetchall()
        return sum(1 for r in rows
                   if filter_matches(fdoc, json.loads(r["envelope_json"])))

    def list_tenants(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM tenants ORDER BY tenant_id").fetchall()
            return [self._tenant_view(r) for r in rows]

    # ------------------------------------------------------------------ #
    # leases / delivery packages
    # ------------------------------------------------------------------ #

    def _lease_expired(self, row: sqlite3.Row) -> bool:
        exp = row["lease_expires_at"]
        return exp is not None and self.now() >= exp

    def acquire(self, tenant_id: str, token: str, *,
                consumer: str = "", max_items: int | None = None,
                lease_seconds: int | None = None) -> dict:
        with self._lock:
            row = self.authenticate(tenant_id, token)
            if not row["active"]:
                self._reject("tenant_inactive", tenant_id, {"op": "acquire"})
                raise E.TenantInactive("tenant is deactivated")

            height = self._height()
            open_row = self.db.execute(
                "SELECT * FROM deliveries WHERE tenant_id=? AND status=?",
                (tenant_id, OPEN)).fetchone()
            if open_row is not None and not self._lease_expired(open_row):
                holder = open_row["lease_holder"]
                if consumer and holder and consumer == holder:
                    # same live consumer re-fetches its lease: identical bytes
                    # and delivery_id, same attempt; a fresh token is handed
                    # back in case the caller lost it
                    return self._reissue_token(open_row, ttl=lease_seconds,
                                               replayed=True)
                self._reject("lease_held", tenant_id, {
                    "delivery_id": open_row["delivery_id"],
                    "lease_holder": holder,
                    "requester": consumer})
                raise E.LeaseHeld(
                    f"an active lease is held by '{holder}' until "
                    f"{open_row['lease_expires_at']}")

            if open_row is not None:
                # expired lease: re-grant the SAME package under the SAME
                # delivery_id and byte content; bump attempt and invalidate the
                # old lease token (a late ack with it is an old-lease reject)
                return self._regrant(open_row, consumer, lease_seconds)

            # cut a new contiguous interval starting at the tenant cursor
            cursor = row["cursor"]
            if cursor >= height:
                return {"delivered": False,
                        "reason": "caught_up",
                        "cursor": cursor, "mirror_height": height}

            fdoc = json.loads(row["filter_json"])
            window = min(int(max_items or DEFAULT_WINDOW), MAX_WINDOW)
            seq_start, seq_end, matched_idx = self._select_interval(
                cursor, height, fdoc, window)
            if matched_idx is None:
                # nothing matching before mirror height: caught up (unmatched
                # records ahead are NOT skipped -- the tenant will read them
                # when new matching records extend the interval)
                return {"delivered": False,
                        "reason": "no_matching_records",
                        "cursor": cursor, "mirror_height": height}

            package, payload, p_hash = self._build_package_payload(
                row, fdoc, seq_start, seq_end)
            ttl = int(lease_seconds or self.lease_seconds)
            expires = _iso_add(self.now(), ttl)
            lease_token = pysecrets.token_urlsafe(24)
            holder_label = consumer or ("consumer-" + lease_token[:8])
            ts = self.now()
            self.db.execute(
                "INSERT INTO deliveries(delivery_id, tenant_id, seq_start, "
                "seq_end, status, attempt, lease_holder, lease_token_hash, "
                "lease_expires_at, payload_blob, payload_sha256, sth_tree_size, "
                "filter_version, match_count, created_at, delivered_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (package["delivery_id"], tenant_id, seq_start, seq_end, OPEN,
                 1, holder_label, self._hash_token(lease_token), expires,
                 payload, p_hash, package["tree_head"]["tree_size"],
                 row["filter_version"], len(matched_idx), ts, ts))
            self._event(EV_DELIVERY, "delivery_granted", tenant_id=tenant_id,
                        detail={"delivery_id": package["delivery_id"],
                                "seq_start": seq_start, "seq_end": seq_end,
                                "match_count": len(matched_idx),
                                "lease_holder": holder_label})
            fresh = self.db.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?",
                (package["delivery_id"],)).fetchone()
            view = self._delivery_view(fresh)
            view["lease_token"] = lease_token
            view["lease_seconds"] = ttl
            return view

    def _select_interval(self, cursor: int, height: int, fdoc: dict,
                         window: int) -> tuple[int, int, list[int]]:
        """Pick [start, end] contiguous, ending at the last matched record.

        Scan forward from cursor; track matched indices.  Stop once ``window``
        matching records are collected or the mirror is exhausted.  The
        interval always ends ON a matching record (never beyond one), so every
        covered sequence is contiguous and no matching record is skipped.
        """
        rows = self.db.execute(
            "SELECT leaf_index, envelope_json FROM leaves "
            "WHERE leaf_index >= ? AND leaf_index < ? ORDER BY leaf_index",
            (cursor, height)).fetchall()
        matched: list[int] = []
        end = cursor - 1
        scanned = 0
        max_scan = max(window * 4, window + 32)
        for r in rows:
            scanned += 1
            if scanned > max_scan and matched:
                break
            env = json.loads(r["envelope_json"])
            if filter_matches(fdoc, env):
                matched.append(r["leaf_index"])
                end = r["leaf_index"]
                if len(matched) >= window:
                    break
        if not matched:
            return cursor, cursor - 1, None  # type: ignore[return-value]
        return cursor, end, matched

    def _build_package_payload(self, row: sqlite3.Row, fdoc: dict,
                               seq_start: int, seq_end: int
                               ) -> tuple[dict, bytes, str]:
        sth = self._last_sth()
        tree_size = sth["tree_size"]
        hashes = self._leaf_hashes_upto(tree_size)
        entries: list[dict] = []
        rows = self.db.execute(
            "SELECT * FROM leaves WHERE leaf_index >= ? AND leaf_index <= ? "
            "ORDER BY leaf_index", (seq_start, seq_end)).fetchall()
        present = {r["leaf_index"] for r in rows}
        for idx in range(seq_start, seq_end + 1):
            if idx not in present:  # defensive: mirror is dense, never a hole
                raise E.Internal(f"mirror gap inside [{seq_start},{seq_end}]")
        match_count = 0
        for r in rows:
            env = json.loads(r["envelope_json"])
            matched = filter_matches(fdoc, env)
            path = [h.hex() for h in inclusion_nodes(hashes, r["leaf_index"])]
            entries.append(package_entry_from_mirror(
                envelope=env if matched else None,
                leaf_index=r["leaf_index"],
                leaf_hash_hex=r["leaf_hash"],
                inclusion_path=path,
                matched=matched))
            match_count += 1 if matched else 0
        did = delivery_id_for(row["tenant_id"], seq_start, seq_end,
                              row["filter_version"])
        package = build_package(
            delivery_id=did, tenant_id=row["tenant_id"],
            seq_start=seq_start, seq_end=seq_end, entries=entries, sth=sth,
            filter_doc=fdoc, filter_version=row["filter_version"],
            created_at=self.now())
        payload = canonical_package_bytes(package)
        return package, payload, package_payload_hash(package)

    def _regrant(self, open_row: sqlite3.Row, consumer: str,
                 lease_seconds: int | None) -> dict:
        """Re-issue an expired package: same id/bytes, new attempt + token."""
        ttl = int(lease_seconds or self.lease_seconds)
        expires = _iso_add(self.now(), ttl)
        new_attempt = open_row["attempt"] + 1
        lease_token = pysecrets.token_urlsafe(24)
        holder = consumer or ("consumer-" + lease_token[:8])
        self.db.execute(
            "UPDATE deliveries SET attempt=?, lease_holder=?, "
            "lease_token_hash=?, lease_expires_at=? WHERE delivery_id=?",
            (new_attempt, holder, self._hash_token(lease_token), expires,
             open_row["delivery_id"]))
        self._event(EV_DELIVERY, "delivery_redelivered",
                    tenant_id=open_row["tenant_id"],
                    detail={"delivery_id": open_row["delivery_id"],
                            "attempt": new_attempt, "lease_holder": holder})
        fresh = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (open_row["delivery_id"],)).fetchone()
        view = self._delivery_view(fresh)
        view["lease_token"] = lease_token
        view["lease_seconds"] = ttl
        return view

    def _reissue_token(self, open_row: sqlite3.Row, *, ttl: int | None,
                       replayed: bool) -> dict:
        """Hand a still-valid lease back to its owner (bytes unchanged)."""
        lease_token = pysecrets.token_urlsafe(24)
        lease_ttl = int(ttl or self.lease_seconds)
        expires = _iso_add(self.now(), lease_ttl)
        self.db.execute(
            "UPDATE deliveries SET lease_token_hash=?, lease_expires_at=? "
            "WHERE delivery_id=?",
            (self._hash_token(lease_token), expires, open_row["delivery_id"]))
        fresh = self.db.execute(
            "SELECT * FROM deliveries WHERE delivery_id=?",
            (open_row["delivery_id"],)).fetchone()
        view = self._delivery_view(fresh, replayed=replayed)
        view["lease_token"] = lease_token
        view["lease_seconds"] = lease_ttl
        return view

    def _delivery_view(self, row: sqlite3.Row, *, replayed: bool = False) -> dict:
        package = json.loads(row["payload_blob"].decode("utf-8"))
        return {
            "delivered": True,
            "delivery_id": row["delivery_id"],
            "tenant_id": row["tenant_id"],
            "seq_start": row["seq_start"],
            "seq_end": row["seq_end"],
            "status": row["status"],
            "attempt": row["attempt"],
            "lease_holder": row["lease_holder"],
            "lease_expires_at": row["lease_expires_at"],
            "expired": self._lease_expired(row),
            "payload_sha256": row["payload_sha256"],
            "sth_tree_size": row["sth_tree_size"],
            "filter_version": row["filter_version"],
            "match_count": row["match_count"],
            "replayed": replayed,
            "package": package,
        }

    def fetch_delivery(self, tenant_id: str, token: str,
                       delivery_id: str) -> dict:
        with self._lock:
            self.authenticate(tenant_id, token)
            row = self.db.execute(
                "SELECT * FROM deliveries WHERE delivery_id=? AND tenant_id=?",
                (delivery_id, tenant_id)).fetchone()
            if row is None:
                raise E.NotFound(f"no delivery {delivery_id} for tenant")
            return self._delivery_view(row)

    def ack(self, tenant_id: str, token: str, delivery_id: str,
            ack_seq: int, *, lease_token: str = "",
            payload_sha256: str = "") -> dict:
        with self._lock:
            self.authenticate(tenant_id, token)
            row = self.db.execute(
                "SELECT * FROM deliveries WHERE delivery_id=? AND tenant_id=?",
                (delivery_id, tenant_id)).fetchone()
            if row is None:
                self._reject("ack_unknown_delivery", tenant_id,
                             {"delivery_id": delivery_id})
                raise E.NotFound(f"no delivery {delivery_id} for tenant")

            # duplicate ack of an already-confirmed package: idempotent, no move
            if row["status"] == ACKED:
                self._event(EV_DELIVERY, "ack_duplicate", tenant_id=tenant_id,
                            detail={"delivery_id": delivery_id,
                                    "cursor": self._tenant_row(tenant_id)["cursor"]})
                return {"acked": True, "idempotent": True,
                        "delivery_id": delivery_id,
                        "cursor": self._tenant_row(tenant_id)["cursor"],
                        "seq_end": row["seq_end"]}

            # open package: the caller must present the CURRENT lease token
            if self._lease_expired(row):
                self._reject("old_lease", tenant_id,
                             {"delivery_id": delivery_id,
                              "expired_at": row["lease_expires_at"]})
                raise E.OldLease("the lease for this delivery has expired; "
                                 "acquire the redelivered package")
            if not lease_token or not pysecrets_equals(
                    self._hash_token(lease_token),
                    row["lease_token_hash"] or ""):
                # wrong/stale lease credential: e.g. the loser of a lease race
                # acking with its superseded token, or a consumer guessing
                self._reject("old_lease", tenant_id,
                             {"delivery_id": delivery_id,
                              "reason": "not_current_holder"})
                raise E.OldLease("lease token is not the current one")

            if payload_sha256 and payload_sha256 != row["payload_sha256"]:
                self._reject("payload_mismatch", tenant_id,
                             {"delivery_id": delivery_id})
                raise E.PayloadMismatch(
                    "acknowledged payload hash differs from the served bytes")

            # ack only the current package's tail; jumping ahead is forbidden
            if ack_seq == row["seq_end"]:
                pass
            elif ack_seq < row["seq_end"]:
                self._reject("wrong_ack", tenant_id,
                             {"delivery_id": delivery_id,
                              "ack_seq": ack_seq,
                              "seq_end": row["seq_end"]})
                raise E.WrongAck(
                    f"ack seq {ack_seq} is before package end {row['seq_end']}")
            else:
                self._reject("skip_ack", tenant_id,
                             {"delivery_id": delivery_id,
                              "ack_seq": ack_seq,
                              "seq_end": row["seq_end"]})
                raise E.SkipAck(
                    f"ack seq {ack_seq} jumps past package end {row['seq_end']}")

            new_cursor = row["seq_end"] + 1
            self.db.execute("BEGIN IMMEDIATE")
            committed = False
            try:
                self.db.execute(
                    "UPDATE deliveries SET status=?, acked_at=? "
                    "WHERE delivery_id=?",
                    (ACKED, self.now(), delivery_id))
                self.db.execute(
                    "UPDATE tenants SET cursor=? WHERE tenant_id=? AND cursor<?",
                    (new_cursor, tenant_id, new_cursor))
                self.db.execute("COMMIT")
                committed = True
            except Exception:
                if not committed:
                    self.db.execute("ROLLBACK")
                raise
            self._event(EV_DELIVERY, "delivery_acked", tenant_id=tenant_id,
                        detail={"delivery_id": delivery_id,
                                "seq_end": row["seq_end"],
                                "new_cursor": new_cursor})
            return {"acked": True, "idempotent": False,
                    "delivery_id": delivery_id, "cursor": new_cursor,
                    "seq_end": row["seq_end"]}

    # ------------------------------------------------------------------ #
    # ops snapshot
    # ------------------------------------------------------------------ #

    def snapshot(self) -> dict:
        with self._lock:
            status = self.mirror_status()
            tenants = self.list_tenants()
            recent = self.list_events(limit=30)
            rejects = self.list_events(category=EV_REJECT, limit=30)
            return {"service": "audit-relay", "at": self.now(),
                    "mirror": status, "tenants": tenants,
                    "events": recent, "rejections": rejects}


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def pysecrets_equals(a: str, b: str) -> bool:
    import hmac as _hmac
    return _hmac.compare_digest(a or "", b or "")


def _iso_add(ts: str, seconds: int) -> str:
    from datetime import datetime, timedelta
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    return (dt + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
