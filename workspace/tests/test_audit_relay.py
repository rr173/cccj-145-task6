"""End-to-end behaviour tests for the auditing feed relay.

Covers the required scenarios: first sync, disconnect-and-resume, dual-consumer
lease contention, timeout redelivery, duplicate ack, wrong/skip ack, tenant
deactivation, cross-tenant tokens, frozen upstream and offline verification.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auditrelay import errors as E
from auditrelay.crypto import canonical_bytes
from auditrelay.fake_upstream import FakeUpstream
from auditrelay.offline_verify import PackageError, verify_package
from auditrelay.relay import ACKED, OPEN, Relay
from auditrelay.store import connect
from auditrelay.upstream import UpstreamClient

SECRET_HEX = "ab" * 32
SECRET = bytes.fromhex(SECRET_HEX)


class FakeClock:
    """Deterministic clock: fixed base time, advanced manually for leases."""

    def __init__(self):
        self.t = datetime(2026, 10, 1, 9, 0, 0)

    def iso(self) -> str:
        return self.t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def advance(self, seconds: float):
        self.t += timedelta(seconds=seconds)


class DirectClient(UpstreamClient):
    """In-process upstream client (no sockets) for deterministic tests."""

    def __init__(self, upstream: FakeUpstream):
        super().__init__("http://direct.invalid", "tok")
        self.upstream = upstream

    def state(self) -> dict:
        from auditrelay.fake_upstream import _UpstreamOffline
        from auditrelay.upstream import UpstreamUnavailable
        try:
            return self.upstream.state()
        except _UpstreamOffline as e:
            raise UpstreamUnavailable("offline") from e

    def inclusion(self, index: int) -> dict:
        from auditrelay.fake_upstream import (_UpstreamNotFound,
                                              _UpstreamOffline)
        try:
            return self.upstream.inclusion(index)
        except _UpstreamOffline as e:
            from auditrelay.upstream import UpstreamUnavailable
            raise UpstreamUnavailable("offline") from e
        except _UpstreamNotFound as e:
            from auditrelay.upstream import UpstreamGap
            raise UpstreamGap("missing leaf") from e


def make_relay(upstream: FakeUpstream, clock: FakeClock, *,
               lease_seconds: int = 30, path: str | None = None) -> Relay:
    conn = connect(path or ":memory:")
    relay = Relay(conn, DirectClient(upstream), SECRET,
                  lease_seconds=lease_seconds, clock=clock.iso)
    return relay


def only_types(*types: str) -> dict:
    return {"rules": [{"event_types": list(types)}], "match": "any"}


class RelayTestBase(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.up = FakeUpstream(SECRET)
        self.relay = make_relay(self.up, self.clock)

    def seed(self, n):
        ids = self.up.seed(n)
        return ids

    def sync(self):
        return self.relay.sync_once()


# --------------------------------------------------------------------------- #
# synchronisation / trust
# --------------------------------------------------------------------------- #

class TestSync(RelayTestBase):
    def test_first_sync_mirrors_dense_verified_leaves(self):
        self.seed(5)
        r = self.sync()
        self.assertTrue(r["advanced"])
        self.assertEqual((r["from"], r["to"]), (0, 5))
        st = self.relay.mirror_status()
        self.assertEqual(st["mirror_height"], 5)
        self.assertEqual(st["stored_leaves"], 5)
        self.assertEqual(st["upstream"]["state"], "healthy")

    def test_sync_is_idempotent_when_caught_up(self):
        self.seed(3)
        self.sync()
        r = self.sync()
        self.assertFalse(r["advanced"])
        self.assertEqual(r["to"], 3)

    def test_incremental_sync_extends(self):
        self.seed(2)
        self.sync()
        self.up.append("share_issued", "x", {"k": 1})
        r = self.sync()
        self.assertEqual((r["from"], r["to"]), (2, 3))
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 3)

    def test_unavailable_upstream_halts_and_keeps_position(self):
        self.seed(3)
        self.sync()
        self.up.set_mode("offline")
        r = self.sync()
        self.assertFalse(r["advanced"])
        self.assertEqual(r["halt_reason"], "upstream_unavailable")
        st = self.relay.mirror_status()
        self.assertEqual(st["mirror_height"], 3)
        self.assertEqual(st["upstream"]["state"], "halted")
        # recovery resumes from exactly the retained position
        self.up.set_mode("healthy")
        self.up.append("share_issued", "y", {})
        r = self.sync()
        self.assertTrue(r["advanced"])
        self.assertEqual((r["from"], r["to"]), (3, 4))

    def test_fallback_height_rejected_position_kept(self):
        self.seed(4)
        self.sync()
        self.up.set_mode("fallback")
        r = self.sync()
        self.assertEqual(r["halt_reason"], "fallback_height")
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 4)
        self.up.set_mode("healthy")
        self.up.append("share_issued", "z", {})
        r = self.sync()
        self.assertEqual((r["from"], r["to"]), (4, 5))

    def test_bad_signature_halts(self):
        self.seed(2)
        self.sync()
        self.up.set_mode("badsig")
        r = self.sync()
        self.assertEqual(r["halt_reason"], "bad_signature")
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 2)

    def test_interval_gap_halts_before_committing_batch(self):
        # trust 2 leaves, then make index 2 unreadable (a hole in the interval)
        self.seed(2)
        self.sync()
        self.up.append("share_issued", "new1", {})
        self.up.set_mode("gap", gap_index=2)
        r = self.sync()
        self.assertIn(r["halt_reason"],
                      ("interval_gap", "proof_invalid",
                       "leaf_hash_mismatch", "gap_or_stale"))
        # nothing from the faulty batch may be committed
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 2)

    def test_tampered_leaf_rejected(self):
        self.seed(2)
        self.sync()
        self.up.append("share_issued", "tamptarget", {})
        self.up.set_mode("badleaf", badleaf_index=2)
        r = self.sync()
        self.assertEqual(r["halt_reason"], "leaf_hash_mismatch")
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 2)

    def test_frozen_upstream_reads_only_to_last_head(self):
        self.seed(4)
        self.sync()
        self.up.set_mode("freeze")
        # upstream appends internally but a frozen log must not expose growth
        self.up.append("share_issued", "after-freeze", {})
        r = self.sync()
        self.assertTrue(r["frozen"])
        self.assertEqual(r["to"], 4)
        self.assertEqual(self.relay.mirror_status()["mirror_height"], 4)

    def test_relay_never_fabricates_records(self):
        # an empty upstream yields an empty mirror, not synthesised leaves
        r = self.sync()
        self.assertEqual(r["to"], 0)
        self.assertEqual(self.relay.mirror_status()["stored_leaves"], 0)


# --------------------------------------------------------------------------- #
# tenants / isolation / filters
# --------------------------------------------------------------------------- #

class TestTenants(RelayTestBase):
    def test_isolated_filters_and_positions(self):
        # types cycle release_sealed, release_voided, share_issued, share_revoked
        self.seed(8)
        self.sync()
        t1 = self.relay.create_tenant("auditor-a",
                                      filter_doc=only_types("share_issued"))
        t2 = self.relay.create_tenant("auditor-b",
                                      filter_doc=only_types("release_sealed"))
        d1 = self.relay.acquire("auditor-a", t1["token"], consumer="a1")
        d2 = self.relay.acquire("auditor-b", t2["token"], consumer="b1")
        # share_issued occurs at index 2,6; release_sealed at 0,4 -- different
        # contiguous intervals and independent payloads
        self.assertEqual(d1["seq_start"], 0)
        self.assertEqual(d1["package"]["entries"][2]["matched"], True)
        self.assertEqual(d2["package"]["entries"][0]["matched"], True)
        self.assertNotEqual(d1["payload_sha256"], d2["payload_sha256"])
        # unmatched entries are hash-only anchors (no content leak)
        self.assertNotIn("envelope", d1["package"]["entries"][0])

    def test_cross_tenant_token_rejected(self):
        t1 = self.relay.create_tenant("ta")
        self.relay.create_tenant("tb")
        with self.assertRaises(E.CrossTenant):
            self.relay.acquire("tb", t1["token"], consumer="x")

    def test_invalid_token_rejected(self):
        self.relay.create_tenant("ta")
        with self.assertRaises(E.InvalidToken):
            self.relay.acquire("ta", "artok.ta.garbage", consumer="x")
        with self.assertRaises(E.InvalidToken):
            self.relay.acquire("ta", "not-a-token", consumer="x")

    def test_deactivated_tenant_blocked_but_state_kept(self):
        self.seed(3)
        self.sync()
        t = self.relay.create_tenant("tdead")
        d = self.relay.acquire("tdead", t["token"], consumer="c")
        self.relay.set_active("tdead", False, reason="offboarding")
        with self.assertRaises(E.TenantInactive):
            self.relay.acquire("tdead", t["token"], consumer="c")
        # the outstanding package can still be acked; cursor preserved
        ack = self.relay.ack("tdead", t["token"], d["delivery_id"],
                            d["seq_end"], lease_token=d["lease_token"])
        self.assertTrue(ack["acked"])
        self.relay.set_active("tdead", True)
        view = self.relay.get_tenant("tdead", t["token"])
        self.assertEqual(view["cursor"], d["seq_end"] + 1)

    def test_filter_change_refused_with_open_lease(self):
        self.seed(2)
        self.sync()
        t = self.relay.create_tenant("tf")
        self.relay.acquire("tf", t["token"], consumer="c")
        with self.assertRaises(E.FilterLocked):
            self.relay.set_filter("tf", t["token"], only_types("share_issued"))

    def test_filter_change_allowed_after_ack_and_versions(self):
        self.seed(2)
        self.sync()
        t = self.relay.create_tenant("tf")
        d = self.relay.acquire("tf", t["token"], consumer="c")
        self.relay.ack("tf", t["token"], d["delivery_id"], d["seq_end"],
                       lease_token=d["lease_token"])
        res = self.relay.set_filter("tf", t["token"],
                                    only_types("share_issued"))
        self.assertEqual(res["filter_version"], 2)


# --------------------------------------------------------------------------- #
# leases / delivery semantics
# --------------------------------------------------------------------------- #

class TestLeases(RelayTestBase):
    def _tenant(self, tid="t1", flt=None):
        return self.relay.create_tenant(tid, filter_doc=flt or {})

    def test_contiguous_by_original_sequence_and_no_skip(self):
        self.seed(6)
        self.sync()
        t = self._tenant(flt=only_types("share_issued"))  # matches index 2 only
        d = self.relay.acquire("t1", t["token"], consumer="c", max_items=1)
        # interval must start at cursor 0 and end ON the matched leaf (2),
        # covering 0,1,2 contiguously -- it cannot jump straight to index 2
        self.assertEqual((d["seq_start"], d["seq_end"]), (0, 2))
        seqs = [e["seq"] for e in d["package"]["entries"]]
        self.assertEqual(seqs, [0, 1, 2])
        self.relay.ack("t1", t["token"], d["delivery_id"], 2,
                       lease_token=d["lease_token"])
        d2 = self.relay.acquire("t1", t["token"], consumer="c", max_items=1)
        # next matched leaf is index 6; with only up to height 6 mirrored,
        # interval [3..6) leaves 6 excluded here -> caught up at this height
        # (no fabrication, no skip). Append more and it resumes at 3.
        self.up.append("share_issued", "subj-0006", {"seq": 6})
        self.up.append("share_revoked", "subj-0007", {"seq": 7})
        self.sync()
        d2 = self.relay.acquire("t1", t["token"], consumer="c", max_items=1)
        self.assertEqual((d2["seq_start"], d2["seq_end"]), (3, 6))

    def test_dual_consumers_second_gets_lease_held(self):
        self.seed(3)
        self.sync()
        t = self._tenant()
        d = self.relay.acquire("t1", t["token"], consumer="consumer-A")
        with self.assertRaises(E.LeaseHeld):
            self.relay.acquire("t1", t["token"], consumer="consumer-B")
        # the winner still sees its own package
        same = self.relay.fetch_delivery("t1", t["token"], d["delivery_id"])
        self.assertEqual(same["payload_sha256"], d["payload_sha256"])

    def test_same_consumer_refetch_returns_identical_bytes(self):
        self.seed(3)
        self.sync()
        t = self._tenant()
        d1 = self.relay.acquire("t1", t["token"], consumer="A")
        d2 = self.relay.acquire("t1", t["token"], consumer="A")
        self.assertEqual(d1["delivery_id"], d2["delivery_id"])
        self.assertEqual(canonical_bytes(d1["package"]),
                         canonical_bytes(d2["package"]))
        self.assertEqual(d1["payload_sha256"], d2["payload_sha256"])

    def test_timeout_redelivers_same_id_and_bytes_with_new_attempt(self):
        self.seed(3)
        self.sync()
        t = self._tenant()
        d1 = self.relay.acquire("t1", t["token"], consumer="A")
        old_token = d1["lease_token"]
        self.clock.advance(31)  # default lease 30s -> expired
        d2 = self.relay.acquire("t1", t["token"], consumer="B")
        self.assertEqual(d1["delivery_id"], d2["delivery_id"])
        self.assertEqual(canonical_bytes(d1["package"]),
                         canonical_bytes(d2["package"]))
        self.assertEqual(d2["attempt"], 2)
        # the loser's old token can no longer ack
        with self.assertRaises(E.OldLease):
            self.relay.ack("t1", t["token"], d1["delivery_id"], d1["seq_end"],
                           lease_token=old_token)
        # the new holder acks successfully
        ok = self.relay.ack("t1", t["token"], d2["delivery_id"], d2["seq_end"],
                            lease_token=d2["lease_token"])
        self.assertTrue(ok["acked"])

    def test_ack_accepts_only_current_package_end(self):
        self.seed(5)
        self.sync()
        t = self._tenant()
        d = self.relay.acquire("t1", t["token"], consumer="A", max_items=3)
        end = d["seq_end"]
        # acking a mid/earlier seq is a wrong (partial) ack, cursor unmoved
        with self.assertRaises(E.WrongAck):
            self.relay.ack("t1", t["token"], d["delivery_id"], end - 1,
                           lease_token=d["lease_token"])
        # acking past the end is a skip ack, cursor unmoved
        with self.assertRaises(E.SkipAck):
            self.relay.ack("t1", t["token"], d["delivery_id"], end + 1,
                           lease_token=d["lease_token"])
        view = self.relay.get_tenant("t1", t["token"])
        self.assertEqual(view["cursor"], 0)
        # exact tail ack advances
        ok = self.relay.ack("t1", t["token"], d["delivery_id"], end,
                            lease_token=d["lease_token"])
        self.assertEqual(ok["cursor"], end + 1)

    def test_duplicate_ack_is_idempotent(self):
        self.seed(3)
        self.sync()
        t = self._tenant()
        d = self.relay.acquire("t1", t["token"], consumer="A")
        a1 = self.relay.ack("t1", t["token"], d["delivery_id"], d["seq_end"],
                            lease_token=d["lease_token"])
        a2 = self.relay.ack("t1", t["token"], d["delivery_id"], d["seq_end"],
                            lease_token=d["lease_token"])
        self.assertTrue(a2["idempotent"])
        self.assertEqual(a1["cursor"], a2["cursor"])

    def test_wrong_payload_hash_rejected(self):
        self.seed(2)
        self.sync()
        t = self._tenant()
        d = self.relay.acquire("t1", t["token"], consumer="A")
        with self.assertRaises(E.PayloadMismatch):
            self.relay.ack("t1", t["token"], d["delivery_id"], d["seq_end"],
                           lease_token=d["lease_token"],
                           payload_sha256="0" * 64)

    def test_slow_tenant_does_not_block_other_tenant(self):
        self.seed(4)
        self.sync()
        ta = self.relay.create_tenant("slow")
        tb = self.relay.create_tenant("fast")
        # slow holds an open lease and never acks
        self.relay.acquire("slow", ta["token"], consumer="sloth")
        # fast keeps consuming to completion independently
        cursor = 0
        while True:
            d = self.relay.acquire("fast", tb["token"], consumer="hare",
                                   max_items=2)
            if not d.get("delivered"):
                break
            self.relay.ack("fast", tb["token"], d["delivery_id"],
                           d["seq_end"], lease_token=d["lease_token"])
            cursor = d["seq_end"] + 1
        self.assertEqual(cursor, 4)
        slow = self.relay.get_tenant("slow", ta["token"])
        self.assertEqual(slow["cursor"], 0)
        self.assertIsNotNone(slow["open_lease"])

    def test_restart_reopens_same_delivery_id_and_bytes(self):
        self.seed(3)
        self.sync()
        path = tempfile.mktemp(suffix=".sqlite")
        try:
            clock = FakeClock()
            up = self.up
            r1 = make_relay(up, clock, lease_seconds=30, path=path)
            r1.sync_once()  # fresh process mirrors the upstream first
            t = r1.create_tenant("persist")
            d = r1.acquire("persist", t["token"], consumer="A")
            token = t["token"]
            did = d["delivery_id"]
            digest = d["payload_sha256"]
            blob = canonical_bytes(d["package"])
            # simulate process restart: a brand new Relay over the same DB
            clock.advance(5)  # not expired yet
            r2 = make_relay(up, clock, lease_seconds=30, path=path)
            row = r2.db.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (did,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], OPEN)
            self.assertEqual(row["payload_blob"], blob)
            self.assertEqual(row["payload_sha256"], digest)
            # the surviving lease can be fetched and acked after restart
            got = r2.fetch_delivery("persist", token, did)
            self.assertEqual(got["payload_sha256"], digest)
            ok = r2.ack("persist", token, did, row["seq_end"],
                        lease_token=d["lease_token"])
            self.assertTrue(ok["acked"])
        finally:
            if os.path.exists(path):
                os.remove(path)


# --------------------------------------------------------------------------- #
# offline verification
# --------------------------------------------------------------------------- #

class TestOfflineVerify(RelayTestBase):
    def test_valid_package_verifies_offline(self):
        self.seed(4)
        self.sync()
        t = self.relay.create_tenant("aud", filter_doc=only_types("share_issued"))
        d = self.relay.acquire("aud", t["token"], consumer="c")
        report = verify_package(d["package"], SECRET,
                                expected_tenant="aud",
                                expected_sha256=d["payload_sha256"])
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["matched_seqs"], [2])
        self.assertEqual(report["tree_size"], 4)

    def test_tampered_package_fails_verification(self):
        self.seed(4)
        self.sync()
        t = self.relay.create_tenant("aud")
        d = self.relay.acquire("aud", t["token"], consumer="c")
        pkg = json.loads(json.dumps(d["package"]))
        pkg["entries"][0]["envelope"]["payload"]["evil"] = True
        with self.assertRaises(PackageError):
            verify_package(pkg, SECRET)

    def test_package_with_wrong_secret_fails(self):
        self.seed(2)
        self.sync()
        t = self.relay.create_tenant("aud")
        d = self.relay.acquire("aud", t["token"], consumer="c")
        with self.assertRaises(PackageError):
            verify_package(d["package"], bytes.fromhex("cd" * 32))


if __name__ == "__main__":
    unittest.main(verbosity=2)
