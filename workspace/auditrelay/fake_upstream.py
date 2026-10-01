"""Demo fault-injecting upstream that speaks the gateway read-only protocol.

For the end-to-end demonstration this small service stands in for (or proxies)
the existing gateway's transparency read surface.  Internally it maintains a
dpgw-compatible append-only Merkle log:

    leaf hash  = SHA256(0x00 || canonical(envelope))
    tree head  = HMAC-SHA256(secret, canonical(checkpoint - sig))

It exposes exactly the two read-only endpoints the relay uses:

    GET /v1/transparency
    GET /v1/transparency/inclusion/<index>

plus a control API used by the demo/CLI to append events and inject faults:

    POST /control/append          {"event_type","subject_id","payload"}
    POST /control/mode            {"mode": "healthy|offline|freeze|gap|badsig|badleaf|fallback"}
    GET  /control/status
    POST /control/healthy

Modes
-----
healthy   : serve the true signed head and every leaf (default)
offline   : answer 503 on every read endpoint (upstream unavailable)
freeze    : the upstream log is frozen; serve only the head AT FREEZE time --
            no growth is visible (relay may read only up to the frozen head)
gap       : omit one leaf (skip an index in responses -> interval gap)
badsig    : serve a head document whose signature is invalid
badleaf   : serve one leaf record with a tampered envelope
fallback  : advertise a signed head at an older (smaller) height
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .crypto import (
    canonical_bytes, checkpoint_signing_body, envelope_hash, hmac_sign,
    inclusion_nodes, leaf_hash_bytes, merkle_root,
)
from .store import now_iso

CHECKPOINT_VERSION = "tc1"
LEAF_EVENTS = ("release_sealed", "release_voided", "share_issued",
               "share_revoked")


class FakeUpstream:
    """In-memory dpgw-compatible transparency log with fault switches."""

    def __init__(self, secret: bytes, *, upstream_id: str = "demo-gateway"):
        self.secret = secret
        self.upstream_id = upstream_id
        self._lock = threading.RLock()
        # dense leaves: list of envelopes; hashes derived
        self.envelopes: list[dict] = []
        self.frozen = False
        self.frozen_size: int | None = None
        self.mode = "healthy"
        # fault tuning (index at which the fault first shows)
        self.gap_index = 0
        self.badleaf_index = 0

    # ------------------------------------------------------------------ #

    def _leaf_hash(self, envelope: dict) -> bytes:
        return envelope_hash(envelope)

    def _hashes(self) -> list[bytes]:
        return [self._leaf_hash(e) for e in self.envelopes]

    def _sign(self, tree_size: int, root: bytes,
              prev_size: int | None, prev_root: bytes | None) -> dict:
        body = {
            "checkpoint_version": CHECKPOINT_VERSION,
            "tree_size": tree_size,
            "root_hash": root.hex(),
            "prev_size": prev_size,
            "prev_root_hash": prev_root.hex() if prev_root is not None else None,
            "issued_at": now_iso(),
        }
        body["sig"] = hmac_sign(self.secret, checkpoint_signing_body(body))
        return body

    def _head_doc(self, size: int) -> dict:
        hashes = self._hashes()[:size]
        root = merkle_root(hashes)
        if size == 0:
            return self._sign(0, root, None, None)
        prev_root = merkle_root(hashes[:size - 1])
        return self._sign(size, root, size - 1, prev_root)

    def _true_size(self) -> int:
        return len(self.envelopes)

    # ------------------------------------------------------------------ #
    # control
    # ------------------------------------------------------------------ #

    def append(self, event_type: str, subject_id: str, payload: dict,
               *, created_at: str | None = None) -> dict:
        with self._lock:
            if self.frozen:
                return {"appended": False, "frozen": True}
            idx = len(self.envelopes)
            envelope = {
                "leaf_version": "tl1",
                "event_type": event_type,
                "event_key": f"{event_type}:{subject_id}",
                "subject_id": subject_id,
                "created_at": created_at or now_iso(),
                "payload": payload,
            }
            self.envelopes.append(envelope)
            return {"appended": True, "leaf_index": idx,
                    "leaf_hash": self._leaf_hash(envelope).hex(),
                    "tree_size": len(self.envelopes)}

    def seed(self, n: int) -> list[int]:
        types = LEAF_EVENTS
        out = []
        for i in range(n):
            et = types[i % len(types)]
            r = self.append(et, f"subj-{i:04d}",
                            {"seq": i, "city": ("BJ", "SH", "SZ")[i % 3],
                             "amount": 100 + i})
            if r.get("appended"):
                out.append(r["leaf_index"])
        return out

    def set_mode(self, mode: str, *, gap_index: int | None = None,
                 badleaf_index: int | None = None) -> dict:
        with self._lock:
            if mode not in ("healthy", "offline", "freeze", "gap", "badsig",
                            "badleaf", "fallback"):
                raise ValueError(f"unknown mode {mode}")
            self.mode = mode
            if gap_index is not None:
                self.gap_index = gap_index
            if badleaf_index is not None:
                self.badleaf_index = badleaf_index
            if mode == "freeze":
                self.frozen = True
                self.frozen_size = self._true_size()
            elif mode == "healthy":
                self.frozen = False
                self.frozen_size = None
            return self.status()

    def status(self) -> dict:
        with self._lock:
            return {
                "mode": self.mode, "true_size": self._true_size(),
                "frozen": self.frozen,
                "frozen_size": self.frozen_size,
                "gap_index": self.gap_index,
                "badleaf_index": self.badleaf_index,
                "upstream_id": self.upstream_id,
            }

    # ------------------------------------------------------------------ #
    # read-only transparency surface (dpgw shaped)
    # ------------------------------------------------------------------ #

    def state(self) -> dict:
        """Return the dpgw ``tl_state`` body (with injected faults)."""
        with self._lock:
            if self.mode == "offline":
                raise _UpstreamOffline()
            if self.mode == "freeze":
                size = self.frozen_size if self.frozen_size is not None \
                    else self._true_size()
                cp = self._head_doc(size)
                return {"tree_size": size,
                        "root_hash": cp["root_hash"],
                        "frozen": True,
                        "freeze_reason": "demo_freeze",
                        "frozen_tree_size": size,
                        "pending_outbox": 0,
                        "checkpoint": cp}
            if self.mode == "fallback":
                # sign a head at an older height: relay must reject the rollback
                true = self._true_size()
                size = max(0, true - 1)
                cp = self._head_doc(size)
                return {"tree_size": size, "root_hash": cp["root_hash"],
                        "frozen": False, "pending_outbox": 0,
                        "checkpoint": cp}
            # healthy / gap / badsig / badleaf advertise the true head size
            true = self._true_size()
            cp = self._head_doc(true)
            if self.mode == "badsig":
                cp = dict(cp)
                cp["sig"] = "deadbeef" * 8
            return {"tree_size": true, "root_hash": cp["root_hash"],
                    "frozen": False, "pending_outbox": 0, "checkpoint": cp}

    def inclusion(self, index: int) -> dict:
        with self._lock:
            if self.mode == "offline":
                raise _UpstreamOffline()
            true = self._true_size()
            if self.mode == "freeze":
                true = self.frozen_size if self.frozen_size is not None else true

            if self.mode == "gap" and index >= self.gap_index:
                # emulate a hole in the upstream interval: this index and
                # everything after it is currently unreadable.  The relay must
                # halt with an interval_gap and keep its last trusted height.
                raise _UpstreamNotFound(f"gap at index {index}")
            served_idx = index
            if not (0 <= index < true):
                raise _UpstreamNotFound(f"leaf {index}")

            envelope = json.loads(json.dumps(self.envelopes[served_idx]))
            hashes = self._hashes()[:true]
            tampered = False
            if self.mode == "badleaf" and index == self.badleaf_index:
                envelope["payload"] = dict(envelope.get("payload", {}))
                envelope["payload"]["tampered"] = True
                tampered = True
            lh_hex = envelope_hash(envelope).hex()
            if tampered:
                # lie about the leaf_hash so it matches the ORIGINAL leaf: the
                # hash-vs-envelope check (not just the proof) must catch it
                lh_hex = self._leaf_hash(
                    self.envelopes[index]).hex()
            # proof is computed against the true dense hashes; the served
            # (possibly shifted/tampered) leaf will not fold correctly
            proof = [h.hex() for h in inclusion_nodes(hashes, index)]
            cp = self._head_doc(true)
            return {
                "leaf_index": index,
                "tree_size": true,
                "root_hash": cp["root_hash"],
                "leaf_hash": lh_hex,
                "event_key": envelope["event_key"],
                "event_type": envelope["event_type"],
                "envelope": envelope,
                "inclusion_path": proof,
                "checkpoint": cp,
            }


class _UpstreamOffline(Exception):
    pass


class _UpstreamNotFound(Exception):
    pass


# --------------------------------------------------------------------------- #
# HTTP wrapper
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    server_version = "demo-upstream/1.0"

    def log_message(self, fmt, *args):  # noqa: N802
        return

    @property
    def up(self) -> FakeUpstream:
        return self.server.up

    @property
    def control_token(self) -> str:
        return self.server.control_token

    def _send(self, status: int, body: Any = None, *,
              content_type: str = "application/json"):
        if isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
        else:
            payload = json.dumps(body, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _control_auth(self) -> bool:
        h = self.headers.get("Authorization", "")
        return h == "Bearer " + self.control_token

    def do_GET(self):  # noqa: N802
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        try:
            if path == "/healthz":
                return self._send(200, {"ok": True, "service": "demo-upstream"})
            if path == "/v1/transparency":
                return self._read(lambda: self.up.state())
            if path.startswith("/v1/transparency/inclusion/"):
                idx = int(path.rsplit("/", 1)[-1])
                return self._read(lambda: self.up.inclusion(idx))
            if path == "/control/status":
                if not self._control_auth():
                    return self._send(401, {"error": "unauthorized"})
                return self._send(200, self.up.status())
            self._send(404, {"error": "not_found"})
        except _UpstreamOffline:
            self._send(503, {"error": "upstream_offline",
                            "message": "upstream is in injected offline mode"})
        except _UpstreamNotFound:
            self._send(404, {"error": "not_found"})
        except Exception as e:  # pragma: no cover
            self._send(500, {"error": "internal_error", "message": str(e)})

    def _read(self, fn):
        try:
            return self._send(200, fn())
        except _UpstreamOffline:
            self._send(503, {"error": "upstream_offline"})
        except _UpstreamNotFound:
            self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        if not self._control_auth():
            return self._send(401, {"error": "unauthorized",
                                    "message": "control token required"})
        try:
            body = self._json()
            if path == "/control/append":
                resp = self.up.append(
                    body.get("event_type", "release_sealed"),
                    body.get("subject_id", "subject"),
                    body.get("payload", {}),
                    created_at=body.get("created_at"))
                return self._send(200, resp)
            if path == "/control/seed":
                ids = self.up.seed(int(body.get("n", 1)))
                return self._send(200, {"seeded": ids, "size": len(ids)})
            if path == "/control/mode":
                resp = self.up.set_mode(
                    body.get("mode", "healthy"),
                    gap_index=body.get("gap_index"),
                    badleaf_index=body.get("badleaf_index"))
                return self._send(200, resp)
            if path == "/control/healthy":
                return self._send(200, self.up.set_mode("healthy"))
            self._send(404, {"error": "not_found"})
        except ValueError as e:
            self._send(400, {"error": "invalid_body", "message": str(e)})
        except Exception as e:  # pragma: no cover
            self._send(500, {"error": "internal_error", "message": str(e)})


def serve(upstream: FakeUpstream, *, host: str = "127.0.0.1", port: int = 0,
          control_token: str = "control") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _Handler)
    server.up = upstream
    server.control_token = control_token
    server.daemon_threads = True
    return server
