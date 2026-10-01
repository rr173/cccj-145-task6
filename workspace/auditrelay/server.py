"""HTTP API for the relay + embedded ops page.

Tenant surface (per-tenant bearer token)::

    GET  /v1/relay/<tid>/status
    POST /v1/relay/<tid>/filter
    POST /v1/relay/<tid>/deliveries           (acquire; {consumer,max_items,lease_seconds})
    GET  /v1/relay/<tid>/deliveries/<dlv>     (re-fetch same bytes)
    POST /v1/relay/<tid>/deliveries/<dlv>/ack ({ack_seq, lease_token, payload_sha256})

Admin surface (admin bearer token)::

    GET  /v1/admin/status
    POST /v1/admin/sync
    POST /v1/admin/tenants                    {tenant_id,name,filter}
    GET  /v1/admin/tenants
    POST /v1/admin/tenants/<tid>/active       {active, reason}
    GET  /v1/admin/events
    POST /v1/admin/export-package/<dlv>       (write-free package read, tenant scoped body)
"""

from __future__ import annotations

import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from . import errors as E
from .webui import UI_ASSETS


class _Handler(BaseHTTPRequestHandler):
    server_version = "auditrelay/1.0"

    def log_message(self, fmt, *args):  # noqa: N802
        return

    @property
    def relay(self):
        return self.server.relay

    @property
    def admin_token(self) -> str:
        return self.server.admin_token

    # ------------------------------------------------------------------ #

    def _send(self, status: int, body: Any = None, *,
              content_type: str = "application/json", raw: bytes | None = None):
        if raw is not None:
            payload = raw
        elif isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
        else:
            payload = json.dumps(body, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise E.InvalidBody("invalid JSON body")
        if not isinstance(data, dict):
            raise E.InvalidBody("JSON body must be an object")
        return data

    def _bearer(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            raise E.Unauthorized("missing bearer token")
        return h[len("Bearer "):].strip()

    def _tenant_token(self) -> str:
        return self._bearer()

    def _admin(self) -> None:
        import hmac as _hmac
        if not _hmac.compare_digest(self._bearer(), self.admin_token):
            raise E.Unauthorized("admin token required")

    def _query(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    # ------------------------------------------------------------------ #

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def _dispatch(self, method: str):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/healthz" and method == "GET":
                return self._send(200, {"ok": True, "service": "audit-relay"})
            if path == "/" or path.startswith("/ops"):
                return self._serve_ui(path)
            routes = self.server.routes.get(method, {})
            for pattern, handler in routes.items():
                m = pattern.match(path)
                if m:
                    return handler(self, **m.groupdict())
            self._send(404, {"error": "not_found", "message": f"{method} {path}"})
        except E.RelayError as e:
            self._send(e.status, e.to_dict())
        except Exception:  # never leak internals
            self._send(500, {"error": "internal_error",
                             "message": "internal error"})

    def _serve_ui(self, path: str):
        rel = "index.html" if path in ("/", "/ops", "/ops/") else path[len("/ops/"):]
        asset = UI_ASSETS.get(rel)
        if asset is None:
            return self._send(404, {"error": "not_found", "message": rel})
        ctype = "text/html" if rel.endswith(".html") else "application/javascript"
        self._send(200, raw=asset.encode("utf-8"), content_type=ctype)

    # ------------------------------------------------------------------ #
    # tenant endpoints
    # ------------------------------------------------------------------ #

    def ep_status(self, tid: str):
        self._send(200, self.relay.get_tenant(tid, self._tenant_token()))

    def ep_filter(self, tid: str):
        body = self._read_json()
        self._send(200, self.relay.set_filter(tid, self._tenant_token(),
                                              body.get("filter", body)))

    def ep_acquire(self, tid: str):
        body = self._read_json()
        resp = self.relay.acquire(
            tid, self._tenant_token(),
            consumer=str(body.get("consumer", "")),
            max_items=body.get("max_items"),
            lease_seconds=body.get("lease_seconds"))
        self._send(200, resp)

    def ep_fetch(self, tid: str, dlv: str):
        self._send(200, self.relay.fetch_delivery(tid, self._tenant_token(), dlv))

    def ep_ack(self, tid: str, dlv: str):
        body = self._read_json()
        if "ack_seq" not in body:
            raise E.InvalidBody("ack_seq is required")
        resp = self.relay.ack(
            tid, self._tenant_token(), dlv, int(body["ack_seq"]),
            lease_token=str(body.get("lease_token", "")),
            payload_sha256=str(body.get("payload_sha256", "")))
        self._send(200, resp)

    # ------------------------------------------------------------------ #
    # admin endpoints
    # ------------------------------------------------------------------ #

    def ep_admin_status(self):
        self._admin()
        self._send(200, self.relay.snapshot())

    def ep_admin_sync(self):
        self._admin()
        self._send(200, self.relay.sync_once())

    def ep_admin_tenants_create(self):
        self._admin()
        body = self._read_json()
        self._send(201, self.relay.create_tenant(
            str(body.get("tenant_id", "")), name=str(body.get("name", "")),
            filter_doc=body.get("filter") or {}))

    def ep_admin_tenants_list(self):
        self._admin()
        self._send(200, {"tenants": self.relay.list_tenants()})

    def ep_admin_tenant_active(self, tid: str):
        self._admin()
        body = self._read_json()
        self._send(200, self.relay.set_active(
            tid, bool(body.get("active", True)),
            reason=str(body.get("reason", ""))))

    def ep_admin_events(self):
        self._admin()
        p = self._query()
        cat = p.get("category")
        tid = p.get("tenant_id")
        self._send(200, {"events": self.relay.list_events(
            category=cat, tenant_id=tid, limit=int(p.get("limit", "100")))})


def _build_routes() -> dict:
    import re

    def rx(path: str) -> re.Pattern:
        return re.compile("^" + re.sub(r"<(\w+)>", r"(?P<\1>[^/]+)", path) + "$")

    get = [
        ("/v1/relay/<tid>/status", _Handler.ep_status),
        ("/v1/relay/<tid>/deliveries/<dlv>", _Handler.ep_fetch),
        ("/v1/admin/status", _Handler.ep_admin_status),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_list),
        ("/v1/admin/events", _Handler.ep_admin_events),
    ]
    post = [
        ("/v1/relay/<tid>/filter", _Handler.ep_filter),
        ("/v1/relay/<tid>/deliveries", _Handler.ep_acquire),
        ("/v1/relay/<tid>/deliveries/<dlv>/ack", _Handler.ep_ack),
        ("/v1/admin/sync", _Handler.ep_admin_sync),
        ("/v1/admin/tenants", _Handler.ep_admin_tenants_create),
        ("/v1/admin/tenants/<tid>/active", _Handler.ep_admin_tenant_active),
    ]
    return {"GET": {rx(p): h for p, h in get},
            "POST": {rx(p): h for p, h in post}}


def serve(relay, admin_token: str, *, host: str = "127.0.0.1",
          port: int = 8090) -> ThreadingHTTPServer:
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((host, port), _Handler)
    server.relay = relay
    server.admin_token = admin_token
    server.routes = _build_routes()
    server.daemon_threads = True
    return server
