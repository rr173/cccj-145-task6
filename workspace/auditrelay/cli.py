"""Command-line interface for the auditing feed relay.

Examples
--------
Initialise (point at an existing gateway's read-only transparency API)::

    python -m auditrelay init ./relay-home \\
        --upstream-url http://127.0.0.1:8080 \\
        --upstream-token <gateway-read-token> \\
        --upstream-secret <hex transparency secret from secrets.json>

Serve with an embedded, fault-injecting demo upstream (no gateway needed)::

    python -m auditrelay serve ./relay-home --demo --demo-seed 8

Drive the demo upstream / tenants and verify packages offline::

    python -m auditrelay demo ./relay-home mode offline
    python -m auditrelay demo ./relay-home append --type share_issued --subj s1
    python -m auditrelay tenant ./relay-home t1 acquire --consumer c1
    python -m auditrelay verify ./package.json --home ./relay-home
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from typing import Any

from . import app as appmod
from .offline_verify import PackageError, verify_file


def _print(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))


def _read_filter_arg(args: argparse.Namespace) -> dict:
    if args.filter_file:
        with open(args.filter_file, "r", encoding="utf-8") as fh:
            return json.load(fh)
    if args.filter_json:
        return json.loads(args.filter_json)
    return {}


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_init(args) -> int:
    secret = args.upstream_secret
    if secret is None:
        raise SystemExit("--upstream-secret (hex) is required")
    try:
        bytes.fromhex(secret)
    except ValueError:
        raise SystemExit("--upstream-secret must be hex")
    res = appmod.bootstrap(
        args.home, upstream_url=args.upstream_url,
        upstream_token=args.upstream_token, upstream_secret_hex=secret,
        lease_seconds=args.lease, sync_interval=args.sync_interval,
        force=args.force)
    out = dict(res)
    out["note"] = ("save the admin_token now; the relay home is independent "
                   "of the gateway")
    _print(out)
    return 0


def cmd_serve(args) -> int:
    from .server import serve as http_serve
    from .syncer import Syncer

    demo = None
    demo_info = None
    if args.demo:
        demo, demo_info = _start_demo(args)
        # point a fresh config at the embedded demo upstream
        cfg = appmod.load_config(args.home)
        cfg["upstream_url"] = demo_info["url"]
        cfg["upstream_token"] = "demo-read-token"
        cfg["upstream_secret"] = demo_info["secret_hex"]
        appmod.write_config(args.home, cfg)
        with open(_demo_path(args.home), "w", encoding="utf-8") as fh:
            json.dump(demo_info, fh, indent=2, sort_keys=True)

    relay = appmod.open_relay(args.home)
    cfg = appmod.load_config(args.home)
    interval = float(cfg.get("sync_interval", appmod.DEFAULT_SYNC_INTERVAL))
    syncer = Syncer(relay, interval)
    syncer.start()

    server = http_serve(relay, cfg["admin_token"], host=args.host, port=args.port)
    actual = server.server_address[1]
    print(f"audit-relay serving on http://{args.host}:{actual}", file=sys.stderr)
    print(f"ops dashboard: http://{args.host}:{actual}/ops", file=sys.stderr)
    if demo is not None:
        print(f"demo upstream: {demo_info['url']} "
              f"(control token {demo_info['control_token']})", file=sys.stderr)

    import signal

    def _stop(_signum, _frame):
        server.shutdown()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        syncer.stop(timeout=2)
        server.server_close()
    return 0


def cmd_sync(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.sync_once())
    return 0


def cmd_status(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.snapshot())
    return 0


def _admin_client(home: str):
    from .upstream import UpstreamClient
    cfg = appmod.load_config(home)
    return None, cfg  # local API usage instead of HTTP for CLI


def cmd_tenant_create(args) -> int:
    relay = appmod.open_relay(args.home)
    res = relay.create_tenant(args.tenant_id, name=args.name or args.tenant_id,
                              filter_doc=_read_filter_arg(args))
    _print(res)
    return 0


def cmd_tenants_list(args) -> int:
    relay = appmod.open_relay(args.home)
    _print({"tenants": relay.list_tenants()})
    return 0


def cmd_tenant_active(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.set_active(args.tenant_id, bool(args.active),
                            reason=args.reason or ""))
    return 0


def cmd_tenant_status(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.get_tenant(args.tenant_id, args.token))
    return 0


def cmd_tenant_filter(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.set_filter(args.tenant_id, args.token, _read_filter_arg(args)))
    return 0


def cmd_acquire(args) -> int:
    relay = appmod.open_relay(args.home)
    resp = relay.acquire(
        args.tenant_id, args.token, consumer=args.consumer or "",
        max_items=args.max_items, lease_seconds=args.lease_seconds)
    if args.out and resp.get("delivered"):
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(resp["package"], fh, ensure_ascii=False,
                      indent=2, sort_keys=True)
        print(f"package written to {args.out}", file=sys.stderr)
    _print(_without_package(resp))
    if resp.get("delivered"):
        print(f"lease_token: {resp['lease_token']}", file=sys.stderr)
    return 0


def cmd_fetch(args) -> int:
    relay = appmod.open_relay(args.home)
    resp = relay.fetch_delivery(args.tenant_id, args.token, args.delivery_id)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(resp["package"], fh, ensure_ascii=False,
                      indent=2, sort_keys=True)
        print(f"package written to {args.out}", file=sys.stderr)
    _print(_without_package(resp))
    return 0


def cmd_ack(args) -> int:
    relay = appmod.open_relay(args.home)
    _print(relay.ack(args.tenant_id, args.token, args.delivery_id, args.ack_seq,
                     lease_token=args.lease_token or "",
                     payload_sha256=args.sha256 or ""))
    return 0


def cmd_verify(args) -> int:
    secret_hex = args.secret
    if secret_hex is None:
        secret_hex = appmod.load_config(args.home)["upstream_secret"]
    report = verify_file(
        args.package, bytes.fromhex(secret_hex),
        expected_tenant=args.tenant, expected_sha256=args.sha256)
    _print(report)
    return 0 if report["ok"] else 2


def _demo_path(home: str) -> str:
    import os
    return os.path.join(home, ".demo.json")


def _start_demo(args):
    import os
    import secrets as pysecrets
    from .fake_upstream import FakeUpstream, serve as demo_serve

    secret_hex = args.demo_secret or pysecrets.token_hex(32)
    upstream = FakeUpstream(bytes.fromhex(secret_hex))
    if args.demo_seed:
        upstream.seed(int(args.demo_seed))
    port = int(args.demo_upstream_port or 0)
    control_token = "demo-control-" + pysecrets.token_urlsafe(12)
    server = demo_serve(upstream, host="127.0.0.1", port=port,
                        control_token=control_token)
    t = threading.Thread(target=server.serve_forever, daemon=True,
                         name="demo-upstream")
    t.start()
    actual = server.server_address[1]
    info = {"url": f"http://127.0.0.1:{actual}",
            "control_token": control_token,
            "secret_hex": secret_hex}
    return upstream, info


def _demo_control(home: str, path: str, body: dict | None = None,
                  method: str = "POST") -> dict:
    import urllib.request
    with open(_demo_path(home), "r", encoding="utf-8") as fh:
        info = json.load(fh)
    url = info["url"] + path
    data = None
    headers = {"Authorization": "Bearer " + info["control_token"]}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def cmd_demo(args) -> int:
    if args.demo_cmd == "seed":
        _print(_demo_control(args.home, "/control/seed", {"n": args.n}))
    elif args.demo_cmd == "append":
        payload = json.loads(args.payload_json) if args.payload_json else {}
        _print(_demo_control(args.home, "/control/append", {
            "event_type": args.type, "subject_id": args.subj,
            "payload": payload}))
    elif args.demo_cmd == "mode":
        body: dict[str, Any] = {"mode": args.mode}
        if args.gap_index is not None:
            body["gap_index"] = args.gap_index
        if args.badleaf_index is not None:
            body["badleaf_index"] = args.badleaf_index
        _print(_demo_control(args.home, "/control/mode", body))
    elif args.demo_cmd == "healthy":
        _print(_demo_control(args.home, "/control/healthy"))
    elif args.demo_cmd == "status":
        _print(_demo_control(args.home, "/control/status", method="GET"))
    return 0


def _without_package(resp: dict) -> dict:
    out = dict(resp)
    pkg = out.pop("package", None)
    if pkg is not None:
        out["entries"] = len(pkg.get("entries", []))
        out["package_note"] = "use --out FILE to save the canonical package"
    return out


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditrelay",
                                description="auditing feed relay")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="initialise an independent relay home")
    s.add_argument("home")
    s.add_argument("--upstream-url", default="http://127.0.0.1:8080")
    s.add_argument("--upstream-token", default="")
    s.add_argument("--upstream-secret", help="hex transparency verify secret")
    s.add_argument("--lease", type=int, default=appmod.DEFAULT_LEASE_SECONDS)
    s.add_argument("--sync-interval", type=float,
                   default=appmod.DEFAULT_SYNC_INTERVAL)
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("serve", help="run HTTP API + background sync + ops UI")
    s.add_argument("home")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8090)
    s.add_argument("--demo", action="store_true",
                   help="run an embedded fault-injecting demo upstream")
    s.add_argument("--demo-seed", type=int, default=0)
    s.add_argument("--demo-upstream-port", type=int, default=0)
    s.add_argument("--demo-secret", help="hex secret (default random)")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("sync", help="run one pull/verify round now")
    s.add_argument("home")
    s.set_defaults(func=cmd_sync)

    s = sub.add_parser("status", help="full relay status snapshot")
    s.add_argument("home")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("tenant-create", help="(admin) create an audit tenant")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("--name")
    s.add_argument("--filter-json")
    s.add_argument("--filter-file")
    s.set_defaults(func=cmd_tenant_create)

    s = sub.add_parser("tenants", help="(admin) list tenants")
    s.add_argument("home")
    s.set_defaults(func=cmd_tenants_list)

    s = sub.add_parser("tenant-active", help="(admin) enable/disable a tenant")
    s.add_argument("home")
    s.add_argument("tenant_id")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--enable", dest="active", action="store_true")
    g.add_argument("--disable", dest="active", action="store_false")
    s.add_argument("--reason", default="")
    s.set_defaults(func=cmd_tenant_active)

    # per-tenant operations
    s = sub.add_parser("t-status", help="tenant: own status")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("--token", required=True)
    s.set_defaults(func=cmd_tenant_status)

    s = sub.add_parser("t-filter", help="tenant: replace filter (no open lease)")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("--token", required=True)
    s.add_argument("--filter-json")
    s.add_argument("--filter-file")
    s.set_defaults(func=cmd_tenant_filter)

    s = sub.add_parser("acquire", help="tenant: acquire a delivery lease")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("--token", required=True)
    s.add_argument("--consumer", default="")
    s.add_argument("--max-items", type=int)
    s.add_argument("--lease-seconds", type=int)
    s.add_argument("--out", help="write the canonical package JSON here")
    s.set_defaults(func=cmd_acquire)

    s = sub.add_parser("fetch", help="tenant: re-fetch a delivery's bytes")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("delivery_id")
    s.add_argument("--token", required=True)
    s.add_argument("--out")
    s.set_defaults(func=cmd_fetch)

    s = sub.add_parser("ack", help="tenant: acknowledge package tail")
    s.add_argument("home")
    s.add_argument("tenant_id")
    s.add_argument("delivery_id")
    s.add_argument("ack_seq", type=int)
    s.add_argument("--token", required=True)
    s.add_argument("--lease-token", default="")
    s.add_argument("--sha256", dest="sha256", default="")
    s.set_defaults(func=cmd_ack)

    s = sub.add_parser("verify", help="offline-verify a captured package file")
    s.add_argument("package")
    s.add_argument("--home", help="relay home to read the verify secret from")
    s.add_argument("--secret", help="hex verify secret (overrides --home)")
    s.add_argument("--tenant")
    s.add_argument("--sha256", help="expected payload_sha256")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("demo", help="drive the embedded demo upstream")
    s.add_argument("home")
    dsub = s.add_subparsers(dest="demo_cmd", required=True)
    d = dsub.add_parser("seed"); d.add_argument("n", type=int)
    d = dsub.add_parser("append")
    d.add_argument("--type", default="release_sealed")
    d.add_argument("--subj", default="subject")
    d.add_argument("--payload-json", default="")
    d = dsub.add_parser("mode")
    d.add_argument("mode", choices=["healthy", "offline", "freeze", "gap",
                                    "badsig", "badleaf", "fallback"])
    d.add_argument("--gap-index", type=int)
    d.add_argument("--badleaf-index", type=int)
    dsub.add_parser("healthy")
    dsub.add_parser("status")
    s.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileExistsError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except PackageError as e:
        print(f"package invalid: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # surface CLI usage errors cleanly
        from .errors import RelayError
        if isinstance(e, RelayError):
            print(json.dumps(e.to_dict(), ensure_ascii=False), file=sys.stderr)
            return 1
        raise
