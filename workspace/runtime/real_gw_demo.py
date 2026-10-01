"""Provision a REAL dpgw gateway with transparency leaves, then serve it.

Uses the same proven flow as tests/test_transparency.py so the real gateway
emits genuine release_sealed / share_issued / share_revoked leaves signed with
its real transparency secret, then serves the read-only transparency HTTP API
that the relay consumes.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, "/workspace")

from dpgw.server import serve as gw_serve
from tests.harness import Harness
from tests.test_transparency import all_catalog_fields, q

PORT = 8123
PERSIST = "/workspace/runtime/real-gw-home"


def iso_in(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def main() -> None:
    tmp = tempfile.mkdtemp()
    h = Harness()
    # relocate nothing: build leaves inside the harness gateway, then point a
    # persistent copy is unnecessary -- we just serve this live instance.
    snap, _, _ = h.publish("v1")
    sid = snap["snapshot_id"]
    for name in ("alpha", "beta"):
        h.grant(name, sid, 5.0)
    ta, tb = h.tid("alpha"), h.tid("beta")
    g = h.gw

    def stmt(city="BJ"):
        return {"snapshot": {"snapshot_id": sid}, "query": q(city)}

    v = g.create_publication("joint1", [stmt()], 2, iso_in(3600), actor="lead")
    vid = v["version_id"]
    g.register_contribution(vid, ta)
    g.register_contribution(vid, tb)
    sealed = g.seal_publication(vid)
    print("leaf0:", sealed["transparency"]["leaf_index"],
          sealed["transparency"]["event_type"], flush=True)

    g.grant_share_fields(vid, ta, all_catalog_fields())
    share = g.create_share(vid, ta, all_catalog_fields(), ttl_seconds=3600)
    print("leaf1:", share["transparency"]["leaf_index"],
          share["transparency"]["event_type"], flush=True)
    g.revoke_share(share["share_id"], reason="demo")
    st = g.tl_state()
    print("tree_size:", st["tree_size"], flush=True)

    # expose the real transparency secret so the relay can verify offline
    secret = json.load(open(os.path.join(h.home, "secrets.json")))
    os.makedirs(PERSIST, exist_ok=True)
    with open(os.path.join(PERSIST, "env.json"), "w") as fh:
        json.dump({"admin_token": h.admin_token,
                   "team_token": h.token("alpha"),
                   "transparency_secret": secret["transparency_secret"],
                   "gw_home": h.home, "port": PORT}, fh, indent=2)

    server = gw_serve(g, host="127.0.0.1", port=PORT)
    print(f"REAL gateway on http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
