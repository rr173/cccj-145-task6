"""Relay home layout, configuration and bootstrap.

Home directory (independent of the gateway)::

    relay-home/
      relay.sqlite      verified mirror + tenants + deliveries + events
      config.json       upstream URL, read token, verification secret (0600)

The relay stores the upstream's *verification* secret so it can check signed
tree heads offline.  It never stores any signing key of its own for upstream
data -- it only mirrors what it verified.
"""

from __future__ import annotations

import json
import os
import secrets as pysecrets

from .relay import Relay
from .store import connect
from .upstream import UpstreamClient

DEFAULT_LEASE_SECONDS = 30
DEFAULT_SYNC_INTERVAL = 2.0


def _config_path(home: str) -> str:
    return os.path.join(home, "config.json")


def write_config(home: str, config: dict) -> str:
    os.makedirs(home, exist_ok=True)
    path = _config_path(home)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, sort_keys=True)
    os.chmod(path, 0o600)
    return path


def bootstrap(home: str, *, upstream_url: str, upstream_token: str,
              upstream_secret_hex: str, lease_seconds: int = DEFAULT_LEASE_SECONDS,
              admin_token: str | None = None, sync_interval: float =
              DEFAULT_SYNC_INTERVAL, force: bool = False) -> dict:
    """Initialise a relay home directory and its independent database."""
    os.makedirs(home, exist_ok=True)
    path = _config_path(home)
    if os.path.exists(path) and not force:
        raise FileExistsError(f"{path} already exists; refusing to overwrite")
    admin = admin_token or ("arradm_" + pysecrets.token_urlsafe(24))
    config = {
        "upstream_url": upstream_url.rstrip("/"),
        "upstream_token": upstream_token,
        "upstream_secret": upstream_secret_hex,
        "lease_seconds": int(lease_seconds),
        "sync_interval": float(sync_interval),
        "admin_token": admin,
    }
    write_config(home, config)
    # create the empty mirror database
    conn = connect(os.path.join(home, "relay.sqlite"))
    from .store import init_db
    init_db(conn)
    conn.close()
    return {"home": os.path.abspath(home), "admin_token": admin,
            "config": {k: v for k, v in config.items()
                       if k not in ("admin_secret",)}}


def load_config(home: str) -> dict:
    with open(_config_path(home), "r", encoding="utf-8") as fh:
        return json.load(fh)


def open_relay(home: str, *, client: UpstreamClient | None = None) -> Relay:
    config = load_config(home)
    secret_hex = config["upstream_secret"]
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as e:
        raise ValueError("upstream_secret in config must be hex") from e
    conn = connect(os.path.join(home, "relay.sqlite"))
    up = client or UpstreamClient(config["upstream_url"],
                                  config["upstream_token"])
    return Relay(conn, up, secret,
                 lease_seconds=int(config.get("lease_seconds",
                                              DEFAULT_LEASE_SECONDS)))


def admin_token(home: str) -> str:
    return load_config(home)["admin_token"]
