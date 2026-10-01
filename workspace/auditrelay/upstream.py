"""HTTP client for the gateway's READ-ONLY transparency interface.

The relay only ever issues GET requests to:

* ``GET /v1/transparency``                     -- signed tree head + state
* ``GET /v1/transparency/inclusion/<index>``   -- leaf + inclusion proof

It never calls an admin or mutating endpoint and never opens the gateway's
database.  Transport problems are normalised into :class:`UpstreamUnavailable`
so the sync loop can stop and keep the last trusted position.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class UpstreamError(Exception):
    kind = "upstream_error"


class UpstreamUnavailable(UpstreamError):
    kind = "unavailable"


class UpstreamGap(UpstreamError):
    """A required leaf index is missing at the upstream (interval gap)."""
    kind = "interval_gap"


class UpstreamProtocol(UpstreamError):
    kind = "protocol_error"


class UpstreamClient:
    def __init__(self, base_url: str, token: str, *, timeout: float = 5.0,
                 user_agent: str = "audit-relay/1.0"):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.user_agent = user_agent

    def _get(self, path: str, *, gap_on_404: bool = False) -> dict:
        url = self.base_url + path
        req = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            if gap_on_404 and e.code in (404, 410):
                raise UpstreamGap(f"missing leaf at {path} (HTTP {e.code})")
            # any other non-2xx from the read surface is treated as an
            # availability problem: the relay stops rather than guesses
            raise UpstreamUnavailable(f"HTTP {e.code} from upstream {path}") from e
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            raise UpstreamUnavailable(f"upstream request failed: {e}") from e
        if status != 200:
            raise UpstreamUnavailable(f"HTTP {status} from upstream {path}")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise UpstreamProtocol(f"non-JSON body from {path}") from e
        if not isinstance(data, dict):
            raise UpstreamProtocol(f"unexpected body type from {path}")
        return data

    def state(self) -> dict:
        return self._get("/v1/transparency")

    def inclusion(self, index: int) -> dict:
        return self._get(f"/v1/transparency/inclusion/{int(index)}",
                         gap_on_404=True)
