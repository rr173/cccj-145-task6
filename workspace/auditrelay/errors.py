"""Typed relay errors that map 1:1 onto HTTP status codes."""

from __future__ import annotations

from . import STATUS


class RelayError(Exception):
    code = "internal_error"
    status = 500

    def __init__(self, message: str = "", *, detail: dict | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail or {}

    def to_dict(self) -> dict:
        out = {"error": self.code, "message": self.message}
        if self.detail:
            out["detail"] = self.detail
        return out


def _make(name: str, code: str, status: int | None = None) -> type:
    return type(name, (RelayError,), {"code": code,
                                      "status": status or STATUS[code]})


InvalidBody = _make("InvalidBody", "invalid_body")
Unauthorized = _make("Unauthorized", "unauthorized")
InvalidToken = _make("InvalidToken", "invalid_token")
CrossTenant = _make("CrossTenant", "cross_tenant_token")
NotFound = _make("NotFound", "not_found")
NoDelivery = _make("NoDelivery", "no_delivery")
TenantInactive = _make("TenantInactive", "tenant_inactive")
LeaseHeld = _make("LeaseHeld", "lease_held")
OldLease = _make("OldLease", "old_lease")
WrongAck = _make("WrongAck", "wrong_ack")
SkipAck = _make("SkipAck", "skip_ack")
FilterLocked = _make("FilterLocked", "filter_locked")
PayloadMismatch = _make("PayloadMismatch", "payload_mismatch")
UpstreamFrozen = _make("UpstreamFrozen", "upstream_frozen")
Internal = _make("Internal", "internal_error")
