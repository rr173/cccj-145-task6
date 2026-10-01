"""auditrelay — standalone auditing feed relay.

The relay pulls *signed tree heads* and *leaf records* from an existing
gateway's READ-ONLY transparency endpoints, verifies every byte itself, and
writes the verified records into its own independent mirror store.  It never
mutates the upstream and never fabricates records: when the upstream is
unavailable, advertises a fallback height, a bad signature, or a gap, the
relay stops at the last trusted position and resumes there on recovery.

Multiple isolated auditing tenants register their own filter rules and consume
the mirror via short leases over contiguous-by-original-sequence delivery
packages.
"""

VERSION = "1.0.0"
SERVICE = "audit-relay"

# error codes (stable; used on the wire and in the rejection log)
E_INTERNAL = "internal_error"
E_INVALID_BODY = "invalid_body"
E_UNAUTHORIZED = "unauthorized"
E_INVALID_TOKEN = "invalid_token"
E_CROSS_TENANT = "cross_tenant_token"
E_NOT_FOUND = "not_found"
E_NO_DELIVERY = "no_delivery"
E_TENANT_INACTIVE = "tenant_inactive"
E_LEASE_HELD = "lease_held"
E_OLD_LEASE = "old_lease"
E_WRONG_ACK = "wrong_ack"
E_SKIP_ACK = "skip_ack"
E_FILTER_LOCKED = "filter_locked"
E_BAD_PAYLOAD = "payload_mismatch"
E_UPSTREAM_FROZEN = "upstream_frozen"

# HTTP status mapping for the codes above
STATUS = {
    E_INTERNAL: 500,
    E_INVALID_BODY: 400,
    E_UNAUTHORIZED: 401,
    E_INVALID_TOKEN: 401,
    E_CROSS_TENANT: 403,
    E_NOT_FOUND: 404,
    E_NO_DELIVERY: 404,
    E_TENANT_INACTIVE: 403,
    E_LEASE_HELD: 409,
    E_OLD_LEASE: 409,
    E_WRONG_ACK: 409,
    E_SKIP_ACK: 409,
    E_FILTER_LOCKED: 409,
    E_BAD_PAYLOAD: 409,
    E_UPSTREAM_FROZEN: 503,
}
