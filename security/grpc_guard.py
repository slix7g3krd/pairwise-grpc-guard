"""gRPC hardening guards.

Each helper is a pure predicate (or a small adapter) intended to be called from
gRPC server interceptors.  The guiding principle throughout is *deny by
default*: anything that is not explicitly allow-listed, signed, bounded, or
mutually authenticated is rejected.

The helpers never surface exception text, stack frames, or internal network
addresses; callers should translate a rejected call into an opaque
``PERMISSION_DENIED`` / ``INVALID_ARGUMENT`` status.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from typing import Any, Mapping, Sequence

# ---------------------------------------------------------------------------
# Reflection
# ---------------------------------------------------------------------------

# Server reflection must stay disabled in production: it lets any caller
# enumerate every service and method.  Every reflection package version is
# denied explicitly rather than relying on the allow-list alone.
_REFLECTION_PREFIXES = (
    "grpc.reflection.",
    "grpc.reflection.v1.",
    "grpc.reflection.v1alpha.",
)

# ---------------------------------------------------------------------------
# Method allow-list
# ---------------------------------------------------------------------------

# Exact, fully-qualified method names only.  Internal/debug/admin entry points
# are deliberately absent.  No prefix or wildcard matching is supported; a
# method that is not listed here is denied.
ALLOWED_METHODS: frozenset[str] = frozenset(
    {
        "UserService.Get",
        "UserService.List",
        "UserService.Update",
        "TenantService.Get",
        "Health.Check",
    }
)

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

# Identity-bearing keys that must never be trusted when supplied by a client:
# identity is derived from the authenticated TLS peer / signed token, never
# from caller-asserted metadata.
_FORBIDDEN_IDENTITY_KEYS = frozenset(
    {
        "user",
        "username",
        "uid",
        "role",
        "roles",
        "admin",
        "tenant",
        "tenant_id",
        "email",
        "x-user",
        "x-tenant-id",
        "x-forwarded-user",
    }
)

_SIGNATURE_KEY = "sig"

# ---------------------------------------------------------------------------
# Interceptor ordering
# ---------------------------------------------------------------------------

# Authentication and validation must run *before* anything that observes or
# persists the request (logging/audit).  A log interceptor placed ahead of
# auth records unauthenticated, attacker-controlled input.
INTERCEPTOR_ORDER: tuple[str, ...] = ("auth", "validate", "log")


def _constant_time_equal(left: str, right: str) -> bool:
    """Constant-time string comparison that is safe for non-ASCII input.

    ``hmac.compare_digest`` raises ``TypeError`` for non-ASCII ``str``
    arguments, which would turn an attacker-controlled value into an
    unhandled server error.  Compare UTF-8 bytes instead.
    """
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except UnicodeError:
        return False


def method_allowed(name: Any) -> bool:
    """Return ``True`` only for an exact, non-reflection, allow-listed method."""
    if not isinstance(name, str) or not name:
        return False
    # Reject anything that is not exactly a known method - no trimming,
    # no prefix/suffix tolerance, no case folding.
    if name != name.strip():
        return False
    lowered = name.lower()
    if any(lowered.startswith(p) for p in _REFLECTION_PREFIXES):
        return False
    return name in ALLOWED_METHODS


def metadata_ok(metadata: Any, secret: Any, *, expected_sig: Any = None) -> bool:
    """Validate caller metadata.

    Rejects caller-asserted identity and requires a signature.

    ``secret`` must be a non-empty configured key.  ``metadata`` must be a
    mapping carrying a non-empty ``sig`` entry and must not assert identity
    keys (``user``, ``tenant``, ``role`` ...), because identity is derived from
    the authenticated peer rather than from the request.

    Signature verification has two modes:

    * ``expected_sig`` given - the supplied ``sig`` is compared against it in
      constant time.  This is the production path: the interceptor computes
      the expected HMAC over the request and passes it in.
    * ``expected_sig`` omitted - only the presence/shape of ``sig`` is
      checked; the caller is responsible for the HMAC comparison (useful when
      the signature covers a body the interceptor does not see).

    Either way, a client cannot gain anything by asserting identity keys.
    """
    if not isinstance(secret, str) or not secret:
        return False
    if not isinstance(metadata, Mapping):
        return False

    keys = {k.lower() if isinstance(k, str) else k for k in metadata}
    if keys & _FORBIDDEN_IDENTITY_KEYS:
        return False

    sig = metadata.get(_SIGNATURE_KEY)
    if not isinstance(sig, str) or not sig:
        return False

    if expected_sig is not None:
        if not isinstance(expected_sig, str) or not expected_sig:
            return False
        return _constant_time_equal(sig, expected_sig)
    return True


def metadata_signature(payload: Any, secret: str) -> str:
    """Compute the canonical HMAC-SHA256 signature for a metadata payload.

    Interceptors use this to build ``expected_sig`` before calling
    :func:`metadata_ok`.  ``payload`` is hashed over its UTF-8 representation
    (``bytes`` are used as-is); separators are canonical so the same logical
    call always yields the same signature.
    """
    if not isinstance(secret, str) or not secret:
        raise ValueError("a non-empty signing secret is required")
    if isinstance(payload, bytes):
        data = payload
    elif isinstance(payload, str):
        data = payload.encode("utf-8")
    else:
        data = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def stream_tenant_ok(authenticated_tenant: Any, requested_tenant: Any) -> bool:
    """Enforce tenant isolation for (client/server) streaming calls.

    The tenant a message targets must match the tenant established by
    authentication.  Both sides must be non-empty strings and must match
    exactly; a streaming subscription may therefore never be pointed at
    another tenant's namespace.
    """
    if not isinstance(authenticated_tenant, str) or not authenticated_tenant:
        return False
    if not isinstance(requested_tenant, str) or not requested_tenant:
        return False
    return _constant_time_equal(authenticated_tenant, requested_tenant)


def deadline_ok(requested_seconds: Any, max_seconds: Any) -> bool:
    """Return ``True`` only when a requested deadline is bounded and positive.

    ``requested_seconds`` must be a finite, positive number (bools are rejected
    despite being ``int`` subclasses) no greater than ``max_seconds``.  Calls
    without a deadline effectively request an unbounded one and are rejected.
    """
    if isinstance(requested_seconds, bool) or isinstance(max_seconds, bool):
        return False
    if not isinstance(requested_seconds, (int, float)):
        return False
    if not isinstance(max_seconds, (int, float)):
        return False
    if not math.isfinite(requested_seconds) or not math.isfinite(max_seconds):
        return False
    if max_seconds <= 0:
        return False
    if requested_seconds <= 0:
        return False
    return requested_seconds <= max_seconds


def max_message_ok(size: Any, limit: Any) -> bool:
    """Reject messages larger than the configured per-message limit.

    Applies to both request and response sizes.  ``size`` must be a
    non-negative integer and ``limit`` a positive integer; the comparison is
    inclusive, so a message exactly at the limit is accepted.
    """
    if isinstance(size, bool) or isinstance(limit, bool):
        return False
    if not isinstance(size, int) or not isinstance(limit, int):
        return False
    if size < 0 or limit <= 0:
        return False
    return size <= limit


def peer_identity(connection: Any) -> str | None:
    """Return the authenticated peer identity taken from the real connection.

    The identity comes solely from the TLS connection state - never from proxy
    headers such as ``x-forwarded-for`` / ``x-forwarded-user``, which the
    client controls.  Without mutual TLS the peer cannot be trusted and
    ``None`` is returned.  The result contains no diagnostics.
    """
    if not isinstance(connection, Mapping):
        return None
    if connection.get("mtls") is not True:
        return None

    peer = connection.get("peer")
    if not isinstance(peer, str):
        return None
    peer = peer.strip()
    if not peer:
        return None
    # Defensive: an identity must not be a free-form diagnostic blob.  Reject
    # values that look like stack traces / internal addresses so nothing
    # sensitive can be propagaged back to the caller.
    if _looks_like_diagnostic(peer):
        return None
    return peer


# ---------------------------------------------------------------------------
# Interceptor assembly / error redaction
# ---------------------------------------------------------------------------

_ALLOWED_INTERCEPTORS = frozenset(INTERCEPTOR_ORDER)


def interceptor_order_ok(names: Any) -> bool:
    """Check that interceptors are registered auth -> validate -> log.

    Unknown or out-of-order interceptors return ``False``; in particular a
    logging interceptor ahead of authentication is rejected.
    """
    if not isinstance(names, Sequence) or isinstance(names, (str, bytes)):
        return False
    if list(names) != list(INTERCEPTOR_ORDER):
        return False
    return set(names) <= _ALLOWED_INTERCEPTORS


_DIAGNOSTIC_PATTERN = re.compile(
    r"(traceback|stack\s*trace|\bFile\s+\"|line\s+\d+|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\b(?:10|172|192|127)\.\d+\.\d+\.\d+\b|"
    r"\.internal\b|:\s*\d{2,5}\b)",
    re.IGNORECASE,
)


def _looks_like_diagnostic(value: str) -> bool:
    return bool(_DIAGNOSTIC_PATTERN.search(value))


def sanitize_error(error: Any) -> str:
    """Map any failure to an opaque, caller-safe status message.

    Stack traces, file paths, host names, internal IPs, and exception text are
    discarded; details belong in server-side logs keyed by a correlation id.
    """
    return "internal error"
