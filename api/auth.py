"""Caller authentication: API keys map to RBAC roles on the server side.

The caller never chooses its own role. Each key in SENTINEL_CALLER_KEYS is bound
to exactly one role; the legacy SENTINEL_API_KEY is accepted as an admin key.
Every rejected request is written to the audit log.
"""

from __future__ import annotations

import hmac
import itertools
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Request

from audit.writer import append_entry
from rbac.roles import get_role

logger = logging.getLogger(__name__)

MIN_KEY_LENGTH = 16
DEMO_ANONYMOUS_ROLE = "readonly"
KEY_HEADER = "X-Sentinel-Key"

_auth_seq = itertools.count(1)
_auth_seq_lock = threading.Lock()


@dataclass(frozen=True)
class AuthConfig:
    caller_keys: tuple[tuple[str, str], ...]
    demo_mode: bool

    @property
    def is_open_demo(self) -> bool:
        """Demo mode with no keys: anonymous callers allowed (never in production)."""
        return self.demo_mode and not self.caller_keys

    def resolve_role(self, presented_key: str) -> Optional[str]:
        """Constant-time lookup: compares against every key, never short-circuits."""
        matched: Optional[str] = None
        presented = presented_key.encode()
        for key, role in self.caller_keys:
            if hmac.compare_digest(presented, key.encode()):
                matched = role
        return matched


def _parse_caller_keys(raw: str) -> dict[str, str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"SENTINEL_CALLER_KEYS is not valid JSON ({exc.msg}). Expected a JSON object "
            "mapping key → role, e.g. '{\"<key>\": \"analyst\"}'. Run `make keys` to "
            "generate one, or put a single admin key in SENTINEL_API_KEY instead."
        ) from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
    ):
        raise ValueError('SENTINEL_CALLER_KEYS must be a JSON object of {"<key>": "<role>"}')
    return parsed


def _validate_key(key: str, role: str) -> None:
    if len(key) < MIN_KEY_LENGTH:
        raise ValueError(f"API keys must be at least {MIN_KEY_LENGTH} characters (role {role!r})")
    get_role(role)  # raises ValueError("Unknown role ...")


def load_auth_config(env: Mapping[str, str]) -> AuthConfig:
    raw = env.get("SENTINEL_CALLER_KEYS", "").strip()
    keys = _parse_caller_keys(raw) if raw else {}
    legacy_admin_key = env.get("SENTINEL_API_KEY", "").strip()
    if legacy_admin_key:
        keys = {**keys, legacy_admin_key: "admin"}
    for key, role in keys.items():
        _validate_key(key, role)
    return AuthConfig(
        caller_keys=tuple(keys.items()),
        demo_mode=env.get("SENTINEL_DEMO_MODE", "") == "1",
    )


def ensure_bootable(config: AuthConfig) -> None:
    """Fail closed: refuse to start without credentials unless demo mode is explicit."""
    if config.caller_keys or config.demo_mode:
        return
    raise RuntimeError(
        "No API keys configured. Set SENTINEL_CALLER_KEYS (JSON map of key → role) "
        "or SENTINEL_API_KEY. For a local unauthenticated demo set SENTINEL_DEMO_MODE=1."
    )


def _audit_auth_denial(request: Request, rule_name: str, message: str, role: str = "") -> None:
    with _auth_seq_lock:
        seq = next(_auth_seq)
    settings = request.app.state.settings
    append_entry(
        {
            "request_id": f"auth-{int(time.time() * 1000)}-{seq}",
            "direction": "ingress",
            "action": "DENY",
            "rule_name": rule_name,
            "deny_message": message,
            "agent_id": "api",
            "role": role,
            "path": request.url.path,
        },
        path=settings.audit_log_path,
        strict=settings.audit_strict,
    )


def _deny(request: Request, status: int, rule_name: str, message: str, role: str = "") -> HTTPException:
    _audit_auth_denial(request, rule_name, message, role)
    return HTTPException(status_code=status, detail=message)


def caller_role(
    request: Request,
    x_sentinel_key: Optional[str] = Header(default=None),
) -> str:
    """FastAPI dependency: resolve the caller's role from its API key."""
    config: AuthConfig = request.app.state.auth
    if not x_sentinel_key:
        if config.is_open_demo:
            logger.warning("DEMO MODE: unauthenticated request to %s served as %r",
                           request.url.path, DEMO_ANONYMOUS_ROLE)
            return DEMO_ANONYMOUS_ROLE
        raise _deny(request, 401, "auth_missing_key", f"Missing {KEY_HEADER} header")
    role = config.resolve_role(x_sentinel_key)
    if role is None:
        raise _deny(request, 401, "auth_invalid_key", f"Invalid {KEY_HEADER}")
    return role


def require_roles(*allowed: str) -> Callable[..., str]:
    """FastAPI dependency factory: caller must hold one of the allowed roles."""
    allowed_set = frozenset(allowed)

    def dependency(
        request: Request,
        x_sentinel_key: Optional[str] = Header(default=None),
    ) -> str:
        config: AuthConfig = request.app.state.auth
        if config.is_open_demo and not x_sentinel_key:
            logger.warning("DEMO MODE: governance endpoint %s is unauthenticated", request.url.path)
            return "admin"
        role = caller_role(request, x_sentinel_key)
        if role not in allowed_set:
            raise _deny(request, 403, "auth_role_denied",
                        f"Role {role!r} may not access {request.url.path}", role)
        return role

    return dependency
