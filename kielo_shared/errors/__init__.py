"""kielo_shared.errors — Python mirror of kielo-shared/errors (Go).

Sweep DDDDD-B3 (2026-06-01): cross-language SoT for canonical error
codes emitted across the entire backend. This module mirrors the
Go-side ``kielo-shared/errors`` package (Sweep DDDDD A1) at the
wire-string + helper level.

Architectural shape:

  - **Code** typed alias (``str`` newtype). All canonical codes
    are ``Code`` instances so static-analysis tools can flag
    typos at module-import time.
  - **Structural defaults**: 13 codes covering the
    ``defaultCodeForStatus`` mapping + upstream proxy semantics.
  - **Auth codes**: 32 AUTH_* (token lifecycle / user state / role /
    handler / refresh) — mirrors auth.go.
  - **BFF codes**: 3 BFF_* — mirrors bff.go.
  - **Feature-limit**: CODE_FEATURE_LIMIT_REACHED — the highest-fanout
    cross-service code.

Cross-language parity:

  The contract test at ``tests/contract/error_code_python_parity_test.go``
  enforces that every Go-side wire string has a matching Python
  constant + vice-versa. Adding a new code on either side without
  the sibling will fail the gate.

Wire shape (canonical envelope):

  When ``Code`` is emitted via the engine's error_envelope.py, the
  rendered JSON shape matches the Go canonical envelope byte-equivalently:

      {
        "error": {
          "code": "VALIDATION_FAILED",
          "message": "...",
          "details": {...},
          "trace_id": "..."
        },
        "message": "..."
      }

Migration discipline:

  - Existing Python inline literals migrate to ``CODE_*`` constants
    at their own pace. The constants are values you can drop in
    directly — ``CODE_VALIDATION_FAILED == "VALIDATION_FAILED"`` so
    everything that consumed the bare string keeps working.
  - New error-emitting code MUST use the typed constants. The Python
    parity contract test pins this discipline.
"""

from __future__ import annotations

from typing import Final, FrozenSet


# --- Typed Code alias --------------------------------------------------
Code = str


# --- Structural defaults (mirror defaults.go) --------------------------

CODE_BAD_REQUEST: Final[Code] = "BAD_REQUEST"
CODE_UNAUTHORIZED: Final[Code] = "UNAUTHORIZED"
CODE_FORBIDDEN: Final[Code] = "FORBIDDEN"
CODE_NOT_FOUND: Final[Code] = "NOT_FOUND"
CODE_CONFLICT: Final[Code] = "CONFLICT"
CODE_VALIDATION_FAILED: Final[Code] = "VALIDATION_FAILED"
CODE_RATE_LIMITED: Final[Code] = "RATE_LIMITED"
CODE_INTERNAL_ERROR: Final[Code] = "INTERNAL_ERROR"
CODE_SERVICE_UNAVAILABLE: Final[Code] = "SERVICE_UNAVAILABLE"
CODE_GENERIC_ERROR: Final[Code] = "ERROR"
CODE_UPSTREAM_UNAVAILABLE: Final[Code] = "UPSTREAM_UNAVAILABLE"
CODE_UPSTREAM_ERROR: Final[Code] = "UPSTREAM_ERROR"
CODE_UPSTREAM_UNCONFIGURED: Final[Code] = "UPSTREAM_UNCONFIGURED"


# --- Auth codes (mirror auth.go) ---------------------------------------
# Names match the Go-side exactly (modulo CamelCase → CODE_UPPER_SNAKE).

# Token lifecycle (7)
CODE_AUTH_TOKEN_MISSING: Final[Code] = "AUTH_TOKEN_MISSING"
CODE_AUTH_TOKEN_MALFORMED: Final[Code] = "AUTH_TOKEN_MALFORMED"
CODE_AUTH_TOKEN_EXPIRED: Final[Code] = "AUTH_TOKEN_EXPIRED"
CODE_AUTH_TOKEN_SIGNATURE_INVALID: Final[Code] = "AUTH_TOKEN_SIGNATURE_INVALID"
CODE_AUTH_TOKEN_ISSUER_INVALID: Final[Code] = "AUTH_TOKEN_ISSUER_INVALID"
CODE_AUTH_TOKEN_CLAIMS_INVALID: Final[Code] = "AUTH_TOKEN_CLAIMS_INVALID"
CODE_AUTH_SESSION_INVALID: Final[Code] = "AUTH_SESSION_INVALID"

# User state (2)
CODE_AUTH_USER_DELETED: Final[Code] = "AUTH_USER_DELETED"
CODE_AUTH_USER_CHECK_FAILED: Final[Code] = "AUTH_USER_CHECK_FAILED"

# Role (2)
CODE_AUTH_ADMIN_REQUIRED: Final[Code] = "AUTH_ADMIN_REQUIRED"
CODE_AUTH_AUTH_REQUIRED: Final[Code] = "AUTH_AUTH_REQUIRED"

# Handler vocabulary (21)
CODE_AUTH_INVALID_REQUEST_FORMAT: Final[Code] = "AUTH_INVALID_REQUEST_FORMAT"
CODE_AUTH_VALIDATION_FAILED: Final[Code] = "AUTH_VALIDATION_FAILED"
CODE_AUTH_INVALID_RESET_TOKEN: Final[Code] = "AUTH_INVALID_RESET_TOKEN"
CODE_AUTH_INVALID_RESET_TOKEN_EMAIL: Final[Code] = "AUTH_INVALID_RESET_TOKEN_EMAIL"
CODE_AUTH_DEVICE_IDENTIFIER_MISSING: Final[Code] = "AUTH_DEVICE_IDENTIFIER_MISSING"
CODE_AUTH_INVALID_CREDENTIALS: Final[Code] = "AUTH_INVALID_CREDENTIALS"
CODE_AUTH_EMAIL_IN_USE: Final[Code] = "AUTH_EMAIL_IN_USE"
CODE_AUTH_REGISTRATION_FAILED: Final[Code] = "AUTH_REGISTRATION_FAILED"
CODE_AUTH_LOGIN_FAILED: Final[Code] = "AUTH_LOGIN_FAILED"
CODE_AUTH_INVALID_SOCIAL_TOKEN: Final[Code] = "AUTH_INVALID_SOCIAL_TOKEN"
CODE_AUTH_SOCIAL_LOGIN_FAILED: Final[Code] = "AUTH_SOCIAL_LOGIN_FAILED"
CODE_AUTH_FORGOT_PASSWORD_FAILED: Final[Code] = "AUTH_FORGOT_PASSWORD_FAILED"
CODE_AUTH_PASSWORD_RESET_FAILED: Final[Code] = "AUTH_PASSWORD_RESET_FAILED"
CODE_AUTH_EMAIL_VERIFICATION_FAILED: Final[Code] = "AUTH_EMAIL_VERIFICATION_FAILED"
CODE_AUTH_INVALID_VERIFICATION_TOKEN: Final[Code] = "AUTH_INVALID_VERIFICATION_TOKEN"
CODE_AUTH_VERIFICATION_TOKEN_EXPIRED: Final[Code] = "AUTH_VERIFICATION_TOKEN_EXPIRED"
CODE_AUTH_ACCOUNT_DELETION_FAILED: Final[Code] = "AUTH_ACCOUNT_DELETION_FAILED"
CODE_AUTH_LOGOUT_FAILED: Final[Code] = "AUTH_LOGOUT_FAILED"
CODE_AUTH_REFRESH_TOKEN_INVALID: Final[Code] = "AUTH_REFRESH_TOKEN_INVALID"
CODE_AUTH_REFRESH_TOKEN_EXPIRED: Final[Code] = "AUTH_REFRESH_TOKEN_EXPIRED"
CODE_AUTH_REFRESH_SESSION_FAILED: Final[Code] = "AUTH_REFRESH_SESSION_FAILED"

# Success codes (3)
CODE_AUTH_PASSWORD_RESET_SENT: Final[Code] = "AUTH_PASSWORD_RESET_SENT"
CODE_AUTH_PASSWORD_RESET_DONE: Final[Code] = "AUTH_PASSWORD_RESET_DONE"
CODE_AUTH_RESET_TOKEN_VALID: Final[Code] = "AUTH_RESET_TOKEN_VALID"


# --- BFF codes (mirror bff.go) -----------------------------------------

CODE_BFF_INVALID_REQUEST_BODY: Final[Code] = "BFF_INVALID_REQUEST_BODY"
CODE_BFF_BACKEND_UNAVAILABLE: Final[Code] = "BFF_BACKEND_UNAVAILABLE"
CODE_BFF_BACKEND_ERROR: Final[Code] = "BFF_BACKEND_ERROR"


# --- Cross-service codes -----------------------------------------------

CODE_FEATURE_LIMIT_REACHED: Final[Code] = "FEATURE_LIMIT_REACHED"
"""User exceeded their plan's daily/monthly feature limit.

Sweep DDDDD A3 (2026-06-01): central SoT for the highest-fanout
cross-service code. Pre-DDDDD: 5 producer services emitted this as
raw inline literals. Post-DDDDD: all 5 producers + the convo
orchestrator's typed APIErrorCode reference this constant.
"""


# --- DefaultForStatus mirror -------------------------------------------

_DEFAULT_FOR_STATUS: Final[dict[int, Code]] = {
    400: CODE_BAD_REQUEST,
    401: CODE_UNAUTHORIZED,
    403: CODE_FORBIDDEN,
    404: CODE_NOT_FOUND,
    409: CODE_CONFLICT,
    422: CODE_VALIDATION_FAILED,
    429: CODE_RATE_LIMITED,
    503: CODE_SERVICE_UNAVAILABLE,
}


def default_for_status(status: int) -> Code:
    """Return the canonical Code for an HTTP status.

    Mirrors ``kerrors.DefaultForStatus`` in Go byte-equivalently.
    """
    if status in _DEFAULT_FOR_STATUS:
        return _DEFAULT_FOR_STATUS[status]
    if status >= 500:
        return CODE_INTERNAL_ERROR
    return CODE_GENERIC_ERROR


# --- Iteration helpers (mirror Go's AllAuthErrorCodes) -----------------

ALL_AUTH_ERROR_CODES: Final[FrozenSet[Code]] = frozenset({
    # Token lifecycle
    CODE_AUTH_TOKEN_MISSING,
    CODE_AUTH_TOKEN_MALFORMED,
    CODE_AUTH_TOKEN_EXPIRED,
    CODE_AUTH_TOKEN_SIGNATURE_INVALID,
    CODE_AUTH_TOKEN_ISSUER_INVALID,
    CODE_AUTH_TOKEN_CLAIMS_INVALID,
    CODE_AUTH_SESSION_INVALID,
    # User state
    CODE_AUTH_USER_DELETED,
    CODE_AUTH_USER_CHECK_FAILED,
    # Role
    CODE_AUTH_ADMIN_REQUIRED,
    CODE_AUTH_AUTH_REQUIRED,
    # Handler vocabulary
    CODE_AUTH_INVALID_REQUEST_FORMAT,
    CODE_AUTH_VALIDATION_FAILED,
    CODE_AUTH_INVALID_RESET_TOKEN,
    CODE_AUTH_INVALID_RESET_TOKEN_EMAIL,
    CODE_AUTH_DEVICE_IDENTIFIER_MISSING,
    CODE_AUTH_INVALID_CREDENTIALS,
    CODE_AUTH_EMAIL_IN_USE,
    CODE_AUTH_REGISTRATION_FAILED,
    CODE_AUTH_LOGIN_FAILED,
    CODE_AUTH_INVALID_SOCIAL_TOKEN,
    CODE_AUTH_SOCIAL_LOGIN_FAILED,
    CODE_AUTH_FORGOT_PASSWORD_FAILED,
    CODE_AUTH_PASSWORD_RESET_FAILED,
    CODE_AUTH_EMAIL_VERIFICATION_FAILED,
    CODE_AUTH_INVALID_VERIFICATION_TOKEN,
    CODE_AUTH_VERIFICATION_TOKEN_EXPIRED,
    CODE_AUTH_ACCOUNT_DELETION_FAILED,
    CODE_AUTH_LOGOUT_FAILED,
    CODE_AUTH_REFRESH_TOKEN_INVALID,
    CODE_AUTH_REFRESH_TOKEN_EXPIRED,
    CODE_AUTH_REFRESH_SESSION_FAILED,
})

ALL_AUTH_SUCCESS_CODES: Final[FrozenSet[Code]] = frozenset({
    CODE_AUTH_PASSWORD_RESET_SENT,
    CODE_AUTH_PASSWORD_RESET_DONE,
    CODE_AUTH_RESET_TOKEN_VALID,
})

ALL_STRUCTURAL_CODES: Final[FrozenSet[Code]] = frozenset({
    CODE_BAD_REQUEST,
    CODE_UNAUTHORIZED,
    CODE_FORBIDDEN,
    CODE_NOT_FOUND,
    CODE_CONFLICT,
    CODE_VALIDATION_FAILED,
    CODE_RATE_LIMITED,
    CODE_INTERNAL_ERROR,
    CODE_SERVICE_UNAVAILABLE,
    CODE_GENERIC_ERROR,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_UPSTREAM_ERROR,
    CODE_UPSTREAM_UNCONFIGURED,
})

ALL_BFF_CODES: Final[FrozenSet[Code]] = frozenset({
    CODE_BFF_INVALID_REQUEST_BODY,
    CODE_BFF_BACKEND_UNAVAILABLE,
    CODE_BFF_BACKEND_ERROR,
})

ALL_CROSS_SERVICE_CODES: Final[FrozenSet[Code]] = frozenset({
    CODE_FEATURE_LIMIT_REACHED,
})


def all_codes() -> FrozenSet[Code]:
    """Return the union of all canonical Code constants."""
    return (
        ALL_AUTH_ERROR_CODES
        | ALL_AUTH_SUCCESS_CODES
        | ALL_STRUCTURAL_CODES
        | ALL_BFF_CODES
        | ALL_CROSS_SERVICE_CODES
    )


__all__ = [
    # Type alias
    "Code",
    # Structural
    "CODE_BAD_REQUEST",
    "CODE_UNAUTHORIZED",
    "CODE_FORBIDDEN",
    "CODE_NOT_FOUND",
    "CODE_CONFLICT",
    "CODE_VALIDATION_FAILED",
    "CODE_RATE_LIMITED",
    "CODE_INTERNAL_ERROR",
    "CODE_SERVICE_UNAVAILABLE",
    "CODE_GENERIC_ERROR",
    "CODE_UPSTREAM_UNAVAILABLE",
    "CODE_UPSTREAM_ERROR",
    "CODE_UPSTREAM_UNCONFIGURED",
    # Auth — token lifecycle
    "CODE_AUTH_TOKEN_MISSING",
    "CODE_AUTH_TOKEN_MALFORMED",
    "CODE_AUTH_TOKEN_EXPIRED",
    "CODE_AUTH_TOKEN_SIGNATURE_INVALID",
    "CODE_AUTH_TOKEN_ISSUER_INVALID",
    "CODE_AUTH_TOKEN_CLAIMS_INVALID",
    "CODE_AUTH_SESSION_INVALID",
    # Auth — user state
    "CODE_AUTH_USER_DELETED",
    "CODE_AUTH_USER_CHECK_FAILED",
    # Auth — role
    "CODE_AUTH_ADMIN_REQUIRED",
    "CODE_AUTH_AUTH_REQUIRED",
    # Auth — handler vocabulary
    "CODE_AUTH_INVALID_REQUEST_FORMAT",
    "CODE_AUTH_VALIDATION_FAILED",
    "CODE_AUTH_INVALID_RESET_TOKEN",
    "CODE_AUTH_INVALID_RESET_TOKEN_EMAIL",
    "CODE_AUTH_DEVICE_IDENTIFIER_MISSING",
    "CODE_AUTH_INVALID_CREDENTIALS",
    "CODE_AUTH_EMAIL_IN_USE",
    "CODE_AUTH_REGISTRATION_FAILED",
    "CODE_AUTH_LOGIN_FAILED",
    "CODE_AUTH_INVALID_SOCIAL_TOKEN",
    "CODE_AUTH_SOCIAL_LOGIN_FAILED",
    "CODE_AUTH_FORGOT_PASSWORD_FAILED",
    "CODE_AUTH_PASSWORD_RESET_FAILED",
    "CODE_AUTH_EMAIL_VERIFICATION_FAILED",
    "CODE_AUTH_INVALID_VERIFICATION_TOKEN",
    "CODE_AUTH_VERIFICATION_TOKEN_EXPIRED",
    "CODE_AUTH_ACCOUNT_DELETION_FAILED",
    "CODE_AUTH_LOGOUT_FAILED",
    "CODE_AUTH_REFRESH_TOKEN_INVALID",
    "CODE_AUTH_REFRESH_TOKEN_EXPIRED",
    "CODE_AUTH_REFRESH_SESSION_FAILED",
    # Auth — success
    "CODE_AUTH_PASSWORD_RESET_SENT",
    "CODE_AUTH_PASSWORD_RESET_DONE",
    "CODE_AUTH_RESET_TOKEN_VALID",
    # BFF
    "CODE_BFF_INVALID_REQUEST_BODY",
    "CODE_BFF_BACKEND_UNAVAILABLE",
    "CODE_BFF_BACKEND_ERROR",
    # Cross-service
    "CODE_FEATURE_LIMIT_REACHED",
    # Helpers
    "default_for_status",
    "all_codes",
    "ALL_AUTH_ERROR_CODES",
    "ALL_AUTH_SUCCESS_CODES",
    "ALL_STRUCTURAL_CODES",
    "ALL_BFF_CODES",
    "ALL_CROSS_SERVICE_CODES",
]
