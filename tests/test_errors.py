"""Sweep DDDDD-B3: tests for the Python kielo_shared.errors mirror.

Pins behavior identical to the Go-side kielo-shared/errors package:
  - Vocabulary discipline (UPPER_SNAKE_CASE codes)
  - Default-for-status byte-equivalent to Go
  - Iteration sets non-empty + properly partitioned
  - No code collision across partitions
"""

from __future__ import annotations

import re

import pytest

from kielo_shared import errors


# --- Vocabulary discipline ---------------------------------------------

_UPPER_SNAKE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def test_all_codes_are_upper_snake_case():
    """Every Code constant in the public surface must match
    ``^[A-Z][A-Z0-9_]*$`` — same gate as Go-side
    TestCentralSoT_AllCodesAreUpperSnakeCase.
    """
    for code in errors.all_codes():
        assert _UPPER_SNAKE_RE.match(code), (
            f"code {code!r} does not match UPPER_SNAKE_CASE pattern"
        )


def test_all_codes_unique():
    """No code value appears in more than one partition. The wire
    string IS the identity — drift between e.g. ALL_AUTH_ERROR_CODES
    and ALL_STRUCTURAL_CODES would mean the same string had two
    semantic meanings.
    """
    partitions = [
        errors.ALL_AUTH_ERROR_CODES,
        errors.ALL_AUTH_SUCCESS_CODES,
        errors.ALL_STRUCTURAL_CODES,
        errors.ALL_BFF_CODES,
        errors.ALL_CROSS_SERVICE_CODES,
    ]
    seen: dict[str, int] = {}
    for idx, partition in enumerate(partitions):
        for code in partition:
            if code in seen:
                raise AssertionError(
                    f"code {code!r} appears in partition {seen[code]} and {idx}"
                )
            seen[code] = idx


def test_all_codes_total_count():
    """The cardinalities must match the Go-side iteration slices
    + parity-test expectations:
      - 32 auth error codes (7 token + 2 user + 2 role + 21 handler)
      - 3 auth success codes
      - 13 structural codes (DDDDD A1 + B2 SERVICE_UNAVAILABLE)
      - 3 BFF codes
      - 1 cross-service code (FEATURE_LIMIT_REACHED)
    Total: 52.

    Mirrors Go-side AllAuthErrorCodes (32) + AllAuthSuccessCodes (3).
    """
    assert len(errors.ALL_AUTH_ERROR_CODES) == 32
    assert len(errors.ALL_AUTH_SUCCESS_CODES) == 3
    assert len(errors.ALL_STRUCTURAL_CODES) == 13
    assert len(errors.ALL_BFF_CODES) == 3
    assert len(errors.ALL_CROSS_SERVICE_CODES) == 1
    assert len(errors.all_codes()) == 32 + 3 + 13 + 3 + 1


# --- default_for_status mirror -----------------------------------------


@pytest.mark.parametrize(
    "status,expected",
    [
        (400, errors.CODE_BAD_REQUEST),
        (401, errors.CODE_UNAUTHORIZED),
        (403, errors.CODE_FORBIDDEN),
        (404, errors.CODE_NOT_FOUND),
        (409, errors.CODE_CONFLICT),
        (422, errors.CODE_VALIDATION_FAILED),
        (429, errors.CODE_RATE_LIMITED),
        (500, errors.CODE_INTERNAL_ERROR),
        (502, errors.CODE_INTERNAL_ERROR),
        (503, errors.CODE_SERVICE_UNAVAILABLE),  # DDDDD-B2 refinement
        (504, errors.CODE_INTERNAL_ERROR),
        (200, errors.CODE_GENERIC_ERROR),
        (301, errors.CODE_GENERIC_ERROR),
        (402, errors.CODE_GENERIC_ERROR),
    ],
)
def test_default_for_status_matches_go(status, expected):
    """Byte-equivalent to Go kerrors.DefaultForStatus.

    The Go-side test at kielo-shared/errors/errors_test.go pins the
    same table.
    """
    assert errors.default_for_status(status) == expected


# --- Cross-language parity smoke ---------------------------------------


def test_feature_limit_reached_constant():
    """The central cross-service code matches the canonical wire string
    that 5 Go services produce.
    """
    assert errors.CODE_FEATURE_LIMIT_REACHED == "FEATURE_LIMIT_REACHED"


def test_canonical_auth_constants_present():
    """Spot-check the high-fanout auth codes that mobile +
    admin both consume via typed unions.
    """
    assert errors.CODE_AUTH_INVALID_CREDENTIALS == "AUTH_INVALID_CREDENTIALS"
    assert errors.CODE_AUTH_TOKEN_EXPIRED == "AUTH_TOKEN_EXPIRED"
    assert errors.CODE_AUTH_TOKEN_MISSING == "AUTH_TOKEN_MISSING"
    assert errors.CODE_AUTH_TOKEN_MALFORMED == "AUTH_TOKEN_MALFORMED"
    assert errors.CODE_AUTH_TOKEN_SIGNATURE_INVALID == "AUTH_TOKEN_SIGNATURE_INVALID"


def test_validation_failed_byte_equivalent_to_go():
    """The wire string MUST be exactly VALIDATION_FAILED — mobile +
    admin consume this in typed unions.
    """
    assert errors.CODE_VALIDATION_FAILED == "VALIDATION_FAILED"


def test_internal_error_byte_equivalent_to_go():
    """The 5xx fallback wire string must match Go's CodeInternalError."""
    assert errors.CODE_INTERNAL_ERROR == "INTERNAL_ERROR"
