from __future__ import annotations

import json
from typing import Any, Optional

TIMING_THRESHOLD_MULTIPLIER = 2.0
MIN_TIMING_THRESHOLD_SECONDS = 2.5

# Strings that indicate a SQL query error was returned — suggests injection.
ERROR_SIGNATURES: dict[str, list[str]] = {
    "mysql": ["You have an error in your SQL syntax", "mysql_fetch", "MySQL server"],
    "mariadb": ["MariaDB", "SQLSTATE"],
    "postgresql": ["pg_query()", "PostgreSQL", "PSQLException"],
    "mssql": ["Unclosed quotation mark", "SQLServer", "OLE DB"],
    "sqlite": ["SQLite3::", "sqlite_query", "SQLITE_ERROR"],
    "generic": ["SQL syntax", "syntax error", "database error", "ORA-", "DB2 SQL"],
}

# Strings that indicate internal ORM/DB implementation details leaked to the
# client — signals poor error handling rather than SQL injection success.
LEAK_SIGNATURES: dict[str, list[str]] = {
    "orm": [
        "SequelizeDatabaseError", "SequelizeConnectionError",
        "TypeORMError", "QueryFailedError",
        "PrismaClientKnownRequestError", "PrismaClientUnknownRequestError",
        "Knex: Timeout",
    ],
    "postgresql": [
        "22P05", "22021", "22001",  # encoding/string violations
        "42601", "42703",           # syntax/column errors
        "23505", "23503",           # constraint violations
    ],
}


def is_timing_anomaly(
    baseline_ms: float,
    response_ms: float,
    expected_delay_seconds: float,
) -> bool:
    return (
        response_ms > baseline_ms * TIMING_THRESHOLD_MULTIPLIER
        and response_ms > MIN_TIMING_THRESHOLD_SECONDS * 1000
    )


def _response_text(response: Any) -> str:
    try:
        return json.dumps(response) if not isinstance(response, str) else response
    except Exception:
        return str(response)


def check_error_strings(response: Any) -> Optional[str]:
    """Return matched DB type if SQL query error signatures appear in response."""
    text_lower = _response_text(response).lower()
    for db_type, sigs in ERROR_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in text_lower:
                return db_type
    return None


def check_error_leak(response: Any) -> Optional[str]:
    """Return matched DB/ORM type if implementation details are leaked in response.

    Distinct from check_error_strings: these signatures indicate the error
    handling layer is exposing internal stack information, not that SQL
    injection succeeded.
    """
    text_lower = _response_text(response).lower()
    for db_type, sigs in LEAK_SIGNATURES.items():
        for sig in sigs:
            if sig.lower() in text_lower:
                return db_type
    return None


def check_reflection(response: Any, expected: str) -> bool:
    """Return True if expected string appears verbatim in the response."""
    try:
        text = json.dumps(response) if not isinstance(response, str) else response
    except Exception:
        text = str(response)
    return expected in text


_AUTH_STATUSES = frozenset({"Rejected", "Invalid", "NotSupported", "NotImplemented"})


def _is_auth_response(response: Any) -> bool:
    """Return True if the response contains an auth decision status (not template evaluation)."""
    text = _response_text(response)
    return any(status in text for status in _AUTH_STATUSES)


def check_template_reflection(
    response: Any,
    expected: str,
    baseline: Any,
    raw_payload: str,
) -> tuple[bool, Optional[str]]:
    """Return (is_finding, pass_reason) for a template injection reflection check.

    All four conditions must hold for a finding:
    - response is not a CALLERROR
    - response does not indicate an auth decision (Rejected/Invalid/etc.)
    - expected evaluated string appears in response but not in clean baseline
    - raw payload string is not simply echoed back verbatim
    """
    if isinstance(response, list) and len(response) > 0 and response[0] == 4:
        return False, None

    if _is_auth_response(response):
        return False, "authorisation_response"

    text = _response_text(response)
    if expected not in text:
        return False, None

    baseline_text = _response_text(baseline) if baseline is not None else ""
    if expected in baseline_text:
        return False, None

    if raw_payload in text:
        return False, None

    return True, None


def responses_differ(resp_a: Any, resp_b: Any) -> bool:
    """Return True if two OCPP response payloads are observably different.

    Strips the per-call message ID (index 1 of the OCPP envelope) before
    comparing so that two calls with identical payloads but different UUIDs
    are not incorrectly reported as differing.
    """
    def _payload(r: Any) -> Any:
        # OCPP envelope: [type, msg_id, payload] — compare only the payload.
        if isinstance(r, list) and len(r) > 2:
            return r[2]
        return r

    def _normalise(r: Any) -> str:
        try:
            return json.dumps(_payload(r), sort_keys=True)
        except Exception:
            return str(_payload(r))

    return _normalise(resp_a) != _normalise(resp_b)
