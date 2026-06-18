from __future__ import annotations

import json
from typing import Any, Optional

TIMING_THRESHOLD_MULTIPLIER = 2.0
MIN_TIMING_THRESHOLD_SECONDS = 2.5

ERROR_SIGNATURES: dict[str, list[str]] = {
    "mysql": ["You have an error in your SQL syntax", "mysql_fetch", "MySQL server"],
    "mariadb": ["MariaDB", "SQLSTATE"],
    "postgresql": ["pg_query()", "PostgreSQL", "PSQLException"],
    "mssql": ["Unclosed quotation mark", "SQLServer", "OLE DB"],
    "sqlite": ["SQLite3::", "sqlite_query", "SQLITE_ERROR"],
    "generic": ["SQL syntax", "syntax error", "database error", "ORA-", "DB2 SQL"],
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


def check_error_strings(response: Any) -> Optional[str]:
    """Return the matched DB type if error signatures are found in response, else None."""
    try:
        text = json.dumps(response) if not isinstance(response, str) else response
    except Exception:
        text = str(response)
    text_lower = text.lower()
    for db_type, sigs in ERROR_SIGNATURES.items():
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
