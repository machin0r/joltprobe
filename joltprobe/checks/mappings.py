"""Central CWE classification for every JoltProbe check.

Keeping the mapping in one place (rather than scattered across check classes)
gives an auditor a single table to review, and lets a test assert that every
registered check has a classification. CWE ids are applied to the check classes
at import time in ``joltprobe.checks`` and flow into every CheckResult, so they
appear in the CLI listing and in JSON/Markdown/HTML reports.

Prose references to specific OCPP clauses stay on the individual findings via the
existing ``references`` field; this table is the machine-usable classification.
"""

from __future__ import annotations

CWE_MAP: dict[str, list[str]] = {
    # ── TLS ──────────────────────────────────────────────────────────────
    "tls.no-tls": ["CWE-319"],          # Cleartext Transmission of Sensitive Information
    "tls.self-signed": ["CWE-295"],     # Improper Certificate Validation
    "tls.version": ["CWE-327"],         # Use of a Broken or Risky Cryptographic Algorithm
    "tls.ciphers": ["CWE-327"],
    "tls.no-client-cert": ["CWE-306"],  # Missing Authentication for Critical Function
    # ── Auth ─────────────────────────────────────────────────────────────
    "auth.no-basic-auth": ["CWE-306"],
    "auth.default-credentials": ["CWE-1392"],   # Use of Default Credentials
    "auth.arbitrary-charger-id": ["CWE-287"],   # Improper Authentication
    "auth.duplicate-identity": ["CWE-287"],
    "auth.no-boot-required": ["CWE-306"],
    "auth.idtag-enumeration": ["CWE-204"],      # Observable Response Discrepancy
    # ── Session ──────────────────────────────────────────────────────────
    "session.meter-without-transaction": ["CWE-345"],   # Insufficient Verification of Data Authenticity
    "session.stop-foreign-transaction": ["CWE-639"],    # Authorization Bypass Through User-Controlled Key
    "session.start-without-auth": ["CWE-862"],          # Missing Authorization
    "session.local-auth-list-abuse": ["CWE-862"],
    "session.connector-status-spoof": ["CWE-345"],
    "session.transaction-id-enumeration": ["CWE-340"],  # Generation of Predictable Numbers/IDs
    "session.concurrent-transactions": ["CWE-362"],     # Race Condition
    # ── Downgrade ────────────────────────────────────────────────────────
    "downgrade.profile-reconnect": ["CWE-757"],  # Selection of Less-Secure Algorithm During Negotiation
    "downgrade.change-config": ["CWE-757"],
    "downgrade.stale-profile": ["CWE-613"],      # Insufficient Session Expiration
    # ── Message handling ─────────────────────────────────────────────────
    "message.malformed-json": ["CWE-20"],        # Improper Input Validation
    "message.oversized-fields": ["CWE-20"],
    "message.wrong-types": ["CWE-20"],
    "message.injection-charger-id": ["CWE-74"],  # Injection
    "message.unknown-action": ["CWE-20"],
    "message.missing-required-fields": ["CWE-20"],
    "message.deeply-nested-json": ["CWE-674"],   # Uncontrolled Recursion
    "message.timestamp-skew": ["CWE-20"],
    "message.unicode-null-bytes": ["CWE-158"],   # Improper Neutralization of Null Byte
    # ── Billing ──────────────────────────────────────────────────────────
    "billing.negative-meter-value": ["CWE-840"],   # Business Logic Errors
    "billing.inflated-meter-value": ["CWE-840"],
    # ── WebSocket ────────────────────────────────────────────────────────
    "websocket.no-subprotocol": ["CWE-20"],
    "websocket.wrong-subprotocol": ["CWE-20"],
    # ── DoS ──────────────────────────────────────────────────────────────
    "dos.connection-flood": ["CWE-400"],   # Uncontrolled Resource Consumption
    "dos.message-rate": ["CWE-770"],       # Allocation of Resources Without Limits or Throttling
    "dos.large-payload": ["CWE-400"],
    # ── Injection ────────────────────────────────────────────────────────
    "injection.chargeboxid": ["CWE-74"],
    "injection.idtag": ["CWE-74"],
    "injection.messageid": ["CWE-74"],
    "injection.metervalues": ["CWE-74"],
    "injection.reason": ["CWE-74"],
    "injection.vendorid": ["CWE-74"],
    "injection.soap": ["CWE-91"],          # XML Injection
    # ── Certificate management (OCPP 2.0.1) ──────────────────────────────
    "cert.sign-preboot": ["CWE-862", "CWE-295"],
    "cert.sign-malformed": ["CWE-20", "CWE-295"],
    # ── Firmware / diagnostics URL handling ──────────────────────────────
    "firmware.update-url": ["CWE-918", "CWE-494"],       # SSRF + Download of Code Without Integrity Check
    "firmware.diagnostics-url": ["CWE-918", "CWE-200"],  # SSRF + Exposure of Sensitive Information
}


def apply_cwe(check_classes) -> None:
    """Attach the CWE classification to each check class in place."""
    for cls in check_classes:
        cls.cwe = CWE_MAP.get(cls.id, [])
