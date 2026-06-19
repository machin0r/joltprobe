from __future__ import annotations

import asyncio
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

import yaml

from ocppscan.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity
from ocppscan.connection import OCPPConnection
from ocppscan.injection.baseline import establish_baseline, establish_connection_baseline
from ocppscan.injection.detector import (
    check_error_leak,
    check_error_strings,
    check_reflection,
    is_timing_anomaly,
    responses_differ,
)

_PAYLOADS_DIR = Path(__file__).parent / "payloads"


def _load_payloads(methods: list[str]) -> list[dict]:
    entries: list[dict] = []
    for method in methods:
        path = _PAYLOADS_DIR / f"{method}.yaml"
        try:
            data = yaml.safe_load(path.read_text())
            if isinstance(data, list):
                entries.extend(data)
        except Exception:
            pass
    return entries


def _second_order_guidance() -> list[str]:
    return [
        "Steve: Operations → Send Local List (retrieves stored idTags); "
        "Data Management → Transactions (queries by stored charger ID); "
        "Steve REST API: query transaction history for the affected charger ID.",
        "OCPP.Core: trigger GetConfiguration from CSMS to charger; "
        "query transaction log via web UI.",
        "CitrineOS: trigger a reporting or export operation via the REST API.",
        "General: watch for page load time increases (time-based blind), "
        "database errors in UI/API responses, or behavioural differences between "
        "stored clean values and stored injection payloads.",
    ]


# ──────────────────────────────────────────────────────────────
# Shared base for OCPP message field checks
# ──────────────────────────────────────────────────────────────

class _BaseFieldCheck(BaseCheck):
    """Base for checks that inject into an OCPP message field."""

    connection_mode = ConnectionMode.DEDICATED
    _applicable_methods: list[str] = []
    _field_name: str = ""
    _remediation: str = ""
    _references: list[str] = []

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        raise NotImplementedError

    async def _clean_probe(self, conn: OCPPConnection) -> Any:
        """Send a clean probe that should return a predictable response."""
        return await self._send_payload(conn, "PROBE_CLEAN")

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        baseline_ms = await establish_baseline(conn)

        payloads = _load_payloads(self._applicable_methods)

        by_id = {p["id"]: p for p in payloads}
        handled: set[str] = set()
        findings: list[dict] = []
        second_order: list[dict] = []
        tested = 0

        clean_resp: Optional[Any] = None
        if any(p.get("method") == "nosql" for p in payloads):
            try:
                clean_resp = await self._clean_probe(conn)
            except Exception:
                pass

        for entry in payloads:
            pid = entry["id"]
            if pid in handled:
                continue

            signal = entry.get("signal", "")

            if signal == "boolean":
                pair_id = entry.get("pair")
                if pair_id and pair_id in by_id:
                    handled.add(pid)
                    handled.add(pair_id)
                    finding = await self._test_boolean_pair(
                        conn, entry, by_id[pair_id]
                    )
                    tested += 2
                    if finding:
                        findings.append(finding)
                continue

            if signal == "behavioural" and entry.get("method") == "nosql":
                finding = await self._test_nosql_behavioural(
                    conn, entry, clean_resp
                )
                tested += 1
                if finding:
                    findings.append(finding)
                continue

            finding = await self._test_single(conn, entry, baseline_ms)
            tested += 1
            if finding:
                if finding.get("status") == "INCONCLUSIVE":
                    second_order.append(finding)
                else:
                    findings.append(finding)

        await conn.close()

        if findings:
            return self._fail(
                f"Injection signal detected in {self._field_name} field "
                f"({len(findings)} finding(s))",
                evidence={
                    "field": self._field_name,
                    "payloads_tested": tested,
                    "findings": findings,
                    "second_order_candidates": second_order,
                },
                remediation=self._remediation,
                references=self._references,
            )

        if second_order:
            return self._inconclusive(
                f"INCONCLUSIVE — second-order injection candidates in {self._field_name}. "
                "Timing payloads accepted without delay. Manual retrieval testing required.",
                evidence={
                    "field": self._field_name,
                    "payloads_tested": tested,
                    "second_order_candidates": second_order,
                    "manual_testing_guidance": _second_order_guidance(),
                },
            )

        return self._pass(
            f"No injection signals in {self._field_name} ({tested} payloads tested)",
            evidence={"field": self._field_name, "payloads_tested": tested},
        )

    async def _test_single(
        self,
        conn: OCPPConnection,
        entry: dict,
        baseline_ms: float,
    ) -> Optional[dict]:
        payload_str = entry["payload"]
        signal = entry.get("signal", "")
        method = entry.get("method", "")

        start = time.monotonic()
        resp: Any = None
        try:
            resp = await self._send_payload(conn, payload_str)
            elapsed = (time.monotonic() - start) * 1000.0
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000.0
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000.0
            resp = {"_exc": str(exc)[:300]}

        if resp is not None:
            db_error = check_error_strings(resp)
            if db_error:
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "db_error",
                    "payload": payload_str,
                    "db_error_type": db_error,
                    "response": str(resp)[:300],
                    "elapsed_ms": round(elapsed, 1),
                }
            leak = check_error_leak(resp)
            if leak:
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "db_error_leaked",
                    "payload": payload_str,
                    "db_error_type": leak,
                    "response": str(resp)[:300],
                    "elapsed_ms": round(elapsed, 1),
                    "note": (
                        "Internal DB/ORM error details returned in the CALLERROR — "
                        "the input reached the DB layer unsanitised. "
                        "The DB may have rejected the value, but the error exposes the ORM/DB stack."
                    ),
                }

        if signal == "timing" and entry.get("delay_seconds"):
            expected_delay = float(entry["delay_seconds"])
            if is_timing_anomaly(baseline_ms, elapsed, expected_delay):
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "timing",
                    "payload": payload_str,
                    "elapsed_ms": round(elapsed, 1),
                    "baseline_ms": round(baseline_ms, 1),
                    "expected_delay_s": expected_delay,
                }
            return None

        if method == "template" and "expected_reflection" in entry:
            if resp is not None and check_reflection(resp, entry["expected_reflection"]):
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "reflection",
                    "payload": payload_str,
                    "expected_reflection": entry["expected_reflection"],
                    "response": str(resp)[:300],
                    "elapsed_ms": round(elapsed, 1),
                }

        # Log injection is unconfirmable remotely — we can send the payload but
        # cannot read the server log to verify it landed unescaped. Connection
        # close is the only black-box signal; everything else is INCONCLUSIVE.
        if method in ("log", "crlf") and signal in (
            "error_or_connection_close",
            "response_header",
        ):
            if resp is None:
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "connection_closed_on_control_chars",
                    "payload": repr(payload_str),
                    "elapsed_ms": round(elapsed, 1),
                    "note": "CSMS closed connection or timed out on payload with control characters",
                }
            if isinstance(resp, list) and resp[0] == 4:
                # CALLERROR is ambiguous: could be field validation (length/enum)
                # rather than rejection of control characters specifically.
                return {
                    "status": "INCONCLUSIVE",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "callerror_ambiguous",
                    "payload": repr(payload_str),
                    "response": str(resp)[:200],
                    "elapsed_ms": round(elapsed, 1),
                    "note": "CSMS returned CALLERROR — could be field validation (length/enum) "
                            "rather than reaction to control characters; verify log output manually",
                }
            if isinstance(resp, list) and resp[0] == 3:
                return {
                    "status": "INCONCLUSIVE",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "control_chars_not_rejected",
                    "payload": repr(payload_str),
                    "elapsed_ms": round(elapsed, 1),
                    "note": "CSMS accepted payload without stripping control characters — "
                            "verify log output manually to confirm injection",
                }

        return None

    async def _test_boolean_pair(
        self,
        conn: OCPPConnection,
        true_entry: dict,
        false_entry: dict,
    ) -> Optional[dict]:
        try:
            resp_true = await self._send_payload(conn, true_entry["payload"])
        except Exception:
            resp_true = None

        try:
            resp_false = await self._send_payload(conn, false_entry["payload"])
        except Exception:
            resp_false = None

        if responses_differ(resp_true, resp_false):
            return {
                "status": "FAIL",
                "payload_id": true_entry["id"],
                "method": "sql",
                "signal": "boolean",
                "true_payload": true_entry["payload"],
                "false_payload": false_entry["payload"],
                "true_response": str(resp_true)[:200],
                "false_response": str(resp_false)[:200],
            }
        return None

    async def _test_nosql_behavioural(
        self,
        conn: OCPPConnection,
        entry: dict,
        clean_resp: Any,
    ) -> Optional[dict]:
        try:
            resp = await self._send_payload(conn, entry["payload"])
        except Exception:
            resp = None

        if clean_resp is not None and resp is not None and responses_differ(clean_resp, resp):
            return {
                "status": "FAIL",
                "payload_id": entry["id"],
                "method": "nosql",
                "signal": "behavioural",
                "payload": entry["payload"],
                "clean_response": str(clean_resp)[:200],
                "injected_response": str(resp)[:200],
                "note": "response differs from clean probe — possible NoSQL operator injection",
            }
        return None


# ──────────────────────────────────────────────────────────────
# injection.chargeboxid
# ──────────────────────────────────────────────────────────────

class InjectionChargeBoxId(BaseCheck):
    id = "injection.chargeboxid"
    name = "Injection in chargeBoxId (URL path)"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Connects with a charger ID containing SQL, NoSQL, log, and template injection payloads in the URL path."
    fail = "Anomalous server behaviour detected. The charger ID likely reaches an injectable context (database, log, template engine)."
    pass_ = "No anomalous behaviour detected. The charger ID appears to be handled safely."

    async def run(self) -> CheckResult:
        baseline_ms = await establish_connection_baseline(self.session)

        payloads = _load_payloads(["sql", "nosql", "log", "template", "xml"])
        by_id = {p["id"]: p for p in payloads}
        handled: set[str] = set()
        findings: list[dict] = []
        second_order: list[dict] = []
        tested = 0

        for entry in payloads:
            pid = entry["id"]
            if pid in handled:
                continue

            signal = entry.get("signal", "")

            if signal == "boolean":
                pair_id = entry.get("pair")
                if pair_id and pair_id in by_id:
                    handled.add(pid)
                    handled.add(pair_id)
                    finding = await self._test_chargeboxid_boolean(
                        entry, by_id[pair_id]
                    )
                    tested += 2
                    if finding:
                        findings.append(finding)
                continue

            finding = await self._test_chargeboxid_payload(entry, baseline_ms)
            tested += 1
            if finding:
                if finding.get("status") == "INCONCLUSIVE":
                    second_order.append(finding)
                else:
                    findings.append(finding)

        if findings:
            return self._fail(
                f"Injection signal detected in chargeBoxId ({len(findings)} finding(s))",
                evidence={
                    "field": "chargeBoxId",
                    "payloads_tested": tested,
                    "findings": findings,
                    "second_order_candidates": second_order,
                },
                remediation=(
                    "Validate charger IDs against the OCPP spec format (alphanumeric/hyphen, "
                    "max 20 chars). Use parameterised queries for all charger ID lookups. "
                    "Strip control characters before logging."
                ),
                references=["CWE-89", "CWE-94", "CWE-117", "OCPP 1.6 Appendix 3"],
            )

        if second_order:
            return self._inconclusive(
                "INCONCLUSIVE — second-order injection candidates in chargeBoxId. "
                "Timing payloads accepted without delay. Manual retrieval testing required.",
                evidence={
                    "field": "chargeBoxId",
                    "payloads_tested": tested,
                    "second_order_candidates": second_order,
                    "manual_testing_guidance": _second_order_guidance(),
                },
            )

        return self._pass(
            f"No injection signals in chargeBoxId ({tested} payloads tested)",
            evidence={"field": "chargeBoxId", "payloads_tested": tested},
        )

    async def _test_chargeboxid_payload(
        self,
        entry: dict,
        baseline_ms: float,
    ) -> Optional[dict]:
        payload_str = entry["payload"]
        signal = entry.get("signal", "")
        method = entry.get("method", "")

        start = time.monotonic()
        conn: Optional[OCPPConnection] = None
        boot_resp: Any = None
        conn_error: Optional[str] = None
        try:
            conn = await self.session.new_connection(
                charger_id=payload_str,
                send_boot=False,
            )
            # Time BootNotification separately — the charger ID DB lookup happens here,
            # not during the WebSocket handshake.
            boot_start = time.monotonic()
            try:
                assert conn is not None
                boot_resp = await conn.send_call(
                    "BootNotification",
                    {"chargePointModel": "OCPPScan", "chargePointVendor": "OCPPScan"}
                    if self.session.version == "1.6"
                    else {
                        "reason": "PowerUp",
                        "chargingStation": {"model": "OCPPScan", "vendorName": "OCPPScan"},
                    },
                )
            except asyncio.TimeoutError:
                boot_resp = None
            elapsed = (time.monotonic() - boot_start) * 1000.0
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000.0
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000.0
            conn_error = str(exc)[:300]
        finally:
            if conn:
                await conn.close()

        error_source = conn_error or (str(boot_resp) if boot_resp else "")

        if error_source:
            db_error = check_error_strings(error_source)
            if db_error:
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "db_error",
                    "payload": payload_str,
                    "db_error_type": db_error,
                    "response": error_source[:300],
                    "elapsed_ms": round(elapsed, 1),
                }
            leak = check_error_leak(error_source)
            if leak:
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "db_error_leaked",
                    "payload": payload_str,
                    "db_error_type": leak,
                    "response": error_source[:300],
                    "elapsed_ms": round(elapsed, 1),
                    "note": (
                        "Internal DB/ORM error details returned in the CALLERROR — "
                        "the input reached the DB layer unsanitised. "
                        "The DB may have rejected the value, but the error exposes the ORM/DB stack."
                    ),
                }

        if signal == "timing" and entry.get("delay_seconds"):
            expected_delay = float(entry["delay_seconds"])
            if is_timing_anomaly(baseline_ms, elapsed, expected_delay):
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "timing",
                    "payload": payload_str,
                    "elapsed_ms": round(elapsed, 1),
                    "baseline_ms": round(baseline_ms, 1),
                    "expected_delay_s": expected_delay,
                }
            return None

        if method == "template" and "expected_reflection" in entry:
            if error_source and check_reflection(error_source, entry["expected_reflection"]):
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "reflection",
                    "payload": payload_str,
                    "expected_reflection": entry["expected_reflection"],
                    "response": error_source[:300],
                    "elapsed_ms": round(elapsed, 1),
                }

        if method in ("log", "crlf") and conn is not None and boot_resp is not None:
            if isinstance(boot_resp, list) and boot_resp[0] == 3:
                return {
                    "status": "INCONCLUSIVE",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "control_chars_not_rejected",
                    "payload": repr(payload_str),
                    "elapsed_ms": round(elapsed, 1),
                    "note": "CSMS accepted charger ID containing control characters — "
                            "verify log output manually to confirm injection",
                }

        return None

    async def _test_chargeboxid_boolean(
        self,
        true_entry: dict,
        false_entry: dict,
    ) -> Optional[dict]:
        async def _attempt(charger_id: str) -> Any:
            try:
                conn = await self.session.new_connection(
                    charger_id=charger_id,
                    send_boot=False,
                )
                try:
                    resp = await conn.send_call(
                        "BootNotification",
                        {"chargePointModel": "OCPPScan", "chargePointVendor": "OCPPScan"}
                        if self.session.version == "1.6"
                        else {
                            "reason": "PowerUp",
                            "chargingStation": {"model": "OCPPScan", "vendorName": "OCPPScan"},
                        },
                    )
                    return {"connected": True, "resp": resp}
                except Exception:
                    return {"connected": True, "resp": None}
                finally:
                    await conn.close()
            except Exception as exc:
                return {"connected": False, "error": str(exc)[:200]}

        resp_true = await _attempt(true_entry["payload"])
        resp_false = await _attempt(false_entry["payload"])

        if responses_differ(resp_true, resp_false):
            return {
                "status": "FAIL",
                "payload_id": true_entry["id"],
                "method": "sql",
                "signal": "boolean",
                "true_payload": true_entry["payload"],
                "false_payload": false_entry["payload"],
                "true_response": str(resp_true)[:200],
                "false_response": str(resp_false)[:200],
            }
        return None


# ──────────────────────────────────────────────────────────────
# injection.idtag
# ──────────────────────────────────────────────────────────────

class InjectionIdTag(_BaseFieldCheck):
    id = "injection.idtag"
    name = "Injection in idTag field"
    severity = Severity.HIGH
    applies_to = ["1.6", "2.0.1"]
    what = "Sends Authorize and StartTransaction with injection payloads in the idTag field."
    fail = "Anomalous responses suggest the idTag reaches an injectable context."
    pass_ = "No anomalous behaviour detected for injection payloads in idTag."
    _applicable_methods = ["sql", "nosql", "log", "template"]
    _field_name = "idTag"
    _remediation = (
        "Use parameterised queries for all idTag lookups. "
        "Validate idTag against OCPP spec format (alphanumeric, max 20 chars). "
        "Strip control characters before writing to logs."
    )
    _references = ["CWE-89", "CWE-94", "CWE-117", "OCPP 1.6 Section 5.4"]

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        if self.session.version == "1.6":
            return await conn.send_call("Authorize", {"idTag": payload_str})
        return await conn.send_call(
            "Authorize",
            {"idToken": {"idToken": payload_str, "type": "ISO14443"}},
        )


# ──────────────────────────────────────────────────────────────
# injection.vendorid
# ──────────────────────────────────────────────────────────────

class InjectionVendorId(_BaseFieldCheck):
    id = "injection.vendorid"
    name = "Injection in DataTransfer vendorId field"
    severity = Severity.HIGH
    applies_to = ["1.6", "2.0.1"]
    what = "Sends DataTransfer messages with injection payloads in the vendorId field."
    fail = "Anomalous responses suggest the vendorId field is not safely handled."
    pass_ = "No anomalous behaviour detected for injection payloads in vendorId."
    _applicable_methods = ["sql", "nosql", "log", "template"]
    _field_name = "vendorId"
    _remediation = (
        "Use parameterised queries when persisting DataTransfer vendorId. "
        "Validate vendorId length and character set. "
        "Strip control characters before logging."
    )
    _references = ["CWE-89", "CWE-94", "CWE-117", "OCPP 1.6 Section 7.1"]

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        return await conn.send_call(
            "DataTransfer",
            {"vendorId": payload_str, "messageId": "probe", "data": ""},
        )


# ──────────────────────────────────────────────────────────────
# injection.messageid
# ──────────────────────────────────────────────────────────────

class InjectionMessageId(_BaseFieldCheck):
    id = "injection.messageid"
    name = "Injection in DataTransfer messageId field"
    severity = Severity.MEDIUM
    applies_to = ["1.6", "2.0.1"]
    what = "Sends DataTransfer messages with injection payloads in the messageId field."
    fail = "Anomalous responses suggest the messageId field reaches an injectable context."
    pass_ = "No anomalous behaviour detected for injection payloads in messageId."
    _applicable_methods = ["sql", "log", "template"]
    _field_name = "messageId"
    _remediation = (
        "Use parameterised queries when persisting DataTransfer messageId. "
        "Strip control characters before logging."
    )
    _references = ["CWE-89", "CWE-117", "OCPP 1.6 Section 7.1"]

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        return await conn.send_call(
            "DataTransfer",
            {"vendorId": "OCPPScan", "messageId": payload_str, "data": ""},
        )


# ──────────────────────────────────────────────────────────────
# injection.reason
# ──────────────────────────────────────────────────────────────

class InjectionReason(_BaseFieldCheck):
    id = "injection.reason"
    name = "Injection in StopTransaction reason field"
    severity = Severity.MEDIUM
    applies_to = ["1.6"]
    what = "Sends StopTransaction messages with injection payloads in the reason field."
    fail = "Anomalous responses suggest the reason field is not safely handled."
    pass_ = "No anomalous behaviour detected for injection payloads in the reason field."
    _applicable_methods = ["sql", "log"]
    _field_name = "reason"
    _remediation = (
        "Use parameterised queries when persisting StopTransaction reason. "
        "Strip control characters before logging."
    )
    _references = ["CWE-89", "CWE-117", "OCPP 1.6 Section 5.11"]

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        ts = "2024-01-01T00:00:00Z"
        return await conn.send_call(
            "StopTransaction",
            {
                "transactionId": 999999,
                "meterStop": 0,
                "timestamp": ts,
                "reason": payload_str,
                "idTag": "OCPPScan",
            },
        )


# ──────────────────────────────────────────────────────────────
# injection.metervalues
# ──────────────────────────────────────────────────────────────

class InjectionMeterValues(_BaseFieldCheck):
    id = "injection.metervalues"
    name = "Injection in MeterValues measurand/location fields"
    severity = Severity.MEDIUM
    applies_to = ["1.6"]
    what = "Sends MeterValues with injection payloads in the measurand and location fields."
    fail = "Anomalous responses suggest meter value fields reach an injectable context."
    pass_ = "No anomalous behaviour detected for injection payloads in MeterValues fields."
    _applicable_methods = ["sql", "log"]
    _field_name = "measurand/location"
    _remediation = (
        "Use parameterised queries when persisting MeterValues fields. "
        "Validate measurand and location against OCPP enum values. "
        "Strip control characters before logging."
    )
    _references = ["CWE-89", "CWE-117", "OCPP 1.6 Section 5.9"]

    async def _send_payload(self, conn: OCPPConnection, payload_str: str) -> Any:
        ts = "2024-01-01T00:00:00Z"
        return await conn.send_call(
            "MeterValues",
            {
                "connectorId": 1,
                "meterValue": [
                    {
                        "timestamp": ts,
                        "sampledValue": [
                            {
                                "value": "100",
                                "measurand": payload_str,
                                "location": payload_str,
                            }
                        ],
                    }
                ],
            },
        )


# ──────────────────────────────────────────────────────────────
# injection.soap
# ──────────────────────────────────────────────────────────────

_SOAP_PATHS = [
    "/CSMS/ChargePointService",
    "/OCPP",
    "/OCPP/service",
    "/ocpp/soap",
]

_SOAP_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:cs="urn://Ocpp/Cs/2012/06/">
  <s:Header>
    <cs:chargeBoxIdentity>{chargeBoxId}</cs:chargeBoxIdentity>
  </s:Header>
  <s:Body>
    <cs:heartbeatRequest/>
  </s:Body>
</s:Envelope>"""


class InjectionSoap(BaseCheck):
    id = "injection.soap"
    name = "XML injection in SOAP endpoint"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6"]
    what = "Attempts to discover a SOAP endpoint and sends XML/XXE injection payloads."
    fail = "The server responded to XML injection indicating unsafe XML parsing (XXE or SSRF risk)."
    pass_ = "No SOAP endpoint found or XML payloads produced no anomalous behaviour."

    async def run(self) -> CheckResult:
        if not getattr(self.session.config, "enable_soap", False):
            return self._skip(
                "SOAP injection requires --soap flag. "
                "Run with --soap to include this check."
            )

        soap_base = self._derive_soap_base_url()
        endpoint_url = await self._find_soap_endpoint(soap_base)
        if not endpoint_url:
            return self._skip(
                f"No SOAP endpoint found at {soap_base} "
                f"(tried: {', '.join(_SOAP_PATHS)})"
            )

        payloads = _load_payloads(["xml"])
        findings: list[dict] = []
        tested = 0

        for entry in payloads:
            finding = await self._test_soap_payload(endpoint_url, entry)
            tested += 1
            if finding:
                findings.append(finding)

        if findings:
            return self._fail(
                f"XML injection signal at SOAP endpoint {endpoint_url} "
                f"({len(findings)} finding(s))",
                evidence={
                    "endpoint": endpoint_url,
                    "payloads_tested": tested,
                    "findings": findings,
                },
                remediation=(
                    "Validate and sanitise all chargeBoxId values before inserting into "
                    "SOAP/XML structures. Use an XML library's escaping rather than "
                    "string concatenation. Disable the SOAP endpoint if unused."
                ),
                references=["CWE-91", "CWE-611", "OCPP 1.5 SOAP spec"],
            )

        return self._pass(
            f"No XML injection signals at SOAP endpoint ({tested} payloads tested)",
            evidence={"endpoint": endpoint_url, "payloads_tested": tested},
        )

    def _derive_soap_base_url(self) -> str:
        parsed = urllib.parse.urlparse(self.session.target)
        scheme = "https" if parsed.scheme in ("wss",) else "http"
        host = parsed.netloc
        return f"{scheme}://{host}"

    async def _find_soap_endpoint(self, base_url: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        for path in _SOAP_PATHS:
            url = base_url + path
            try:
                def _probe(u: str) -> bool:
                    req = urllib.request.Request(
                        u,
                        method="POST",
                        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
                        data=b"<probe/>",
                    )
                    try:
                        urllib.request.urlopen(req, timeout=5)
                        return True
                    except urllib.error.HTTPError as e:
                        # Any HTTP response (even 400/500) means a server is there
                        return e.code < 503
                    except Exception:
                        return False

                found = await loop.run_in_executor(None, _probe, url)
                if found:
                    return url
            except Exception:
                pass
        return None

    async def _test_soap_payload(self, endpoint_url: str, entry: dict) -> Optional[dict]:
        payload_str = entry["payload"]
        method = entry.get("method", "xml")
        signal = entry.get("signal", "")

        body = _SOAP_TEMPLATE.format(chargeBoxId=payload_str).encode("utf-8")

        loop = asyncio.get_event_loop()

        def _post() -> tuple[int, str]:
            req = urllib.request.Request(
                endpoint_url,
                method="POST",
                headers={
                    "Content-Type": "application/soap+xml; charset=utf-8",
                    "SOAPAction": '""',
                },
                data=body,
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read(4096).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                return e.code, e.read(4096).decode("utf-8", errors="replace")
            except Exception as exc:
                return 0, str(exc)

        try:
            status_code, response_text = await loop.run_in_executor(None, _post)
        except Exception as exc:
            return None

        db_error = check_error_strings(response_text)
        if db_error:
            return {
                "status": "FAIL",
                "payload_id": entry["id"],
                "method": method,
                "signal": "error",
                "payload": payload_str,
                "db_error_type": db_error,
                "http_status": status_code,
                "response": response_text[:300],
            }

        if signal == "error" and status_code == 500:
            xml_error_terms = ["xml", "parse", "unexpected token", "well-formed", "entity"]
            resp_lower = response_text.lower()
            if any(t in resp_lower for t in xml_error_terms):
                return {
                    "status": "FAIL",
                    "payload_id": entry["id"],
                    "method": method,
                    "signal": "xml_parse_error",
                    "payload": payload_str,
                    "http_status": status_code,
                    "response": response_text[:300],
                    "note": "500 response with XML parse error — structure injection possible",
                }

        return None
