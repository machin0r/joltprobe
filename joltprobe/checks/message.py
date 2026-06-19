from __future__ import annotations

import asyncio
import base64
import json

import websockets

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


_INJECTION_CHARGER_IDS = [
    "' OR '1'='1",
    "admin'--",
    "../../../etc/passwd",
    "CP001\r\nX-Injected: header",
    "<script>alert(1)</script>",
]


class MessageMalformedJson(BaseCheck):
    id = "message.malformed-json"
    name = "Malformed JSON accepted"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends syntactically invalid JSON (truncated frames, mismatched brackets, invalid escapes) over the WebSocket."
    fail = "The server did not close the connection or return a protocol error. Malformed input may cause undefined behaviour."
    pass_ = "The server closed the connection or returned a CALLERROR for malformed JSON."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        malformed_payloads = [
            "{invalid json",
            "[2, 'id', 'Heartbeat', {]",
            "null",
            "[]",
            "true",
        ]

        accepted_any = False
        evidence_list = []

        for payload_str in malformed_payloads:
            try:
                await conn.send_raw(payload_str)
                try:
                    raw = await asyncio.wait_for(conn._ws.recv(), timeout=3.0)
                    data = json.loads(raw)
                    if isinstance(data, list) and data[0] == 4:
                        evidence_list.append({"payload": payload_str, "response": "CALLERROR (correct)"})
                    else:
                        accepted_any = True
                        evidence_list.append({"payload": payload_str, "response": str(data)[:100], "issue": "non-error response"})
                except asyncio.TimeoutError:
                    accepted_any = True
                    evidence_list.append({"payload": payload_str, "response": "timeout (no CALLERROR returned)"})
            except Exception as e:
                evidence_list.append({"payload": payload_str, "send_error": str(e)[:100]})
                break

        await conn.close()

        if accepted_any:
            return self._fail(
                "CSMS did not return a CALLERROR for structurally invalid JSON",
                evidence={"samples": evidence_list},
                remediation=(
                    "Parse and validate all incoming WebSocket messages. "
                    "Return a CALLERROR with code 'FormationViolation' for malformed JSON."
                ),
                references=["OCPP 1.6 Section 4", "OCPP 2.0.1 Section 4"],
            )
        return self._pass(
            "CSMS returned CALLERROR for all malformed JSON inputs",
            evidence={"samples": evidence_list[:3]},
        )


class MessageOversizedFields(BaseCheck):
    id = "message.oversized-fields"
    name = "Oversized string fields accepted"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP messages with string fields many times larger than the specified OCPP maximums."
    fail = "Oversized fields were accepted. Buffer overflows or database truncation issues may exist downstream."
    pass_ = "The server rejected messages containing oversized field values."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        oversized = "A" * 10_000
        if self.session.version == "1.6":
            payload: dict = {
                "connectorId": 1,
                "idTag": oversized[:20] + "X" * 980,
                "meterStart": 0,
                "timestamp": "2024-01-01T00:00:00Z",
            }
            action = "StartTransaction"
        else:
            payload = {
                "reason": "PowerUp",
                "chargingStation": {"model": oversized, "vendorName": oversized},
            }
            action = "BootNotification"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            await conn.close()
            if msg_type == 3:
                return self._fail(
                    f"CSMS accepted a message with a string field of length {len(oversized)} characters",
                    evidence={"field_length": len(oversized), "action": action},
                    remediation=(
                        "Enforce OCPP spec-defined field length limits. "
                        "Return FormationViolation CALLERROR for fields exceeding maximum length."
                    ),
                    references=["OCPP 1.6 Appendix 3", "OCPP 2.0.1 Appendix"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for oversized field",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive(
                "No response to oversized field message (timeout)",
                evidence={"field_length": len(oversized)},
            )
        except Exception as e:
            await conn.close()
            return self._error(str(e))


class MessageWrongTypes(BaseCheck):
    id = "message.wrong-types"
    name = "Incorrect field types accepted"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP messages with incorrect field types (e.g. integer where a string is expected)."
    fail = "Type-mismatched fields were accepted. Type coercion bugs or unexpected code paths may be triggered."
    pass_ = "The server rejected messages with incorrect field types."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        # connectorId should be integer, send a string
        if self.session.version == "1.6":
            payload: dict = {
                "connectorId": "one",        # wrong: should be integer
                "idTag": "TEST",
                "meterStart": "zero",        # wrong: should be integer
                "timestamp": 12345,          # wrong: should be string
            }
            action = "StartTransaction"
        else:
            payload = {
                "reason": 42,               # wrong: should be string
                "chargingStation": "not-an-object",  # wrong: should be object
            }
            action = "BootNotification"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            await conn.close()
            if msg_type == 3:
                return self._fail(
                    "CSMS accepted a message with incorrect field types (e.g. string where integer expected)",
                    evidence={"action": action, "bad_fields": {"connectorId": "string instead of int"}},
                    remediation=(
                        "Validate field types against the OCPP JSON schema before processing. "
                        "Return TypeConstraintViolation CALLERROR for type mismatches."
                    ),
                    references=["OCPP 1.6 Appendix 3", "OCPP 2.0.1 Section 4"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for wrong field types",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive("No response to wrong-type message (timeout)")
        except Exception as e:
            await conn.close()
            return self._error(str(e))


class MessageInjectionChargerId(BaseCheck):
    id = "message.injection-charger-id"
    name = "Injection payload in charger ID"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Uses a charger ID containing SQL, XSS, and path traversal payloads in the WebSocket URL path."
    fail = "The server accepted the connection. The charger ID value likely reaches log storage or a database unsanitised."
    pass_ = "The server rejected or safely handled the injection payload in the charger ID path."

    async def run(self) -> CheckResult:
        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        connect_kwargs: dict = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        accepted: list[str] = []

        for charger_id in _INJECTION_CHARGER_IDS:
            url = f"{self.session.target.rstrip('/')}/{charger_id}"
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(url, subprotocols=[subprotocol], **connect_kwargs),
                    timeout=self.session.timeout,
                )
                await ws.close()
                accepted.append(charger_id)
            except Exception:
                pass

        if accepted:
            return self._fail(
                f"CSMS accepted connections with injection payload charger IDs ({len(accepted)} accepted)",
                evidence={"accepted_payloads": accepted},
                remediation=(
                    "Validate charger IDs against the OCPP spec format (alphanumeric, max 20 chars). "
                    "Reject connections where the charger ID URL path segment contains special characters. "
                    "Sanitise charger IDs before use in SQL queries and log statements."
                ),
                references=["CWE-89", "CWE-117", "OCPP 1.6 Appendix 3"],
            )
        return self._pass(
            "CSMS rejected all injection payload charger IDs at the connection level",
            evidence={"tested_payloads": len(_INJECTION_CHARGER_IDS)},
        )


class MessageUnknownAction(BaseCheck):
    id = "message.unknown-action"
    name = "Unknown action handling"
    severity = Severity.LOW
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends CALL frames with action names not defined in the OCPP specification."
    fail = "The server did not return a CALLERROR. Unknown actions are silently accepted, masking protocol violations."
    pass_ = "The server returned CALLERROR NotImplemented or NotSupported for the unknown action."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        try:
            resp = await conn.send_call("JoltProbeProbe_NonExistentAction_XYZ", {})
            msg_type = resp[0]
            if msg_type == 4:
                error_code = resp[2] if len(resp) > 2 else ""
                return self._pass(
                    "CSMS returned a well-formed CALLERROR for an unknown action",
                    evidence={"error_code": error_code, "action": "JoltProbeProbe_NonExistentAction_XYZ"},
                )
            return self._fail(
                "CSMS returned a CALLRESULT (not CALLERROR) for an unknown action",
                evidence={"response_type": msg_type, "response": resp},
                remediation=(
                    "Return a CALLERROR with code 'NotImplemented' or 'NotSupported' "
                    "for unrecognised action types."
                ),
                references=["OCPP 1.6 Section 4", "OCPP 2.0.1 Section 4"],
            )
        except asyncio.TimeoutError:
            return self._fail(
                "CSMS did not respond to an unknown action (timeout — possible crash or hang)",
                evidence={"action": "JoltProbeProbe_NonExistentAction_XYZ"},
                remediation="Return a CALLERROR for unknown action types rather than silently dropping them.",
                references=["OCPP 1.6 Section 4"],
            )
        except Exception as e:
            return self._error(str(e))


class MessageDeeplyNestedJson(BaseCheck):
    id = "message.deeply-nested-json"
    name = "Deeply nested JSON"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends a JSON payload with 200+ levels of recursive nesting inside an OCPP message."
    fail = "The server processed the deeply nested payload. Recursive parsers may stack overflow under load."
    pass_ = "The server rejected or disconnected for the pathologically nested payload."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        if self.session.version == "1.6":
            inner: dict = {"chargePointModel": "JoltProbe", "chargePointVendor": "JoltProbe"}
        else:
            inner = {"reason": "PowerUp", "chargingStation": {"model": "JoltProbe", "vendorName": "JoltProbe"}}

        payload: dict = inner
        for _ in range(500):
            payload = {"a": payload}

        try:
            resp = await conn.send_call("BootNotification", payload)
            await conn.close()
            if resp[0] == 4:
                return self._pass(
                    "CSMS returned a prompt CALLERROR for a 500-level deeply nested JSON payload",
                    evidence={"nesting_depth": 500, "callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._fail(
                "CSMS returned CALLRESULT (not CALLERROR) for a 500-level deeply nested JSON payload",
                evidence={"nesting_depth": 500, "response_type": resp[0]},
                remediation=(
                    "Set a maximum JSON nesting depth in the parser (e.g. 32 levels). "
                    "Return FormationViolation CALLERROR for payloads exceeding the depth limit."
                ),
                references=["OCPP 1.6 Section 4", "CVE-2020-25658"],
            )
        except asyncio.TimeoutError:
            await conn.close()
            return self._fail(
                "CSMS did not respond to a 500-level deeply nested JSON payload within timeout (possible parser recursion/DoS)",
                evidence={"nesting_depth": 500},
                remediation=(
                    "Set a maximum JSON nesting depth in the parser. "
                    "Return FormationViolation CALLERROR for excessively nested payloads rather than hanging."
                ),
                references=["OCPP 1.6 Section 4", "CVE-2020-25658"],
            )
        except Exception as e:
            await conn.close()
            return self._error(str(e))


class MessageTimestampSkew(BaseCheck):
    id = "message.timestamp-skew"
    name = "Extreme timestamp values"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP messages with timestamps set years in the past or future."
    fail = "Extreme timestamps were accepted without rejection. Billing records can be backdated or postdated."
    pass_ = "The server rejected or normalised extreme timestamp values."

    def _meter_payload_with_ts(self, ts: str) -> dict:
        if self.session.version == "1.6":
            return {
                "connectorId": 1,
                "meterValue": [{
                    "timestamp": ts,
                    "sampledValue": [{"value": "0", "unit": "Wh"}],
                }],
            }
        return {
            "evseId": 1,
            "meterValue": [{
                "timestamp": ts,
                "sampledValue": [{
                    "value": 0,
                    "measurand": "Energy.Active.Import.Register",
                    "unitOfMeasure": {"unit": "Wh"},
                }],
            }],
        }

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        extreme_timestamps = [
            "1970-01-01T00:00:00Z",
            "2099-12-31T23:59:59Z",
        ]
        accepted = []
        responses = []

        for ts in extreme_timestamps:
            try:
                resp = await conn.send_call("MeterValues", self._meter_payload_with_ts(ts))
                if resp[0] == 3:
                    accepted.append(ts)
                responses.append({
                    "timestamp": ts,
                    "response_type": "CALLRESULT" if resp[0] == 3 else "CALLERROR",
                })
            except asyncio.TimeoutError:
                responses.append({"timestamp": ts, "response_type": "timeout"})
            except Exception as e:
                responses.append({"timestamp": ts, "error": str(e)[:100]})

        if accepted:
            return self._fail(
                f"CSMS accepted MeterValues with extreme timestamp(s): {accepted}",
                evidence={"accepted_timestamps": accepted, "responses": responses},
                remediation=(
                    "Enforce a clock-skew window on timestamp fields (e.g. reject timestamps more than 24 hours "
                    "from server time). Validate timestamp ranges before writing to time-series databases."
                ),
                references=["OCPP 1.6 Section 5.11", "OCPP 2.0.1 Section 12.4"],
            )
        return self._pass(
            "CSMS returned error for all extreme timestamp values",
            evidence={"tested_timestamps": extreme_timestamps, "responses": responses},
        )


class MessageUnicodeNullBytes(BaseCheck):
    id = "message.unicode-null-bytes"
    name = "Unicode and null byte injection"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Embeds null bytes (\\u0000), Unicode control characters, and bidirectional markers in string fields."
    fail = "Payloads with null bytes or control characters were accepted. Log injection or database truncation may result."
    pass_ = "The server rejected or safely handled dangerous Unicode and null-byte content."

    async def run(self) -> CheckResult:
        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        connect_kwargs: dict = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        def _boot_msg(vendor: str) -> str:
            if self.session.version == "1.6":
                payload = {"chargePointVendor": vendor, "chargePointModel": "JoltProbe"}
            else:
                payload = {"reason": "PowerUp", "chargingStation": {"model": "JoltProbe", "vendorName": vendor}}
            return json.dumps([2, "uni001", "BootNotification", payload])

        injection_cases = [
            ("null_byte", "vendor\x00injection"),
            ("rtl_override", "vendor‮injection"),
            ("unicode_bom", "﻿vendor"),
        ]
        lone_surrogate_raw = (
            '[2, "uni002", "BootNotification", '
            '{"chargePointVendor": "vendor\\ud800injection", "chargePointModel": "JoltProbe"}]'
        )

        accepted = []
        evidence_list = []

        all_cases = [(n, None, s) for n, s in injection_cases] + [("lone_surrogate", lone_surrogate_raw, None)]

        for case_name, raw_msg, injection_str in all_cases:
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(url, subprotocols=[subprotocol], **connect_kwargs),
                    timeout=self.session.timeout,
                )
                try:
                    if raw_msg:
                        msg = raw_msg
                    else:
                        msg = _boot_msg(injection_str)  # type: ignore[arg-type]
                    await ws.send(msg)
                    raw_resp = await asyncio.wait_for(ws.recv(), timeout=self.session.timeout)
                    data = json.loads(raw_resp)
                    is_callresult = isinstance(data, list) and data[0] == 3
                    if is_callresult:
                        accepted.append(case_name)
                    evidence_list.append({
                        "case": case_name,
                        "response_type": "CALLRESULT" if is_callresult else "CALLERROR/other",
                    })
                except asyncio.TimeoutError:
                    evidence_list.append({"case": case_name, "response_type": "timeout"})
                except Exception as exc:
                    evidence_list.append({"case": case_name, "error": str(exc)[:100]})
                finally:
                    try:
                        await ws.close()
                    except Exception:
                        pass
            except Exception as exc:
                evidence_list.append({"case": case_name, "connection_error": str(exc)[:100]})

        if accepted:
            return self._fail(
                f"CSMS accepted BootNotification with malicious Unicode/null injection(s): {accepted}",
                evidence={"accepted_cases": accepted, "details": evidence_list},
                remediation=(
                    "Sanitise string fields in incoming OCPP messages. "
                    "Reject or strip null bytes, lone Unicode surrogates, and bidirectional control characters. "
                    "Return FormationViolation CALLERROR for payloads containing disallowed characters."
                ),
                references=["CWE-116", "CWE-20", "OCPP 1.6 Appendix 3"],
            )

        connection_errors = [e for e in evidence_list if "connection_error" in e]
        if len(connection_errors) == len(all_cases):
            first_err = connection_errors[0].get("connection_error", "")
            return self._error(
                f"Could not connect for any injection case — check credentials or target: {first_err}"
            )

        return self._pass(
            "CSMS rejected all Unicode and null byte injection payloads",
            evidence={"details": evidence_list},
        )


class MessageMissingRequiredFields(BaseCheck):
    id = "message.missing-required-fields"
    name = "Missing required fields accepted"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP messages with required fields absent from the payload."
    fail = "Messages with missing required fields were processed. Schema validation is not enforced server-side."
    pass_ = "The server returned a CALLERROR for messages with missing required fields."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        # BootNotification requires chargePointModel and chargePointVendor (1.6)
        if self.session.version == "1.6":
            payload: dict = {}  # all required fields missing
            action = "BootNotification"
        else:
            payload = {"reason": "PowerUp"}  # chargingStation is required but missing
            action = "BootNotification"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            await conn.close()
            if msg_type == 3:
                return self._fail(
                    f"CSMS accepted a {action} message with required fields omitted",
                    evidence={"action": action, "sent_payload": payload},
                    remediation=(
                        "Validate all required fields against the OCPP JSON schema before processing. "
                        "Return TypeConstraintViolation or OccurrenceConstraintViolation CALLERROR."
                    ),
                    references=["OCPP 1.6 Section 4.2.1", "OCPP 2.0.1 Section 4"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for message with missing required fields",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive("No response to message with missing required fields (timeout)")
        except Exception as e:
            await conn.close()
            return self._error(str(e))
