from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class BillingNegativeMeterValue(BaseCheck):
    id = "billing.negative-meter-value"
    name = "Negative energy meter reading"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends a MeterValues message reporting a negative energy reading (e.g. −999 Wh)."
    fail = "The negative reading was accepted. An attacker could generate credit-like billing entries."
    pass_ = "The server rejected or flagged the negative meter value."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        if self.session.version == "1.6":
            payload: dict = {
                "connectorId": 1,
                "meterValue": [{
                    "timestamp": _ts(),
                    "sampledValue": [{
                        "value": "-999999",
                        "measurand": "Energy.Active.Import.Register",
                        "unit": "Wh",
                    }],
                }],
            }
        else:
            payload = {
                "evseId": 1,
                "meterValue": [{
                    "timestamp": _ts(),
                    "sampledValue": [{
                        "value": -999999,
                        "measurand": "Energy.Active.Import.Register",
                        "unitOfMeasure": {"unit": "Wh"},
                    }],
                }],
            }

        try:
            resp = await conn.send_call("MeterValues", payload)
            if resp[0] == 3:
                return self._fail(
                    "CSMS accepted MeterValues with a large negative energy reading (-999999 Wh)",
                    evidence={
                        "injected_value": "-999999",
                        "measurand": "Energy.Active.Import.Register",
                        "response": resp[2] if len(resp) > 2 else {},
                    },
                    remediation=(
                        "Validate that energy meter readings are physically plausible (non-negative for import registers). "
                        "Reject or flag MeterValues where Energy.Active.Import.Register is negative."
                    ),
                    references=["OCPP 1.6 Section 5.11", "OCPP 2.0.1 Section 12.4"],
                )
            if resp[0] == 4:
                return self._pass(
                    "CSMS returned CALLERROR for MeterValues with a negative energy reading",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response type", evidence={"response": resp})
        except asyncio.TimeoutError:
            return self._inconclusive(
                "No response to MeterValues with negative value (timeout)",
                evidence={"injected_value": "-999999"},
            )
        except Exception as e:
            return self._error(str(e))


class BillingInflatedMeterValue(BaseCheck):
    id = "billing.inflated-meter-value"
    name = "Non-monotonic meter reading"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends MeterValues where readings decrease over time (non-monotonic sequence)."
    fail = "Decreasing readings were accepted. Billing totals can be manipulated by resetting the meter counter."
    pass_ = "The server rejected or flagged the non-monotonic meter readings."

    def _meter_payload(self, value: int) -> dict:
        if self.session.version == "1.6":
            return {
                "connectorId": 1,
                "meterValue": [{
                    "timestamp": _ts(),
                    "sampledValue": [{
                        "value": str(value),
                        "measurand": "Energy.Active.Import.Register",
                        "unit": "Wh",
                    }],
                }],
            }
        return {
            "evseId": 1,
            "meterValue": [{
                "timestamp": _ts(),
                "sampledValue": [{
                    "value": value,
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

        readings = [1000, 500, 2000]
        responses = []
        all_accepted = True

        for value in readings:
            try:
                resp = await conn.send_call("MeterValues", self._meter_payload(value))
                accepted = resp[0] == 3
                responses.append({
                    "value_wh": value,
                    "response_type": "CALLRESULT" if resp[0] == 3 else "CALLERROR",
                    "response": resp[2] if len(resp) > 2 else {},
                })
                if not accepted:
                    all_accepted = False
            except asyncio.TimeoutError:
                responses.append({"value_wh": value, "response_type": "timeout"})
                all_accepted = False
            except Exception as e:
                responses.append({"value_wh": value, "error": str(e)[:100]})
                all_accepted = False

        if all_accepted:
            return self._fail(
                "CSMS accepted a non-monotonic sequence of meter readings (1000 Wh → 500 Wh → 2000 Wh) without error",
                evidence={"readings_sent": readings, "responses": responses},
                remediation=(
                    "Validate that Energy.Active.Import.Register values are monotonically non-decreasing. "
                    "Reject or flag meter readings that are lower than the previously accepted value for the same connector."
                ),
                references=["OCPP 1.6 Section 5.11", "OCPP 2.0.1 Section 12.4"],
            )
        return self._pass(
            "CSMS rejected at least one reading in the non-monotonic sequence (1000 → 500 → 2000 Wh)",
            evidence={"readings_sent": readings, "responses": responses},
        )
