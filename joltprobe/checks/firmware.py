from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity

# A non-resolvable canary host (RFC 6761 .invalid) used as the attacker-controlled
# location. It is deliberately inert: the point of the probe is whether the CSMS
# *accepts* a charger-supplied URL, not to make the target reach any real host.
# The remediation notes that internal/link-local targets are the real SSRF risk.
_CANARY_URL = "http://joltprobe-ssrf-canary.invalid/marker"


def _is_callresult(resp: list) -> bool:
    return isinstance(resp, list) and len(resp) > 0 and resp[0] == 3


def _detail(resp: list):
    return resp[2] if (isinstance(resp, list) and len(resp) > 2) else resp


class _UrlDirectiveCheck(BaseCheck):
    """Shared logic for probing whether a CSMS acts on a charger-supplied URL.

    UpdateFirmware / GetDiagnostics / GetLog are CSMS→Charging Station messages: in
    normal operation the CSMS chooses the URL. This probe sends the message *to* the
    CSMS with an attacker-controlled location. A spec-compliant CSMS has no inbound
    handler and returns a CALLERROR (NotImplemented), which we treat as the expected,
    safe outcome. A CALLRESULT means the CSMS is wired to act on charger-supplied
    firmware/diagnostics directives — an SSRF / data-exfiltration surface.
    """

    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]

    def _build_call(self) -> tuple[str, dict]:
        raise NotImplementedError

    async def run(self) -> CheckResult:
        action, payload = self._build_call()
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        try:
            resp = await conn.send_call(action, payload)
        except asyncio.TimeoutError:
            return self._inconclusive(
                f"No response to inbound {action} — cannot confirm whether the CSMS acts on "
                "charger-supplied URLs."
            )
        except Exception as e:
            return self._error(str(e))

        if _is_callresult(resp):
            return self._fail(
                f"CSMS returned a result for inbound {action} carrying an attacker-controlled URL, "
                "indicating it processes charger-supplied firmware/diagnostics locations",
                evidence={"action": action, "url": _CANARY_URL, "response": _detail(resp)},
                remediation=(
                    f"{action} is a CSMS→Charging Station message; a CSMS should not act on it as "
                    "an inbound request. Reject it with a CALLERROR. Never fetch or relay a URL "
                    "supplied by a charging station without allow-listing the host — arbitrary "
                    "URLs allow SSRF to internal/link-local services and exfiltration to attacker "
                    "hosts."
                ),
                references=[
                    "CWE-918: Server-Side Request Forgery (SSRF)",
                    "OCPP 2.0.1 Part 2 — Firmware Management / Diagnostics",
                ],
            )

        # CALLERROR (e.g. NotImplemented) is the expected compliant response.
        return self._pass(
            f"CSMS rejected inbound {action} (expected: it is a CSMS→CP message)",
            evidence={"action": action, "response": _detail(resp)},
        )


class FirmwareUpdateUrl(_UrlDirectiveCheck):
    id = "firmware.update-url"
    name = "CSMS acts on charger-supplied UpdateFirmware URL"
    severity = Severity.HIGH
    what = (
        "Sends UpdateFirmware inbound to the CSMS with a firmware download location pointing at "
        "an attacker-controlled URL."
    )
    fail = (
        "The CSMS processed a charger-supplied firmware download URL. Arbitrary locations enable "
        "SSRF against internal services and delivery of attacker-hosted firmware."
    )
    pass_ = "The CSMS rejected the inbound UpdateFirmware directive."

    def _build_call(self) -> tuple[str, dict]:
        if self.session.version == "1.6":
            retrieve = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            return "UpdateFirmware", {"location": _CANARY_URL, "retrieveDate": retrieve}
        retrieve = (datetime.now(timezone.utc) + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        return "UpdateFirmware", {
            "requestId": 1,
            "firmware": {"location": _CANARY_URL, "retrieveDateTime": retrieve},
        }


class DiagnosticsUploadUrl(_UrlDirectiveCheck):
    id = "firmware.diagnostics-url"
    name = "CSMS acts on charger-supplied diagnostics upload URL"
    severity = Severity.HIGH
    what = (
        "Sends GetDiagnostics (1.6) / GetLog (2.0.1) inbound to the CSMS with an upload location "
        "pointing at an attacker-controlled URL."
    )
    fail = (
        "The CSMS processed a charger-supplied diagnostics upload URL. Arbitrary locations enable "
        "SSRF and exfiltration of diagnostics data to an attacker host."
    )
    pass_ = "The CSMS rejected the inbound diagnostics directive."

    def _build_call(self) -> tuple[str, dict]:
        if self.session.version == "1.6":
            return "GetDiagnostics", {"location": _CANARY_URL}
        return "GetLog", {
            "logType": "DiagnosticsLog",
            "requestId": 1,
            "log": {"remoteLocation": _CANARY_URL},
        }
