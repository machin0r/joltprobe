from __future__ import annotations

import asyncio
import base64

import websockets

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


class DowngradeProfileReconnect(BaseCheck):
    id = "downgrade.profile-reconnect"
    name = "Security profile downgrade on reconnect"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["2.0.1"]
    what = "Reconnects to the server using a lower security profile than previously negotiated."
    fail = "The downgraded connection was accepted. An attacker can force a reconnect to strip security controls."
    pass_ = "The server rejected the lower-profile reconnection."

    async def run(self) -> CheckResult:
        if self.session.version != "2.0.1":
            return self._skip("This check applies to OCPP 2.0.1 only")

        if not self.session.is_tls():
            return self._skip("Target uses plaintext (ws://); downgrade check requires TLS baseline")

        # After an SP2 session, try reconnecting via ws:// (SP0)
        plain_url = self.session.target.replace("wss://", "ws://").replace("https://", "http://")
        url = f"{plain_url.rstrip('/')}/{self.session.charger_id}"
        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, subprotocols=["ocpp2.0.1"], open_timeout=self.session.timeout),
                timeout=self.session.timeout,
            )
            await ws.close()
            return self._fail(
                "CSMS accepted a plaintext (SP0) reconnection after a TLS (SP2) session was established",
                evidence={"downgrade_url": url, "result": "101 Switching Protocols"},
                remediation=(
                    "Once a charger has negotiated Security Profile 2 or 3, reject subsequent "
                    "connections on a lower security profile. Log the downgrade attempt."
                ),
                references=["OCPP 2.0.1 Section 10.3", "OCPP Security Whitepaper Section 6.3"],
            )
        except Exception as e:
            msg = str(e).lower()
            if "101" not in msg:
                return self._pass(
                    "CSMS rejected the plaintext (SP0) reconnection attempt",
                    evidence={"rejection": str(e)[:200]},
                )
            return self._error(str(e))


class DowngradeChangeConfig(BaseCheck):
    id = "downgrade.change-config"
    name = "ChangeConfiguration to lower security profile"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["2.0.1"]
    what = "Sends ChangeConfiguration to lower the CSMS security profile setting."
    fail = "The server accepted the change. Security profile can be downgraded remotely without physical access."
    pass_ = "The server rejected the security-downgrading configuration change."

    async def run(self) -> CheckResult:
        # SetVariables is a CSMS→CP message in OCPP 2.0.1. A CSMS has no handler for receiving
        # SetVariables from a charger and will always return CALLERROR NotImplemented — the same
        # response a compliant CSMS returns for any unrecognised inbound CALL. There is no OCPP
        # message a charger can send to instruct the CSMS to lower its own security profile.
        # Reconnect-based downgrade is already covered by downgrade.profile-reconnect.
        return self._skip(
            "SetVariables is a CSMS→CP message in OCPP 2.0.1; a CSMS does not handle it as an "
            "inbound request from a charger. Any spec-compliant CSMS returns CALLERROR NotImplemented, "
            "which this check would record as PASS — making it indistinguishable from a genuinely "
            "hardened system. Reconnect-based downgrade is covered by downgrade.profile-reconnect."
        )


class DowngradeStaleProfile(BaseCheck):
    id = "downgrade.stale-profile"
    name = "Stale lower-profile credentials retained"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["2.0.1"]
    what = "After upgrading to a higher security profile, checks whether old lower-profile credentials still authenticate."
    fail = "Old credentials remain valid after a profile upgrade. Compromised lower-profile credentials persist."
    pass_ = "Old credentials were invalidated following the security profile upgrade."

    async def run(self) -> CheckResult:
        if self.session.version != "2.0.1":
            return self._skip("This check applies to OCPP 2.0.1 only")

        if self.session.config.username is None:
            return self._skip(
                "Skipping: no credentials provided. Provide --username/--password to test SP1 credential invalidation."
            )

        # After establishing an SP2 (TLS) session, verify that SP1 Basic Auth still works on ws://
        plain_url = self.session.target.replace("wss://", "ws://").replace("https://", "http://")
        token = base64.b64encode(
            f"{self.session.config.username}:{self.session.config.password or ''}".encode()
        ).decode()
        url = f"{plain_url.rstrip('/')}/{self.session.charger_id}"

        try:
            ws = await asyncio.wait_for(
                websockets.connect(
                    url,
                    subprotocols=["ocpp2.0.1"],
                    additional_headers={"Authorization": f"Basic {token}"},
                    open_timeout=self.session.timeout,
                ),
                timeout=self.session.timeout,
            )
            await ws.close()
            return self._fail(
                "SP1 Basic Auth credentials remain valid after SP2 upgrade — stale credentials not invalidated",
                evidence={
                    "sp1_url": url,
                    "username": self.session.config.username,
                    "result": "Connection accepted",
                },
                remediation=(
                    "When upgrading to Security Profile 2 or 3, invalidate previously issued SP1 credentials "
                    "as required by OCPP 2.0.1 Section 10.3.4."
                ),
                references=["OCPP 2.0.1 Section 10.3.4", "OCPP Security Whitepaper"],
            )
        except Exception as e:
            msg = str(e).lower()
            if "101" not in msg:
                return self._pass(
                    "SP1 Basic Auth credentials are invalidated after SP2 upgrade (connection rejected)",
                    evidence={"rejection": str(e)[:200]},
                )
            return self._error(str(e))
