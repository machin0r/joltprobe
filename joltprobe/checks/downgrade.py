from __future__ import annotations

import asyncio
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

        import websockets

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
        if self.session.version != "2.0.1":
            return self._skip("This check applies to OCPP 2.0.1 only")

        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        payload = {
            "setVariableData": [
                {
                    "attributeValue": "0",
                    "component": {"name": "SecurityCtrlr"},
                    "variable": {"name": "SecurityProfile"},
                }
            ]
        }

        try:
            resp = await conn.send_call("SetVariables", payload)
            msg_type = resp[0]
            if msg_type == 3:
                resp_payload = resp[2] if len(resp) > 2 else {}
                results = resp_payload.get("setVariableResult", [])
                if results:
                    attr_status = results[0].get("attributeStatus", "unknown")
                    if attr_status in ("Accepted",):
                        return self._fail(
                            "CSMS accepted a SetVariables request to lower the SecurityProfile to 0",
                            evidence={"attribute_status": attr_status, "response": resp_payload},
                            remediation=(
                                "Reject SetVariables requests that attempt to lower the SecurityProfile. "
                                "Require out-of-band authorisation or firmware update to change security profile."
                            ),
                            references=["OCPP 2.0.1 Section 10.3.3", "OCPP Security Whitepaper"],
                        )
                    return self._pass(
                        f"CSMS rejected the SecurityProfile downgrade request (status: {attr_status})",
                        evidence={"attribute_status": attr_status},
                    )
                return self._inconclusive("Empty setVariableResult in response", evidence={"response": resp_payload})
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for SecurityProfile downgrade attempt",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            return self._inconclusive("No response to SetVariables(SecurityProfile=0) (timeout)")
        except Exception as e:
            return self._error(str(e))


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
        import websockets

        plain_url = self.session.target.replace("wss://", "ws://").replace("https://", "http://")
        import base64

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
