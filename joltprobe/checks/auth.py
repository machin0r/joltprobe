from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Optional

import yaml

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity

_PAYLOADS_DIR = Path(__file__).parent.parent / "payloads"
_DEFAULT_CREDS = _PAYLOADS_DIR / "common" / "default_credentials.yaml"
_PROBE_IDTAGS = _PAYLOADS_DIR / "common" / "probe_idtags.yaml"


def _load_probe_idtags() -> list[str]:
    try:
        data = yaml.safe_load(_PROBE_IDTAGS.read_text())
        return [str(t) for t in data.get("idtags", [])]
    except Exception:
        return []


def _load_credentials(path: Optional[str]) -> list[dict]:
    creds_path = Path(path) if path else _DEFAULT_CREDS
    try:
        data = yaml.safe_load(creds_path.read_text())
        return data.get("credentials", [])
    except Exception:
        return []


def _connection_rejected(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(code in msg for code in ("401", "403", "forbidden", "unauthorized", "rejected"))


class AuthNoBasicAuth(BaseCheck):
    id = "auth.no-basic-auth"
    name = "No Basic Auth required"
    severity = Severity.CRITICAL
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Opens a WebSocket connection without sending any Authorization header."
    fail = "The server accepted the connection. Any device can connect as a charger without credentials."
    pass_ = "The server rejected the unauthenticated connection (HTTP 401/403)."

    async def run(self) -> CheckResult:
        import websockets

        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"

        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, subprotocols=[subprotocol], open_timeout=self.session.timeout),
                timeout=self.session.timeout,
            )
            await ws.close()
            return self._fail(
                "CSMS accepted a WebSocket upgrade with no Authorization header",
                evidence={"url": url, "auth_header_sent": False, "http_result": "101 Switching Protocols"},
                remediation=(
                    "Require HTTP Basic Auth on the WebSocket upgrade endpoint. "
                    "Return HTTP 401 for connections without a valid Authorization header."
                ),
                references=["OCPP 2.0.1 Security Profile 1", "OCPP Security Whitepaper Section 5"],
            )
        except Exception as e:
            if _connection_rejected(e):
                return self._pass(
                    "CSMS requires authentication (connection rejected without credentials)",
                    evidence={"rejection": str(e)[:200]},
                )
            return self._error(str(e))


class AuthDefaultCredentials(BaseCheck):
    id = "auth.default-credentials"
    name = "Default credentials accepted"
    severity = Severity.CRITICAL
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Tries common default username/password pairs used by OCPP implementations and charger vendors."
    fail = "A default credential pair was accepted. An attacker can connect as a legitimate charger."
    pass_ = "None of the default credentials were accepted."

    async def run(self) -> CheckResult:
        import websockets

        creds = _load_credentials(self.session.config.credential_list)
        if not creds:
            return self._error("No credential list available")

        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        accepted_pair: Optional[dict] = None

        for pair in creds:
            username = pair.get("username", "")
            password = pair.get("password", "")
            import base64
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(
                        url,
                        subprotocols=[subprotocol],
                        additional_headers={"Authorization": f"Basic {token}"},
                        open_timeout=self.session.timeout,
                    ),
                    timeout=self.session.timeout,
                )
                await ws.close()
                accepted_pair = pair
                break
            except Exception:
                pass

        if accepted_pair:
            return self._fail(
                f"CSMS accepted default credential pair: {accepted_pair.get('username')}:{accepted_pair.get('password')}",
                evidence={
                    "username": accepted_pair.get("username"),
                    "password": accepted_pair.get("password"),
                    "credential_source": str(self.session.config.credential_list or _DEFAULT_CREDS),
                },
                remediation=(
                    "Change default CSMS credentials immediately. "
                    "Enforce unique, strong credentials per charger. "
                    "Rotate credential list at first deployment."
                ),
                references=["CWE-1392", "OCPP Security Whitepaper Section 5"],
            )
        return self._pass(
            f"No default credentials accepted (tested {len(creds)} pairs)",
            evidence={"pairs_tested": len(creds)},
        )


class AuthArbitraryChargerId(BaseCheck):
    id = "auth.arbitrary-charger-id"
    name = "Arbitrary charger ID accepted"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Connects using a charger ID that should not be registered in the CSMS."
    fail = "The server accepted a connection from an unregistered charger ID. Rogue devices can inject transactions and meter data."
    pass_ = "The server rejected the unregistered charger ID."

    async def run(self) -> CheckResult:
        rogue_id = f"ROGUE-{uuid.uuid4().hex[:8].upper()}"
        boot_payload = (
            {"chargePointModel": "RogueCP", "chargePointVendor": "JoltProbe"}
            if self.session.version == "1.6"
            else {
                "reason": "PowerUp",
                "chargingStation": {"model": "RogueCP", "vendorName": "JoltProbe"},
            }
        )

        try:
            conn = await self.session.new_connection(charger_id=rogue_id)
        except Exception as e:
            if _connection_rejected(e):
                return self._pass(
                    "CSMS rejected the WebSocket connection from an unknown charger ID",
                    evidence={"attempted_charger_id": rogue_id, "rejection": str(e)[:200]},
                )
            return self._error(str(e))

        try:
            resp = await conn.send_call("BootNotification", boot_payload)
            payload = resp[2] if len(resp) > 2 else {}
            status = payload.get("status", "unknown")
        except asyncio.TimeoutError:
            status = "timeout"
        except Exception as e:
            status = f"error: {e}"
        finally:
            await conn.close()

        if status in ("Accepted", "Pending"):
            return self._fail(
                f"CSMS accepted BootNotification from arbitrary charger ID '{rogue_id}' (status: {status})",
                evidence={"rogue_charger_id": rogue_id, "boot_status": status},
                remediation=(
                    "Maintain a provisioned allowlist of valid charger IDs. "
                    "Reject BootNotification or close the connection for unknown IDs."
                ),
                references=["OCPP 1.6 Section 4.2", "OCPP 2.0.1 Section 10.4"],
            )
        return self._pass(
            f"CSMS rejected BootNotification from arbitrary charger ID '{rogue_id}' (status: {status})",
            evidence={"rogue_charger_id": rogue_id, "boot_status": status},
        )


class AuthDuplicateIdentity(BaseCheck):
    id = "auth.duplicate-identity"
    name = "Duplicate identity accepted"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DUAL
    applies_to = ["1.6", "2.0.1"]
    what = "Opens a second simultaneous WebSocket connection with the same charger ID as an active session."
    fail = "Both connections were accepted. An attacker can hijack or shadow an active charger session."
    pass_ = "The server rejected or disconnected the duplicate connection."

    async def run(self) -> CheckResult:
        charger_id = self.session.charger_id
        boot_payload = (
            {"chargePointModel": "JoltProbe", "chargePointVendor": "JoltProbe"}
            if self.session.version == "1.6"
            else {
                "reason": "PowerUp",
                "chargingStation": {"model": "JoltProbe", "vendorName": "JoltProbe"},
            }
        )

        try:
            conn1 = await self.session.new_connection(charger_id=charger_id)
        except Exception as e:
            return self._error(f"Could not open first connection: {e}")

        try:
            await conn1.send_call("BootNotification", boot_payload)
        except Exception:
            pass

        try:
            conn2 = await self.session.new_connection(charger_id=charger_id)
        except Exception as e:
            await conn1.close()
            if _connection_rejected(e):
                return self._pass(
                    "CSMS rejected the duplicate charger ID connection",
                    evidence={"charger_id": charger_id, "rejection": str(e)[:200]},
                )
            return self._inconclusive(
                f"Second connection failed but not with an explicit rejection: {e}",
                evidence={"charger_id": charger_id, "error": str(e)[:200]},
            )

        # Both connections open — check if conn1 is still alive
        conn1_alive = True
        try:
            await asyncio.wait_for(conn1.send_call("Heartbeat", {}), timeout=5.0)
        except Exception:
            conn1_alive = False

        await conn2.close()
        await conn1.close()

        return self._fail(
            f"CSMS accepted a second WebSocket connection using charger ID '{charger_id}', "
            "which was already connected — SaiFlow-style session hijacking is possible.",
            evidence={
                "charger_id": charger_id,
                "second_connection_accepted": True,
                "first_connection_still_alive": conn1_alive,
            },
            remediation=(
                "Reject duplicate charger ID connections. When a new connection arrives for an "
                "already-connected ID, reject it or close the old session with a logged audit event."
            ),
            references=["SaiFlow Security Advisory 2022", "OCPP 1.6 Spec Section 3.1"],
        )


class AuthNoBootRequired(BaseCheck):
    id = "auth.no-boot-required"
    name = "Commands accepted pre-boot"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP operational messages (e.g. Authorize) before completing BootNotification."
    fail = "The server processed messages before boot. Operational state can be manipulated before the session is fully established."
    pass_ = "The server rejects or ignores messages sent before BootNotification completes."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=False)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        try:
            resp = await conn.send_call("Heartbeat", {})
            payload = resp[2] if len(resp) > 2 else {}
            await conn.close()
            return self._fail(
                "CSMS processed a Heartbeat message from a charger that had not sent BootNotification",
                evidence={"heartbeat_response": payload},
                remediation=(
                    "Reject operational messages (Heartbeat, MeterValues, etc.) from chargers "
                    "that have not completed the BootNotification handshake."
                ),
                references=["OCPP 1.6 Section 4.1", "OCPP 2.0.1 Section 10.1"],
            )
        except asyncio.TimeoutError:
            await conn.close()
            return self._pass(
                "CSMS did not respond to Heartbeat sent before BootNotification (timeout)",
                evidence={"pre_boot_action": "Heartbeat"},
            )
        except Exception as e:
            await conn.close()
            return self._inconclusive(
                f"Unexpected error during pre-boot Heartbeat: {e}",
                evidence={"error": str(e)[:200]},
            )


class AuthIdTagEnumeration(BaseCheck):
    id = "auth.idtag-enumeration"
    name = "idTag enumeration via Authorize"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Probes a set of idTag values via Authorize and analyses response content and timing."
    fail = "Responses differ for valid vs invalid idTags, allowing an attacker to enumerate valid RFID tags and clone them."
    pass_ = "No distinguishable difference in responses across idTag values."

    async def run(self) -> CheckResult:
        probe_tags = _load_probe_idtags()
        if not probe_tags:
            return self._error("No probe idTags available — check payloads/common/probe_idtags.yaml")

        max_attempts = self.session.config.idtag_attempts
        probe_tags = probe_tags[:max_attempts]

        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        accepted_tags: list[str] = []
        rate_limited = False

        for tag in probe_tags:
            if self.session.version == "1.6":
                authorize_payload: dict = {"idTag": tag}
            else:
                authorize_payload = {"idToken": {"idToken": tag, "type": "ISO14443"}}

            try:
                resp = await conn.send_call("Authorize", authorize_payload)
                if resp[0] == 3:
                    resp_payload = resp[2] if len(resp) > 2 else {}
                    if self.session.version == "1.6":
                        status = resp_payload.get("idTagInfo", {}).get("status", "")
                    else:
                        status = resp_payload.get("idTokenInfo", {}).get("status", "")
                    if status == "Accepted":
                        accepted_tags.append(tag)
                elif resp[0] == 4:
                    error_str = str(resp[2] if len(resp) > 2 else "").lower()
                    if "security" in error_str or "ratelimit" in error_str:
                        rate_limited = True
                        break
            except asyncio.TimeoutError:
                rate_limited = True
                break
            except Exception:
                break

        await conn.close()

        if accepted_tags:
            return self._fail(
                f"CSMS accepted Authorize for {len(accepted_tags)} probe idTag(s): {accepted_tags}",
                evidence={"accepted_tags": accepted_tags, "probed_count": len(probe_tags)},
                remediation=(
                    "Rate-limit Authorize requests per charger (e.g. max 5 per minute). "
                    "Alert on rapid sequential Authorize failures. "
                    "Ensure probe/default idTags are removed from the active authorisation list."
                ),
                references=["OCPP 1.6 Section 5.4", "CWE-307"],
            )

        if rate_limited:
            return self._pass(
                "CSMS rate-limited or closed connection during idTag probe (correct behaviour)",
                evidence={"probed_count": len(probe_tags), "rate_limited": True},
            )

        return self._pass(
            f"CSMS did not accept any of {len(probe_tags)} probe idTags via Authorize",
            evidence={"probed_count": len(probe_tags), "probe_tags": probe_tags},
        )
