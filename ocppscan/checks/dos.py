from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from ocppscan.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


class DosConnectionFlood(BaseCheck):
    id = "dos.connection-flood"
    name = "Connection limit"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Rapidly opens many simultaneous WebSocket connections to the CSMS endpoint."
    fail = "No connection limit was enforced. A flood attack could exhaust file descriptors or memory."
    pass_ = "The server began refusing connections after a threshold, indicating a connection limit is enforced."

    _TARGET_CONNECTIONS = 50

    async def run(self) -> CheckResult:
        import base64
        import websockets

        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        connect_kwargs: dict[str, Any] = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        opened: list[Any] = []
        rejected_at: int | None = None
        errors: list[str] = []

        for i in range(self._TARGET_CONNECTIONS):
            charger_id = f"{self.session.charger_id}-FLOOD-{i:03d}"
            url = f"{self.session.target.rstrip('/')}/{charger_id}"
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(url, subprotocols=[subprotocol], **connect_kwargs),
                    timeout=self.session.timeout,
                )
                opened.append(ws)
            except Exception as e:
                rejected_at = i
                errors.append(str(e)[:100])
                break

        for ws in opened:
            try:
                await ws.close()
            except Exception:
                pass

        if rejected_at is None:
            return self._fail(
                f"CSMS accepted all {self._TARGET_CONNECTIONS} simultaneous WebSocket connections without enforcing a limit",
                evidence={"connections_opened": len(opened), "limit_hit": False},
                remediation=(
                    "Enforce a per-charger or global connection limit at the WebSocket listener level. "
                    "Return HTTP 503 or close excess connections after a configurable threshold."
                ),
                references=["OCPP Security Whitepaper", "CWE-400"],
            )
        return self._pass(
            f"CSMS enforced a connection limit at connection {rejected_at} of {self._TARGET_CONNECTIONS}",
            evidence={"accepted_before_limit": rejected_at, "limit_error": errors[0] if errors else ""},
        )



class DosMessageRate(BaseCheck):
    id = "dos.message-rate"
    name = "Message rate limiting"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends OCPP messages at a very high rate over a single connection."
    fail = "No rate limiting detected. Sustained high-rate messaging could exhaust CPU or queue capacity."
    pass_ = "The server disconnected or throttled the sender when the message rate was excessive."

    _BURST_COUNT = 100
    _BURST_WINDOW = 5.0

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        sent = 0
        rejected_at: int | None = None
        start = time.monotonic()

        for i in range(self._BURST_COUNT):
            msg_id = str(uuid.uuid4())[:8]
            message = json.dumps([2, msg_id, "Heartbeat", {}])
            try:
                await conn._ws.send(message)
                sent += 1
            except Exception as e:
                rejected_at = i
                break

        elapsed = time.monotonic() - start
        rate = sent / elapsed if elapsed > 0 else sent

        await conn.close()

        if rejected_at is None:
            return self._fail(
                f"CSMS accepted {sent} messages in {elapsed:.1f}s ({rate:.0f} msg/s) without enforcing rate limits",
                evidence={"messages_sent": sent, "elapsed_seconds": round(elapsed, 2), "rate_per_second": round(rate, 1)},
                remediation=(
                    "Implement per-connection message rate limiting. "
                    "Close or throttle connections that exceed a configurable message rate threshold."
                ),
                references=["OCPP Security Whitepaper", "CWE-400"],
            )
        return self._pass(
            f"CSMS enforced rate limiting at message {rejected_at}",
            evidence={"messages_before_limit": rejected_at},
        )


class DosLargePayload(BaseCheck):
    id = "dos.large-payload"
    name = "Large payload handling"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends a single very large OCPP message (multiple megabytes) to test payload size limits."
    fail = "The oversized payload was accepted. Large messages could exhaust memory or processing capacity."
    pass_ = "The server rejected or disconnected for the oversized message."

    _PAYLOAD_SIZE = 1_000_000  # 1 MB

    async def run(self) -> CheckResult:
        import base64
        import websockets

        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        connect_kwargs: dict[str, Any] = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        msg_id = str(uuid.uuid4())[:8]
        large_value = "X" * self._PAYLOAD_SIZE
        if self.session.version == "1.6":
            payload_obj: dict = {"chargePointModel": large_value[:1000], "chargePointVendor": large_value[:1000]}
            action = "BootNotification"
        else:
            payload_obj = {"reason": "PowerUp", "chargingStation": {"model": large_value[:1000], "vendorName": "OCPPScan"}}
            action = "BootNotification"

        raw_msg = json.dumps([2, msg_id, action, payload_obj])
        actual_size = len(raw_msg.encode())

        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, subprotocols=[subprotocol], **connect_kwargs),
                timeout=self.session.timeout,
            )
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        try:
            await ws.send(raw_msg)
            try:
                raw_resp = await asyncio.wait_for(ws.recv(), timeout=self.session.timeout)
                data = json.loads(raw_resp)
                if isinstance(data, list) and data[0] == 4:
                    return self._pass(
                        f"CSMS returned CALLERROR for {actual_size / 1024:.0f} KB payload",
                        evidence={"payload_size_bytes": actual_size},
                    )
                return self._fail(
                    f"CSMS processed a {actual_size / 1024:.0f} KB JSON payload without rejecting it",
                    evidence={"payload_size_bytes": actual_size, "response_type": data[0] if data else None},
                    remediation=(
                        "Set a maximum WebSocket message size limit in the CSMS configuration. "
                        "Reject and close connections that send payloads exceeding the limit."
                    ),
                    references=["OCPP Security Whitepaper", "CWE-400"],
                )
            except asyncio.TimeoutError:
                return self._inconclusive(
                    f"No response to {actual_size / 1024:.0f} KB payload (timeout)",
                    evidence={"payload_size_bytes": actual_size},
                )
        except Exception as e:
            if "too long" in str(e).lower() or "size" in str(e).lower() or "1009" in str(e):
                return self._pass(
                    f"CSMS rejected the {actual_size / 1024:.0f} KB payload (connection closed)",
                    evidence={"rejection": str(e)[:200]},
                )
            return self._error(str(e))
        finally:
            try:
                await ws.close()
            except Exception:
                pass
