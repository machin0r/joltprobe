from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Any

import websockets

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


class DosConnectionFlood(BaseCheck):
    id = "dos.connection-flood"
    name = "Connection limit"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Rapidly opens many simultaneous WebSocket connections using the same charger ID."
    fail = "No connection limit was enforced. A flood attack could exhaust file descriptors or memory."
    pass_ = (
        "The server refused some connections. Note: because all connections share one "
        "charger ID, a per-charger duplicate-identity policy (see auth.duplicate-identity) "
        "produces this same result — it does not necessarily indicate a flood/connection-count limit."
    )

    _TARGET_CONNECTIONS = 50

    async def _try_connect(
        self,
        url: str,
        subprotocol: str,
        connect_kwargs: dict[str, Any],
    ) -> tuple[Any, str | None]:
        """Return (websocket, None) on success or (None, error_string) on failure."""
        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, subprotocols=[subprotocol], **connect_kwargs),
                timeout=self.session.timeout,
            )
            return ws, None
        except Exception as e:
            return None, str(e)[:100]

    async def run(self) -> CheckResult:
        subprotocol = "ocpp1.6" if self.session.version == "1.6" else "ocpp2.0.1"
        connect_kwargs: dict[str, Any] = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        # Use the same charger ID for all connections. A per-charger limit (the realistic
        # deployment model) is only exercised when all connections share the same ID.
        # Unique IDs per connection would bypass a per-charger limit and only detect a
        # global limit, which is a much weaker signal.
        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"

        results = await asyncio.gather(
            *[self._try_connect(url, subprotocol, connect_kwargs) for _ in range(self._TARGET_CONNECTIONS)],
            return_exceptions=False,
        )

        opened = [ws for ws, err in results if ws is not None]
        errors = [err for ws, err in results if err is not None]

        for ws in opened:
            try:
                await ws.close()
            except Exception:
                pass

        if not errors:
            return self._fail(
                f"CSMS accepted all {self._TARGET_CONNECTIONS} simultaneous WebSocket connections "
                f"from the same charger ID without enforcing a per-charger connection limit",
                evidence={"connections_opened": len(opened), "charger_id": self.session.charger_id},
                remediation=(
                    "Enforce a per-charger connection limit at the WebSocket listener level. "
                    "Return HTTP 503 or close excess connections after a configurable threshold."
                ),
                references=["OCPP Security Whitepaper", "CWE-400"],
            )
        return self._pass(
            f"CSMS refused {len(errors)} of {self._TARGET_CONNECTIONS} same-charger-ID "
            f"connections ({len(opened)} accepted) — this may reflect a connection/flood "
            f"limit or a duplicate-identity policy",
            evidence={
                "accepted": len(opened),
                "rejected": len(errors),
                "first_rejection": errors[0] if errors else "",
                "note": (
                    "All connections used the same charger ID; rejections may be caused by a "
                    "duplicate-identity policy rather than a flood/connection-count limit."
                ),
            },
        )



class DosMessageRate(BaseCheck):
    id = "dos.message-rate"
    name = "Message rate limiting"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = (
        "Sends a burst of OCPP messages over a single connection and checks whether the "
        "server closes the connection mid-burst. Detects rate limiting implemented as "
        "connection termination only — response throttling or queuing is not measured, "
        "because responses are not read back."
    )
    fail = (
        "The server accepted the full burst without closing the connection. No "
        "connection-termination rate limit was observed (response-level throttling is "
        "not measured by this check)."
    )
    pass_ = "The server closed the connection during the burst, indicating a connection-termination rate limit."

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
                await conn.send_raw(message)
                sent += 1
            except Exception as e:
                rejected_at = i
                break

        elapsed = time.monotonic() - start
        rate = sent / elapsed if elapsed > 0 else sent

        await conn.close()

        if rejected_at is None:
            return self._fail(
                f"CSMS accepted a burst of {sent} messages in {elapsed:.1f}s ({rate:.0f} msg/s) "
                f"without closing the connection (connection-termination rate limiting not "
                f"observed; response-level throttling is not measured by this check)",
                evidence={"messages_sent": sent, "elapsed_seconds": round(elapsed, 2), "rate_per_second": round(rate, 1)},
                remediation=(
                    "Implement per-connection message rate limiting. "
                    "Close or throttle connections that exceed a configurable message rate threshold."
                ),
                references=["OCPP Security Whitepaper", "CWE-400"],
            )
        return self._pass(
            f"CSMS closed the connection during the burst at message {rejected_at} (connection-termination rate limit)",
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
        # DataTransfer.data has no length restriction in the OCPP spec, so this
        # reliably produces a ~1 MB message regardless of protocol version.
        raw_msg = json.dumps([2, msg_id, "DataTransfer", {
            "vendorId": "JoltProbe",
            "messageId": "probe",
            "data": large_value,
        }])
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
