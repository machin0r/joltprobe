from __future__ import annotations

import asyncio

import websockets
import websockets.exceptions

from ocppscan.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


class WebsocketNoSubprotocol(BaseCheck):
    id = "websocket.no-subprotocol"
    name = "No subprotocol header"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Connects without the Sec-WebSocket-Protocol header that declares the OCPP version."
    fail = "The connection was accepted without a subprotocol. Protocol negotiation can be bypassed entirely."
    pass_ = "The server rejected connections without the required subprotocol header."

    async def run(self) -> CheckResult:
        import base64

        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
        connect_kwargs: dict = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        try:
            ws = await asyncio.wait_for(
                websockets.connect(url, **connect_kwargs),
                timeout=self.session.timeout,
            )
            response_headers = {k: v for k, v in ws.response_headers.items()
                                if "websocket" in k.lower() or "upgrade" in k.lower()}
            await ws.close()
            return self._fail(
                "CSMS accepted a WebSocket upgrade with no Sec-WebSocket-Protocol header (HTTP 101 returned)",
                evidence={
                    "url": url,
                    "sec_websocket_protocol_sent": None,
                    "http_status": 101,
                    "response_headers": response_headers,
                },
                remediation=(
                    "Per RFC 6455 §4.2.2, if the server requires a subprotocol and none is offered by the client, "
                    "the handshake must be aborted. Return HTTP 400 or close the connection without sending HTTP 101."
                ),
                references=["RFC 6455 §4.2.2", "OCPP 1.6 Section 3.1", "OCPP 2.0.1 Section 3.1"],
            )
        except websockets.exceptions.InvalidHandshake:
            return self._pass(
                "CSMS rejected WebSocket upgrade with no Sec-WebSocket-Protocol header (correct behaviour per RFC 6455)",
                evidence={"url": url, "sec_websocket_protocol_sent": None},
            )
        except asyncio.TimeoutError:
            return self._error("Connection attempt timed out")
        except Exception as e:
            msg = str(e).lower()
            if any(x in msg for x in ("400", "401", "403", "rejected", "forbidden", "refused")):
                return self._pass(
                    "CSMS rejected WebSocket upgrade with no Sec-WebSocket-Protocol header",
                    evidence={"url": url, "rejection": str(e)[:200]},
                )
            return self._error(str(e))


class WebsocketWrongSubprotocol(BaseCheck):
    id = "websocket.wrong-subprotocol"
    name = "Mismatched subprotocol"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Connects declaring an incorrect Sec-WebSocket-Protocol value."
    fail = "The mismatched subprotocol was accepted. Clients can misrepresent their protocol version."
    pass_ = "The server rejected the connection with the wrong subprotocol."

    async def run(self) -> CheckResult:
        import base64

        url = f"{self.session.target.rstrip('/')}/{self.session.charger_id}"
        connect_kwargs: dict = {"open_timeout": self.session.timeout}
        if self.session.config.username:
            token = base64.b64encode(
                f"{self.session.config.username}:{self.session.config.password or ''}".encode()
            ).decode()
            connect_kwargs["additional_headers"] = {"Authorization": f"Basic {token}"}

        if self.session.version == "1.6":
            wrong_protos = ["ocpp2.0.1", "ocpp0.0"]
        else:
            wrong_protos = ["ocpp1.6", "ocpp0.0"]

        accepted_protos: list[str] = []

        for proto in wrong_protos:
            try:
                ws = await asyncio.wait_for(
                    websockets.connect(url, subprotocols=[proto], **connect_kwargs),
                    timeout=self.session.timeout,
                )
                await ws.close()
                accepted_protos.append(proto)
            except websockets.exceptions.InvalidHandshake:
                pass
            except Exception:
                pass

        if accepted_protos:
            return self._fail(
                f"CSMS accepted WebSocket upgrade with mismatched subprotocol(s): {accepted_protos}",
                evidence={
                    "url": url,
                    "target_version": self.session.version,
                    "accepted_wrong_protocols": accepted_protos,
                    "tested_protocols": wrong_protos,
                },
                remediation=(
                    "Reject WebSocket upgrades that request a subprotocol not supported by this CSMS. "
                    "For OCPP 1.6, accept only 'ocpp1.6'; for OCPP 2.0.1, accept only 'ocpp2.0.1'."
                ),
                references=["RFC 6455 §4.2.2", "OCPP 1.6 Section 3.1", "OCPP 2.0.1 Section 3.1"],
            )
        return self._pass(
            f"CSMS rejected all mismatched subprotocol attempts ({wrong_protos})",
            evidence={"url": url, "tested_protocols": wrong_protos},
        )
