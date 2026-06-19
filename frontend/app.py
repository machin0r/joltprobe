import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

HERE = Path(__file__).parent

_which = shutil.which("ocppscan")
OCPPSCAN_CMD: list[str] = [_which] if _which else [sys.executable, "-m", "ocppscan.cli"]

app = FastAPI(title="OCPPScan", docs_url=None, redoc_url=None)

# Per-check explanatory text injected into the manifest served to the UI.
CHECK_DETAIL: dict[str, dict[str, str]] = {
    "tls.no-tls": {
        "what": "Attempts a raw plaintext WebSocket (ws://) connection. A secure CSMS should refuse it.",
        "fail": "The server accepts unencrypted connections. All traffic — credentials, meter data, commands — is visible on the network. Disable the plaintext listener and enforce wss:// only.",
        "pass": "The server did not accept a plaintext connection.",
    },
    "tls.self-signed": {
        "what": "Inspects the TLS certificate chain presented during the handshake.",
        "fail": "The server uses a self-signed certificate. Clients cannot verify server identity, enabling man-in-the-middle attacks without detection.",
        "pass": "The certificate chains to a recognised CA.",
    },
    "tls.version": {
        "what": "Negotiates TLS and checks whether deprecated versions (1.0, 1.1) are accepted.",
        "fail": "TLS 1.0 or 1.1 accepted. These have known vulnerabilities (POODLE, BEAST). Restrict to TLS 1.2+.",
        "pass": "Only TLS 1.2 or later is accepted.",
    },
    "tls.ciphers": {
        "what": "Enumerates cipher suites offered by the server during the TLS handshake.",
        "fail": "Weak ciphers offered (RC4, NULL, export-grade, anonymous). Traffic may be decrypted offline.",
        "pass": "Only strong, modern cipher suites are offered.",
    },
    "tls.no-client-cert": {
        "what": "Completes a TLS handshake without presenting a client certificate. OCPP Security Profile 3 requires mutual TLS.",
        "fail": "The server does not require a client certificate. Any host on the network can impersonate a charger.",
        "pass": "The server requires a client certificate (mutual TLS enforced).",
    },
    "auth.no-basic-auth": {
        "what": "Opens a WebSocket connection without sending any Authorization header.",
        "fail": "The server accepted the connection. Any device can connect as a charger without credentials.",
        "pass": "The server rejected the unauthenticated connection (HTTP 401/403).",
    },
    "auth.default-credentials": {
        "what": "Tries common default username/password pairs used by OCPP implementations and charger vendors.",
        "fail": "A default credential pair was accepted. An attacker can connect as a legitimate charger.",
        "pass": "None of the default credentials were accepted.",
    },
    "auth.arbitrary-charger-id": {
        "what": "Connects using a charger ID that should not be registered in the CSMS.",
        "fail": "The server accepted a connection from an unregistered charger ID. Rogue devices can inject transactions and meter data.",
        "pass": "The server rejected the unregistered charger ID.",
    },
    "auth.duplicate-identity": {
        "what": "Opens a second simultaneous WebSocket connection with the same charger ID as an active session.",
        "fail": "Both connections were accepted. An attacker can hijack or shadow an active charger session.",
        "pass": "The server rejected or disconnected the duplicate connection.",
    },
    "auth.no-boot-required": {
        "what": "Sends OCPP operational messages (e.g. Authorize) before completing BootNotification.",
        "fail": "The server processed messages before boot. Operational state can be manipulated before the session is fully established.",
        "pass": "The server rejects or ignores messages sent before BootNotification completes.",
    },
    "auth.idtag-enumeration": {
        "what": "Probes a set of idTag values via Authorize and analyses response content and timing.",
        "fail": "Responses differ for valid vs invalid idTags, allowing an attacker to enumerate valid RFID tags and clone them.",
        "pass": "No distinguishable difference in responses across idTag values.",
    },
    "session.meter-without-transaction": {
        "what": "Sends MeterValues referencing a transaction ID that does not exist.",
        "fail": "The server accepted the meter readings. Fraudulent billing entries can be injected without a real transaction.",
        "pass": "The server rejected meter values for an unknown transaction ID.",
    },
    "session.stop-foreign-transaction": {
        "what": "Sends StopTransaction using a transaction ID from a different charger's active session.",
        "fail": "The server allowed the cross-session stop. Any charger can terminate another charger's session.",
        "pass": "The server rejected the StopTransaction for a foreign transaction ID.",
    },
    "session.start-without-auth": {
        "what": "Attempts StartTransaction without a prior successful Authorize exchange.",
        "fail": "The server permitted the transaction to start without authorisation. Charging begins without a valid RFID or app token.",
        "pass": "The server requires authorisation before accepting StartTransaction.",
    },
    "session.local-auth-list-abuse": {
        "what": "Sends an unsolicited SendLocalList to add entries to the server's authorisation cache.",
        "fail": "The server accepted the list modification. An attacker can whitelist arbitrary idTags for offline charging.",
        "pass": "The server rejected the unsolicited SendLocalList.",
    },
    "session.connector-status-spoof": {
        "what": "Sends StatusNotification with a manipulated connector state (e.g. Available while a transaction is running).",
        "fail": "The server accepted the spoofed status. Active sessions can be hidden or connectors can be made to appear unavailable.",
        "pass": "The server ignored or rejected the inconsistent status notification.",
    },
    "session.transaction-id-enumeration": {
        "what": "Probes sequential transaction IDs via StopTransaction to infer active or historical sessions.",
        "fail": "The server responds differently to valid vs invalid transaction IDs, enabling enumeration of charging history.",
        "pass": "Consistent responses regardless of transaction ID validity.",
    },
    "session.concurrent-transactions": {
        "what": "Attempts to start two transactions simultaneously on the same connector.",
        "fail": "The server accepted both. Double-billing or meter data corruption may occur.",
        "pass": "The server rejected the second concurrent transaction on the same connector.",
    },
    "downgrade.profile-reconnect": {
        "what": "Reconnects to the server using a lower security profile than previously negotiated.",
        "fail": "The downgraded connection was accepted. An attacker can force a reconnect to strip security controls.",
        "pass": "The server rejected the lower-profile reconnection.",
    },
    "downgrade.change-config": {
        "what": "Sends ChangeConfiguration to lower the CSMS security profile setting.",
        "fail": "The server accepted the change. Security profile can be downgraded remotely without physical access.",
        "pass": "The server rejected the security-downgrading configuration change.",
    },
    "downgrade.stale-profile": {
        "what": "After upgrading to a higher security profile, checks whether old lower-profile credentials still authenticate.",
        "fail": "Old credentials remain valid after a profile upgrade. Compromised lower-profile credentials persist.",
        "pass": "Old credentials were invalidated following the security profile upgrade.",
    },
    "message.malformed-json": {
        "what": "Sends syntactically invalid JSON (truncated frames, mismatched brackets, invalid escapes) over the WebSocket.",
        "fail": "The server did not close the connection or return a protocol error. Malformed input may cause undefined behaviour.",
        "pass": "The server closed the connection or returned a CALLERROR for malformed JSON.",
    },
    "message.oversized-fields": {
        "what": "Sends OCPP messages with string fields many times larger than the specified OCPP maximums.",
        "fail": "Oversized fields were accepted. Buffer overflows or database truncation issues may exist downstream.",
        "pass": "The server rejected messages containing oversized field values.",
    },
    "message.wrong-types": {
        "what": "Sends OCPP messages with incorrect field types (e.g. integer where a string is expected).",
        "fail": "Type-mismatched fields were accepted. Type coercion bugs or unexpected code paths may be triggered.",
        "pass": "The server rejected messages with incorrect field types.",
    },
    "message.injection-charger-id": {
        "what": "Uses a charger ID containing SQL, XSS, and path traversal payloads in the WebSocket URL path.",
        "fail": "The server accepted the connection. The charger ID value likely reaches log storage or a database unsanitised.",
        "pass": "The server rejected or safely handled the injection payload in the charger ID path.",
    },
    "message.unknown-action": {
        "what": "Sends CALL frames with action names not defined in the OCPP specification.",
        "fail": "The server did not return a CALLERROR. Unknown actions are silently accepted, masking protocol violations.",
        "pass": "The server returned CALLERROR NotImplemented or NotSupported for the unknown action.",
    },
    "message.missing-required-fields": {
        "what": "Sends OCPP messages with required fields absent from the payload.",
        "fail": "Messages with missing required fields were processed. Schema validation is not enforced server-side.",
        "pass": "The server returned a CALLERROR for messages with missing required fields.",
    },
    "message.deeply-nested-json": {
        "what": "Sends a JSON payload with 200+ levels of recursive nesting inside an OCPP message.",
        "fail": "The server processed the deeply nested payload. Recursive parsers may stack overflow under load.",
        "pass": "The server rejected or disconnected for the pathologically nested payload.",
    },
    "message.timestamp-skew": {
        "what": "Sends OCPP messages with timestamps set years in the past or future.",
        "fail": "Extreme timestamps were accepted without rejection. Billing records can be backdated or postdated.",
        "pass": "The server rejected or normalised extreme timestamp values.",
    },
    "message.unicode-null-bytes": {
        "what": "Embeds null bytes (\\u0000), Unicode control characters, and bidirectional markers in string fields.",
        "fail": "Payloads with null bytes or control characters were accepted. Log injection or database truncation may result.",
        "pass": "The server rejected or safely handled dangerous Unicode and null-byte content.",
    },
    "billing.negative-meter-value": {
        "what": "Sends a MeterValues message reporting a negative energy reading (e.g. −999 Wh).",
        "fail": "The negative reading was accepted. An attacker could generate credit-like billing entries.",
        "pass": "The server rejected or flagged the negative meter value.",
    },
    "billing.inflated-meter-value": {
        "what": "Sends MeterValues where readings decrease over time (non-monotonic sequence).",
        "fail": "Decreasing readings were accepted. Billing totals can be manipulated by resetting the meter counter.",
        "pass": "The server rejected or flagged the non-monotonic meter readings.",
    },
    "websocket.no-subprotocol": {
        "what": "Connects without the Sec-WebSocket-Protocol header that declares the OCPP version.",
        "fail": "The connection was accepted without a subprotocol. Protocol negotiation can be bypassed entirely.",
        "pass": "The server rejected connections without the required subprotocol header.",
    },
    "websocket.wrong-subprotocol": {
        "what": "Connects declaring an incorrect Sec-WebSocket-Protocol value.",
        "fail": "The mismatched subprotocol was accepted. Clients can misrepresent their protocol version.",
        "pass": "The server rejected the connection with the wrong subprotocol.",
    },
    "dos.connection-flood": {
        "what": "Rapidly opens many simultaneous WebSocket connections to the CSMS endpoint.",
        "fail": "No connection limit was enforced. A flood attack could exhaust file descriptors or memory.",
        "pass": "The server began refusing connections after a threshold, indicating a connection limit is enforced.",
    },
    "dos.message-rate": {
        "what": "Sends OCPP messages at a very high rate over a single connection.",
        "fail": "No rate limiting detected. Sustained high-rate messaging could exhaust CPU or queue capacity.",
        "pass": "The server disconnected or throttled the sender when the message rate was excessive.",
    },
    "dos.large-payload": {
        "what": "Sends a single very large OCPP message (multiple megabytes) to test payload size limits.",
        "fail": "The oversized payload was accepted. Large messages could exhaust memory or processing capacity.",
        "pass": "The server rejected or disconnected for the oversized message.",
    },
    "injection.chargeboxid": {
        "what": "Connects with a charger ID containing SQL, NoSQL, log, and template injection payloads in the URL path.",
        "fail": "Anomalous server behaviour detected. The charger ID likely reaches an injectable context (database, log, template engine).",
        "pass": "No anomalous behaviour detected. The charger ID appears to be handled safely.",
    },
    "injection.idtag": {
        "what": "Sends Authorize and StartTransaction with injection payloads in the idTag field.",
        "fail": "Anomalous responses suggest the idTag reaches an injectable context.",
        "pass": "No anomalous behaviour detected for injection payloads in idTag.",
    },
    "injection.vendorid": {
        "what": "Sends DataTransfer messages with injection payloads in the vendorId field.",
        "fail": "Anomalous responses suggest the vendorId field is not safely handled.",
        "pass": "No anomalous behaviour detected for injection payloads in vendorId.",
    },
    "injection.messageid": {
        "what": "Sends DataTransfer messages with injection payloads in the messageId field.",
        "fail": "Anomalous responses suggest the messageId field reaches an injectable context.",
        "pass": "No anomalous behaviour detected for injection payloads in messageId.",
    },
    "injection.reason": {
        "what": "Sends StopTransaction messages with injection payloads in the reason field.",
        "fail": "Anomalous responses suggest the reason field is not safely handled.",
        "pass": "No anomalous behaviour detected for injection payloads in the reason field.",
    },
    "injection.metervalues": {
        "what": "Sends MeterValues with injection payloads in the measurand and location fields.",
        "fail": "Anomalous responses suggest meter value fields reach an injectable context.",
        "pass": "No anomalous behaviour detected for injection payloads in MeterValues fields.",
    },
    "injection.soap": {
        "what": "Attempts to discover a SOAP endpoint and sends XML/XXE injection payloads.",
        "fail": "The server responded to XML injection indicating unsafe XML parsing (XXE or SSRF risk).",
        "pass": "No SOAP endpoint found or XML payloads produced no anomalous behaviour.",
    },
}


def _build_checks_manifest() -> dict:
    from ocppscan.checks import CATEGORIES

    result = {}
    for category, check_classes in CATEGORIES.items():
        result[category] = [
            {
                "id": cls.id,
                "name": cls.name,
                "severity": cls.severity.value if hasattr(cls.severity, "value") else cls.severity,
                "applies_to": cls.applies_to,
                **CHECK_DETAIL.get(cls.id, {"what": "", "fail": "", "pass": ""}),
            }
            for cls in check_classes
        ]
    return result


CHECKS_MANIFEST: dict = _build_checks_manifest()


@app.get("/", response_class=HTMLResponse)
async def root():
    return (HERE / "index.html").read_text(encoding="utf-8")


@app.get("/checks")
async def get_checks():
    return JSONResponse(CHECKS_MANIFEST)


@app.get("/scan-result/{scan_id}")
async def get_scan_result(scan_id: str):
    if not all(c in "0123456789abcdef" for c in scan_id):
        return JSONResponse({"error": "invalid id"}, status_code=400)
    path = Path(tempfile.gettempdir()) / f"ocppscan-{scan_id}.json"
    if not path.exists():
        return JSONResponse({"error": "not found"}, status_code=404)
    try:
        return JSONResponse(json.loads(path.read_text()))
    except Exception:
        return JSONResponse({"error": "parse error"}, status_code=500)


class ScanRequest(BaseModel):
    target: str
    charger_id: str
    version: str = "1.6"
    checks: Optional[str] = None
    timeout: float = 10.0
    security_profile: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enable_dos: bool = False
    enable_soap: bool = False
    idtag_attempts: int = 20


class RunCheckRequest(BaseModel):
    check_id: str
    target: str
    charger_id: str
    version: str = "1.6"
    timeout: float = 10.0
    security_profile: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


def _build_scan_cmd(req: ScanRequest, result_file: Optional[str] = None) -> list[str]:
    cmd = [*OCPPSCAN_CMD, "scan", req.target, "--charger-id", req.charger_id]
    cmd += ["--version", req.version]
    if req.checks:
        cmd += ["--checks", req.checks]
    if req.timeout != 10.0:
        cmd += ["--timeout", str(req.timeout)]
    if req.security_profile is not None:
        cmd += ["--security-profile", str(req.security_profile)]
    if req.username:
        cmd += ["--username", req.username]
    if req.password:
        cmd += ["--password", req.password]
    if req.enable_dos:
        cmd += ["--enable-dos"]
    if req.enable_soap:
        cmd += ["--soap"]
    if req.idtag_attempts != 20:
        cmd += ["--idtag-attempts", str(req.idtag_attempts)]
    if result_file:
        cmd += ["--output", result_file]
    return cmd


def _build_check_cmd(req: RunCheckRequest) -> list[str]:
    cmd = [*OCPPSCAN_CMD, "checks", "run", req.check_id]
    cmd += ["--target", req.target, "--charger-id", req.charger_id]
    cmd += ["--version", req.version]
    if req.timeout != 10.0:
        cmd += ["--timeout", str(req.timeout)]
    if req.security_profile is not None:
        cmd += ["--security-profile", str(req.security_profile)]
    if req.username:
        cmd += ["--username", req.username]
    if req.password:
        cmd += ["--password", req.password]
    return cmd


async def _stream_subprocess(
    cmd: list[str],
    scan_id: Optional[str] = None,
):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "NO_COLOR": "1", "TERM": "dumb", "FORCE_COLOR": "0"},
    )
    try:
        if proc.stdout:
            async for line in proc.stdout:
                text = line.decode("utf-8", errors="replace").rstrip("\n")
                yield f"data: {json.dumps({'line': text})}\n\n"
        await proc.wait()
        done: dict = {"done": True, "exit_code": proc.returncode}
        if scan_id:
            done["scan_id"] = scan_id
        yield f"data: {json.dumps(done)}\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
        raise


@app.post("/scan")
async def run_scan(req: ScanRequest):
    scan_id = uuid.uuid4().hex
    result_path = Path(tempfile.gettempdir()) / f"ocppscan-{scan_id}.json"
    cmd = _build_scan_cmd(req, result_file=str(result_path))
    return StreamingResponse(_stream_subprocess(cmd, scan_id=scan_id), media_type="text/event-stream")


@app.post("/run-check")
async def run_check(req: RunCheckRequest):
    cmd = _build_check_cmd(req)
    return StreamingResponse(_stream_subprocess(cmd), media_type="text/event-stream")


def main():
    import uvicorn

    reload = bool(os.getenv("OCPPSCAN_DEV"))
    uvicorn.run(
        "frontend.app:app" if reload else app,
        host="127.0.0.1",
        port=8080,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
