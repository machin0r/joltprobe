from __future__ import annotations

import asyncio

from joltprobe.checks.base import Status
from joltprobe.checks.cert import CertSignPreBoot, CertSignMalformedCsr
from joltprobe.checks.firmware import FirmwareUpdateUrl, DiagnosticsUploadUrl


class FakeConn:
    def __init__(self, response=None, raise_exc: Exception | None = None):
        self._response = response
        self._raise = raise_exc
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    async def send_call(self, action, payload):
        self.calls.append((action, payload))
        if self._raise is not None:
            raise self._raise
        return self._response

    async def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, version="2.0.1", response=None, raise_exc=None):
        self.version = version
        self.conn = FakeConn(response=response, raise_exc=raise_exc)

    async def new_connection(self, *args, **kwargs):
        return self.conn

    async def get_shared_connection(self):
        return self.conn


def _run(check_cls, session):
    return asyncio.run(check_cls(session).run())


# ── cert.sign-preboot ────────────────────────────────────────────────────────

def test_sign_preboot_fail_on_accepted():
    s = FakeSession(response=[3, "id", {"status": "Accepted"}])
    r = _run(CertSignPreBoot, s)
    assert r.status == Status.FAIL
    assert s.conn.calls[0][0] == "SignCertificate"


def test_sign_preboot_pass_on_rejected():
    s = FakeSession(response=[3, "id", {"status": "Rejected"}])
    assert _run(CertSignPreBoot, s).status == Status.PASS


def test_sign_preboot_pass_on_callerror():
    s = FakeSession(response=[4, "id", "SecurityError", "no", {}])
    assert _run(CertSignPreBoot, s).status == Status.PASS


def test_sign_preboot_inconclusive_on_timeout():
    s = FakeSession(raise_exc=asyncio.TimeoutError())
    assert _run(CertSignPreBoot, s).status == Status.INCONCLUSIVE


def test_sign_preboot_skips_on_16():
    s = FakeSession(version="1.6", response=[3, "id", {"status": "Accepted"}])
    assert _run(CertSignPreBoot, s).status == Status.SKIP


# ── cert.sign-malformed ──────────────────────────────────────────────────────

def test_sign_malformed_fail_on_accepted():
    s = FakeSession(response=[3, "id", {"status": "Accepted"}])
    assert _run(CertSignMalformedCsr, s).status == Status.FAIL


def test_sign_malformed_pass_on_callerror():
    s = FakeSession(response=[4, "id", "FormationViolation", "bad csr", {}])
    assert _run(CertSignMalformedCsr, s).status == Status.PASS


# ── firmware.update-url / firmware.diagnostics-url ────────────────────────────

def test_firmware_update_fail_on_callresult():
    s = FakeSession(response=[3, "id", {"status": "Accepted"}])
    r = _run(FirmwareUpdateUrl, s)
    assert r.status == Status.FAIL
    assert s.conn.calls[0][0] == "UpdateFirmware"


def test_firmware_update_pass_on_callerror():
    s = FakeSession(response=[4, "id", "NotImplemented", "n/a", {}])
    assert _run(FirmwareUpdateUrl, s).status == Status.PASS


def test_diagnostics_uses_getlog_on_201():
    s = FakeSession(version="2.0.1", response=[4, "id", "NotImplemented", "n/a", {}])
    _run(DiagnosticsUploadUrl, s)
    assert s.conn.calls[0][0] == "GetLog"


def test_diagnostics_uses_getdiagnostics_on_16():
    s = FakeSession(version="1.6", response=[4, "id", "NotImplemented", "n/a", {}])
    _run(DiagnosticsUploadUrl, s)
    assert s.conn.calls[0][0] == "GetDiagnostics"


def test_firmware_update_payload_shape_201():
    s = FakeSession(version="2.0.1", response=[4, "id", "NotImplemented", "n/a", {}])
    _run(FirmwareUpdateUrl, s)
    _, payload = s.conn.calls[0]
    assert "firmware" in payload and "location" in payload["firmware"]


def test_firmware_update_payload_shape_16():
    s = FakeSession(version="1.6", response=[4, "id", "NotImplemented", "n/a", {}])
    _run(FirmwareUpdateUrl, s)
    _, payload = s.conn.calls[0]
    assert "location" in payload and "retrieveDate" in payload
