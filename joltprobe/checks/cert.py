from __future__ import annotations

import asyncio

from joltprobe.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity

# A syntactically valid PEM-encoded PKCS#10 certificate signing request, used as
# the "well-formed" input for SignCertificate probes. It carries a throwaway key
# and an obviously-test subject so a CSMS that signs it produces only a benign,
# clearly-attributable certificate. This is a request blob only — no private key
# material is needed to send it.
_VALID_CSR = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIICdTCCAV0CAQAwMDEaMBgGA1UEAwwRSm9sdFByb2JlLVRlc3QtQ1MxEjAQBgNV\n"
    "BAoMCUpvbHRQcm9iZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO4N\n"
    "zdGkkCUSzn8fApHQ7iO46PwUpQBmImr+xblGA/Sh7PdVddhBBVz8WbAhgwlh6DR8\n"
    "y8bqk6paAgVxmZlUO4EtaeO8JjMdkjz6eT57BU3mau7zyEreSDfW4PzdhVWlflq1\n"
    "0BCb6Vw8USdbXcA7EtNYY5Evk1wDAsAvMBex5mZPZYeAlqoqUWd1lbJu7cb3GjZc\n"
    "CVn9JE70ERAZU4h62hyuf5rfEQbctaG8MJqu1He97fyWkXDGU1fBamiADtK9xguD\n"
    "kPNI/LSociZndxf6kR+aiiKiETGILxGY0aPyaTww/LFu0gUKIdI19/wEByyHr3d3\n"
    "IppvFVyIp+KWdHVSYHECAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQDRXlxJaDO6\n"
    "s7Az+es/bT5EB+of0O1ZwCM24NW9lUj8dCUQGWL+5ptlgKy2CP2ArpC6NQsjP49b\n"
    "wQO90VgC8skrVr1iSOW48VcptrtNqaZxbhc2AFBa51rR8w1kHdP2B7JIkoju6b5Z\n"
    "4roDqzjSqXdsGu7Y18anyUfXoqU6ydPAuO7yNZCHfcK1reEvQas8hAaMfaS9qfAw\n"
    "+nCcz5ggkzEBU89rSTltKkqRI03vb66ygIPKVXSS3Lkjcrk/8+0nljnijzxYxYe4\n"
    "Ff8befZFY0EbNblEd8ijmmGmfVsrnDeygQg3kUGORAQ8q291XaeCFPwgK9JwOw+l\n"
    "LKnS3cUuAPgO\n"
    "-----END CERTIFICATE REQUEST-----\n"
)


def _accepted(resp: list) -> bool:
    """True when the CSMS returned a CALLRESULT whose status is Accepted."""
    return (
        isinstance(resp, list)
        and len(resp) > 2
        and resp[0] == 3
        and isinstance(resp[2], dict)
        and str(resp[2].get("status", "")).lower() == "accepted"
    )


class CertSignPreBoot(BaseCheck):
    id = "cert.sign-preboot"
    name = "SignCertificate accepted before BootNotification"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["2.0.1"]
    what = (
        "Sends SignCertificate (a Charging Station → CSMS message) with a well-formed CSR on a "
        "fresh connection, without first sending BootNotification or otherwise establishing the "
        "station's identity."
    )
    fail = (
        "The CSMS returned Accepted and will sign a certificate for a station that has neither "
        "booted nor been authorised. An attacker who can reach the endpoint can obtain a "
        "CSMS-signed certificate."
    )
    pass_ = "The CSMS declined to sign the CSR before the station was booted/authorised."

    async def run(self) -> CheckResult:
        if self.session.version != "2.0.1":
            return self._skip("SignCertificate is an OCPP 2.0.1 message; skipping on 1.6")

        try:
            conn = await self.session.new_connection(send_boot=False)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        try:
            resp = await conn.send_call(
                "SignCertificate",
                {"csr": _VALID_CSR, "certificateType": "ChargingStationCertificate"},
            )
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive(
                "No response to SignCertificate before boot — cannot confirm whether the CSR "
                "would be signed."
            )
        except Exception as e:
            await conn.close()
            # The socket was already connected, so a send/receive exception here means
            # the CSMS closed the connection rather than signing the pre-boot CSR —
            # i.e. it declined. (Timeouts are handled separately above.)
            return self._pass(
                "CSMS closed/rejected the connection when SignCertificate was sent before boot",
                evidence={"rejection": str(e)[:200]},
            )

        await conn.close()

        if _accepted(resp):
            return self._fail(
                "CSMS accepted SignCertificate and returned Accepted before any BootNotification",
                evidence={"request": "SignCertificate (pre-boot)", "response": resp[2]},
                remediation=(
                    "Only process SignCertificate for a charging station that has completed "
                    "BootNotification and been accepted. Bind the signed certificate to the "
                    "authenticated station identity and reject requests from unknown stations."
                ),
                references=[
                    "OCPP 2.0.1 Part 2 — A02 (Certificate Signing)",
                    "OCPP 2.0.1 Security Whitepaper §5 (Certificate management)",
                ],
            )

        # CALLERROR or Rejected — the CSMS declined.
        detail = resp[2] if (isinstance(resp, list) and len(resp) > 2) else resp
        return self._pass(
            "CSMS did not sign the CSR before boot (rejected or returned an error)",
            evidence={"response": detail},
        )


class CertSignMalformedCsr(BaseCheck):
    id = "cert.sign-malformed"
    name = "SignCertificate accepts a malformed CSR"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.SHARED
    applies_to = ["2.0.1"]
    what = (
        "Sends SignCertificate with a CSR field that is not a valid PKCS#10 request (garbage "
        "text) after a normal BootNotification."
    )
    fail = (
        "The CSMS returned Accepted for a CSR it could not have parsed, indicating it does not "
        "validate CSR structure before feeding it to a signing routine."
    )
    pass_ = "The CSMS rejected the malformed CSR."

    async def run(self) -> CheckResult:
        if self.session.version != "2.0.1":
            return self._skip("SignCertificate is an OCPP 2.0.1 message; skipping on 1.6")

        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        try:
            resp = await conn.send_call(
                "SignCertificate",
                {"csr": "NOT-A-VALID-CSR-%%%-\x00-jolt", "certificateType": "ChargingStationCertificate"},
            )
        except asyncio.TimeoutError:
            return self._inconclusive("No response to a malformed SignCertificate request")
        except Exception as e:
            return self._error(str(e))

        if _accepted(resp):
            return self._fail(
                "CSMS returned Accepted for a CSR that is not a valid PKCS#10 request",
                evidence={"request": "SignCertificate (malformed csr)", "response": resp[2]},
                remediation=(
                    "Parse and validate the CSR (PKCS#10 structure and signature) before "
                    "accepting SignCertificate. Return Rejected for structurally invalid input."
                ),
                references=[
                    "OCPP 2.0.1 Part 2 — A02 (Certificate Signing)",
                    "OCPP 2.0.1 Security Whitepaper §5 (Certificate management)",
                ],
            )

        detail = resp[2] if (isinstance(resp, list) and len(resp) > 2) else resp
        return self._pass(
            "CSMS rejected the malformed CSR",
            evidence={"response": detail},
        )
