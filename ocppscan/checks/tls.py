from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlparse

from ocppscan.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


class TLSNoTLS(BaseCheck):
    id = "tls.no-tls"
    name = "Plaintext connection accepted"
    severity = Severity.CRITICAL
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Attempts a raw plaintext WebSocket (ws://) connection. A secure CSMS should refuse it."
    fail = "The server accepts unencrypted connections. All traffic — credentials, meter data, commands — is visible on the network. Disable the plaintext listener and enforce wss:// only."
    pass_ = "The server did not accept a plaintext connection."

    async def run(self) -> CheckResult:
        parsed = urlparse(self.session.target)

        if parsed.scheme in ("ws", "http"):
            return self._fail(
                "Target endpoint uses plaintext (ws://) — no TLS in use at all",
                evidence={"url": self.session.target, "scheme": parsed.scheme},
                remediation=(
                    "Configure the CSMS to only accept encrypted (wss://) connections. "
                    "Redirect or reject all plaintext WebSocket upgrade requests."
                ),
                references=["OCPP Security Whitepaper", "OCPP 2.0.1 Security Profile 1+"],
            )

        host, port = self.session.get_host_port()
        path = f"{parsed.path.rstrip('/')}/{self.session.charger_id}"

        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.session.timeout,
            )
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Protocol: ocpp1.6\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(512), timeout=self.session.timeout)
            writer.close()
            resp_str = response.decode(errors="replace")

            if resp_str.startswith("HTTP/1.1 101") or "101" in resp_str[:30]:
                return self._fail(
                    "CSMS accepts plaintext WebSocket connections (ws://) despite having a TLS endpoint",
                    evidence={
                        "plain_url": f"ws://{host}:{port}{path}",
                        "response_line": resp_str.splitlines()[0] if resp_str else "",
                    },
                    remediation="Disable the plaintext WebSocket listener. Enforce TLS for all OCPP connections.",
                    references=["OCPP Security Whitepaper"],
                )
            return self._pass(
                "CSMS does not accept plaintext WebSocket connections",
                evidence={"response_line": resp_str.splitlines()[0] if resp_str else ""},
            )
        except asyncio.TimeoutError:
            return self._pass(
                "Plaintext port not reachable (connection timed out)",
                evidence={"host": host, "port": port},
            )
        except ConnectionRefusedError:
            return self._pass(
                "Plaintext port not reachable (connection refused)",
                evidence={"host": host, "port": port},
            )
        except Exception as e:
            return self._error(str(e))


class TLSSelfSigned(BaseCheck):
    id = "tls.self-signed"
    name = "Self-signed certificate accepted"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Inspects the TLS certificate chain presented during the handshake."
    fail = "The server uses a self-signed certificate. Clients cannot verify server identity, enabling man-in-the-middle attacks without detection."
    pass_ = "The certificate chains to a recognised CA."

    async def run(self) -> CheckResult:
        if not self.session.is_tls():
            return self._skip("Target uses plaintext (ws://); TLS certificate check not applicable")

        host, port = self.session.get_host_port()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self.session.timeout,
            )
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert(binary_form=False) if ssl_obj else None
            writer.close()
            await asyncio.sleep(0)

            if not cert:
                return self._inconclusive("Could not retrieve peer certificate")

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            if subject == issuer:
                return self._fail(
                    f"Server presents a self-signed certificate (CN: {subject.get('commonName', 'unknown')})",
                    evidence={"subject": subject, "issuer": issuer},
                    remediation=(
                        "Replace the self-signed certificate with one issued by a trusted CA. "
                        "Consider an internal PKI or Let's Encrypt."
                    ),
                    references=["OCPP 2.0.1 Security Profile 2+", "OCPP Security Whitepaper"],
                )
            return self._pass(
                "Server presents a CA-signed certificate",
                evidence={"subject": subject, "issuer": issuer},
            )
        except Exception as e:
            return self._error(str(e))


class TLSVersion(BaseCheck):
    id = "tls.version"
    name = "Weak TLS version"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Negotiates TLS and checks whether deprecated versions (1.0, 1.1) are accepted."
    fail = "TLS 1.0 or 1.1 accepted. These have known vulnerabilities (POODLE, BEAST). Restrict to TLS 1.2+."
    pass_ = "Only TLS 1.2 or later is accepted."

    async def run(self) -> CheckResult:
        if not self.session.is_tls():
            return self._skip("Target uses plaintext (ws://); TLS version check not applicable")

        host, port = self.session.get_host_port()
        accepted: list[str] = []

        for label, tls_ver in [("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = tls_ver
                ctx.maximum_version = tls_ver
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.session.timeout,
                )
                writer.close()
                await asyncio.sleep(0)
                accepted.append(label)
            except Exception:
                pass

        if accepted:
            return self._fail(
                f"CSMS accepts weak TLS version(s): {', '.join(accepted)}",
                evidence={"accepted_weak_versions": accepted},
                remediation=(
                    "Set minimum TLS version to 1.2 in the server configuration. "
                    "Disable TLS 1.0 and TLS 1.1."
                ),
                references=["NIST SP 800-52r2", "OCPP Security Whitepaper"],
            )
        return self._pass(
            "CSMS does not accept TLS 1.0 or TLS 1.1",
            evidence={"tested_versions": ["TLSv1.0", "TLSv1.1"]},
        )


class TLSCiphers(BaseCheck):
    id = "tls.ciphers"
    name = "Weak cipher suites"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Enumerates cipher suites offered by the server during the TLS handshake."
    fail = "Weak ciphers offered (RC4, NULL, export-grade, anonymous). Traffic may be decrypted offline."
    pass_ = "Only strong, modern cipher suites are offered."

    _WEAK_CIPHERS = [
        "NULL-MD5",
        "NULL-SHA",
        "DES-CBC-SHA",
        "RC4-MD5",
        "RC4-SHA",
        "EXP-RC4-MD5",
        "EXP-DES-CBC-SHA",
        "ADH-AES128-SHA",
    ]

    async def run(self) -> CheckResult:
        if not self.session.is_tls():
            return self._skip("Target uses plaintext (ws://); cipher check not applicable")

        host, port = self.session.get_host_port()
        accepted: list[str] = []

        for cipher in self._WEAK_CIPHERS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_ciphers(cipher)
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.session.timeout,
                )
                ssl_obj = writer.get_extra_info("ssl_object")
                negotiated = ssl_obj.cipher() if ssl_obj else None
                writer.close()
                await asyncio.sleep(0)
                accepted.append(negotiated[0] if negotiated else cipher)
            except Exception:
                pass

        if accepted:
            return self._fail(
                f"CSMS accepts weak cipher suite(s): {', '.join(accepted)}",
                evidence={"accepted_weak_ciphers": accepted},
                remediation=(
                    "Restrict allowed cipher suites to AEAD ciphers (AES-GCM, ChaCha20-Poly1305). "
                    "Disable NULL, RC4, DES, and EXPORT ciphers."
                ),
                references=["NIST SP 800-52r2", "OWASP TLS Cheat Sheet"],
            )
        return self._pass(
            "CSMS does not accept known weak cipher suites",
            evidence={"tested_ciphers": self._WEAK_CIPHERS},
        )


class TLSNoClientCert(BaseCheck):
    id = "tls.no-client-cert"
    name = "Client certificate not enforced"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.RAW
    applies_to = ["1.6", "2.0.1"]
    what = "Completes a TLS handshake without presenting a client certificate. OCPP Security Profile 3 requires mutual TLS."
    fail = "The server does not require a client certificate. Any host on the network can impersonate a charger."
    pass_ = "The server requires a client certificate (mutual TLS enforced)."

    async def run(self) -> CheckResult:
        sp = self.session.security_profile
        if sp is None or sp < 2:
            return self._skip(
                "Skipping: requires --security-profile 2 or 3. "
                "This check only applies when the CSMS is declared to use Security Profile 2 or 3."
            )
        if not self.session.is_tls():
            return self._skip("Target uses plaintext (ws://); client certificate check not applicable")

        host, port = self.session.get_host_port()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Intentionally no client certificate

        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx),
                timeout=self.session.timeout,
            )
            writer.close()
            await asyncio.sleep(0)
            return self._fail(
                f"CSMS accepted a TLS connection without a client certificate despite Security Profile {sp}",
                evidence={
                    "declared_security_profile": sp,
                    "client_cert_provided": False,
                    "result": "TLS handshake succeeded",
                },
                remediation=(
                    "Enable mutual TLS (mTLS) on the CSMS TLS listener. "
                    "Require and verify client certificates for Security Profile 2 and 3."
                ),
                references=["OCPP 2.0.1 Section 10.3", "OCPP Security Whitepaper"],
            )
        except ssl.SSLError as e:
            if "certificate" in str(e).lower() or "handshake" in str(e).lower():
                return self._pass(
                    "CSMS correctly requires a client certificate",
                    evidence={"ssl_rejection": str(e)},
                )
            return self._error(f"Unexpected SSL error: {e}")
        except Exception as e:
            return self._error(str(e))
