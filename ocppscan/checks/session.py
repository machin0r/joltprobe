from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from ocppscan.checks.base import BaseCheck, CheckResult, ConnectionMode, Severity


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class SessionMeterWithoutTransaction(BaseCheck):
    id = "session.meter-without-transaction"
    name = "MeterValues without active transaction"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends MeterValues referencing a transaction ID that does not exist."
    fail = "The server accepted the meter readings. Fraudulent billing entries can be injected without a real transaction."
    pass_ = "The server rejected meter values for an unknown transaction ID."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        fake_txn_id = 999999
        if self.session.version == "1.6":
            payload: dict = {
                "connectorId": 1,
                "transactionId": fake_txn_id,
                "meterValue": [
                    {
                        "timestamp": _ts(),
                        "sampledValue": [{"value": "0", "unit": "Wh"}],
                    }
                ],
            }
            action = "MeterValues"
        else:
            payload = {
                "evseId": 1,
                "customData": None,
                "meterValue": [
                    {
                        "timestamp": _ts(),
                        "sampledValue": [{"value": 0, "measurand": "Energy.Active.Import.Register", "unitOfMeasure": {"unit": "Wh"}}],
                    }
                ],
            }
            action = "MeterValues"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            if msg_type == 3:
                return self._fail(
                    f"CSMS accepted MeterValues referencing non-existent transaction ID {fake_txn_id}",
                    evidence={"fake_transaction_id": fake_txn_id, "response": resp[2] if len(resp) > 2 else {}},
                    remediation=(
                        "Validate that the transaction ID in MeterValues refers to an active transaction "
                        "started by the same charger. Return a CALLERROR for unknown transaction IDs."
                    ),
                    references=["OCPP 1.6 Section 5.11", "OCPP 2.0.1 Section 12.4"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for MeterValues with unknown transaction ID",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response type", evidence={"response": resp})
        except asyncio.TimeoutError:
            return self._inconclusive(
                "No response to MeterValues with fake transaction ID (timeout)",
                evidence={"fake_transaction_id": fake_txn_id},
            )
        except Exception as e:
            return self._error(str(e))


class SessionStopForeignTransaction(BaseCheck):
    id = "session.stop-foreign-transaction"
    name = "StopTransaction for foreign transaction"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends StopTransaction using a transaction ID from a different charger's active session."
    fail = "The server allowed the cross-session stop. Any charger can terminate another charger's session."
    pass_ = "The server rejected the StopTransaction for a foreign transaction ID."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        fake_txn_id = 888888
        if self.session.version == "1.6":
            payload: dict = {
                "transactionId": fake_txn_id,
                "meterStop": 0,
                "timestamp": _ts(),
                "reason": "Local",
            }
            action = "StopTransaction"
        else:
            payload = {
                "eventType": "Ended",
                "timestamp": _ts(),
                "seqNo": 1,
                "transactionInfo": {"transactionId": str(fake_txn_id), "stoppedReason": "Local"},
                "evse": {"id": 1},
            }
            action = "TransactionEvent"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            if msg_type == 3:
                resp_payload = resp[2] if len(resp) > 2 else {}
                id_tag_info = resp_payload.get("idTagInfo", {})
                status = id_tag_info.get("status", "unknown")
                return self._fail(
                    f"CSMS accepted StopTransaction for non-existent transaction ID {fake_txn_id}",
                    evidence={
                        "fake_transaction_id": fake_txn_id,
                        "response_status": status,
                        "response": resp_payload,
                    },
                    remediation=(
                        "Validate that StopTransaction references a transaction ID that is active "
                        "and was started by the same charger. Reject or log mismatches."
                    ),
                    references=["OCPP 1.6 Section 5.15", "OCPP 2.0.1 Section 12"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for StopTransaction with unknown transaction ID",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response type", evidence={"response": resp})
        except asyncio.TimeoutError:
            return self._inconclusive(
                "No response to StopTransaction with fake transaction ID (timeout)",
            )
        except Exception as e:
            return self._error(str(e))


class SessionStartWithoutAuth(BaseCheck):
    id = "session.start-without-auth"
    name = "StartTransaction without authorisation"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6"]
    what = "Attempts StartTransaction without a prior successful Authorize exchange."
    fail = "The server permitted the transaction to start without authorisation. Charging begins without a valid RFID or app token."
    pass_ = "The server requires authorisation before accepting StartTransaction."

    async def run(self) -> CheckResult:
        if self.session.version != "1.6":
            return self._skip("This check is OCPP 1.6 only (use TransactionEvent for 2.0.1)")

        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        # StartTransaction without a prior Authorize call
        payload = {
            "connectorId": 1,
            "idTag": "UNAUTH-TAG-9999",
            "meterStart": 0,
            "timestamp": _ts(),
        }

        try:
            resp = await conn.send_call("StartTransaction", payload)
            msg_type = resp[0]
            await conn.close()
            if msg_type == 3:
                resp_payload = resp[2] if len(resp) > 2 else {}
                id_tag_info = resp_payload.get("idTagInfo", {})
                status = id_tag_info.get("status", "unknown")
                if status == "Accepted":
                    return self._fail(
                        "CSMS accepted StartTransaction with an unrecognised idTag without prior Authorize",
                        evidence={"idTag": "UNAUTH-TAG-9999", "response_status": status},
                        remediation=(
                            "Require a successful Authorize call before accepting StartTransaction. "
                            "Reject idTags not in the local auth list or not validated against the backend."
                        ),
                        references=["OCPP 1.6 Section 5.4", "OCPP 1.6 Section 5.11"],
                    )
                return self._pass(
                    f"CSMS rejected StartTransaction without prior authorization (idTag status: {status})",
                    evidence={"response_status": status},
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for StartTransaction without auth",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive("No response to StartTransaction without auth (timeout)")
        except Exception as e:
            await conn.close()
            return self._error(str(e))


class SessionConnectorStatusSpoof(BaseCheck):
    id = "session.connector-status-spoof"
    name = "Connector status spoofing"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends StatusNotification with a manipulated connector state (e.g. Available while a transaction is running)."
    fail = "The server accepted the spoofed status. Active sessions can be hidden or connectors can be made to appear unavailable."
    pass_ = "The server ignored or rejected the inconsistent status notification."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        spoof_statuses = ["Faulted", "Unavailable"]
        accepted = []

        for status in spoof_statuses:
            if self.session.version == "1.6":
                payload: dict = {
                    "connectorId": 1,
                    "errorCode": "NoError",
                    "status": status,
                    "timestamp": _ts(),
                }
            else:
                payload = {
                    "timestamp": _ts(),
                    "connectorStatus": status,
                    "evseId": 1,
                    "connectorId": 1,
                }
            try:
                resp = await conn.send_call("StatusNotification", payload)
                if resp[0] == 3:
                    accepted.append(status)
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        if accepted:
            return self._fail(
                f"CSMS accepted StatusNotification with spoofed connector state(s): {accepted}. "
                "A charger can mark itself or other connectors out of service without a physical event.",
                evidence={"accepted_statuses": accepted, "connector_id": 1},
                remediation=(
                    "Validate StatusNotification state transitions server-side. "
                    "Log and alert on unexpected transitions (e.g. Faulted without a prior error event). "
                    "Do not blindly reflect charger-reported status to operators without validation."
                ),
                references=["OCPP 1.6 Section 5.14", "OCPP 2.0.1 Section 7.3"],
            )
        return self._pass(
            "CSMS did not accept spoofed StatusNotification states without error",
            evidence={"tested_statuses": spoof_statuses},
        )


class SessionTransactionIdEnumeration(BaseCheck):
    id = "session.transaction-id-enumeration"
    name = "Transaction ID enumeration"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Probes sequential transaction IDs via StopTransaction to infer active or historical sessions."
    fail = "The server responds differently to valid vs invalid transaction IDs, enabling enumeration of charging history."
    pass_ = "Consistent responses regardless of transaction ID validity."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        accepted_ids = []
        max_attempts = 20

        for txn_id in range(1, max_attempts + 1):
            if self.session.version == "1.6":
                payload: dict = {
                    "transactionId": txn_id,
                    "meterStop": 0,
                    "timestamp": _ts(),
                    "reason": "Local",
                }
                action = "StopTransaction"
            else:
                payload = {
                    "eventType": "Ended",
                    "timestamp": _ts(),
                    "seqNo": txn_id,
                    "transactionInfo": {
                        "transactionId": str(txn_id),
                        "stoppedReason": "Local",
                    },
                    "evse": {"id": 1},
                }
                action = "TransactionEvent"

            try:
                resp = await conn.send_call(action, payload)
                if resp[0] == 3:
                    accepted_ids.append(txn_id)
            except asyncio.TimeoutError:
                break
            except Exception:
                break

        await conn.close()

        if accepted_ids:
            return self._fail(
                f"CSMS returned CALLRESULT for StopTransaction with {len(accepted_ids)} sequential transaction ID(s) "
                f"not started by this charger (IDs: {accepted_ids[:5]}{'...' if len(accepted_ids) > 5 else ''})",
                evidence={
                    "accepted_transaction_ids": accepted_ids,
                    "probed_range": f"1–{max_attempts}",
                },
                remediation=(
                    "Validate that StopTransaction (or TransactionEvent Ended) references a transaction ID "
                    "that was started by the same charger. Return CALLERROR for foreign or unknown IDs."
                ),
                references=["OCPP 1.6 Section 5.15", "OCPP 2.0.1 Section 12"],
            )
        return self._pass(
            f"CSMS did not accept StopTransaction for any of {max_attempts} probed sequential transaction IDs",
            evidence={"probed_range": f"1–{max_attempts}"},
        )


class SessionConcurrentTransactions(BaseCheck):
    id = "session.concurrent-transactions"
    name = "Concurrent transactions on same connector"
    severity = Severity.MEDIUM
    connection_mode = ConnectionMode.DEDICATED
    applies_to = ["1.6", "2.0.1"]
    what = "Attempts to start two transactions simultaneously on the same connector."
    fail = "The server accepted both. Double-billing or meter data corruption may occur."
    pass_ = "The server rejected the second concurrent transaction on the same connector."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.new_connection(send_boot=True)
        except Exception as e:
            return self._error(f"Could not connect: {e}")

        if self.session.version == "1.6":
            start_payload: dict = {
                "connectorId": 1,
                "idTag": "OCPPSCAN-TEST",
                "meterStart": 0,
                "timestamp": _ts(),
            }
            action = "StartTransaction"
        else:
            start_payload = {
                "eventType": "Started",
                "timestamp": _ts(),
                "seqNo": 1,
                "transactionInfo": {"transactionId": "scan-txn-1"},
                "idToken": {"idToken": "OCPPSCAN-TEST", "type": "ISO14443"},
                "evse": {"id": 1, "connectorId": 1},
            }
            action = "TransactionEvent"

        first_txn_id = None
        try:
            resp1 = await conn.send_call(action, start_payload)
            if resp1[0] == 3:
                resp_payload = resp1[2] if len(resp1) > 2 else {}
                first_txn_id = resp_payload.get("transactionId")
        except asyncio.TimeoutError:
            await conn.close()
            return self._inconclusive("No response to first StartTransaction (timeout)")
        except Exception as e:
            await conn.close()
            return self._error(str(e))

        if self.session.version == "1.6":
            start_payload2: dict = {
                "connectorId": 1,
                "idTag": "OCPPSCAN-TEST2",
                "meterStart": 0,
                "timestamp": _ts(),
            }
        else:
            start_payload2 = {
                "eventType": "Started",
                "timestamp": _ts(),
                "seqNo": 2,
                "transactionInfo": {"transactionId": "scan-txn-2"},
                "idToken": {"idToken": "OCPPSCAN-TEST2", "type": "ISO14443"},
                "evse": {"id": 1, "connectorId": 1},
            }

        try:
            resp2 = await conn.send_call(action, start_payload2)
            await conn.close()
            if resp2[0] == 3:
                resp_payload2 = resp2[2] if len(resp2) > 2 else {}
                second_txn_id = resp_payload2.get("transactionId")
                id_tag_info = resp_payload2.get("idTagInfo", {})
                status = id_tag_info.get("status", "unknown")
                if status == "Accepted" or second_txn_id:
                    return self._fail(
                        "CSMS accepted a second StartTransaction on connector 1 while a transaction was already active",
                        evidence={
                            "first_transaction_id": first_txn_id,
                            "second_transaction_id": second_txn_id,
                            "second_response_status": status,
                        },
                        remediation=(
                            "Track active transaction state per connector. "
                            "Reject StartTransaction on a connector that already has an active transaction."
                        ),
                        references=["OCPP 1.6 Section 5.11", "OCPP 2.0.1 Section 12"],
                    )
                return self._pass(
                    f"CSMS rejected second StartTransaction on connector 1 (status: {status})",
                    evidence={"second_response_status": status},
                )
            if resp2[0] == 4:
                return self._pass(
                    "CSMS returned CALLERROR for second StartTransaction on already-active connector",
                    evidence={"callerror_code": resp2[2] if len(resp2) > 2 else ""},
                )
            return self._inconclusive("Unexpected response to second StartTransaction", evidence={"response": resp2})
        except asyncio.TimeoutError:
            await conn.close()
            return self._pass(
                "CSMS did not respond to second StartTransaction on same connector (timeout — likely rejected)",
            )
        except Exception as e:
            await conn.close()
            return self._error(str(e))


class SessionLocalAuthListAbuse(BaseCheck):
    id = "session.local-auth-list-abuse"
    name = "Local auth list manipulation"
    severity = Severity.HIGH
    connection_mode = ConnectionMode.SHARED
    applies_to = ["1.6", "2.0.1"]
    what = "Sends an unsolicited SendLocalList to add entries to the server's authorisation cache."
    fail = "The server accepted the list modification. An attacker can whitelist arbitrary idTags for offline charging."
    pass_ = "The server rejected the unsolicited SendLocalList."

    async def run(self) -> CheckResult:
        try:
            conn = await self.session.get_shared_connection()
        except Exception as e:
            return self._error(f"Could not obtain shared connection: {e}")

        if self.session.version == "1.6":
            payload: dict = {
                "listVersion": 1,
                "updateType": "Full",
                "localAuthorizationList": [
                    {"idTag": "INJECTED-ADMIN", "idTagInfo": {"status": "Accepted"}},
                    {"idTag": "BACKDOOR-9999", "idTagInfo": {"status": "Accepted"}},
                ],
            }
            action = "SendLocalList"
        else:
            payload = {
                "versionNumber": 1,
                "updateType": "Full",
                "localAuthorizationList": [
                    {
                        "idToken": {"idToken": "INJECTED-ADMIN", "type": "ISO14443"},
                        "idTokenInfo": {"status": "Accepted"},
                    }
                ],
            }
            action = "SendLocalList"

        try:
            resp = await conn.send_call(action, payload)
            msg_type = resp[0]
            if msg_type == 3:
                resp_payload = resp[2] if len(resp) > 2 else {}
                return self._fail(
                    "CSMS accepted a SendLocalList command sent by the charger, "
                    "allowing injection of arbitrary idTags into the local auth list",
                    evidence={"injected_tags": ["INJECTED-ADMIN", "BACKDOOR-9999"], "response": resp_payload},
                    remediation=(
                        "SendLocalList should only be accepted from the CSMS to the charger, never the reverse. "
                        "Return NotImplemented or SecurityError for CP-originated SendLocalList calls."
                    ),
                    references=["OCPP 1.6 Section 5.7", "OCPP 2.0.1 Section 10.6"],
                )
            if msg_type == 4:
                return self._pass(
                    "CSMS returned CALLERROR for CP-originated SendLocalList (correct behaviour)",
                    evidence={"callerror_code": resp[2] if len(resp) > 2 else ""},
                )
            return self._inconclusive("Unexpected response", evidence={"response": resp})
        except asyncio.TimeoutError:
            return self._pass(
                "CSMS did not respond to CP-originated SendLocalList (timeout — likely ignored)",
            )
        except Exception as e:
            return self._error(str(e))
