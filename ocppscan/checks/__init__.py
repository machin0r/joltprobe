from ocppscan.checks.tls import TLSNoTLS, TLSSelfSigned, TLSVersion, TLSCiphers, TLSNoClientCert
from ocppscan.checks.auth import (
    AuthNoBasicAuth,
    AuthDefaultCredentials,
    AuthArbitraryChargerId,
    AuthDuplicateIdentity,
    AuthNoBootRequired,
    AuthIdTagEnumeration,
)
from ocppscan.checks.session import (
    SessionMeterWithoutTransaction,
    SessionStopForeignTransaction,
    SessionStartWithoutAuth,
    SessionLocalAuthListAbuse,
    SessionConnectorStatusSpoof,
    SessionTransactionIdEnumeration,
    SessionConcurrentTransactions,
)
from ocppscan.checks.downgrade import (
    DowngradeProfileReconnect,
    DowngradeChangeConfig,
    DowngradeStaleProfile,
)
from ocppscan.checks.message import (
    MessageMalformedJson,
    MessageOversizedFields,
    MessageWrongTypes,
    MessageInjectionChargerId,
    MessageUnknownAction,
    MessageMissingRequiredFields,
    MessageDeeplyNestedJson,
    MessageTimestampSkew,
    MessageUnicodeNullBytes,
)
from ocppscan.checks.billing import BillingNegativeMeterValue, BillingInflatedMeterValue
from ocppscan.checks.websocket import WebsocketNoSubprotocol, WebsocketWrongSubprotocol
from ocppscan.checks.dos import DosConnectionFlood, DosMessageRate, DosLargePayload

ALL_CHECKS = [
    TLSNoTLS,
    TLSSelfSigned,
    TLSVersion,
    TLSCiphers,
    TLSNoClientCert,
    AuthNoBasicAuth,
    AuthDefaultCredentials,
    AuthArbitraryChargerId,
    AuthDuplicateIdentity,
    AuthNoBootRequired,
    AuthIdTagEnumeration,
    SessionMeterWithoutTransaction,
    SessionStopForeignTransaction,
    SessionStartWithoutAuth,
    SessionLocalAuthListAbuse,
    SessionConnectorStatusSpoof,
    SessionTransactionIdEnumeration,
    SessionConcurrentTransactions,
    DowngradeProfileReconnect,
    DowngradeChangeConfig,
    DowngradeStaleProfile,
    MessageMalformedJson,
    MessageOversizedFields,
    MessageWrongTypes,
    MessageInjectionChargerId,
    MessageUnknownAction,
    MessageMissingRequiredFields,
    MessageDeeplyNestedJson,
    MessageTimestampSkew,
    MessageUnicodeNullBytes,
    BillingNegativeMeterValue,
    BillingInflatedMeterValue,
    WebsocketNoSubprotocol,
    WebsocketWrongSubprotocol,
    DosConnectionFlood,
    DosMessageRate,
    DosLargePayload,
]

CATEGORIES: dict[str, list] = {
    "tls": [TLSNoTLS, TLSSelfSigned, TLSVersion, TLSCiphers, TLSNoClientCert],
    "auth": [AuthNoBasicAuth, AuthDefaultCredentials, AuthArbitraryChargerId, AuthDuplicateIdentity, AuthNoBootRequired, AuthIdTagEnumeration],
    "session": [SessionMeterWithoutTransaction, SessionStopForeignTransaction, SessionStartWithoutAuth, SessionLocalAuthListAbuse, SessionConnectorStatusSpoof, SessionTransactionIdEnumeration, SessionConcurrentTransactions],
    "downgrade": [DowngradeProfileReconnect, DowngradeChangeConfig, DowngradeStaleProfile],
    "message": [MessageMalformedJson, MessageOversizedFields, MessageWrongTypes, MessageInjectionChargerId, MessageUnknownAction, MessageMissingRequiredFields, MessageDeeplyNestedJson, MessageTimestampSkew, MessageUnicodeNullBytes],
    "billing": [BillingNegativeMeterValue, BillingInflatedMeterValue],
    "websocket": [WebsocketNoSubprotocol, WebsocketWrongSubprotocol],
    "dos": [DosConnectionFlood, DosMessageRate, DosLargePayload],
}

CHECK_BY_ID: dict[str, type] = {cls.id: cls for cls in ALL_CHECKS}
