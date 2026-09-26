from joltprobe.checks.tls import TLSNoTLS, TLSSelfSigned, TLSVersion, TLSCiphers, TLSNoClientCert
from joltprobe.checks.auth import (
    AuthNoBasicAuth,
    AuthDefaultCredentials,
    AuthArbitraryChargerId,
    AuthDuplicateIdentity,
    AuthNoBootRequired,
    AuthIdTagEnumeration,
)
from joltprobe.checks.session import (
    SessionMeterWithoutTransaction,
    SessionStopForeignTransaction,
    SessionStartWithoutAuth,
    SessionLocalAuthListAbuse,
    SessionConnectorStatusSpoof,
    SessionTransactionIdEnumeration,
    SessionConcurrentTransactions,
)
from joltprobe.checks.downgrade import (
    DowngradeProfileReconnect,
    DowngradeChangeConfig,
    DowngradeStaleProfile,
)
from joltprobe.checks.message import (
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
from joltprobe.checks.billing import BillingNegativeMeterValue, BillingInflatedMeterValue
from joltprobe.checks.websocket import WebsocketNoSubprotocol, WebsocketWrongSubprotocol
from joltprobe.checks.dos import DosConnectionFlood, DosMessageRate, DosLargePayload
from joltprobe.checks.cert import CertSignPreBoot, CertSignMalformedCsr
from joltprobe.checks.firmware import FirmwareUpdateUrl, DiagnosticsUploadUrl
from joltprobe.injection.checks import (
    InjectionChargeBoxId,
    InjectionIdTag,
    InjectionVendorId,
    InjectionMessageId,
    InjectionReason,
    InjectionMeterValues,
    InjectionSoap,
)

_ALL_INJECTION = [
    InjectionChargeBoxId,
    InjectionIdTag,
    InjectionVendorId,
    InjectionMessageId,
    InjectionReason,
    InjectionMeterValues,
    InjectionSoap,
]

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
    CertSignPreBoot,
    CertSignMalformedCsr,
    FirmwareUpdateUrl,
    DiagnosticsUploadUrl,
    *_ALL_INJECTION,
]

CATEGORIES: dict[str, list] = {
    "tls": [TLSNoTLS, TLSSelfSigned, TLSVersion, TLSCiphers, TLSNoClientCert],
    "auth": [AuthNoBasicAuth, AuthDefaultCredentials, AuthArbitraryChargerId, AuthDuplicateIdentity, AuthNoBootRequired, AuthIdTagEnumeration],
    "session": [SessionMeterWithoutTransaction, SessionStopForeignTransaction, SessionStartWithoutAuth, SessionLocalAuthListAbuse, SessionConnectorStatusSpoof, SessionTransactionIdEnumeration, SessionConcurrentTransactions],
    "downgrade": [DowngradeProfileReconnect, DowngradeChangeConfig, DowngradeStaleProfile],
    "cert": [CertSignPreBoot, CertSignMalformedCsr],
    "firmware": [FirmwareUpdateUrl, DiagnosticsUploadUrl],
    "message": [MessageMalformedJson, MessageOversizedFields, MessageWrongTypes, MessageInjectionChargerId, MessageUnknownAction, MessageMissingRequiredFields, MessageDeeplyNestedJson, MessageTimestampSkew, MessageUnicodeNullBytes],
    "billing": [BillingNegativeMeterValue, BillingInflatedMeterValue],
    "websocket": [WebsocketNoSubprotocol, WebsocketWrongSubprotocol],
    "dos": [DosConnectionFlood, DosMessageRate, DosLargePayload],
    "injection": [
        InjectionChargeBoxId,
        InjectionIdTag,
        InjectionVendorId,
        InjectionMessageId,
        InjectionReason,
        InjectionMeterValues,
        InjectionSoap,
    ],
}

CHECK_BY_ID: dict[str, type] = {cls.id: cls for cls in ALL_CHECKS}

# Attach the CWE classification to every check class so it flows into results,
# the CLI listing, and reports.
from joltprobe.checks.mappings import apply_cwe  # noqa: E402

apply_cwe(ALL_CHECKS)
