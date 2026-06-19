from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from joltprobe.connection import ScanSession


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"
    INCONCLUSIVE = "INCONCLUSIVE"


class ConnectionMode(str, Enum):
    SHARED = "SHARED"
    DEDICATED = "DEDICATED"
    RAW = "RAW"
    DUAL = "DUAL"


@dataclass
class CheckResult:
    id: str
    name: str
    severity: Severity
    status: Status
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
        }


class BaseCheck:
    id: str = ""
    name: str = ""
    severity: Severity = Severity.INFO
    connection_mode: ConnectionMode = ConnectionMode.SHARED
    applies_to: list[str] = ["1.6", "2.0.1"]
    what: str = ""
    fail: str = ""
    pass_: str = ""

    def __init__(self, session: "ScanSession") -> None:
        self.session = session

    async def run(self) -> CheckResult:
        raise NotImplementedError

    def _skip(self, reason: str) -> CheckResult:
        return CheckResult(
            id=self.id,
            name=self.name,
            severity=self.severity,
            status=Status.SKIP,
            description=reason,
        )

    def _error(self, reason: str) -> CheckResult:
        return CheckResult(
            id=self.id,
            name=self.name,
            severity=self.severity,
            status=Status.ERROR,
            description=f"Check could not complete: {reason}",
            evidence={"error": reason},
        )

    def _pass(self, description: str, evidence: Optional[dict] = None) -> CheckResult:
        return CheckResult(
            id=self.id,
            name=self.name,
            severity=self.severity,
            status=Status.PASS,
            description=description,
            evidence=evidence or {},
        )

    def _fail(
        self,
        description: str,
        evidence: Optional[dict] = None,
        remediation: str = "",
        references: Optional[list[str]] = None,
    ) -> CheckResult:
        return CheckResult(
            id=self.id,
            name=self.name,
            severity=self.severity,
            status=Status.FAIL,
            description=description,
            evidence=evidence or {},
            remediation=remediation,
            references=references or [],
        )

    def _inconclusive(self, description: str, evidence: Optional[dict] = None) -> CheckResult:
        return CheckResult(
            id=self.id,
            name=self.name,
            severity=self.severity,
            status=Status.INCONCLUSIVE,
            description=description,
            evidence=evidence or {},
        )
