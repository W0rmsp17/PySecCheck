from __future__ import annotations
from typing import List, Any
from datetime import datetime, timedelta, timezone
from tenantsec.core.findings import Finding

Severity = str  # Literal types already in Finding; keep simple here.

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def days_ago(n: int) -> datetime:
    return utc_now() - timedelta(days=n)

def add(findings: List[Finding], *, id: str, title: str, severity: Severity,
        summary: str, remediation: str = "", docs: str = "", evidence: Any = None):
    findings.append(Finding(
        id=id,
        title=title,
        severity=severity,      # "info"|"low"|"medium"|"high"|"critical"
        summary=summary,
        remediation=remediation or None,
        docs=docs or None,
        evidence=evidence or None,
    ))
