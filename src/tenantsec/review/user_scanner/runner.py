# src/tenantsec/review/user_scanner/runner.py
from __future__ import annotations
from typing import List
from tenantsec.core.findings import Finding
from .sheets import load_user_sheets
from .checks import REGISTRY

def run_user_checks(tenant_id: str) -> List[Finding]:
    sheets = load_user_sheets(tenant_id)
    findings: List[Finding] = []
    for chk in REGISTRY:
        try:
            chk(sheets, findings)
        except Exception as e:
            findings.append(Finding(
                id="user.check.error",
                title=f"User check failed in {getattr(chk, '__name__', 'unknown')}",
                severity="low",
                summary=str(e),
            ))
    return findings
