from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.findings import Finding
#from . import register

# If you don't have risky user checks yet, keep this empty file with no-ops.
# Example check (optional):
# @register
# def chk_risky_signin_detected(sheets: Dict[str, Any], findings: List[Finding]) -> None:
#     risky = (sheets.get("risky_users") or {}).get("items", [])
#     for u in risky:
#         findings.append(Finding(
#             id="user.risky_signin_detected",
#             title=f"Risky sign-in detected for {u.get('userPrincipalName') or u.get('id')}",
#             severity="high",
#             summary="Identity Protection reported a risky sign-in.",
#             remediation="Investigate sign-ins and consider blocking/reseting credentials.",
#             evidence=[{"userId": u.get("id"), "riskLevel": u.get("riskLevel")}],
#         ))
