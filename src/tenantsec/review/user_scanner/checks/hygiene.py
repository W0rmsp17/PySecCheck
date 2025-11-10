from __future__ import annotations
from typing import Dict, Any, List
from datetime import datetime
from ..helpers import add, days_ago
#from . import register
from datetime import datetime, timedelta, timezone
from tenantsec.core.findings import Finding

#@register
def user_inactive_90d(sheets: Dict[str, Any], findings: List[Any]) -> None:
    cutoff = days_ago(90)
    for u in sheets["users"]["items"]:
        last = u.get("lastSignInDateTime")
        if not last:
            continue
        try:
            dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except Exception:
            continue
        if dt < cutoff:
            upn = u.get("userPrincipalName") or u.get("id")
            add(findings,
                id="user.account.stale",
                title=f"Inactive user >90d: {upn}",
                severity="medium",
                summary="Account shows no sign-ins in the last 90 days.",
                remediation="Review with owner; disable or remove if no longer needed.",
                evidence=[{"lastSignIn": last, "userId": u.get("id"), "upn": upn}],
            )

#@register
def user_has_global_admin(sheets: Dict[str, Any], findings: List[Any]) -> None:
    for u in sheets["users"]["items"]:
        roles = set(u.get("roles") or [])
        if any("Global Administrator" in r for r in roles):
            upn = u.get("userPrincipalName") or u.get("id")
            add(findings,
                id="user.account.global_admin",
                title=f"User has Global Admin role: {upn}",
                severity="high",
                summary="Global Admin rights should be limited and protected with strong controls.",
                remediation="Reduce standing Global Admins; prefer PIM activation with approvals and MFA.",
                docs="https://learn.microsoft.com/entra/identity/privileged-identity-management/pim-configure",
                evidence=[{"roles": list(roles), "userId": u.get("id")}],
            )

def _add(finds: List[Finding], **kw): finds.append(Finding(**kw))
def _now_utc() -> datetime: return datetime.now(timezone.utc)

def chk_user_inactive_90d(sheets: Dict[str, Any], finds: List[Finding]) -> None:
    cutoff = _now_utc() - timedelta(days=90)
    for u in (sheets.get("users") or {}).get("items", []):
        last = u.get("lastSignInDateTime")
        if not last:
            continue
        try:
            last_ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
        except Exception:
            continue
        if last_ts < cutoff:
            _add(finds,
                 id="user.account.stale",
                 title=f"Inactive user >90d: {u.get('userPrincipalName')}",
                 severity="medium",
                 summary="User account shows no sign-ins in the last 90 days.",
                 remediation="Review with owner; disable or remove if no longer needed.",
                 evidence=[{"lastSignIn": last, "userId": u.get("id"), "upn": u.get("userPrincipalName")}])