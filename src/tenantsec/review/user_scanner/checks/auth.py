'''
from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.findings import Finding

def _add(finds: List[Finding], **kw): finds.append(Finding(**kw))

def _tenant_country(sheets: Dict[str, Any]) -> str:
    return (sheets.get("org") or {}).get("organization", {}).get("country") or ""

def chk_user_mfa_disabled(sheets: Dict[str, Any], finds: List[Finding]) -> None:
    for u in (sheets.get("users") or {}).get("items", []):
        if not u.get("mfaEnabled", False):
            _add(finds,
                id="user.mfa.disabled",
                title=f"User without MFA: {u.get('userPrincipalName')}",
                severity="high",
                summary="This user does not have MFA enabled.",
                remediation="Enable MFA for the user or require via Conditional Access.",
                docs="https://learn.microsoft.com/entra/identity/authentication/howto-mfa-userstates",
                evidence=[{"userId": u.get("id"), "upn": u.get("userPrincipalName")}])

def chk_signin_foreign_country(sheets: Dict[str, Any], finds: List[Finding]) -> None:
    tenant_ctry = _tenant_country(sheets)
    if not tenant_ctry:
        return
    for s in (sheets.get("signins") or {}).get("items", []):
        if (s.get("status") or "").lower() != "success":
            continue
        c = (s.get("country") or "").upper()
        if not c or c == tenant_ctry.upper():
            continue
        _add(finds,
            id="user.signin.foreign_country",
            title="Successful sign-in from a foreign country",
            severity="high",
            summary=f"User {s.get('userPrincipalName') or s.get('userId')} signed in from {c} (tenant country {tenant_ctry}).",
            remediation="Verify travel; consider CA by country or require MFA for non-trusted locations.",
            docs="https://learn.microsoft.com/entra/identity/conditional-access/location-condition",
            evidence=[{"userId": s.get("userId"), "upn": s.get("userPrincipalName"),
                       "country": c, "time": s.get("createdDateTime")}])
'''

from tenantsec.review.user_scanner.sheets import load_user_sheets
from tenantsec.core.findings import Finding
from datetime import datetime, timezone
from math import radians, sin, cos, sqrt, atan2
#from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.findings import Finding



def _add(finds: List[Finding], **kw): finds.append(Finding(**kw))

def _tenant_country(sheets: Dict[str, Any]) -> str:
    return (sheets.get("org") or {}).get("organization", {}).get("country") or ""

def chk_user_mfa_disabled(sheets: Dict[str, Any], finds: List[Finding]) -> None:
    for u in (sheets.get("users") or {}).get("items", []):
        if not u.get("mfaEnabled", False):
            _add(finds,
                id="user.mfa.disabled",
                title=f"User without MFA: {u.get('userPrincipalName')}",
                severity="high",
                summary="This user does not have MFA enabled.",
                remediation="Enable MFA for the user or require via Conditional Access.",
                docs="https://learn.microsoft.com/entra/identity/authentication/howto-mfa-userstates",
                evidence=[{"userId": u.get("id"), "upn": u.get("userPrincipalName")}])


def _distance_km(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2): return 0
    R = 6371
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    return R * 2 * atan2(sqrt(a), sqrt(1 - a))

def chk_signin_foreign_country(tenant_id: str) -> list[Finding]:
    sheets = load_user_sheets(tenant_id)
    org_country = ((sheets.get("org") or {}).get("organization") or {}).get("country", "")
    sby = (sheets.get("signins_by_user") or {}).get("items", {})
    results = []

    for uid, logs in sby.items():
        for s in logs:
            ctry = (s.get("country") or "").upper()
            if not ctry or not org_country: 
                continue
            if ctry != org_country.upper() and s.get("status") == "success":
                results.append(Finding(
                    id="user.signin.foreign_country",
                    severity="HIGH",
                    title=f"Sign-in from foreign country: {s.get('upn')}",
                    description=f"Successful sign-in from {ctry}, tenant region {org_country}.",
                    remediation="Review sign-in and confirm user travel; enforce location-based CA policies.",
                    evidence=[{
                        "userId": uid,
                        "upn": s.get("upn"),
                        "country": ctry,
                        "city": s.get("city"),
                        "ip": s.get("ip"),
                        "time": s.get("createdDateTime"),
                    }]
                ))
                break  # one per user

    return results


def chk_signin_impossible_travel(tenant_id: str) -> list[Finding]:
    sheets = load_user_sheets(tenant_id)
    sby = (sheets.get("signins_by_user") or {}).get("items", {})
    results = []

    for uid, logs in sby.items():
        logs = sorted(logs, key=lambda x: x.get("createdDateTime") or "")
        prev = None
        for s in logs:
            if not prev:
                prev = s; continue
            # skip if same country
            if (s.get("country") or "") == (prev.get("country") or ""):
                prev = s; continue
            t1 = datetime.fromisoformat(prev["createdDateTime"].replace("Z", "+00:00"))
            t2 = datetime.fromisoformat(s["createdDateTime"].replace("Z", "+00:00"))
            hours = abs((t2 - t1).total_seconds() / 3600)
            if hours < 6:  # 6-hour impossible window
                results.append(Finding(
                    id="user.signin.impossible_travel",
                    severity="HIGH",
                    title=f"Impossible travel sign-in: {s.get('upn')}",
                    description=f"Sign-ins from {prev.get('country')} and {s.get('country')} within {hours:.1f}h.",
                    remediation="Investigate for credential compromise.",
                    evidence=[prev, s]
                ))
                break
            prev = s

    return results
