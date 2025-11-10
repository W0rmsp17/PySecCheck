from __future__ import annotations
from typing import Optional
from .store import write_sheet
# Import your adapter(s) or services that fetch fresh data:
# from tenantsec.review.user_sheet_adapter import (
#     fetch_org_for_user_sheet,
#     fetch_users_for_user_sheet,
#     fetch_signins_for_user_sheet,
#     fetch_mail_rules_for_user_sheet,
#     fetch_risky_users_for_user_sheet,
# )

def refresh_user_org(tenant_id: str, data: dict) -> None:
    # Expected: {"organization": {"country": "US", "display_name": "..."}}
    write_sheet(tenant_id, "org", data)

def refresh_users(tenant_id: str, data: dict) -> None:
    # Expected: {"items": [ {id, userPrincipalName, mfaEnabled, lastSignInDateTime, ...}, ... ]}
    write_sheet(tenant_id, "users", data)

def refresh_signins(tenant_id: str, data: dict) -> None:
    # Expected: {"items": [ {userId, userPrincipalName, status, country, createdDateTime}, ... ]}
    write_sheet(tenant_id, "signins", data)

def refresh_mail_rules(tenant_id: str, data: dict) -> None:
    # Expected: {"items": [ {userId, userPrincipalName, rules:[{name,actions:{forwardTo[],forwardToExternal}}]}, ... ]}
    write_sheet(tenant_id, "mail_rules", data)

def refresh_risky_users(tenant_id: str, data: dict) -> None:
    # Expected: {"items": [ {userId/upn, riskLevel, riskDetail, lastSeen}, ... ]}
    write_sheet(tenant_id, "risky_users", data)

def refresh_all_user_sheets(
    tenant_id: str,
    *,
    org: Optional[dict]=None,
    users: Optional[dict]=None,
    signins: Optional[dict]=None,
    mail_rules: Optional[dict]=None,
    risky_users: Optional[dict]=None,
) -> None:
    if org is not None:        refresh_user_org(tenant_id, org)
    if users is not None:      refresh_users(tenant_id, users)
    if signins is not None:    refresh_signins(tenant_id, signins)
    if mail_rules is not None: refresh_mail_rules(tenant_id, mail_rules)
    if risky_users is not None:refresh_risky_users(tenant_id, risky_users)
