from __future__ import annotations
from typing import List
from tenantsec.core.findings import Finding
from .runner import run_user_checks
from .refresh import refresh_all_user_sheets

def run_user_checks_with_refresh(
    tenant_id: str,
    *,
    org: dict,
    users: dict,
    signins: dict,
    mail_rules: dict,
    risky_users: dict,
) -> List[Finding]:
    refresh_all_user_sheets(
        tenant_id,
        org=org,
        users=users,
        signins=signins,
        mail_rules=mail_rules,
        risky_users=risky_users,
    )
    return run_user_checks(tenant_id)

'''
from tenantsec.review.user_scanner.maintenance import purge_user_cache
purge_user_cache(tenant_id)
'''