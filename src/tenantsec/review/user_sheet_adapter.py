# src/tenantsec/review/user_sheet_adapter.py
from __future__ import annotations
from typing import Any, Dict, List
from tenantsec.core.cache_manager import tenant_cache_dir, write_json_atomic

def ensure_user_sheets(tenant_id: str) -> None:
    """
    Populate USER/org.json, USER/users.json, USER/signins.json, USER/mail_rules.json.
    Replace the sample with real calls into your *_service modules when ready.
    """
    base = tenant_cache_dir(tenant_id) / "USER"
    base.mkdir(parents=True, exist_ok=True)

    # --- SAMPLE / FAKE DATA (so checks show up now) ---
    org = {"organization": {"country": "US", "display_name": "SampleCo"}}

    users = {"items": [
        {"id": "u1", "userPrincipalName": "alice@example.com", "mfaEnabled": False,
         "lastSignInDateTime": "2025-08-01T10:00:00Z"},
        {"id": "u2", "userPrincipalName": "bob@example.com", "mfaEnabled": True,
         "lastSignInDateTime": "2025-01-01T00:00:00Z"},
    ]}

    signins = {"items": [
        {"userId": "u1", "userPrincipalName": "alice@example.com",
         "status": "success", "country": "AU", "createdDateTime": "2025-11-06T12:00:00Z"},
        {"userId": "u2", "userPrincipalName": "bob@example.com",
         "status": "success", "country": "US", "createdDateTime": "2025-11-06T11:00:00Z"},
    ]}

    mail_rules = {"items": [
        {"userId": "u1", "userPrincipalName": "alice@example.com",
         "rules": [
            {"name": "Forward external", "actions": {"forwardTo": ["exfil@evil.net"], "forwardToExternal": True}}
         ]},
        {"userId": "u2", "userPrincipalName": "bob@example.com",
         "rules": [
            {"name": "Normal rule", "actions": {"forwardTo": [], "forwardToExternal": False}}
         ]},
    ]}

    write_json_atomic(base / "org.json", org)
    write_json_atomic(base / "users.json", users)
    write_json_atomic(base / "signins.json", signins)
    write_json_atomic(base / "mail_rules.json", mail_rules)

def _render_report(self, findings, tenant_id):
    header = ["=== PySecCheck — User Security Review ===", f"Tenant: {tenant_id}", ""]
    if not findings:
        # optionally peek at sheet sizes for debug
        from tenantsec.review.user_scanner import load_user_sheets
        sheets = load_user_sheets(tenant_id)
        u = len(sheets.get("users", {}).get("items", []))
        s = len(sheets.get("signins", {}).get("items", []))
        m = len(sheets.get("mail_rules", {}).get("items", []))
        return "\n".join(header + [f"No user findings. ✅  (users:{u} signins:{s} rules:{m})"])
    blocks = [format_finding_to_text(f) for f in findings]
    return "\n".join(header + blocks)