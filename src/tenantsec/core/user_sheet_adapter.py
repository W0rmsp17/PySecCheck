# src/tenantsec/core/user_sheet_adapter.py
from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.cache import cache_dir, read_json

def get_users_index_sheet(tenant_id: str) -> Dict[str, Any]:
    """
    Adapter over user_service's cache:
      cache_dir(tenant_id, "Static") / users_index.json

    Returns normalized structure for scanners:
      {
        "items": [{
          "id": str,
          "userPrincipalName": str | None,
          "displayName": str | None,
          "accountEnabled": bool | None,
          "roles": List[str],
          "license_skus": List[str],
          "lastSignInDateTime": str | None,   # ISO8601
          "passwordNeverExpires": bool,
          "mfaEnabled": bool
        }],
        "raw_fields": [...]
      }
    """
    path = cache_dir(tenant_id, "Static") / "users_index.json"
    data = read_json(path) or {"users": [], "fields": []}

    items_out: List[Dict[str, Any]] = []
    for u in data.get("users", []):
        mfa_state = u.get("mfa_state") 
        items_out.append({
            "id": u.get("id"),
            "userPrincipalName": u.get("upn") or u.get("userPrincipalName") or u.get("mail"),
            "displayName": u.get("display_name") or u.get("displayName"),
            "accountEnabled": u.get("accountEnabled"),
            "roles": u.get("roles") or [],
            "license_skus": u.get("license_skus") or u.get("license_names") or [],
            "lastSignInDateTime": u.get("last_sign_in"),         
            "passwordNeverExpires": bool(u.get("passwordNeverExpires", False)),
            "mfaEnabled": (mfa_state == "Registered"),
        })

    return {"items": items_out, "raw_fields": data.get("fields", [])}

def _test_adapter_fake():
  
    fake = {
        "users": [{
            "id": "u1",
            "upn": "alex@contoso.com",
            "display_name": "Alex",
            "accountEnabled": True,
            "roles": ["Global Administrator"],
            "license_skus": ["SPE_E5"],
            "last_sign_in": "2025-10-20T12:00:00Z",
            "passwordNeverExpires": True,
            "mfa_state": "Registered"
        }],
        "fields": []
    }