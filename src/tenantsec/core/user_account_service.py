# src/tenantsec/core/user_account_service.py
from __future__ import annotations
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_cache_dir, read_json, write_json_atomic

def fetch_users(tenant_id: str):
    cache = tenant_cache_dir(tenant_id) / "USER" / "users.json"
    try:
        cached = read_json(cache)
        if cached:
            return cached
    except Exception:
        pass

    client = GraphClient(tenant_id)
    data = client.get_json("/users?$select=id,displayName,userPrincipalName,accountEnabled,signInActivity,passwordPolicies")

    items = []
    for u in data.get("value", []):
        items.append({
            "id": u["id"],
            "userPrincipalName": u.get("userPrincipalName"),
            "displayName": u.get("displayName"),
            "accountEnabled": u.get("accountEnabled"),
            "lastSignInDateTime": (u.get("signInActivity") or {}).get("lastSignInDateTime"),
            "passwordNeverExpires": "PasswordNeverExpires" in (u.get("passwordPolicies") or ""),
        })

    out = {"items": items}
    write_json_atomic(cache, out)
    return out
