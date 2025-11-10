# src/tenantsec/core/user_exchange_service.py
from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_cache_dir, read_json, write_json_atomic

def fetch_mail_rules(tenant_id: str) -> Dict[str, Any]:
    """
    Collects inbox message rules for all users (Exchange Online).
    GET /users/{id}/mailFolders/inbox/messageRules
    """
    cache = tenant_cache_dir(tenant_id) / "USER" / "mail_rules.json"
    try:
        cached = read_json(cache)
        if cached:
            return cached
    except Exception:
        pass

    client = GraphClient(tenant_id)
    users = client.get_json("/users?$select=id,userPrincipalName").get("value", [])
    out_items: List[Dict[str, Any]] = []

    for u in users:
        uid = u["id"]
        upn = u["userPrincipalName"]
        rules = client.get_json(f"/users/{uid}/mailFolders/inbox/messageRules").get("value", [])
        out_items.append({"userId": uid, "userPrincipalName": upn, "rules": rules})

    out = {"items": out_items}
    write_json_atomic(cache, out)
    return out
