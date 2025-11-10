# src/tenantsec/core/user_risk_service.py
from __future__ import annotations
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_cache_dir, read_json, write_json_atomic

def fetch_risky_users(tenant_id: str):
    cache = tenant_cache_dir(tenant_id) / "USER" / "risky_users.json"
    try:
        cached = read_json(cache)
        if cached:
            return cached
    except Exception:
        pass

    client = GraphClient(tenant_id)
    data = client.get_json("/identityProtection/riskyUsers?$top=100")
    out = {"items": data.get("value", [])}
    write_json_atomic(cache, out)
    return out
