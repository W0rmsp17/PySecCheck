# src/tenantsec/core/user_signin_service.py
from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_cache_dir, read_json, write_json_atomic
from datetime import datetime, timedelta

def fetch_signins(tenant_id: str) -> Dict[str, Any]:
    """
    Pulls recent sign-in logs from Microsoft Graph.
    GET /auditLogs/signIns?$top=1000&$orderby=createdDateTime desc
    """
    cache = tenant_cache_dir(tenant_id) / "USER" / "signins.json"
    try:
        cached = read_json(cache)
        if cached:
            return cached
    except Exception:
        pass

    client = GraphClient(tenant_id)
    data = client.get_json("/auditLogs/signIns?$top=1000&$orderby=createdDateTime desc")

    # Simplify and normalize
    items = []
    for e in data.get("value", []):
        items.append({
            "userId": e.get("userId"),
            "userPrincipalName": e.get("userPrincipalName"),
            "createdDateTime": e.get("createdDateTime"),
            "country": e.get("location", {}).get("countryOrRegion"),
            "status": (e.get("status", {}).get("errorCode") == 0) and "success" or "failure",
            "clientAppUsed": e.get("clientAppUsed"),
            "authenticationRequirement": e.get("authenticationRequirement"),
        })
    out = {"items": items, "fetched_at": datetime.utcnow().isoformat()}
    write_json_atomic(cache, out)
    return out


def fetch_user_licenses(tenant_id: str):
    cache = tenant_cache_dir(tenant_id) / "USER" / "licenses.json"
    try:
        cached = read_json(cache)
        if cached:
            return cached
    except Exception:
        pass

    client = GraphClient(tenant_id)
    data = client.get_json("/users?$select=id,userPrincipalName,assignedLicenses")
    out = {"items": data.get("value", [])}
    write_json_atomic(cache, out)
    return out