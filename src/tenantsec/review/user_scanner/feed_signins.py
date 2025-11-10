# src/tenantsec/review/user_scanner/feed_signins.py
from __future__ import annotations
from typing import Dict, Any, List
from datetime import datetime, timedelta, timezone
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_root
from tenantsec.core.cache import read_json, write_json_atomic
from collections import defaultdict

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def ensure_org_country_cache(tenant_id: str, *, graph: GraphClient) -> str:
    """Write USER/org.json with at least {'organization': {'country': 'XX', 'display_name': '...'}}."""
    user_root = tenant_root(tenant_id) / "USER"
    user_root.mkdir(parents=True, exist_ok=True)

    # Prefer Static/org_summary.json if present
    static_org = read_json(tenant_root(tenant_id) / "Static" / "org_summary.json") or {}
    country = (static_org.get("organization") or {}).get("country")
    display = (static_org.get("organization") or {}).get("display_name")

    if not country or not display:
        # Minimal live fetch
        try:
            org = graph.get_json("/v1.0/organization?$select=id,displayName,country")
            vals = (org.get("value") or [])
            if vals:
                display = display or vals[0].get("displayName")
                country = country or vals[0].get("country")
        except Exception:
            pass

    org_doc = {"organization": {"display_name": display or "Tenant", "country": (country or "").upper()}}
    write_json_atomic(user_root / "org.json", org_doc)
    return str(user_root / "org.json")

def build_signins_cache(tenant_id: str, *, graph: GraphClient, days: int = 7) -> str:
    """Write USER/signins.json with normalized records for user checks."""
    user_root = tenant_root(tenant_id) / "USER"
    user_root.mkdir(parents=True, exist_ok=True)

    since = _iso(_now_utc() - timedelta(days=days))
    select = ",".join([
        "id","createdDateTime","userId","userPrincipalName","status",
        "ipAddress","location","clientAppUsed","conditionalAccessStatus"
    ])
    url = f"/v1.0/auditLogs/signIns?$filter=createdDateTime ge {since}&$select={select}&$top=999"

    items: List[Dict[str, Any]] = []
    for page in graph.get_paged_values(url):
        for s in (page.get("value") or []):
            loc = s.get("location") or {}
            items.append({
                "id": s.get("id"),
                "userId": s.get("userId"),
                "userPrincipalName": s.get("userPrincipalName"),
                "createdDateTime": s.get("createdDateTime"),
                "status": (s.get("status") or {}).get("errorCode", 0) == 0 and "success" or "failed",
                "ip": s.get("ipAddress"),
                "country": (loc.get("countryOrRegion") or "").upper(),
                "state": loc.get("state"),
                "city": loc.get("city"),
                "clientApp": s.get("clientAppUsed"),
                "ca": s.get("conditionalAccessStatus"),
            })

    write_json_atomic(user_root / "signins.json", {"items": items, "since": since})
    return str(user_root / "signins.json")

def build_user_signins_by_user(tenant_id: str, *, graph: GraphClient, days: int = 30, top: int = 999) -> str:
    user_root = tenant_root(tenant_id) / "USER"
    user_root.mkdir(parents=True, exist_ok=True)

    since = _iso(_now_utc() - timedelta(days=days))
    select = ",".join([
        "id","createdDateTime","userId","userPrincipalName","status",
        "ipAddress","location","clientAppUsed","conditionalAccessStatus"  # <- removed signInEventTypes
    ])
    url = f"/v1.0/auditLogs/signIns?$filter=createdDateTime ge {since}&$select={select}&$top={top}"

    grouped = defaultdict(list)
    for page in graph.get_paged_values(url):
        for s in (page.get("value") or []):
            uid = s.get("userId") or ""
            if not uid: continue
            loc = s.get("location") or {}
            status_ok = (s.get("status") or {}).get("errorCode", 0) == 0
            grouped[uid].append({
                "createdDateTime": s.get("createdDateTime"),
                "status": "success" if status_ok else "failed",
                "ip": s.get("ipAddress"),
                "country": (loc.get("countryOrRegion") or "").upper(),
                "state": loc.get("state"),
                "city": loc.get("city"),
                "clientApp": s.get("clientAppUsed"),
                "eventTypes": [],  # placeholder; v1.0 doesn’t return signInEventTypes
                "ca": s.get("conditionalAccessStatus"),
                "upn": s.get("userPrincipalName"),
            })

    for uid in list(grouped.keys()):
        grouped[uid].sort(key=lambda r: r.get("createdDateTime") or "", reverse=True)
        grouped[uid] = grouped[uid][:200]

    out = user_root / "signins_by_user.json"
    write_json_atomic(out, {"since": since, "items": grouped})
    return str(out)
