from __future__ import annotations
from datetime import datetime, timedelta, timezone
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache import cache_dir, write_json_atomic
from tenantsec.app import event_bus
import pathlib, time

def _path(tenant_id: str) -> pathlib.Path:
    return cache_dir(tenant_id, "Polled") / "signins_summary.json"

def list_recent_signins(graph: GraphClient, tenant_id: str, days: int = 7, page_cap: int = 5) -> dict:
    """
    Permissions: AuditLog.Read.All
    Pulls a limited window/page-cap to avoid huge files; stores counts by result.
    """
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    # Note: filter on createdDateTime ge <since> (Graph filter format)
    url = f"/v1.0/auditLogs/signIns?$filter=createdDateTime ge {since}&$top=100"

    total = 0
    by_status = {}
    pages = 0
    items = []

    for page in graph.get_paged_values(url, page_limit=page_cap):
        vals = page.get("value", [])
        for v in vals:
            total += 1
            key = (v.get("status") or {}).get("errorCode", 0)
            by_status[str(key)] = by_status.get(str(key), 0) + 1
        items.extend(vals)
        pages += 1

    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "window_days": days,
        "pages": pages,
        "total": total,
        "by_status_code": by_status,
        "sample": items[:250]  # keep a small slice for UI drill-in
    }
    cp = _path(tenant_id)
    write_json_atomic(cp, out)
    print(f"[{__name__}] wrote {cp}")
    event_bus.publish("audit.signins.ready", {"tenant_id": tenant_id, "total": total})
    return out
