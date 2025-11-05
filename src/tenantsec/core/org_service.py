# src/tenantsec/core/org_service.py
from __future__ import annotations
import time, pathlib
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache import cache_dir, write_json_atomic
from tenantsec.app import event_bus

def _path(tenant_id: str) -> pathlib.Path:
    return cache_dir(tenant_id, "Static") / "org_summary.json"

def get_org_summary(graph: GraphClient, tenant_id: str) -> dict:
    select = ",".join([
        "id","displayName","country","countryLetterCode","preferredLanguage",
        "createdDateTime","defaultUsageLocation","tenantType",
        "onPremisesSyncEnabled","onPremisesLastSyncDateTime",
        "technicalNotificationMails","directorySizeQuota"
    ])
    data = graph.get_json(f"/v1.0/organization?$select={select}")
    org = (data.get("value") or [{}])[0]

    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "organization": {
            "id": org.get("id",""),
            "display_name": org.get("displayName",""),
            "country": org.get("country"),
            "country_code": org.get("countryLetterCode"),
            "preferred_language": org.get("preferredLanguage"),
            "created": org.get("createdDateTime"),
            "usage_location": org.get("defaultUsageLocation"),
            "tenant_type": org.get("tenantType"),
            "onprem_sync_enabled": org.get("onPremisesSyncEnabled"),
            "onprem_last_sync": org.get("onPremisesLastSyncDateTime"),
            "technical_mails": org.get("technicalNotificationMails") or [],
            "dir_quota": org.get("directorySizeQuota") or {},
        }
    }
    cp = _path(tenant_id)
    write_json_atomic(cp, out)
    event_bus.publish("org.info.ready", {"tenant_id": tenant_id})
    print(f"[org_service] wrote {cp}")
    return out

# src/tenantsec/core/org_service.py
from tenantsec.app import event_bus
from tenantsec.core.data_gateway import DataGateway
from tenantsec.http.errors import HttpError

def list_subscribed_skus(graph, tenant_id: str) -> list[dict]:
    """
    GET /v1.0/subscribedSkus
    Requires Application: Directory.Read.All
    """
    try:
        res = graph.get_json("/v1.0/subscribedSkus")
        items = res.get("value", [])  # Graph returns {"value": [...]}
    except HttpError as e:
        print(f"[org_service] subscribedSkus failed: {e}")
        items = []

    gw = DataGateway(tenant_id)
    gw.set_subscribed_skus(items)
    event_bus.publish("org.skus.ready", {"tenant_id": tenant_id, "count": len(items)})
    return items
