from __future__ import annotations
import time, pathlib
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache import cache_dir, write_json_atomic
from tenantsec.app import event_bus

def _path(tenant_id: str) -> pathlib.Path:
    return cache_dir(tenant_id, "Static") / "licenses.json"

def snapshot_tenant_skus(graph: GraphClient, tenant_id: str) -> dict:
    """
    Permissions: Organization.Read.All or Directory.Read.All
    Captures SKU inventory (quantities & plans) for the tenant.
    """
    sel = "skuId,skuPartNumber,capabilityStatus,appliesTo,prepaidUnits,consumedUnits,servicePlans"

    data = graph.get_json(f"/v1.0/subscribedSkus?$select={sel}")
    items = data.get("value", [])

    skus = []
    sku_map = {}  # for user enrichment reuse if needed
    for s in items:
        sku_id = s.get("skuId")
        sku_num = s.get("skuPartNumber")
        skus.append({
            "skuId": sku_id,
            "skuPartNumber": sku_num,
            "capabilityStatus": s.get("capabilityStatus"),
            "appliesTo": s.get("appliesTo"),
            "prepaidUnits": s.get("prepaidUnits") or {},
            "consumedUnits": s.get("consumedUnits"),
            "servicePlans": s.get("servicePlans") or []
        })
        if sku_id and sku_num:
            sku_map[sku_id] = sku_num

    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "skus": skus,
    }
    cp = _path(tenant_id)
    write_json_atomic(cp, out)
    event_bus.publish("licenses.inventory.ready", {"tenant_id": tenant_id, "sku_count": len(skus)})
    print(f"[license_service] wrote {cp}")
    return out
