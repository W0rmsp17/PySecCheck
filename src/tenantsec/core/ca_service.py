# src/tenantsec/core/ca_service.py
from __future__ import annotations
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.cache import write_json_atomic
from tenantsec.app import event_bus

def snapshot_conditional_access(graph, tenant_id: str) -> dict:
    pol = graph.get_json("/v1.0/identity/conditionalAccess/policies") or {}
    loc = graph.get_json("/v1.0/identity/conditionalAccess/namedLocations") or {}
    ca = {
        "policies": pol.get("value", []),
        "namedLocations": loc.get("value", []),
    }

    gw = DataGateway(tenant_id)
    policies = gw.get_policies() or {}
    policies["conditional_access"] = ca
    write_json_atomic(gw._path("policies.json", "Static"), policies)

    event_bus.publish("policies.ca.ready", {
        "tenant_id": tenant_id,
        "policies": len(ca["policies"]),
        "namedLocations": len(ca["namedLocations"]),
    })
    return ca
