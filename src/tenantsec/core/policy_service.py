from __future__ import annotations
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache import cache_dir, write_json_atomic
from tenantsec.app import event_bus
import pathlib, time

def _path(tenant_id: str) -> pathlib.Path:
    return cache_dir(tenant_id, "Static") / "policies.json"

def snapshot_policies(graph: GraphClient, tenant_id: str) -> dict:
    """
    Permissions: Policy.Read.All
    Captures CA policies (trimmed) + authentication methods policy state.
    """
    # Conditional Access (trim to main props to keep file sane)
    ca_sel = "id,displayName,state,createdDateTime,modifiedDateTime"
    ca = graph.get_json(f"/v1.0/identity/conditionalAccess/policies?$select={ca_sel}")

    # Auth methods policy (overall posture)
    amp = graph.get_json("/v1.0/policies/authenticationMethodsPolicy?$select=id,description,state")

    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "conditional_access": ca.get("value", []),
        "auth_methods_policy": amp or {}
    }
    cp = _path(tenant_id)
    write_json_atomic(cp, out)
    event_bus.publish("policies.ready", {"tenant_id": tenant_id})
    return out
