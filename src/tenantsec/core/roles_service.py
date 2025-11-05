from __future__ import annotations
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache import cache_dir, read_json, write_json_atomic
from tenantsec.app import event_bus
import pathlib, time

def _path(tenant_id: str) -> pathlib.Path:
    return cache_dir(tenant_id, "Static") / "roles.json"

def list_directory_roles(graph: GraphClient, tenant_id: str) -> dict:
    """
    Permissions: RoleManagement.Read.Directory (or Directory.Read.All)
    Stores roles with member counts and member ids (light).
    """
    roles = []
    # Active roles
    for page in graph.get_paged_values("/v1.0/directoryRoles?$select=id,displayName,roleTemplateId"):
        for r in page.get("value", []):
            rid = r.get("id"); name = r.get("displayName","")
            members = []
            # Members per role (id only to keep file small)
            for mpage in graph.get_paged_values(f"/v1.0/directoryRoles/{rid}/members?$select=id"):
                for m in mpage.get("value", []):
                    mid = m.get("id")
                    if mid: members.append(mid)
            roles.append({
                "id": rid,
                "name": name,
                "member_count": len(members),
                "members": members
            })

    cp = _path(tenant_id)
    out = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "roles": roles
    }
    write_json_atomic(cp, out)
    event_bus.publish("roles.ready", {"tenant_id": tenant_id, "role_count": len(roles)})
    return out
