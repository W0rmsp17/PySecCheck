from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.cache import write_json_atomic

def _paged_get(graph: GraphClient, path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    url = f"/v1.0{path}"
    while True:
        page = graph.get_json(url)
        out.extend(page.get("value", []))
        url = page.get("@odata.nextLink")
        if not url:
            break
        if url.startswith("https://graph.microsoft.com"):
            url = url[len("https://graph.microsoft.com"):]
    return out

def snapshot_oauth_inventory(graph: GraphClient, tenant_id: str) -> Dict[str, Any]:
    sps = _paged_get(graph, "/servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,accountEnabled,appRoles,oauth2PermissionScopes,addIns,passwordCredentials,keyCredentials,info,replyUrls")
    apps = _paged_get(graph, "/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials,requiredResourceAccess")
    grants = _paged_get(graph, "/oauth2PermissionGrants?$select=id,clientId,resourceId,scope,consentType,principalId")

    try:
        auth_policies = _paged_get(graph, "/policies/authorizationPolicy?$select=id,defaultUserRolePermissions,permissionGrantPolicyIdsAssigned")
    except Exception:
        auth_policies = []

    data = {
        "servicePrincipals": sps,
        "applications": apps,
        "oauth2PermissionGrants": grants,
        "authorizationPolicies": auth_policies,
        "fetched_at": graph.now_iso() if hasattr(graph, "now_iso") else None,
    }

    gw = DataGateway(tenant_id)
    path = gw._path("oauth_apps.json", "Static")
    write_json_atomic(path, data)
    return data
