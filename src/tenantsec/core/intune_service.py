# src/tenantsec/core/intune_service.py
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

def snapshot_intune_inventory(graph: GraphClient, tenant_id: str) -> Dict[str, Any]:
    try:
        compliance = _paged_get(graph, "/deviceManagement/deviceCompliancePolicies")
    except Exception:
        compliance = []
    try:
        configuration = _paged_get(graph, "/deviceManagement/deviceConfigurations")
    except Exception:
        configuration = []
    try:
        settings_catalog = _paged_get(graph, "/deviceManagement/configurationPolicies")
    except Exception:
        settings_catalog = []

    data = {
        "deviceCompliancePolicies": compliance,
        "deviceConfigurationPolicies": configuration,      # legacy config profiles
        "configurationPolicies": settings_catalog,         # settings catalog (new style)
    }

    gw = DataGateway(tenant_id)
    write_json_atomic(gw._path("intune_policies.json", "Static"), data)
    return data
