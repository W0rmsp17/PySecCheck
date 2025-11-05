from __future__ import annotations
from typing import Dict, Any
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.cache import write_json_atomic

def snapshot_exchange_inventory(graph: GraphClient, tenant_id: str) -> Dict[str, Any]:
    # Exchange-specific checks
    # Example of getting transport rules, mail settings, etc. For simplicity, using mockup calls.
    try:
        # Get transport rules (this should ideally be fetched from Exchange Online's API)
        transport_rules = graph.get_json("/v1.0/transportRules")
        mail_settings = graph.get_json("/v1.0/mailSettings")
    except Exception as e:
        transport_rules = []
        mail_settings = {}

    data = {
        "transportRules": transport_rules,
        "mailSettings": mail_settings,
        "fetched_at": graph.now_iso() if hasattr(graph, "now_iso") else None,
    }

    gw = DataGateway(tenant_id)
    path = gw._path("exchange_policies.json", "Static")
    write_json_atomic(path, data)
    return data
