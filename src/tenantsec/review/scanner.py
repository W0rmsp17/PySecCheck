# src/tenantsec/review/scanner.py
from typing import List, Dict, Any
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.findings import Finding
from tenantsec.features.registry import ca_rule_set
from tenantsec.review.evaluator import run_rules
from tenantsec.features.registry import ca_rule_set, admin_roles_rule_set, org_config_rule_set, oauth_rule_set
from tenantsec.features.oauth_apps.rules_org import RuleOverPrivilegedApps
from tenantsec.features.registry import exchange_rule_set, intune_rule_set

def _load_sheets(gw: DataGateway) -> Dict[str, Any]:
    return {
        "policies": gw.get_policies(),
        "roles": gw.get_roles(),
        "org": gw.get_org_summary(),
        "org_config": gw.get_org_config(), 
        "users": {"items": gw.get_users_index()},
        "signins": gw.get_signins_summary(),
        "licenses": gw.get_license_inventory(),
        "oauth": gw.get_oauth_inventory(),
        "exchange": gw.get_exchange_policies() if hasattr(gw, "get_exchange_policies") else {},
        "intune": gw.get_intune_policies(), 
    }


def run_org_checks(tenant_id: str) -> List[Finding]:
    gw = DataGateway(tenant_id)
    sheets = _load_sheets(gw)
    rules = org_rule_catalog()  
    findings, _ = run_rules(rules, sheets)
    return findings

def run_all_checks(tenant_id: str) -> List[Finding]:
    return run_org_checks(tenant_id) 

def org_rule_catalog():
    rules = []
    rules += ca_rule_set()
    rules += admin_roles_rule_set()
    rules += org_config_rule_set()  
    rules += oauth_rule_set()
    rules += exchange_rule_set()
    rules += intune_rule_set()
    return rules

def oauth_rule_set():
    return [
        RuleOverPrivilegedApps(
            id="oauth.overprivileged_apps",
            title="Overprivileged apps detected",
            severity="high",
            weight=7,
            description="Identify apps with overly permissive permissions.",
            remediation="Review app permissions and restrict excessive privileges.",
            docs="https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/permissions-consent",
            tags=["oauth", "apps", "security"]
        )
    ]

def load_sheets_for_ai(tenant_id: str) -> Dict[str, Any]:
    gw = DataGateway(tenant_id)
    return {
        "policies": gw.get_policies(),
        "roles": gw.get_roles(),
        "org": gw.get_org_summary(),
        "users": {"items": gw.get_users_index()},
        "signins": gw.get_signins_summary(),
        "licenses": gw.get_license_inventory(),
        "org_config": getattr(gw, "get_org_config", lambda: {})(),
        "oauth": getattr(gw, "get_oauth_inventory", lambda: {})(),
        "exchange": getattr(gw, "get_exchange_config", lambda: {})(),
        "intune": getattr(gw, "get_intune_policies", lambda: {})(),
    }
