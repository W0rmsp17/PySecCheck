from __future__ import annotations
from typing import Dict, Any
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.cache import write_json_atomic

def snapshot_org_config(graph: GraphClient, tenant_id: str) -> Dict[str, Any]:
    # Security Defaults (official)
    # GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy
    sec_defaults = {}
    try:
        sec_defaults = graph.get_json("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
    except Exception:
        pass

    # Authentication methods policy (heuristic to infer SSPR posture)
    # GET /v1.0/policies/authenticationMethodsPolicy
    auth_methods = {}
    try:
        auth_methods = graph.get_json("/v1.0/policies/authenticationMethodsPolicy")
    except Exception:
        pass

    # Heuristics for SSPR:
    # If your tenant exposes an explicit SSPR object, adapt here.
    sspr_enabled = False
    sspr_mfa_required = False
    try:
        # Some tenants surface SSPR posture via registration/enforcement requirements:
        # Look for "registrationEnforcement", "registrationRequirements", or similar hints.
        reg = (auth_methods.get("registrationEnforcement") or {})
        sspr_enabled = bool(reg)  # if any enforcement exists, assume SSPR enabled
        # If any MFA-capable methods are required-for-reset, treat as "gated by MFA"
        # This is heuristic; refine as you gather real payloads.
        reqs = (reg.get("authenticationMethodsRegistrationCampaign") or {})
        # e.g. "snoozeDurationInDays", "state", "includeTargets"
        # Not definitive; allow manual override via cache if needed.
        # Keep conservative default: don't claim MFA-required unless we see it clearly.
        sspr_mfa_required = False
    except Exception:
        pass

    data = {
        "securityDefaultsEnabled": bool(sec_defaults.get("isEnabled")) if sec_defaults else None,
        "raw": {
            "identitySecurityDefaultsEnforcementPolicy": sec_defaults or {},
            "authenticationMethodsPolicy": auth_methods or {},
        },
        # Baseline booleans (override-able by editing cache file manually if needed)
        "ssprEnabled": sspr_enabled,
        "ssprMfaRequired": sspr_mfa_required,
    }

    gw = DataGateway(tenant_id)
    write_json_atomic(gw._path("org_config.json", "Static"), data)
    return data
