# src/tenantsec/features/conditional_access/util.py
from __future__ import annotations
from typing import Dict, Any, Iterable, Set, List

ADMIN_ROLE_IDS: Set[str] = {
    # Global Administrator, Privileged Role Admin, etc.
    "62e90394-69f5-4237-9190-012177145e10",
    "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "29232cdf-9323-42fd-ade2-1d097af3e4de",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
    "158c047a-c907-4556-b7ef-446551a6b5f7",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe",
    "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",
}

def _list(v: Any) -> List[Any]:
    if v is None: return []
    return v if isinstance(v, list) else [v]

def ca_sheet(policies_blob: Dict[str, Any]) -> Dict[str, Any]:
    ca = (policies_blob or {}).get("conditional_access") or {}
    return {
        "policies": _list(ca.get("policies")),
        "namedLocations": _list(ca.get("namedLocations")),
    }

def policy_targets_admin_roles(p: Dict[str, Any]) -> bool:
    roles = set(_list(((p.get("conditions") or {}).get("users") or {}).get("includeRoles")))
    return bool(roles.intersection(ADMIN_ROLE_IDS))

def policy_requires_mfa(p: Dict[str, Any]) -> bool:
    gc = p.get("grantControls") or {}
    builtins = set(_list(gc.get("builtInControls")))
    return "mfa" in builtins or bool(gc.get("authenticationStrength"))

def is_enabled(p: Dict[str, Any]) -> bool:
    return (p.get("state") or "").lower() == "enabled"

def excludes_anyone(p: Dict[str, Any]) -> bool:
    u = (p.get("conditions") or {}).get("users") or {}
    return any(_list(u.get("excludeUsers"))) or any(_list(u.get("excludeGroups"))) or any(_list(u.get("excludeRoles")))

def exclude_evidence(p: Dict[str, Any]) -> Dict[str, Any]:
    u = (p.get("conditions") or {}).get("users") or {}
    return {
        "excludeUsers": _list(u.get("excludeUsers")),
        "excludeGroups": _list(u.get("excludeGroups")),
        "excludeRoles": _list(u.get("excludeRoles")),
    }

LEGACY_CATEGORIES = {"exchangeActiveSync", "other"}  
def targets_legacy_clients(p: Dict[str, Any]) -> bool:
    cats = set(_list((p.get("conditions") or {}).get("clientAppTypes")))
    return bool(cats.intersection(LEGACY_CATEGORIES)) or "all" in cats

def policy_blocks_access(p: Dict[str, Any]) -> bool:
    gc = p.get("grantControls") or {}
    builtins = set(_list(gc.get("builtInControls")))
    if "block" in builtins: return True
    return gc.get("operator") == "OR" and not builtins

def targets_all_users(p: Dict[str, Any]) -> bool:
    users = ((p.get("conditions") or {}).get("users") or {})
    iu = _list(users.get("includeUsers"))
    ig = _list(users.get("includeGroups"))
    return ("All" in iu) or ("All" in ig)

def locations_all_except_trusted(p: Dict[str, Any]) -> bool:
    loc = (p.get("conditions") or {}).get("locations") or {}
    inc = set(_list(loc.get("includeLocations")))
    exc = set(_list(loc.get("excludeLocations")))
    return ("All" in inc) and (("AllTrusted" in exc) or ("trusted" in {l.lower() for l in exc}))

def session_signin_frequency_configured(p: Dict[str, Any]) -> bool:
    sc = (p.get("sessionControls") or {}).get("signInFrequency") or {}
    return bool(sc.get("isEnabled"))

def session_persistent_browser_disabled(p: Dict[str, Any]) -> bool:
    pb = (p.get("sessionControls") or {}).get("persistentBrowser") or {}
    mode = (pb.get("mode") or "").lower()
    return bool(pb.get("isEnabled")) and mode == "never"
