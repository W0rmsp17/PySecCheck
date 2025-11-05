# src/tenantsec/features/conditional_access/resolve.py
from __future__ import annotations
from typing import Dict, Any, List

def _id_to_upn_map(sheets: Dict[str, Any]) -> Dict[str, str]:
    items = ((sheets.get("users") or {}).get("items")) or []
    return {u.get("id"): (u.get("upn") or u.get("userPrincipalName") or u.get("mail") or u.get("displayName") or u.get("id"))
            for u in items}

def _role_id_to_name_map(sheets: Dict[str, Any]) -> Dict[str, str]:
    roles_obj = sheets.get("roles") or {}
    roles = roles_obj.get("roles") or roles_obj.get("value") or []
    return {r.get("id"): (r.get("displayName") or r.get("templateId") or r.get("id")) for r in roles}

def enrich_exclusion_names(sheets: Dict[str, Any], ev: Dict[str, Any]) -> Dict[str, Any]:
    """Add *_names arrays alongside excludeUsers/Groups/Roles."""
    users = ev.get("excludeUsers") or []
    groups = ev.get("excludeGroups") or []
    roles  = ev.get("excludeRoles")  or []

    upn_map = _id_to_upn_map(sheets)
    role_map = _role_id_to_name_map(sheets)

    ev = dict(ev)  # copy
    if users:
        ev["excludeUsers_names"] = [upn_map.get(uid, uid) for uid in users]
    if groups:
        # until we cache groups, show the IDs verbatim:
        ev["excludeGroups_names"] = groups
    if roles:
        ev["excludeRoles_names"] = [role_map.get(rid, rid) for rid in roles]
    return ev
