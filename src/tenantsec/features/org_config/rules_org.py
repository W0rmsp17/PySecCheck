# src/tenantsec/features/org_config/rules_org.py
from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule


class RuleSecurityDefaultsCompensated(Rule):
    """
    If Security Defaults are disabled, verify compensating CA MFA exists for:
      - ALL users (includeUsers == "All" with Grant: MFA)
      - Admin roles (includeRoles non-empty with Grant: MFA)
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        org_cfg = sheets.get("org_config") or {}
        sec_defaults = org_cfg.get("securityDefaultsEnabled")

        # If Security Defaults are ON, we're good.
        if sec_defaults is True:
            return []

        # Defaults OFF → require compensating Conditional Access (CA) policies.
        ca = (sheets.get("policies") or {}).get("conditional_access", {})
        policies = ca.get("policies", []) or []

        has_all_mfa = False
        has_admin_mfa = False

        for p in policies:
            if (p.get("state") or "").lower() != "enabled":
                continue

            cond = p.get("conditions") or {}
            users = cond.get("users") or {}
            include_users = users.get("includeUsers") or []
            include_roles = users.get("includeRoles") or []

            grant = p.get("grantControls") or {}
            builtins = [str(b).lower() for b in (grant.get("builtInControls") or [])]

            if "mfa" in builtins:
                if "All" in include_users:
                    has_all_mfa = True
                if include_roles:
                    has_admin_mfa = True

        if has_all_mfa and has_admin_mfa:
            return []

        return [{
            "reason": "Security Defaults disabled without compensating CA MFA for all users and admins.",
            "securityDefaultsEnabled": sec_defaults,
            "hasAllUsersMfa": has_all_mfa,
            "hasAdminMfa": has_admin_mfa,
        }]


class RuleSsprConfigured(Rule):
    """
    Ensure Self-Service Password Reset (SSPR) is enabled AND gated by MFA.
    Notes:
      - These flags come from org_config.json snapshot (heuristic until richer Graph mapping is added).
      - Keys: ssprEnabled (bool), ssprMfaRequired (bool)
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        org_cfg = sheets.get("org_config") or {}
        enabled = org_cfg.get("ssprEnabled")
        mfa_req = org_cfg.get("ssprMfaRequired")

        if enabled and mfa_req:
            return []

        return [{
            "reason": "Self-Service Password Reset not fully configured (enabled + MFA required).",
            "ssprEnabled": enabled,
            "ssprMfaRequired": mfa_req,
        }]
