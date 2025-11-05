from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule
from tenantsec.features.conditional_access.util import (
    ca_sheet, is_enabled, policy_requires_mfa, targets_all_users,
    locations_all_except_trusted, targets_legacy_clients, policy_blocks_access,
    session_signin_frequency_configured, session_persistent_browser_disabled,
    policy_targets_admin_roles, excludes_anyone, exclude_evidence
)
from tenantsec.features.conditional_access.resolve import enrich_exclusion_names

class RuleMfaAllUsers(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        candidates = []
        for p in ca["policies"]:
            if not is_enabled(p): continue
            if targets_all_users(p) and policy_requires_mfa(p):
                if excludes_anyone(p):
                    candidates.append(enrich_exclusion_names(sheets, {
                        "policyId": p.get("id"),
                        "displayName": p.get("displayName"),
                        **exclude_evidence(p),
                        "note": "MFA-for-all policy present but has exclusions.",
                    }))
                else:
                    return []  
        if candidates:
            return [{"reason": "MFA for all users present but exclusions exist.", **candidates[0]}]
        return [{"reason": "No enabled CA policy requiring MFA for all users found."}]

class RuleUnknownLocationsStepUpOrBlock(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        for p in ca["policies"]:
            if not is_enabled(p): continue
            if locations_all_except_trusted(p) and (policy_requires_mfa(p) or policy_blocks_access(p)):
                return []  # PASS
        return [{"reason": "No enabled CA policy that steps-up (MFA) or blocks access from non-trusted locations."}]

class RuleSessionControlsConfigured(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        for p in ca["policies"]:
            if not is_enabled(p): continue
            if session_signin_frequency_configured(p):
                if session_persistent_browser_disabled(p):
                    return []  
                return [{"reason": "Sign-in frequency configured but Persistent Browser not set to 'Never'.",
                         "policyId": p.get("id"), "displayName": p.get("displayName")}]
        return [{"reason": "No enabled CA policy with session controls (sign-in frequency)."}]

class RuleAdminAuthStrength(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        for p in ca["policies"]:
            if not is_enabled(p): continue
            if policy_targets_admin_roles(p):
                gc = p.get("grantControls") or {}
                if gc.get("authenticationStrength"):
                    return [] 
                if policy_requires_mfa(p):
           
                    return [{"reason": "Admins protected by basic MFA, not Authentication Strength.",
                             "policyId": p.get("id"), "displayName": p.get("displayName")}]
        return [{"reason": "No enabled admin-targeted CA policy with Authentication Strength (or even basic MFA)."}]
