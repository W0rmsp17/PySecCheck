# src/tenantsec/features/mfa_enforcement/rules.py
from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule
from tenantsec.features.conditional_access.util import (
    ca_sheet, is_enabled, policy_targets_admin_roles,
    policy_requires_mfa, excludes_anyone, exclude_evidence
)

class RuleMfaForAdminsNoExcludes(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        policies = ca["policies"]
        # PASS criteria: at least one enabled policy → targets admin roles → requires MFA → no excludes
        for p in policies:
            if not is_enabled(p): continue
            if not policy_targets_admin_roles(p): continue
            if not policy_requires_mfa(p): continue
            if excludes_anyone(p):  # misconfiguration risk
                # FAIL with evidence (policy found but has excludes)
                return [{
                    "reason": "Admin-MFA policy contains exclusions",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                    **exclude_evidence(p),
                }]
            # Happy path: strict policy found
            return []  # PASS
        # No qualifying policy
        return [{"reason": "No enabled CA policy requiring MFA for admin roles found."}]
