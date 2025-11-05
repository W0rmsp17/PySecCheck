# src/tenantsec/features/legacy_auth/rules.py
from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule
from tenantsec.features.conditional_access.util import (
    ca_sheet, is_enabled, targets_legacy_clients, policy_blocks_access
)

class RuleBlockLegacyAuth(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        ca = ca_sheet(sheets.get("policies") or {})
        policies = ca["policies"]
        for p in policies:
            if not is_enabled(p): continue
            if targets_legacy_clients(p) and policy_blocks_access(p):
                return []  # PASS
        return [{"reason": "No enabled CA policy detected that blocks legacy (basic) authentication."}]
