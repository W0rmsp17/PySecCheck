from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule

class RuleExternalForwardingBlocked(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inventory = sheets.get("exchange_policies") or {}
        rules = inventory.get("transportRules", [])
        # Check if any transport rule blocks forwarding to external addresses
        for rule in rules:
            if "forwarding" in rule.get("action", "").lower() and "external" in rule.get("conditions", "").lower():
                return []  # Pass if blocked
        return [{"reason": "No transport rule blocks forwarding to external addresses."}]

class RuleLegacyAuthDisabled(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inventory = sheets.get("exchange_policies") or {}
        mail_settings = inventory.get("mailSettings", {})
        # Check if legacy auth is disabled (POP/IMAP/SMTP)
        if not mail_settings.get("legacyAuthDisabled", False):
            return [{"reason": "Legacy authentication (POP/IMAP/SMTP) is not disabled."}]
        return []

class RuleMalwarePolicyConfigured(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inventory = sheets.get("exchange_policies") or {}
        # Check for Malware/ATP policies
        if not inventory.get("malwarePolicy", {}).get("enabled", False):
            return [{"reason": "No malware or ATP policies configured."}]
        return []
