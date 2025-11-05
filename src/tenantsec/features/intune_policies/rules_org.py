# src/tenantsec/features/intune_policies/rules_org.py
from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule

def _inv(sheets: Dict[str, Any]) -> Dict[str, Any]:
    return sheets.get("intune") or sheets.get("intune_policies") or {}

def _enabled(p: Dict[str, Any]) -> bool:
    # many Intune objects use "assignments"; treat presence as “in effect”
    return True  # be permissive; Intune doesn’t always have a simple 'state'

class RuleBaselinePoliciesPresent(Rule):
    """
    Expect at least:
      - ≥1 deviceCompliancePolicies (baseline compliance)
      - ≥1 deviceConfigurationPolicies or configurationPolicies (baseline config)
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        comp = [p for p in inv.get("deviceCompliancePolicies", []) if _enabled(p)]
        conf_legacy = [p for p in inv.get("deviceConfigurationPolicies", []) if _enabled(p)]
        conf_catalog = [p for p in inv.get("configurationPolicies", []) if _enabled(p)]

        if comp and (conf_legacy or conf_catalog):
            return []
        return [{
            "reason": "Missing Intune baselines (compliance and/or configuration).",
            "counts": {
                "deviceCompliancePolicies": len(comp),
                "deviceConfigurationPolicies": len(conf_legacy),
                "configurationPolicies": len(conf_catalog),
            }
        }]

class RuleJailbreakBlock(Rule):
    """
    Flag if policies don’t block jailbroken/rooted devices.
    Common keys across platform policies (any that appear True → PASS):
      - securityBlockJailbrokenDevices
      - jailbreakBlocked / rootedDeviceBlocked / blockJailbrokenDevices
    """
    KEYS = {
        "securityBlockJailbrokenDevices",
        "jailbreakBlocked",
        "rootedDeviceBlocked",
        "blockJailbrokenDevices",
        "securityBlockRootedDevices",
    }

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        comp = inv.get("deviceCompliancePolicies", []) or []
        seen_true = False
        evidence = []

        for p in comp:
            vals = {k: p.get(k) for k in self.KEYS if k in p}
            if any(bool(v) for v in vals.values()):
                seen_true = True
            if vals:
                evidence.append({
                    "displayName": p.get("displayName"),
                    "flags": {k: bool(v) for k, v in vals.items()}
                })

        if seen_true:
            return []
        return [{
            "reason": "No compliance policy found that explicitly blocks jailbroken/rooted devices.",
            "evidence": evidence or "no relevant keys found in compliance policies"
        }]

class RuleRequireCompliantDevice(Rule):
    """
    CA tie-in check: ensure at least one enabled CA policy requires compliant device.
    Uses sheets['policies']['conditional_access'] dataset.
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = (sheets.get("policies") or {}).get("conditional_access", {})
        ca = policies.get("policies", []) or []
        hits = []
        for p in ca:
            if (p.get("state") or "").lower() != "enabled":
                continue
            grant = p.get("grantControls") or {}
            builtins = [b.lower() for b in (grant.get("builtInControls") or [])]
            if "compliantdevice" in builtins:
                hits.append({"id": p.get("id"), "displayName": p.get("displayName")})

        if hits:
            return []
        return [{
            "reason": "No enabled CA policy requires compliant device.",
            "expectedControl": "grantControls.builtInControls includes 'compliantDevice'",
        }]
