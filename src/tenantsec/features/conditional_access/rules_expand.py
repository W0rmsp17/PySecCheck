from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule
from tenantsec.features.conditional_access.util import ca_sheet
# Helper: enumerate Conditional Access policies
def _policies(sheets):
    return ca_sheet(sheets.get("policies") or {}).get("policies", [])


# -----------------------------
# Require MFA for risky sign-ins
# -----------------------------
class RuleMfaForRiskySignIns(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        findings = []

        for p in policies:
            if p.get("state") != "enabled":
                continue
            cond = p.get("conditions", {})
            grant = p.get("grantControls", {}) or {}

            sign_risks = cond.get("signInRiskLevels") or cond.get("userRiskLevels") or []
            if not sign_risks:
                continue

            builtins = [b.lower() for b in grant.get("builtInControls", [])]
            if "mfa" not in builtins:
                findings.append({
                    "reason": "Risky sign-in policy does not require MFA.",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                    "riskLevels": sign_risks,
                })

        if findings:
            return findings
        return []  # pass if at least one risky sign-in policy requires MFA


# -----------------------------
# Require MFA for guests
# -----------------------------
class RuleGuestMfaRequired(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        found_guest_policy = False
        findings = []

        for p in policies:
            if p.get("state") != "enabled":
                continue
            users = (p.get("conditions", {}) or {}).get("users", {})
            guests = users.get("includeGuestsOrExternalUsers")
            if not guests:
                continue

            grant = p.get("grantControls", {}) or {}
            builtins = [b.lower() for b in grant.get("builtInControls", [])]
            if "mfa" in builtins:
                found_guest_policy = True
                break
            else:
                findings.append({
                    "reason": "Guest/external user policy exists but does not require MFA.",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                })

        if not found_guest_policy:
            findings.append({
                "reason": "No enabled CA policy found requiring MFA for guest/external users."
            })

        return findings


# -----------------------------
# Disabled but important policies
# -----------------------------
class RuleDisabledPolicyAudit(Rule):
    KEYWORDS = [
        "mfa", "admin", "privileged", "legacy", "risky", "guest", "external"
    ]

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        findings = []

        for p in policies:
            if p.get("state") == "disabled":
                name = (p.get("displayName") or "").lower()
                if any(k in name for k in self.KEYWORDS):
                    findings.append({
                        "reason": f"Important CA policy is disabled: {p.get('displayName')}",
                        "policyId": p.get("id"),
                        "state": p.get("state"),
                    })

        return findings


# -----------------------------
# Device compliance or hybrid enforcement
# -----------------------------
class RuleDeviceComplianceEnforced(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        findings = []

        for p in policies:
            if p.get("state") != "enabled":
                continue
            cond = p.get("conditions", {})
            devices = cond.get("devices", {})
            if not devices:
                continue

            if devices.get("deviceFilter") not in ["compliant", "hybrid"]:
                findings.append({
                    "reason": "Device compliance or hybrid join not enforced for this policy.",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                })

        if findings:
            return findings
        return []  # pass if at least one policy enforces compliance


# -----------------------------
# Stale (unchanged) policies older than 180 days
# -----------------------------
class RuleStalePolicies(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        findings = []

        for p in policies:
            modified = p.get("modifiedDateTime", "")
            if not modified:
                continue
            # Compare date strings, flagging if older than 180 days
            from datetime import datetime, timedelta
            modified_date = datetime.fromisoformat(modified.rstrip("Z"))
            if modified_date < datetime.now() - timedelta(days=180):
                findings.append({
                    "reason": "Policy is stale and hasn't been modified in the last 180 days.",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                    "lastModified": modified_date.strftime("%Y-%m-%d"),
                })

        return findings


# -----------------------------
# Excessive exclusions in policies
# -----------------------------
class RuleExcessiveExclusions(Rule):
    EXCLUSION_THRESHOLD = 50  # Customize this based on what you deem "excessive"

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        policies = _policies(sheets)
        findings = []

        for p in policies:
            if p.get("state") != "enabled":
                continue
            users = (p.get("conditions", {}) or {}).get("users", {})
            exclude_users = users.get("excludeUsers", [])
            exclude_groups = users.get("excludeGroups", [])
            exclude_roles = users.get("excludeRoles", [])
            total_exclusions = len(exclude_users) + len(exclude_groups) + len(exclude_roles)

            if total_exclusions >= self.EXCLUSION_THRESHOLD:
                findings.append({
                    "reason": f"Policy contains too many exclusions ({total_exclusions}).",
                    "policyId": p.get("id"),
                    "displayName": p.get("displayName"),
                    "exclusions": {
                        "users": len(exclude_users),
                        "groups": len(exclude_groups),
                        "roles": len(exclude_roles),
                    }
                })

        return findings
