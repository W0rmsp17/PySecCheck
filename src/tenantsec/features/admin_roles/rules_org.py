# src/tenantsec/features/admin_roles/rules_org.py
from __future__ import annotations
from typing import List, Dict, Any, Set
from tenantsec.review.rules import Rule

# Global Administrator + key privileged roles
ADMIN_ROLE_TEMPLATE_IDS: Set[str] = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Conditional Access Administrator
}

def _role_members(sheets: Dict[str, Any], template_ids: Set[str]) -> List[Dict[str, Any]]:
    roles = (sheets.get("roles") or {}).get("roles") or []
    members: List[Dict[str, Any]] = []
    for r in roles:
        if r.get("templateId") in template_ids:
            for m in r.get("members", []) or []:
                members.append(m)  # expected keys: id, upn/displayName, mfa_state, mfa_methods...
    return members


class RuleGlobalAdminCount(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        roles = (sheets.get("roles") or {}).get("roles") or []
        ga_count = 0
        for r in roles:
            if r.get("templateId") == "62e90394-69f5-4237-9190-012177145e10":
                ga_count = len(r.get("members", []) or [])
                break
        if ga_count <= 2:
            return []  # PASS baseline
        return [{"reason": f"Global Administrator count is {ga_count} (recommended ≤ 2)."}]


class RuleAdminsWithoutMfa(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        members = _role_members(sheets, ADMIN_ROLE_TEMPLATE_IDS)
        offenders: List[Dict[str, Any]] = []
        for m in members:
            state = (m.get("mfa_state") or m.get("mfaState") or "").lower()
            methods = [str(x).lower() for x in (m.get("mfa_methods") or m.get("mfaMethods") or [])]
            upn = m.get("upn") or m.get("userPrincipalName") or m.get("displayName") or m.get("id")
            if state in ("", "disabled", "notenabled", "unknown"):
                offenders.append({"id": m.get("id"), "upn": upn, "reason": "MFA not enabled"})
            elif methods and set(methods).issubset({"sms", "voice"}):
                offenders.append({"id": m.get("id"), "upn": upn, "reason": "Weak MFA (SMS/voice only)"})
        if not offenders:
            return []
        return [{"reason": "Privileged roles have members without strong MFA.", "members": offenders}]


class RuleEmergencyAccounts(Rule):
    """
    Expect 1–2 'break-glass' accounts:
      - Typically excluded from admin-MFA policy
      - Should not be used in normal operations (recent sign-ins flagged)
    """
    EXPECTED_MIN = 1
    EXPECTED_MAX = 2
    RECENT_DAYS = 30

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        import re
        from datetime import datetime, timedelta

        users = (sheets.get("users") or {}).get("items") or []
        ca = (sheets.get("policies") or {}).get("conditional_access", {}) or {}
        ca_policies = ca.get("policies", []) or []

        # Heuristic: match by name
        candidates: List[Dict[str, Any]] = []
        for u in users:
            upn = (u.get("upn") or u.get("userPrincipalName") or "").lower()
            disp = (u.get("displayName") or "").lower()
            if re.search(r"(break.?glass|emergency|panic)", upn) or re.search(r"(break.?glass|emergency|panic)", disp):
                candidates.append(u)

        # Collect exclusions from admin MFA policies for evidence
        excluded_user_ids = set()
        for p in ca_policies:
            if (p.get("state") or "").lower() != "enabled":
                continue
            users_cond = (p.get("conditions") or {}).get("users") or {}
            for uid in (users_cond.get("excludeUsers") or []):
                excluded_user_ids.add(uid)

        # Evaluate usage (recent sign-ins)
        now = datetime.utcnow()
        used_recently = []
        evidence_accounts = []
        for u in candidates:
            uid = u.get("id")
            upn = u.get("upn") or u.get("userPrincipalName") or u.get("displayName") or uid
            last_raw = u.get("last_sign_in") or u.get("lastSignInDateTime") or ""
            recent = False
            if last_raw:
                try:
                    dt = datetime.fromisoformat(str(last_raw).rstrip("Z"))
                    recent = (now - dt) <= timedelta(days=self.RECENT_DAYS)
                except Exception:
                    pass
            if recent:
                used_recently.append({"id": uid, "upn": upn, "lastSignIn": last_raw})
            evidence_accounts.append({
                "id": uid,
                "upn": upn,
                "excludedFromAdminMfa": uid in excluded_user_ids
            })

        # Decisions
        if not candidates:
            return [{"reason": "No emergency (break-glass) accounts detected."}]
        if len(candidates) > self.EXPECTED_MAX:
            return [{"reason": f"Too many emergency accounts ({len(candidates)}). Expected ≤ {self.EXPECTED_MAX}.",
                     "accounts": evidence_accounts}]
        if used_recently:
            return [{"reason": "Emergency accounts used recently.", "accounts": used_recently}]
        # PASS baseline: present (≤ 2) and not used recently
        return []
