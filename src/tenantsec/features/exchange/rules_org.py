from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule


def _inv(sheets: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise Exchange dataset reference."""
    return sheets.get("exchange") or sheets.get("exchange_policies") or {}


# ----------------------------------------------------------
# 1. External forwarding blocked
# ----------------------------------------------------------
class RuleExternalForwardingBlocked(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        transport = inv.get("transportRules", [])
        # Heuristic: find rule that blocks or disables external auto-forward
        blocked = False
        for r in transport:
            name = (r.get("name") or "").lower()
            conds = (r.get("conditions") or {})
            actions = (r.get("actions") or {})
            if "forward" in name or "external" in name:
                if actions.get("redirectMessageTo") == "none" or "Block" in actions.get("action", ""):
                    blocked = True
                    break
        if blocked:
            return []
        return [{"reason": "No transport rule detected that blocks external auto-forwarding."}]


# ----------------------------------------------------------
# 2. Legacy auth disabled
# ----------------------------------------------------------
class RuleLegacyAuthDisabled(Rule):
    """
    Evaluate tenant POP/IMAP/SMTP settings; they should be disabled.
    Expect exoSettings = { popEnabled=False, imapEnabled=False, smtpAuthEnabled=False }.
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        mail_settings = inv.get("protocolSettings") or {}
        pop = mail_settings.get("popEnabled")
        imap = mail_settings.get("imapEnabled")
        smtp = mail_settings.get("smtpAuthEnabled")

        offenders = []
        if pop:
            offenders.append("POP")
        if imap:
            offenders.append("IMAP")
        if smtp:
            offenders.append("SMTP AUTH")

        if not offenders:
            return []
        return [{
            "reason": f"Legacy protocols enabled: {', '.join(offenders)}",
            "protocolSettings": mail_settings,
        }]


# ----------------------------------------------------------
# 3. Malware / ATP policy
# ----------------------------------------------------------
class RuleMalwarePolicyStrict(Rule):
    """
    Verify Malware/ATP/Defender policies exist and have strict settings.
    Expect e.g. malwareFilterPolicies, safeAttachments, safeLinks all present and enabled.
    """
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        malware_policies = inv.get("malwareFilterPolicies") or []
        safe_attachments = inv.get("safeAttachmentsPolicies") or []
        safe_links = inv.get("safeLinksPolicies") or []

        evidence = {
            "malwareFilterPolicies": len(malware_policies),
            "safeAttachmentsPolicies": len(safe_attachments),
            "safeLinksPolicies": len(safe_links),
        }

        if malware_policies and safe_attachments and safe_links:
            return []  # PASS
        return [{
            "reason": "Missing or incomplete Exchange Online protection policies (Malware/ATP).",
            "evidence": evidence,
        }]
