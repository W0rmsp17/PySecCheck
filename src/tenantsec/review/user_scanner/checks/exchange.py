from __future__ import annotations
from typing import Dict, Any, List
from ..helpers import add
#from . import register
from tenantsec.core.findings import Finding

def _broad(cond: dict|None) -> bool:
    return not cond or not any(cond.get(k) for k in ("fromAddresses","recipients","subjectContains","senderContains","bodyContains"))

#@register
def mailbox_rule_rss(sheets, findings):
    for e in (sheets.get("mail_rules") or {}).get("items", []):
        for r in e.get("rules", []):
            act = r.get("actions") or {}
            # Graph returns actions.moveToFolder (folder ID). Also fallback to rule name.
            target = (act.get("moveToFolder") or r.get("name") or "")
            if "rss" in target.lower():
                add(findings,
                    id="user.mail.rss_rule",
                    title=f"Rule moves mail to RSS: {e.get('userPrincipalName')}",
                    severity="high",
                    summary="Inbox rule moves messages to an RSS folder.",
                    remediation="Disable/remove the rule; verify legitimacy with the user.",
                    evidence=[{"rule": r.get("name"), "moveToFolder": act.get("moveToFolder"),
                               "upn": e.get("userPrincipalName")}])


#@register
def mailbox_rule_delete_all(sheets, findings):
    for e in (sheets.get("mail_rules") or {}).get("items", []):
        for r in e.get("rules", []):
            act = r.get("actions") or {}
            if (act.get("delete") or act.get("moveToDeletedItems")) and _broad(r.get("conditions") or {}):
                add(findings,
                    id="user.mail.delete_on_arrival",
                    title=f"Rule deletes/auto-discards mail: {e.get('userPrincipalName')}",
                    severity="medium",
                    summary="Broad delete-to-Deleted Items rule may hide messages.",
                    remediation="Tighten conditions or remove the rule.",
                    evidence=[{"rule": r.get("name"), "upn": e.get("userPrincipalName")}])

#@register
def mailbox_rule_mark_read_all(sheets, findings):
    for e in (sheets.get("mail_rules") or {}).get("items", []):
        for r in e.get("rules", []):
            act = r.get("actions") or {}
            if act.get("markAsRead") and _broad(r.get("conditions") or {}):
                add(findings,
                    id="user.mail.mark_as_read_auto",
                    title=f"Rule auto-marks mail as read: {e.get('userPrincipalName')}",
                    severity="low",
                    summary="Broad mark-as-read rule can mask activity.",
                    remediation="Remove or add precise conditions.",
                    evidence=[{"rule": r.get("name"), "upn": e.get("userPrincipalName")}])


def mailbox_rule_forward_external(sheets, findings):
    for e in (sheets.get("mail_rules") or {}).get("items", []):
        upn = e.get("userPrincipalName") or ""
        tenant_domain = upn.split("@",1)[1].lower() if "@" in upn else ""
        for r in e.get("rules", []):
            act = r.get("actions") or {}
            fwd = act.get("forwardTo") or act.get("redirectTo") or []
            externals = []
            for rec in fwd:
                addr = ((rec.get("emailAddress") or {}).get("address") or "").lower()
                if addr and tenant_domain and not addr.endswith(tenant_domain):
                    externals.append(addr)
            if externals and _broad(r.get("conditions") or {}):
                add(findings,
                    id="user.mail.forward_external",
                    title=f"Rule forwards mail externally: {upn}",
                    severity="high",
                    summary="Inbox rule forwards messages to external recipient(s).",
                    remediation="Disable the rule and investigate possible exfiltration.",
                    evidence=[{"rule": r.get("name"), "external": externals, "upn": upn}])
