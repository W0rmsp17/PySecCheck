from __future__ import annotations
from typing import List, Dict, Any
from tenantsec.review.rules import Rule
from .rules_org import *

HIGH_PRIV_STRINGS = {
    "Directory.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "User.ReadWrite.All",
    "Application.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Mail.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    "Device.ReadWrite.All",
    "Reports.Read.All",
}

def _inv(sheets: Dict[str, Any]) -> Dict[str, Any]:
    # Normalize to whatever you put in scanner: sheets["oauth"] = gw.get_oauth_inventory()
    return sheets.get("oauth") or sheets.get("oauth_apps") or {}

class RuleOverPrivilegedApps(Rule):  # <-- canonical name
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        sps = inv.get("servicePrincipals", []) or []
        grants = inv.get("oauth2PermissionGrants", []) or []

        sp_by_id = {sp.get("id"): sp for sp in sps}

        findings: List[Dict[str, Any]] = []

        # Static exposed scopes on resource SPs (weak signal but useful evidence)
        for sp in sps:
            bad_scopes = []
            for scope in (sp.get("oauth2PermissionScopes") or []):
                val = scope.get("value") or ""
                if val in HIGH_PRIV_STRINGS:
                    bad_scopes.append(val)
            if bad_scopes:
                findings.append({
                    "reason": "Service principal exposes high-priv scopes.",
                    "servicePrincipal": sp.get("displayName") or sp.get("id"),
                    "appId": sp.get("appId"),
                    "scopes": sorted(set(bad_scopes)),
                })

        # Granted scopes (client -> resource)
        for g in grants:
            scope_str = g.get("scope") or ""
            if not scope_str:
                continue
            scopes = {s.strip() for s in scope_str.split() if s.strip()}
            hit = scopes.intersection(HIGH_PRIV_STRINGS)
            if not hit:
                continue
            client = sp_by_id.get(g.get("clientId"))
            resource = sp_by_id.get(g.get("resourceId"))
            findings.append({
                "reason": "OAuth grant includes high-priv scopes.",
                "client": (client or {}).get("displayName") or g.get("clientId"),
                "resource": (resource or {}).get("displayName") or g.get("resourceId"),
                "scopes": sorted(hit),
                "consentType": g.get("consentType"),
                "principalId": g.get("principalId"),
            })

        return findings

class RuleUnusedAppSecrets(Rule):
    SOON_DAYS = 30
    LONG_YEARS = 2

    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        from datetime import datetime, timedelta
        inv = _inv(sheets)
        apps = inv.get("applications", []) or []
        sps = inv.get("servicePrincipals", []) or []

        now = datetime.utcnow()
        soon = now + timedelta(days=self.SOON_DAYS)

        def scan_creds(entity):
            out = []
            for cred in (entity.get("passwordCredentials") or []):
                end = cred.get("endDateTime")
                start = cred.get("startDateTime")
                if not end:
                    continue
                try:
                    dt_end = datetime.fromisoformat(str(end).rstrip("Z"))
                    expired = dt_end < now
                    expiring_soon = (not expired) and (dt_end <= soon)
                    long_lived = False
                    if start:
                        dt_start = datetime.fromisoformat(str(start).rstrip("Z"))
                        long_lived = (dt_end - dt_start).days >= 365 * self.LONG_YEARS
                    if expired or expiring_soon or long_lived:
                        out.append({
                            "keyId": cred.get("keyId"),
                            "start": start,
                            "end": end,
                            "expired": expired,
                            "expiringSoon": expiring_soon,
                            "longLived": long_lived,
                        })
                except Exception:
                    pass
            return out

        findings: List[Dict[str, Any]] = []
        for app in apps:
            issues = scan_creds(app)
            if issues:
                findings.append({
                    "reason": "Application secrets require attention.",
                    "application": app.get("displayName") or app.get("appId"),
                    "credentials": issues,
                })
        for sp in sps:
            issues = scan_creds(sp)
            if issues:
                findings.append({
                    "reason": "Service principal secrets require attention.",
                    "servicePrincipal": sp.get("displayName") or sp.get("appId"),
                    "credentials": issues,
                })
        return findings

class RuleUserConsentRisky(Rule):
    def evaluate(self, sheets: Dict[str, Any]) -> List[Dict[str, Any]]:
        inv = _inv(sheets)
        pols = inv.get("authorizationPolicies") or []
        if not pols:
            return [{"reason": "No authorizationPolicy data available (cannot verify user consent posture)."}]

        findings: List[Dict[str, Any]] = []
        for p in pols:
            durp = (p.get("defaultUserRolePermissions") or {})
            allow_create = durp.get("allowedToCreateApps")
            grants = set(p.get("permissionGrantPolicyIdsAssigned") or [])
            permissive = any("AllPrincipals" in g or "Allows" in g for g in grants)
            if allow_create or permissive:
                findings.append({
                    "reason": "User consent posture may allow risky self-consent.",
                    "allowedToCreateApps": allow_create,
                    "permissionGrantPolicyIdsAssigned": list(grants),
                })
        return findings
