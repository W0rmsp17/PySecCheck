# src/tenantsec/ui/presenters/user_report_render.py
from __future__ import annotations
from collections import defaultdict
from typing import List, Dict
from tenantsec.core.findings import Finding

CATEGORY_PREFIXES = {
    "🛡️ Authentication / Sign-in": ("user.signin.", "user.mfa."),
    "🛡️ Exchange / Mailbox Rules": ("user.mail.",),
    "🛡️ Account Hygiene":         ("user.account.",),
    "🛡️ Risk Indicators":         ("user.risk.",),
    "🛡️ Licensing / Usage":       ("user.license.",),
}

def _user_key(f: Finding) -> str:
    # Try UPN from evidence; fall back to Finding title suffix or "Unknown"
    ev = (f.evidence or [])
    for e in ev:
        upn = (e or {}).get("upn")
        if upn: return upn
    # Fallback heuristic: after last ": "
    if ": " in f.title: return f.title.split(": ", 1)[-1].strip()
    return "Unknown"

def _cat_of(f: Finding) -> str:
    fid = f.id or ""
    for cat, prefs in CATEGORY_PREFIXES.items():
        if any(fid.startswith(p) for p in prefs): return cat
    return "🛡️ Other"

def render_user_report(tenant_id: str, findings: List[Finding]) -> str:
    header = [
        "=== PySecCheck — User Security Review ===",
        f"Tenant: {tenant_id}",
        "",
        "🧩 User Checks — Categorized",
        ""
    ]
    if not findings:
        return "\n".join(header + ["No user findings. ✅"])

    # group by user -> category -> list[Finding]
    per_user: Dict[str, Dict[str, List[Finding]]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        per_user[_user_key(f)][_cat_of(f)].append(f)

    lines = header[:]
    for upn in sorted(per_user.keys(), key=lambda s: s.lower()):
        lines.append(f"— {upn}")
        cats = per_user[upn]
        for cat, prefixes in CATEGORY_PREFIXES.items():
            lines.append(f"  {cat}")
            fs = cats.get(cat, [])
            if not fs:
                if cat == "🛡️ Risk Indicators":
                    lines.append("    • No evidence of risky sign-ins in the evaluated window")
                else:
                    lines.append("    • No findings detected ✅")
                continue
            for f in fs:
                lines.append(f"    [{f.severity.upper()}] {f.title}")
                lines.append(f"      • id: {f.id}")
                lines.append(f"      • {f.summary}")
                if f.remediation: lines.append(f"      • remediation: {f.remediation}")
                if f.docs:        lines.append(f"      • docs: {f.docs}")
                if f.evidence:
                    lines.append("      • evidence:")
                    for e in f.evidence:
                        kv = ", ".join(f"{k}={v}" for k, v in (e or {}).items() if v is not None)
                        lines.append(f"        - {kv}")
            lines.append("")  # gap after category
        lines.append("")      # gap after user
    return "\n".join(lines)
