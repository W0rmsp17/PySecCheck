# src/tenantsec/review/user_scanner/sheets.py
from __future__ import annotations
from typing import Dict, Any
from pathlib import Path
from tenantsec.core.cache import cache_dir, read_json
from tenantsec.core.cache_manager import tenant_root
from datetime import datetime, timezone
'''
def load_user_sheets(tenant_id: str) -> Dict[str, Any]:
    """
    Loads cached user-related sheets for user checks.
    Expected files (all optional):
      USER/org.json
      USER/users.json
      USER/signins.json
      USER/mail_rules.json
    """
    base = cache_dir(tenant_id, "USER")
    base.mkdir(parents=True, exist_ok=True)

    def _read(name: str):
        try:
            return read_json(base / f"{name}.json")
        except Exception:
            return None

    return {
        "org": _read("org") or {},
        "users": _read("users") or {"items": []},
        "signins": _read("signins") or {"items": []},
        "mail_rules": _read("mail_rules") or {"items": []},
    }


TTL_ORG        = 24 * 3600
TTL_USERS      = 3600
TTL_SIGNINS    = 10 * 60
TTL_RULES      = 30 * 60
TTL_RISKY      = 10 * 60

def _user_bucket(tenant_id: str) -> Path:
    # Put all user-review inputs under <tenant>/USER/
    p = tenant_root(tenant_id) / "USER"
    p.mkdir(parents=True, exist_ok=True)
    return p

# src/tenantsec/review/user_scanner/sheets.py
def read_sheet(
    root: Path | str,
    name: str,
    default: dict | None = None,
    max_age_sec: int | None = None,
    **_ignored
) -> dict:
    root = Path(root)  # <-- fix: ensure Path
    data = read_json(root / f"{name}.json")
    if not isinstance(data, dict):
        return default or {}
    return data



def load_user_sheets(tenant_id: str) -> Dict[str, Any]:
    org        = read_sheet(tenant_id, "org",        max_age_sec=TTL_ORG)     or {}
    users      = read_sheet(tenant_id, "users",      max_age_sec=TTL_USERS)   or {"items": []}
    signins    = read_sheet(tenant_id, "signins",    max_age_sec=TTL_SIGNINS) or {"items": []}
    mail_rules = read_sheet(tenant_id, "mail_rules", max_age_sec=TTL_RULES)   or {"items": []}
    risky      = read_sheet(tenant_id, "risky_users",max_age_sec=TTL_RISKY)   or {"items": []}

    return {
        "org": org,
        "users": users,
        "signins": signins,
        "mail_rules": mail_rules,
        "risky_users": risky,
    }

'''


def _parse_utc(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None

def _adapt_users_from_static(tenant_id: str, *, max_age_sec: int = 86400) -> Dict[str, Any]:
    p = tenant_root(tenant_id) / "Static" / "users_index.json"
    data = read_json(p) or {}
    fa = _parse_utc(data.get("fetched_at", "")) or datetime.min.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    allow_stale_fallback = True

    if not allow_stale_fallback and (now - fa).total_seconds() > max_age_sec:
        return {"items": []}

    items = []
    for u in data.get("users", []):
        items.append({
            "id": u.get("id"),
            "userPrincipalName": u.get("upn") or u.get("display_name"),
            "displayName": u.get("display_name"),
            "jobTitle": u.get("job_title"),
            "lastSignInDateTime": u.get("last_sign_in"),
            "roles": u.get("roles"),
            "mfaEnabled": (u.get("mfa_state") == "Registered"),
        })
    return {"items": items}
'''
def load_user_sheets(tenant_id: str) -> Dict[str, Any]:
    user_root = tenant_root(tenant_id) / "USER"
    user_root.mkdir(parents=True, exist_ok=True)

    org = read_json(user_root / "org.json") or {}
    users = read_json(user_root / "users.json")
    if not users or not users.get("items"):
        # ↑ fallback to Static, but with generous TTL so we don’t drop users after 24h
        users = _adapt_users_from_static(tenant_id, max_age_sec=30*86400)

    signins    = read_json(user_root / "signins.json")    or {"items": []}
    mail_rules = read_json(user_root / "mail_rules.json") or {"items": []}
    return {"org": org, "users": users, "signins": signins, "mail_rules": mail_rules}
'''


def load_user_sheets(tenant_id: str) -> Dict[str, Any]:
    user_root = tenant_root(tenant_id) / "USER"
    user_root.mkdir(parents=True, exist_ok=True)

    org         = read_json(user_root / "org.json")              or {}
    users       = read_json(user_root / "users.json")
    if not users or not users.get("items"):
        users   = _adapt_users_from_static(tenant_id, max_age_sec=86400)

    signins     = read_json(user_root / "signins.json")          or {"items": []}
    mail_rules  = read_json(user_root / "mail_rules.json")       or {"items": []}
    sby_user    = read_json(user_root / "signins_by_user.json")  or {"items": {}}

    return {"org": org, "users": users, "signins": signins, "mail_rules": mail_rules, "signins_by_user": sby_user}


from tenantsec.review.user_scanner.sheets import load_user_sheets
from tenantsec.ui.presenters.review_render import format_finding_to_text

def render_user_report(tenant_id: str, findings):
    sheets = load_user_sheets(tenant_id)
    sby = (sheets.get("signins_by_user") or {}).get("items", {})
    org_country = ((sheets.get("org") or {}).get("organization") or {}).get("country", "")

    header = [
        "=== PySecCheck — User Security Review ===",
        f"Tenant: {tenant_id}",
        "",
        "🧩 User Checks — Categorized",
        ""
    ]

    def user_key(f):
        ev = f.evidence or []
        if isinstance(ev, list) and ev:
            rec = ev[0] if isinstance(ev[0], dict) else {}
            return rec.get("upn") or rec.get("userPrincipalName") or rec.get("userId") or "Unknown user"
        t = (f.title or "")
        return t.split(": ", 1)[1].strip() if ": " in t else "Unknown user"

    by_user = {}
    for f in findings:
        by_user.setdefault(user_key(f), []).append(f)

    if not by_user:
        return "\n".join(header + ["No user findings. ✅"])

    id_to_upn = {}
    for u in (sheets.get("users") or {}).get("items", []):
        if u.get("id"):
            id_to_upn[u["id"]] = u.get("userPrincipalName") or u.get("upn") or u["id"]

    def render_recent_signins(upn: str):
        entries = []
        for uid, logs in sby.items():
            if id_to_upn.get(uid, "").lower() == upn.lower():
                entries = logs; break
        if not entries:
            for logs in sby.values():
                if logs and (logs[0].get("upn") or "").lower() == upn.lower():
                    entries = logs; break

        if not entries:
            return ["    • No evidence of risky sign-ins in the evaluated window"]

        out = ["    Recent sign-ins (30d):"]
        for e in entries[:3]:
            ctry = (e.get("country") or "").upper()
            flag = " ⚠" if org_country and ctry and ctry != org_country.upper() and e.get("status") == "success" else ""
            out.append(
                f"      - {e.get('createdDateTime')} • {e.get('city')},{ctry} • {e.get('status')} • {e.get('clientApp')} • {e.get('ip')}{flag}"
            )
        return out

    categories = [
        ("🛡️ Authentication / Sign-in", ("user.signin.", "user.mfa.")),
        ("🛡️ Exchange / Mailbox Rules", ("user.mail.",)),
        ("🛡️ Account Hygiene",         ("user.account.",)),
        ("🛡️ Risk Indicators",         ("user.risk.",)),
        ("🛡️ Licensing / Usage",       ("user.license.",)),
    ]

    lines = header[:]
    for user in sorted(by_user.keys(), key=str.lower):
        lines.append(f"— {user}")
        ufinds = by_user[user]

        had_auth = False
        for label, prefixes in categories:
            items = [f for f in ufinds if any(f.id.startswith(p) for p in prefixes)]
            lines.append(f"  {label}")
            if items:
                if label == "🛡️ Authentication / Sign-in":
                    had_auth = True
                for f in items:
                    for ln in format_finding_to_text(f).splitlines():
                        lines.append("    " + ln)
            else:
                lines.append("    • No findings detected ✅")

            if label == "🛡️ Authentication / Sign-in":
                lines += render_recent_signins(user)
            lines.append("")

    return "\n".join(lines)
