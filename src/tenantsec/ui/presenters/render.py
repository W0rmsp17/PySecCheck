# src/tenantsec/ui/presenters/render.py
from __future__ import annotations
from typing import Dict, Any, Iterable, List, Optional

def _fmt_key(k: str) -> str:
    return k.replace("_", " ").title()

def _fmt_val(v: Any) -> str:
    if v is None or v == "":
        return "—"
    if isinstance(v, (list, tuple)):
        return ", ".join(map(str, v))
    return str(v)

def render_lines_from_dict(
    data: Dict[str, Any],
    wanted_fields: Optional[Iterable[str]],
    label_map: Optional[Dict[str, str]] = None
) -> List[str]:
    """
    Render lines in the ORDER specified by wanted_fields.
    If a key is missing in data, show an em dash for the value.
    """
    lines: List[str] = []
    wanted = list(wanted_fields or [])
    for k in wanted:
        label = (label_map or {}).get(k, _fmt_key(k))
        v = data.get(k, None)
        lines.append(f"{label}: {_fmt_val(v)}")
    return lines if lines else ["(No fields selected)"]

def render_org(org: Dict[str, Any], prefs: Dict[str, Any]) -> List[str]:
    return render_lines_from_dict(org or {}, prefs.get("org_fields", []))

def render_user(user: Dict[str, Any], prefs: Dict[str, Any]) -> List[str]:
    return render_lines_from_dict(user or {}, prefs.get("user_fields", []))

def render_skus(skus: List[Dict[str, Any]]) -> List[str]:
    """
    Produces lines like:
      DEVELOPERPACK_E5: 6/25 used (Enabled)
    Falls back safely if fields are missing.
    """
    lines: List[str] = []
    for s in skus or []:
        part = s.get("skuPartNumber") or s.get("accountName") or s.get("skuId", "")[:8]
        consumed = s.get("consumedUnits", 0)
        prepaid = (s.get("prepaidUnits") or {}).get("enabled", 0)
        status = s.get("capabilityStatus", "—")
        lines.append(f"{part}: {consumed}/{prepaid} used ({status})")
    return lines or ["(No licenses found)"]
