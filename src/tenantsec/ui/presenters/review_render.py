from __future__ import annotations
from typing import Any, Dict, List, Optional

def _header_line(sev: str, title: str) -> str:
    return f"[{sev.upper()}] {title}"

def _kv_line(key: str, val: str) -> str:
    return f"  • {key}: {val}"

def _bullet_line(text: str) -> str:
    return f"  • {text}"

def _indent_block(s: str, n: int = 2) -> str:
    pad = " " * n
    return "\n".join(pad + line if line else "" for line in s.splitlines())

def _fmt_scopes(v: Any) -> str:
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return str(v)

def _format_dict_table(rows: List[Dict[str, Any]], column_order: List[str]) -> str:
    """
    Simple text table for Tk Text widget (monospace feel using alignment).
    """
    if not rows:
        return ""

    # Compute column widths
    widths: List[int] = []
    for col in column_order:
        w = len(col)
        for r in rows:
            w = max(w, len(str(r.get(col, "") or "")))
        widths.append(w)

    # Build lines
    hdr = "  " + "  ".join(col.ljust(w) for col, w in zip(column_order, widths))
    sep = "  " + "  ".join("-" * w for w in widths)
    body_lines: List[str] = []
    for r in rows:
        body_lines.append(
            "  " + "  ".join(str(r.get(col, "") or "").ljust(w) for col, w in zip(column_order, widths))
        )

    return "\n".join([hdr, sep] + body_lines)

def _group_by_reason(evidence: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for e in evidence:
        reason = e.get("reason", "—")
        groups.setdefault(reason, []).append(e)
    return groups

def _format_oauth_evidence(evidence: List[Dict[str, Any]]) -> str:
    """
    Make 'Overprivileged apps' readable:
      - Group by reason
      - Two tables:
          1) Service principals exposing high-priv scopes
          2) OAuth grants with high-priv scopes
    """
    groups = _group_by_reason(evidence)

    lines: List[str] = []

    # 1) SPs with high-priv scopes
    sp_rows: List[Dict[str, Any]] = []
    for e in groups.get("Service principal exposes high-priv scopes.", []):
        sp_rows.append({
            "Service Principal": e.get("servicePrincipal") or e.get("client") or "—",
            "AppId": e.get("appId") or "—",
            "Scopes": _fmt_scopes(e.get("scopes")),
        })
    if sp_rows:
        lines.append("  Reason: Service principals expose high-priv scopes")
        lines.append(_format_dict_table(sp_rows, ["Service Principal", "AppId", "Scopes"]))
        lines.append("")

    # 2) Tenant grants with high-priv scopes
    grant_rows: List[Dict[str, Any]] = []
    for e in groups.get("OAuth grant includes high-priv scopes.", []):
        grant_rows.append({
            "Client": e.get("client") or "—",
            "Resource": e.get("resource") or "—",
            "Scopes": _fmt_scopes(e.get("scopes")),
            "Consent": e.get("consentType") or "—",
        })
    if grant_rows:
        lines.append("  Reason: OAuth grants include high-priv scopes")
        lines.append(_format_dict_table(grant_rows, ["Client", "Resource", "Scopes", "Consent"]))
        lines.append("")

    # Fallback: dump any other reasons in grouped bullet form
    for reason, entries in groups.items():
        if reason in ("Service principal exposes high-priv scopes.", "OAuth grant includes high-priv scopes."):
            continue
        lines.append(f"  Reason: {reason}")
        for e in entries:
            parts: List[str] = []
            for k in ("servicePrincipal", "client", "resource", "appId", "scopes", "consentType"):
                v = e.get(k)
                if v:
                    parts.append(f"{k}={v if k != 'scopes' else _fmt_scopes(v)}")
            lines.append("    - " + "; ".join(parts) if parts else "    - (no details)")
        lines.append("")

    return "\n".join(lines).rstrip()

def _format_generic_list_of_dicts(evidence: List[Dict[str, Any]]) -> str:
    """
    Generic formatter: group by reason and emit bullet sub-items.
    """
    groups = _group_by_reason(evidence)
    lines: List[str] = []
    for reason, items in groups.items():
        lines.append(f"  Reason: {reason}")
        for it in items:
            kvs = [f"{k}={it[k]}" for k in it.keys() if k != "reason"]
            lines.append("    - " + (", ".join(kvs) if kvs else "(no details)"))
        lines.append("")
    return "\n".join(lines).rstrip()

def format_finding_to_text(f) -> str:
    """
    Pretty, readable block for the Tk Text widget.
    Aligns with the current Finding dataclass:
      id, title, severity, summary, remediation, docs, evidence, ...
    """
    lines: List[str] = []
    lines.append(_header_line(f.severity, f.title))
    lines.append(_kv_line("id", f.id))

    # NOTE: Finding no longer has 'description'; use 'summary'
    summary: Optional[str] = getattr(f, "summary", None)
    if summary:
        lines.append(_bullet_line(summary))

    if getattr(f, "remediation", None):
        lines.append(_kv_line("remediation", f.remediation))
    if getattr(f, "docs", None):
        lines.append(_kv_line("docs", f.docs))

    # Evidence formatting
    ev = getattr(f, "evidence", None)
    if ev is None:
        return "\n".join(lines)

    lines.append("  • evidence:")

    # Special handling for oauth.overprivileged_apps
    if f.id == "oauth.overprivileged_apps" and isinstance(ev, list) and ev and isinstance(ev[0], dict):
        pretty = _format_oauth_evidence(ev)
        if pretty:
            lines.append(pretty)
            return "\n".join(lines)

    # Generic handling for list[dict]
    if isinstance(ev, list) and ev and isinstance(ev[0], dict):
        lines.append(_format_generic_list_of_dicts(ev))
        return "\n".join(lines)

    # Fallbacks
    if isinstance(ev, (str, int, float)):
        lines.append(f"    {ev}")
    else:
        try:
            import json
            lines.append(_indent_block(json.dumps(ev, indent=2, ensure_ascii=False), 2))
        except Exception:
            lines.append(_indent_block(str(ev), 2))

    return "\n".join(lines)
