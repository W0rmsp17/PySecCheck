from __future__ import annotations
import json
import os
import re
import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

from tenantsec.core.ai_prefs import load_ai_settings
from tenantsec.core.cache import cache_dir, read_json, write_json_atomic



class AIConfigError(RuntimeError):
    """Raised when AI settings (e.g., API key) are not configured."""



def _get_settings() -> Dict[str, Any]:
    s = load_ai_settings()
    if not s.get("api_key"):
        raise AIConfigError("ChatGPT/OpenAI API key is not configured.")
    return s

def _chosen_model(default: str = "gpt-4o-mini") -> str:
    s = _get_settings()
    return (s.get("model") or default).strip()

def _base_url() -> str:
    s = _get_settings()
    return (s.get("base_url") or "https://api.openai.com").rstrip("/")


def _http_post_json(url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            err_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_text = str(e)
        raise RuntimeError(f"HTTP {e.code} error: {err_text}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}") from e


def call_llm(system: str, prompt: str, *, model: Optional[str] = None, temperature: float = 0.2) -> str:
    """
    Minimal OpenAI-compatible Chat Completions call via stdlib urllib.
    Reads API config from tenantsec.core.ai_prefs.

    Supports OpenAI-style endpoints:
      base_url: https://api.openai.com
      path:     /v1/chat/completions
    """
    s = _get_settings()
    api_key = s["api_key"]
    base_url = _base_url()
    mdl = (model or _chosen_model()).strip()

    url = f"{base_url}/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": mdl,
        "temperature": temperature,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }

    res = _http_post_json(url, headers, body)
    try:
        return res["choices"][0]["message"]["content"]
    except Exception:
        raise RuntimeError(f"LLM response error: {json.dumps(res, ensure_ascii=False)[:1000]}")


# =========================
# Caching helpers
# =========================
def _ai_dir(tenant_id: str):
    return cache_dir(tenant_id, "AI")

def cache_get(tenant_id: str, name: str):
    return read_json(_ai_dir(tenant_id) / f"{name}.json")

def cache_put(tenant_id: str, name: str, data: Dict[str, Any]):
    write_json_atomic(_ai_dir(tenant_id) / f"{name}.json", data)


# =========================
# Redaction + context builders
# =========================
def _redact_upn(s: str) -> str:
    import re
    def repl(m):
        h = hashlib.sha1(m.group(0).encode("utf-8")).hexdigest()[:6]
        return f"<user#{h}>"
    return re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", repl, s)

def _lite_findings(findings: List[Any], max_ev_chars: int = 800) -> List[Dict[str, Any]]:
    out = []
    for f in findings:
        ev = getattr(f, "evidence", None)
        ev_str = ""
        if ev is not None:
            try:
                ev_str = json.dumps(ev, ensure_ascii=False)
            except Exception:
                ev_str = str(ev)
        ev_str = _redact_upn(ev_str)[:max_ev_chars]
        out.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            # IMPORTANT: Finding uses 'summary' now (not 'description')
            "summary": getattr(f, "summary", ""),
            "remediation": getattr(f, "remediation", ""),
            "evidence_hint": ev_str,
        })
    return out

def _hash_rules(findings: List[Any]) -> str:
    key = "|".join(f"{f.id}:{f.severity}" for f in findings)
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


# =========================
# JSON helpers
# =========================
_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)

def _strip_code_fences(s: str) -> str:
    return _FENCE_RE.sub("", s.strip())

def _parse_llm_json(s: str) -> Dict[str, Any]:
    s = _strip_code_fences(s)
    return json.loads(s)


# =========================
# Prompts / schemas
# =========================
EXEC_SYSTEM = (
    "You are a Microsoft 365 tenant security reviewer. Be precise, action-oriented, and cite finding IDs. "
    "Prefer concise bullets. Output only valid JSON per the requested schema."
)

EXEC_PROMPT = """Task: Produce an executive security summary from PySecCheck results.

Inputs:
- Tenant: {tenant_meta}
- Findings (lite): {findings_lite}
- Context: {org_small_context}

Requirements:
Return ONLY valid JSON matching this schema:
{schema}

Rules:
- Summarize at org level first (overview, headline_risks, quick_wins, roadmap).
- Build user_findings_table as compact rows: hash UPNs already provided in findings_lite/evidence, list key issues (e.g., 'MFA disabled'), set mfa_enabled True/False, add brief notes if helpful.
- Do NOT include mailbox rules or per-user narrative.
- Keep lists concise (max 5 items each).
- Scoring: start 100; subtract per finding by severity (HIGH 6–10, MEDIUM 3–5, LOW 1–2); not below 0.
"""

EXEC_SCHEMA = {
  "overall_score": 0,
  "org_overview": {
    "tenant_id": "string",
    "tenant_name": "string",
    "user_count": 0
  },
  "headline_risks": [{"id": "string", "why": "string", "impact": "string", "priority": 1}],
  "quick_wins": [{"action": "string", "owner": "string", "eta_days": 7}],
  "roadmap": [{"theme": "string", "items": [{"action": "string", "eta_days": 14}]}],
  "user_findings_table": [
    {"user_hash": "string", "issues": ["string"], "mfa_enabled": False, "notes": "string"}
  ]
}


TECH_SYSTEM = (
    "You are a Microsoft 365 tenant security remediator. Produce concise, actionable Markdown. "
    "Each section references the finding id."
)

TECH_PROMPT = """Task: Produce a technical remediation report.

Inputs:
- Findings: {findings_full}
- Sheets (subset): {sheets_subset}

Output Markdown with sections:
# Overview (score guess + counts)
## Priority Risks
## Remediation Plan
### {per_finding_heading}
## Appendices

Be concrete and concise.
"""



def build_exec_context(sheets: Dict[str, Any], findings: List[Any]) -> Dict[str, Any]:
    org_cfg = sheets.get("org_config") or {}
    users = (sheets.get("users") or {}).get("items", []) or []
    return {
        "tenant_meta": {
            "tenant_id": (sheets.get("org") or {}).get("tenantId", "unknown"),
            "tenant_name": (sheets.get("org") or {}).get("organization", {}).get("display_name") or "unknown",
            "user_count": len(users),
        },
        "findings_lite": _lite_findings(findings),
        "org_small_context": {
            "securityDefaultsEnabled": org_cfg.get("securityDefaultsEnabled"),
            "ssprEnabled": org_cfg.get("ssprEnabled"),
            "ssprMfaRequired": org_cfg.get("ssprMfaRequired"),
        },
    }

def build_tech_context(sheets: Dict[str, Any], findings: List[Any]) -> Dict[str, Any]:
    sub = {
        "policies": (sheets.get("policies") or {}).get("conditional_access", {}).get("policies", []),
        "roles": (sheets.get("roles") or {}).get("roles", []),
        "licenses": (sheets.get("licenses") or {}).get("skus", []),
    }
    # IMPORTANT: 'summary' instead of 'description'
    return {
        "findings_full": json.loads(json.dumps([{
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "summary": getattr(f, "summary", ""),
            "remediation": getattr(f, "remediation", ""),
            "evidence": getattr(f, "evidence", None),
        } for f in findings], ensure_ascii=False)),
        "sheets_subset": sub,
    }


_WEIGHTS = {"critical": 10, "high": 8, "medium": 4, "low": 2, "info": 0}

def compute_overall_score(findings: List[Any]) -> int:
    total = 100
    for f in findings:
        total -= _WEIGHTS.get(str(getattr(f, "severity", "")).lower(), 6)
    return max(0, total)



def generate_exec_summary(tenant_id: str, sheets: Dict[str, Any], findings: List[Any]) -> Dict[str, Any]:
    ctx = build_exec_context(sheets, findings)
    users_compact = _compact_users(sheets)
    sig_src = json.dumps({
        "tenant_meta": ctx["tenant_meta"],
        "findings_lite": ctx["findings_lite"],
        "org_small_context": ctx["org_small_context"],
        "users": users_compact,             # <-- include users in cache key
    }, ensure_ascii=False)
    sig = hashlib.sha1(sig_src.encode("utf-8")).hexdigest()[:10]
    key = f"exec_summary_{sig}"
    cached = cache_get(tenant_id, key)
    if cached: return cached

    prompt = EXEC_PROMPT.format(
        tenant_meta=json.dumps(ctx["tenant_meta"], ensure_ascii=False),
        findings_lite=json.dumps(ctx["findings_lite"], ensure_ascii=False),
        org_small_context=json.dumps(ctx["org_small_context"], ensure_ascii=False),
        schema=json.dumps(EXEC_SCHEMA, indent=2),
    )
    data = _parse_llm_json(call_llm(EXEC_SYSTEM, prompt, model=_chosen_model(), temperature=0.2))
    data["overall_score"] = compute_overall_score(findings)
    data["org_overview"] = ctx["tenant_meta"]
    data["user_findings_table"] = users_compact   # <-- force into report
    cache_put(tenant_id, key, data)
    return data

def _compact_users(sheets: Dict[str,Any]) -> List[Dict[str,Any]]:
    users = (sheets.get("users") or {}).get("items", []) or []
    def hash_upn(u):
        upn = (u.get("upn") or "").strip().lower()
        return u.get("user_hash") or (f"user#{hashlib.sha1(upn.encode('utf-8')).hexdigest()[:10]}" if upn else "user#unknown")
    out = []
    for u in users:
        out.append({
            "user_hash": hash_upn(u),
            "issues": u.get("issues") or [],
            "mfa_enabled": bool(u.get("mfa_enabled")),
            "notes": ""
        })
    return out        


def generate_technical_report_md(tenant_id: str, sheets: Dict[str, Any], findings: List[Any]) -> str:
    ctx = build_tech_context(sheets, findings)
    sig_src = json.dumps({
        "findings_full": ctx["findings_full"],
        "sheets_subset": ctx["sheets_subset"],
    }, ensure_ascii=False)
    sig = hashlib.sha1(sig_src.encode("utf-8")).hexdigest()[:10]
    key = f"tech_report_{sig}"

    cached = cache_get(tenant_id, key)
    if cached and isinstance(cached, Dict) and "markdown" in cached:
        return cached["markdown"]

    prompt = TECH_PROMPT.format(
        findings_full=json.dumps(ctx["findings_full"], ensure_ascii=False),
        sheets_subset=json.dumps(ctx["sheets_subset"], ensure_ascii=False),
        per_finding_heading="{id}: {title}",
    )
    out = call_llm(TECH_SYSTEM, prompt, model=_chosen_model(), temperature=0.2)
    md = _redact_upn(out)
    users = (sheets.get("users") or {}).get("items", []) or []
    if users:
        lines = ["\n## Appendix: User Findings\n", "| User | MFA | Issues |", "|---|---|---|"]
        for u in users:
            name = u.get("user_hash") or u.get("upn","unknown")
            mfa = "Yes" if u.get("mfa_enabled") else "No"
            issues = ", ".join(u.get("issues") or [])
            lines.append(f"| {name} | {mfa} | {issues} |")
        md += "\n" + "\n".join(lines)
    cache_put(tenant_id, key, {"markdown": md})
    return md



def test_connection() -> str:
    """
    Tiny/cheap sanity check. Returns 'PONG' on success.
    """
    reply = call_llm(
        "You are a function.",
        "Reply with the single word: PONG.",
        model=_chosen_model(),
        temperature=0.0,
    )
    return reply.strip()
