from __future__ import annotations
import os, json, pathlib
from typing import Dict, Any

# Where to store prefs (aligns with your cache under %APPDATA%\PySecCheck\data\…)
def _root_dir() -> pathlib.Path:
    if os.name == "nt":
        base = pathlib.Path(os.getenv("APPDATA", pathlib.Path.home() / "AppData" / "Roaming"))
        return base / "PySecCheck" / "data" / "config"
    # mac/linux
    base = pathlib.Path(os.getenv("XDG_CONFIG_HOME", pathlib.Path.home() / ".config"))
    return base / "PySecCheck" / "data" / "config"

_PREFS_PATH = _root_dir() / "display_prefs.json"

_DEFAULT: Dict[str, Any] = {
    "org_fields": ["display_name", "country_code", "tenant_type", "created"],
    "user_fields": ["upn", "job_title", "license_skus", "mfa_state", "last_sign_in"],
}

def load_display_prefs() -> Dict[str, Any]:
    try:
        if _PREFS_PATH.exists():
            txt = _PREFS_PATH.read_text(encoding="utf-8")
            if txt.strip():
                data = json.loads(txt)
                # ensure keys exist
                data.setdefault("org_fields", list(_DEFAULT["org_fields"]))
                data.setdefault("user_fields", list(_DEFAULT["user_fields"]))
                return data
    except Exception:
        pass
    return dict(_DEFAULT)

def save_display_prefs(prefs: Dict[str, Any]) -> None:
    _PREFS_PATH.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "org_fields": [str(x) for x in prefs.get("org_fields", [])],
        "user_fields": [str(x) for x in prefs.get("user_fields", [])],
    }
    tmp = _PREFS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_PREFS_PATH)
