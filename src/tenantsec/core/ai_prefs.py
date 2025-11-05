# src/tenantsec/core/ai_prefs.py
from __future__ import annotations
import os, json, pathlib
from typing import Dict, Any
from tenantsec.core.cache import _base_dir, write_json_atomic, read_json  # reuse your helpers

def _settings_path() -> pathlib.Path:
    # app-wide (not tenant-specific) config blob
    cfg_dir = _base_dir() / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    return cfg_dir / "ai_settings.json"

_DEFAULTS: Dict[str, Any] = {
    "provider": "openai",
    "model": "gpt-5",      # you can let the user override
    "api_key": "",         # stored locally; consider OS keyring if needed
    "base_url": "",        # optional (e.g., Azure OpenAI or proxy)
}

def load_ai_settings() -> Dict[str, Any]:
    data = read_json(_settings_path()) or {}
    out = _DEFAULTS.copy()
    out.update({k: v for k, v in data.items() if k in _DEFAULTS})
    # allow env override for api key
    env_key = os.environ.get("OPENAI_API_KEY")
    if env_key:
        out["api_key"] = env_key
    return out

def save_ai_settings(settings: Dict[str, Any]) -> None:
    s = _DEFAULTS.copy()
    s.update({k: v for k, v in settings.items() if k in _DEFAULTS})
    write_json_atomic(_settings_path(), s)
