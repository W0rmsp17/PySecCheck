import json, os, pathlib

def load_appsettings() -> dict:
    p = pathlib.Path("config/appsettings.json")
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8").strip()
        if not text:
            return {}
        return json.loads(text)
    except Exception:
        # malformed JSON → fall back to defaults
        return {}

def get_http_config():
    cfg = load_appsettings().get("http", {})
    return {
        "timeout_seconds": int(cfg.get("timeout_seconds", 30)),
        "max_retries": int(cfg.get("max_retries", 4)),
        "max_concurrency": int(cfg.get("max_concurrency", 6)),
    }
