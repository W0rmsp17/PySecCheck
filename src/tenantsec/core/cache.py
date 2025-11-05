# src/tenantsec/core/cache.py
from __future__ import annotations
import json, os, sys, pathlib, tempfile
from typing import Any, Optional

APP_NAME = "PySecCheck"

def _base_dir() -> pathlib.Path:
    if sys.platform.startswith("win"):
        root = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return pathlib.Path(root) / APP_NAME
    elif sys.platform == "darwin":
        return pathlib.Path.home() / "Library" / "Application Support" / APP_NAME
    else:
        return pathlib.Path.home() / ".local" / "share" / APP_NAME

def cache_dir(tenant_id: str, bucket: str) -> pathlib.Path:
    p = _base_dir() / "data" / "cache" / tenant_id / bucket
    p.mkdir(parents=True, exist_ok=True); return p

def read_json(path: pathlib.Path) -> Optional[dict[str, Any]]:
    if not path.exists(): return None
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception: return None

def write_json_atomic(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix="._", suffix=".json")
    os.close(fd)
    pathlib.Path(tmp).write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)
