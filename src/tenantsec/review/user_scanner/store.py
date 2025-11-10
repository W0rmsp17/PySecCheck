from __future__ import annotations
import time
from pathlib import Path
from typing import Any, Optional
from tenantsec.core.cache import cache_dir, read_json, write_json_atomic

BUCKET = "USER"

def _bucket_dir(tenant_id: str) -> Path:
    return cache_dir(tenant_id, BUCKET)

def sheet_path(tenant_id: str, name: str) -> Path:
    return _bucket_dir(tenant_id) / f"{name}.json"

def write_sheet(tenant_id: str, name: str, payload: dict) -> None:
    data = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **payload,
    }
    write_json_atomic(sheet_path(tenant_id, name), data)

def read_sheet(tenant_id: str, name: str, *, max_age_sec: Optional[int] = None) -> Optional[dict]:
    p = sheet_path(tenant_id, name)
    data = read_json(p)
    if not data:
        return None
    if max_age_sec is None:
        return data

    # TTL check
    try:
        # Use file mtime; simpler and reliable
        age = time.time() - p.stat().st_mtime
        if age > max_age_sec:
            return None
    except Exception:
        pass
    return data
