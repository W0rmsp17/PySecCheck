# src/tenantsec/core/cache_manager.py
from __future__ import annotations
import shutil
from pathlib import Path
from tenantsec.core.cache import cache_dir

def tenant_root(tenant_id: str) -> Path:
    # cache_dir returns .../<tenant>/<bucket>; go up one to tenant root
    return cache_dir(tenant_id, "Static").parent

def clear_bucket(tenant_id: str, bucket: str) -> None:
    root = tenant_root(tenant_id)
    target = root / bucket
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True, exist_ok=True)

def clear_all(tenant_id: str) -> None:
    root = tenant_root(tenant_id)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True, exist_ok=True)
