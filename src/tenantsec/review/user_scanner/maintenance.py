from __future__ import annotations
from tenantsec.core.cache_manager import clear_bucket

def purge_user_cache(tenant_id: str) -> None:
    clear_bucket(tenant_id, "USER")
