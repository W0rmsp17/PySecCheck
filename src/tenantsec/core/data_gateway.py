from __future__ import annotations
import pathlib
from typing import Any, Dict, List, Optional

from tenantsec.core.cache import cache_dir, read_json, write_json_atomic

# File names
USERS_FILE      = "users_index.json"
ORG_FILE        = "org_summary.json"
ROLES_FILE      = "roles.json"
POLICIES_FILE   = "policies.json"
LICENSES_FILE   = "licenses.json"          
SIGNINS_FILE    = "signins_summary.json"

class DataGateway:
    """Read-only façade over cache (fast, null-safe)."""
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id

    # ---------- path helpers ----------
    def _path(self, name: str, bucket: str) -> pathlib.Path:
        return cache_dir(self.tenant_id, bucket) / name

    # ---------- users ----------
    def users_path(self, bucket: str = "Static") -> pathlib.Path:
        return self._path(USERS_FILE, bucket)

    def get_users_index(self, bucket: str = "Static") -> List[Dict[str, Any]]:
        data = read_json(self.users_path(bucket)) or {}
        return data.get("users", [])

    def get_user_by_id(self, user_id: str, bucket: str = "Static") -> Optional[Dict[str, Any]]:
        for u in self.get_users_index(bucket):
            if u.get("id") == user_id:
                return u
        return None

    def list_user_fields(self, bucket: str = "Static") -> List[str]:
        data = read_json(self.users_path(bucket)) or {}
        return data.get("fields", [])

    def users_fetched_at(self, bucket: str = "Static") -> Optional[str]:
        data = read_json(self.users_path(bucket)) or {}
        return data.get("fetched_at")

    # ---------- organization ----------
    def get_org_summary(self) -> Dict[str, Any]:
        return read_json(self._path(ORG_FILE, "Static")) or {}

    # ---------- roles (directory) ----------
    def get_roles(self) -> Dict[str, Any]:
        return read_json(self._path(ROLES_FILE, "Static")) or {"roles": []}

    # ---------- policies ----------
    def get_policies(self) -> Dict[str, Any]:
        return read_json(self._path(POLICIES_FILE, "Static")) or {}

    # ---------- licenses (tenant inventory) ----------
    LICENSES_FILE = "licenses.json"

    def get_license_inventory(self) -> Dict[str, Any]:
        """
        Return {"skus": [...]} regardless of file shape.
        Prefers Static/licenses.json with key "skus".
        Falls back to Graph-style "value" and legacy file name.
        """
        # Preferred file/shape
        data = read_json(self._path(LICENSES_FILE, "Static")) or {}
        skus = data.get("skus")
        if skus is None:
            val = data.get("value")
            if isinstance(val, list):
                skus = val

        # Legacy filename fallback (subscribed_skus.json)
        if not skus:
            legacy = read_json(self._path("subscribed_skus.json", "Static")) or {}
            if isinstance(legacy, list):
                skus = legacy
            else:
                v = legacy.get("value")
                if isinstance(v, list):
                    skus = v

        return {"skus": skus or []}

    def set_subscribed_skus(self, items: List[Dict[str, Any]]) -> None:
        """
        Persist subscribed SKUs into Static/licenses.json as {"skus": [...]}
        """
        write_json_atomic(self._path(LICENSES_FILE, "Static"), {"skus": list(items or [])})

    def get_subscribed_skus(self) -> List[Dict[str, Any]]:
        inv = self.get_license_inventory()
        return inv.get("skus", []) or []

    def has_subscribed_skus(self) -> bool:
        return bool(self.get_subscribed_skus())

    # ---------- sign-ins summary (polled) ----------
    def get_signins_summary(self) -> Dict[str, Any]:
        return read_json(self._path(SIGNINS_FILE, "Polled")) or {}

    # ---------- small conveniences ----------
    def count_users(self) -> int:
        return len(self.get_users_index())

    def list_user_upns(self) -> List[str]:
        return [u.get("upn","") for u in self.get_users_index()]

    # ---------- readiness ----------
    def has_users(self) -> bool:
        data = read_json(self.users_path()) or {}
        return bool(data.get("users"))

    def has_org(self) -> bool:
        return bool(read_json(self._path(ORG_FILE, "Static")))

    def has_roles(self) -> bool:
        d = read_json(self._path(ROLES_FILE, "Static")) or {}
        return bool(d.get("roles"))

    def has_policies(self) -> bool:
        return bool(read_json(self._path(POLICIES_FILE, "Static")))

    def has_signins(self) -> bool:
        return bool(read_json(self._path(SIGNINS_FILE, "Polled")))

    def get_exchange_inventory(self) -> Dict[str, Any]:
        return read_json(self._path("exchange_policies.json", "Static")) or {}

    def has_exchange_inventory(self) -> bool:
        return bool(self.get_exchange_inventory())

    def get_exchange_policies(self) -> Dict[str, Any]:
        return read_json(self._path("exchange_policies.json", "Static")) or {}

    def get_oauth_inventory(self) -> dict:
        return read_json(self._path("oauth_apps.json", "Static")) or {}
 
    def has_oauth_inventory(self) -> bool:
        return bool(self.get_oauth_inventory())
    
    def get_intune_policies(self) -> Dict[str, Any]:
        return read_json(self._path("intune_policies.json", "Static")) or {}

    def has_intune_policies(self) -> bool:  
        return bool(self.get_intune_policies())

    def get_org_config(self) -> Dict[str, Any]:
        return read_json(self._path("org_config.json", "Static")) or {}

    def has_org_config(self) -> bool:
        return bool(self.get_org_config())
