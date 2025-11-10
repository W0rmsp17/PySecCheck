from __future__ import annotations
from typing import List
import pathlib, time

from tenantsec.app import event_bus
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.models import UserLite
from tenantsec.core.cache import cache_dir, read_json, write_json_atomic
from tenantsec.http.errors import HttpError


def _cache_path(tenant_id: str, bucket: str) -> pathlib.Path:
    return cache_dir(tenant_id, bucket) / "users_index.json"




def list_users(
    graph: GraphClient,
    tenant_id: str,
    *,
    use_cache: bool = True,
    bucket: str = "Static",
    page_limit: int | None = None,
) -> List[UserLite]:
    """
    Phase A: fast index. Writes a base cache with 'fields' and basic user rows.
    Only constructs UserLite from minimal fields so cached enrichments don't break it.
    """
    cp = _cache_path(tenant_id, bucket)

    if use_cache:
        cached = read_json(cp) or {}
        cached_users = cached.get("users", [])
        if cached_users:
            out: List[UserLite] = []
            for u in cached_users:
                out.append(UserLite(
                    id=u.get("id", ""),
                    upn=u.get("upn", ""),
                    display_name=u.get("display_name") or u.get("upn", ""),
                    job_title=u.get("job_title"),
                ))
            return out

    users: List[UserLite] = []
    select = "id,displayName,userPrincipalName,jobTitle"
    for it in graph.get_paged_values(f"/v1.0/users?$select={select}&$top=999", page_limit=page_limit):
        users.append(UserLite(
            id=it.get("id", ""),
            upn=it.get("userPrincipalName", ""),
            display_name=it.get("displayName") or it.get("userPrincipalName", ""),
            job_title=it.get("jobTitle"),
        ))

    data = {
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fields": ["id", "upn", "display_name", "job_title"], 
        "users": [u.__dict__ for u in users],
    }
    write_json_atomic(cp, data)
    return users


def enrich_licenses(graph: GraphClient, tenant_id: str):
    """
    Attach human-readable license names per user.
    Adds/updates 'license_names' and appends field name to 'fields'.
    """
    cp = _cache_path(tenant_id, "Static")
    try:
        data = read_json(cp) or {"users": [], "fields": []}
        users = data.get("users", [])

        # 1) SKU map
        sku_map = {}
        for page in graph.get_paged_values("/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits"):
            for s in page.get("value", []):
                sku_map[s.get("skuId")] = s.get("skuPartNumber")

        # 2) Per-user assigned licenses
        user_licenses = {}
        for page in graph.get_paged_values("/v1.0/users?$select=id,assignedLicenses&$top=999"):
            for u in page.get("value", []):
                uid = u.get("id")
                if not uid:
                    continue
                names = [sku_map.get(a.get("skuId"), a.get("skuId")) for a in (u.get("assignedLicenses") or []) if a.get("skuId")]
                user_licenses[uid] = names

        # 3) Merge
        for u in users:
            uid = u.get("id")
            if uid in user_licenses:
                u["license_names"] = user_licenses[uid]

        if "license_names" not in data.get("fields", []):
            data["fields"].append("license_names")

        write_json_atomic(cp, data)
        event_bus.publish("users.list.updated", {
            "tenant_id": tenant_id,
            "added_fields": ["license_names"],
        })
        print(f"[user_service] enriched licenses for {len(user_licenses)} users")

    except HttpError as ex:
        print(f"[user_service] License enrichment failed: {ex}")


def enrich_roles(graph: GraphClient, tenant_id: str):
    """
    Add 'roles': [...] for users who are members of directory roles.
    """
    cp = _cache_path(tenant_id, "Static")
    try:
        data = read_json(cp) or {"users": [], "fields": []}
        users = data.get("users", [])

        # Roles
        role_map = {}
        for page in graph.get_paged_values("/v1.0/directoryRoles?$select=id,displayName"):
            for r in page.get("value", []):
                rid = r.get("id")
                if rid:
                    role_map[rid] = r.get("displayName", "Unknown")

        # Members per role
        role_members = {}
        for role_id, name in role_map.items():
            for page in graph.get_paged_values(f"/v1.0/directoryRoles/{role_id}/members?$select=id"):
                for m in page.get("value", []):
                    mid = m.get("id")
                    if mid:
                        role_members.setdefault(mid, []).append(name)

        # Merge
        for u in users:
            uid = u.get("id")
            if uid in role_members:
                u["roles"] = sorted(role_members[uid])

        if "roles" not in data.get("fields", []):
            data["fields"].append("roles")

        write_json_atomic(cp, data)
        event_bus.publish("users.list.updated", {
            "tenant_id": tenant_id,
            "added_fields": ["roles"],
        })
        print(f"[user_service] enriched roles for {len(role_members)} users")

    except HttpError as ex:
        print(f"[user_service] Role enrichment failed: {ex}")


from tenantsec.http.errors import ForbiddenError, ThrottleError, HttpError

def enrich_mfa_state(graph: GraphClient, tenant_id: str):
    """
    Add 'mfa_state': 'Registered' | 'NotRegistered'
    Requires Microsoft Graph Application permission: Reports.Read.All (with admin consent).
    """
    cp = _cache_path(tenant_id, "Static")
    try:
        data = read_json(cp) or {"users": [], "fields": []}
        users = data.get("users", [])

        mfa_map = {}
        for page in graph.get_paged_values("/v1.0/reports/credentialUserRegistrationDetails?$top=999"):
            for u in page.get("value", []):
                uid = u.get("id")
                if uid:
                    mfa_map[uid] = "Registered" if u.get("isMfaRegistered") else "NotRegistered"

        for u in users:
            uid = u.get("id")
            if uid in mfa_map:
                u["mfa_state"] = mfa_map[uid]

        if "mfa_state" not in data.get("fields", []):
            data["fields"].append("mfa_state")

        write_json_atomic(cp, data)
        event_bus.publish("users.list.updated", {
            "tenant_id": tenant_id,
            "added_fields": ["mfa_state"],
        })
        print(f"[user_service] enriched MFA for {len(mfa_map)} users")

    except ForbiddenError:
        print("[user_service] MFA enrichment skipped (403) – add Reports.Read.All and grant admin consent")
    except ThrottleError as ex:
        print(f"[user_service] MFA enrichment throttled: {ex}")
    except HttpError as ex:
        print(f"[user_service] MFA enrichment failed: {ex}")



def enrich_signin_activity(graph: GraphClient, tenant_id: str):
    """
    Add 'last_sign_in' from users.signInActivity (if present for your tenant).
    Fallback to audit logs can be added later.
    """
    cp = _cache_path(tenant_id, "Static")
    try:
        data = read_json(cp) or {"users": [], "fields": []}
        users = data.get("users", [])

        user_signins = {}
        for page in graph.get_paged_values("/v1.0/users?$select=id,signInActivity&$top=999"):
            for u in page.get("value", []):
                sid = u.get("id")
                activity = u.get("signInActivity")
                if sid and activity:
                    user_signins[sid] = activity.get("lastSignInDateTime")

        for u in users:
            uid = u.get("id")
            if uid in user_signins:
                u["last_sign_in"] = user_signins[uid]

        if "last_sign_in" not in data.get("fields", []):
            data["fields"].append("last_sign_in")

        write_json_atomic(cp, data)
        event_bus.publish("users.list.updated", {
            "tenant_id": tenant_id,
            "added_fields": ["last_sign_in"],
        })
        print(f"[user_service] enriched sign-in activity for {len(user_signins)} users")

    except HttpError as ex:
        print(f"[user_service] Sign-in enrichment failed: {ex}")


def enrich_license_details(graph: GraphClient, tenant_id: str, *, max_users: int | None = None):
    """
    Per user: add only 'license_skus' (list of skuPartNumber). No servicePlans.
    """
    cp = _cache_path(tenant_id, "Static")
    try:
        data = read_json(cp) or {"users": [], "fields": []}
        users = data.get("users", [])

        count = 0
        for u in users:
            uid = u.get("id")
            if not uid:
                continue
            if max_users is not None and count >= max_users:
                break

            ld = graph.get_json(f"/v1.0/users/{uid}/licenseDetails?$select=skuPartNumber")
            items = ld.get("value", [])

            skus = []
            for item in items:
                sku_num = item.get("skuPartNumber")
                if sku_num:
                    skus.append(sku_num)

            if skus:
                u["license_skus"] = sorted(set(skus))

            u.pop("license_details", None)

            count += 1

        fields = data.setdefault("fields", [])
        if "license_skus" not in fields:
            fields.append("license_skus")

        if "license_details" in fields:
            fields.remove("license_details")

        write_json_atomic(cp, data)
        event_bus.publish("users.list.updated", {
            "tenant_id": tenant_id,
            "added_fields": ["license_skus"],
        })
        print(f"[user_service] enriched license_skus for ~{count} users")

    except HttpError as ex:
        print(f"[user_service] License SKU enrichment failed: {ex}")

def enrich_profile(graph: GraphClient, tenant_id: str):
    """
    Pull a richer set of user properties to expand what's available to display.
    Lightweight, paged; avoids per-user GET calls.
    """
    cp = _cache_path(tenant_id, "Static")
    data = read_json(cp) or {"users": [], "fields": []}
    users = data.get("users", [])
    if not users:
        return

    sel = ",".join([
        "id","userPrincipalName","displayName","jobTitle","mail","mobilePhone",
        "officeLocation","givenName","surname","userType","accountEnabled",
        "createdDateTime","department","companyName","usageLocation"
    ])

    idx = {u.get("id"): u for u in users}

    for page in graph.get_paged_values(f"/v1.0/users?$select={sel}&$top=999"):
        for it in page.get("value", []):
            uid = it.get("id")
            row = idx.get(uid)
            if not uid or not row:
                continue

            row["upn"] = it.get("userPrincipalName", row.get("upn"))
            row["display_name"] = it.get("displayName", row.get("display_name"))
            row["job_title"] = it.get("jobTitle", row.get("job_title"))
            for k in ("mail","mobilePhone","officeLocation","givenName","surname","userType",
                      "accountEnabled","createdDateTime","department","companyName","usageLocation"):
                v = it.get(k)
                if v is not None:
                    row[k] = v

    f = set(data.get("fields", []))
    f.update(["mail","mobilePhone","officeLocation","givenName","surname","userType",
              "accountEnabled","createdDateTime","department","companyName","usageLocation"])
    data["fields"] = sorted(f)

    write_json_atomic(cp, data)
    event_bus.publish("users.list.updated", {"tenant_id": tenant_id, "added_fields": list(f)})
