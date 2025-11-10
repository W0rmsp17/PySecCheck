# src/tenantsec/review/user_scanner/feed_mail.py
from __future__ import annotations
from typing import Dict, Any, List
from tenantsec.core.graph_client import GraphClient
from tenantsec.core.cache_manager import tenant_root
from tenantsec.core.cache import read_json, write_json_atomic

from tenantsec.http.errors import NotFoundError, ForbiddenError

def build_mail_rules_cache(tenant_id: str, *, graph: GraphClient, max_users: int|None=None) -> str:
    root = tenant_root(tenant_id) / "USER"; root.mkdir(parents=True, exist_ok=True)
    idx = read_json(tenant_root(tenant_id) / "Static" / "users_index.json") or {}
    users = idx.get("users", [])
    out = []; count = 0

    for u in users:
        if max_users is not None and count >= max_users: break
        uid = u.get("id"); upn = u.get("upn") or u.get("display_name")
        if not uid: continue

        try:
            # folder map (may 404 if no mailbox)
            folder_map = {}
            for f in graph.get_paged_values(f"/v1.0/users/{uid}/mailFolders?$select=id,displayName"):
                fid, name = f.get("id"), f.get("displayName")
                if fid: folder_map[fid] = name

            # inbox rules (may also 404/403)
            rules_slim = []
            for r in graph.get_paged_values(f"/v1.0/users/{uid}/mailFolders/inbox/messageRules?$top=999"):
                acts = r.get("actions") or {}
                mid = acts.get("moveToFolder")
                if mid and "moveToFolderName" not in acts:
                    acts["moveToFolderName"] = folder_map.get(mid)
                rules_slim.append({
                    "id": r.get("id"),
                    "name": r.get("displayName") or r.get("name"),
                    "conditions": r.get("conditions"),
                    "actions": acts,
                    "sequence": r.get("sequence"),
                    "isEnabled": r.get("isEnabled"),
                })

            out.append({"userId": uid, "userPrincipalName": upn, "rules": rules_slim})
            count += 1

        except NotFoundError:

            out.append({"userId": uid, "userPrincipalName": upn, "rules": [], "note": "no_mailbox"})
            continue
        except ForbiddenError as e:
            # Missing permission or mailbox not accessible — record and continue
            out.append({"userId": uid, "userPrincipalName": upn, "rules": [], "note": "forbidden"})
            continue

    write_json_atomic(root / "mail_rules.json", {"items": out})
    return str(root / "mail_rules.json")

