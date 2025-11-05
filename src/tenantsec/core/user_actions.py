from __future__ import annotations
from typing import Optional, Dict, Any
from tenantsec.app import event_bus
from tenantsec.core.graph_client import GraphClient
from tenantsec.http.errors import HttpError, ForbiddenError, UnauthorizedError, ThrottleError

# Well-known ID for the password authentication method in Microsoft Graph
# (passwordAuthenticationMethod)
_PASSWORD_METHOD_WELLKNOWN_ID = "28c10230-6103-485e-b985-444c60001490"


def _publish(ok: bool, event: str, tenant_id: str, user_id: str, payload: Dict[str, Any]):
    data = {"tenant_id": tenant_id, "user_id": user_id, "ok": ok}
    data.update(payload)
    event_bus.publish(event, data)


def _resolve_password_method_id(graph: GraphClient, user_id: str) -> Optional[str]:
    """
    Try the well-known id; if API rejects it, enumerate methods and find the password method.
    """
    # Fast path: use well-known id (works for most tenants)
    try:
        # A cheap HEAD/GET would be nice, but Graph doesn't offer HEAD. We enumerate if needed.
        return _PASSWORD_METHOD_WELLKNOWN_ID
    except Exception:
        pass

    # Slow path: enumerate methods and find the passwordAuthenticationMethod
    try:
        methods = graph.get_json(f"/v1.0/users/{user_id}/authentication/methods")
        for m in methods.get("value", []):
            # Example: {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "..."}
            otype = m.get("@odata.type", "")
            if "passwordAuthenticationMethod" in otype:
                mid = m.get("id")
                if mid:
                    return mid
    except HttpError:
        pass
    return None


# ---------------------------
# Temporary Access Pass (TAP)
# ---------------------------
def generate_tap(
    graph: GraphClient,
    tenant_id: str,
    user_id: str,
    *,
    lifetime_in_minutes: int = 60,
    is_usable_once: bool = True,
    start_datetime: Optional[str] = None,  # ISO 8601 like "2025-11-02T10:00:00Z"
) -> Dict[str, Any]:
    """
    Create a Temporary Access Pass for a user.
    Permissions: TemporaryAccessPassAuthenticationMethod.ReadWrite.All
    Docs: POST /users/{id}/authentication/temporaryAccessPassMethods
    """
    body: Dict[str, Any] = {
        "lifetimeInMinutes": int(lifetime_in_minutes),
        "isUsableOnce": bool(is_usable_once),
    }
    if start_datetime:
        body["startDateTime"] = start_datetime

    try:
        res = graph.post_json(f"/v1.0/users/{user_id}/authentication/temporaryAccessPassMethods", json=body)
        # Response contains the TAP value (sensitive)
        tap_value = res.get("temporaryAccessPass")
        result = {
            "tap": tap_value,
            "lifetimeInMinutes": res.get("lifetimeInMinutes"),
            "isUsableOnce": res.get("isUsableOnce"),
            "startDateTime": res.get("startDateTime"),
            "createdDateTime": res.get("createdDateTime"),
            "methodId": res.get("id"),
        }
        # Do NOT print() the TAP; only publish via event.
        _publish(True, "user.action.tap.created", tenant_id, user_id, {"result": result})
        return result

    except (UnauthorizedError, ForbiddenError) as e:
        _publish(False, "user.action.tap.created", tenant_id, user_id, {
            "error": "not_authorized",
            "message": str(e),
            "hint": "Grant TemporaryAccessPassAuthenticationMethod.ReadWrite.All and admin consent.",
        })
        raise
    except ThrottleError as e:
        _publish(False, "user.action.tap.created", tenant_id, user_id, {
            "error": "throttled",
            "message": str(e),
            "hint": "Service throttled. Try again shortly.",
        })
        raise
    except HttpError as e:
        _publish(False, "user.action.tap.created", tenant_id, user_id, {
            "error": "http_error",
            "message": str(e),
        })
        raise
    except Exception as e:
        _publish(False, "user.action.tap.created", tenant_id, user_id, {
            "error": "unexpected",
            "message": str(e),
        })
        raise


def _patch_json(graph, url: str, json: Dict[str, Any]) -> Dict[str, Any] | None:
    """
    Tries common GraphClient shapes in order:
      patch_json → request_json(PATCH) → request(PATCH) → call(PATCH) → patch
    Returns the parsed JSON if available, else None for clients that return no body.
    """
    if hasattr(graph, "patch_json"):
        return graph.patch_json(url, json=json)
    if hasattr(graph, "request_json"):
        return graph.request_json("PATCH", url, json=json)
    if hasattr(graph, "request"):
        return graph.request("PATCH", url, json=json)
    if hasattr(graph, "call"):
        return graph.call("PATCH", url, json=json)
    # last chance: some clients expose .patch()
    return graph.patch(url, json=json)


def change_password(
    graph: GraphClient,
    tenant_id: str,
    user_id: str,
    new_password: str
) -> Dict[str, Any]:
    """
    App-only compatible password change via passwordProfile.
    Requires one of (Application): User.ReadWrite.All or Directory.ReadWrite.All
      (User.ManageIdentities.All / User.EnableDisableAccount.All can also apply)
    PATCH /v1.0/users/{id}
    """
    payload = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": False,
            "password": new_password,
        }
    }

    try:
        _patch_json(graph, f"/v1.0/users/{user_id}", json=payload)
        res = {"ok": True}
        _publish(True, "user.action.password.changed", tenant_id, user_id, {"result": res})
        return res

    except (UnauthorizedError, ForbiddenError) as e:
        _publish(False, "user.action.password.changed", tenant_id, user_id, {
            "error": "not_authorized",
            "message": str(e),
            "hint": "Grant User.ReadWrite.All or Directory.ReadWrite.All (Application) and admin consent.",
        })
        raise
    except ThrottleError as e:
        _publish(False, "user.action.password.changed", tenant_id, user_id, {
            "error": "throttled",
            "message": str(e),
            "hint": "Service throttled. Try again shortly.",
        })
        raise
    except HttpError as e:
        _publish(False, "user.action.password.changed", tenant_id, user_id, {
            "error": "http_error",
            "message": str(e),
        })
        raise
    except Exception as e:
        _publish(False, "user.action.password.changed", tenant_id, user_id, {
            "error": "unexpected",
            "message": str(e),
        })
        raise