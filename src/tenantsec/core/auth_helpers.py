from __future__ import annotations
import time
from dataclasses import dataclass
import msal
import requests

# Reuse the same error classes from core.auth
from tenantsec.core.auth import (
    AuthError, InvalidTenantId, InvalidClientId, InvalidClientSecret,
    NetworkError, ConsentRequired
)

GRAPH = "https://graph.microsoft.com"
SCOPES = ["https://graph.microsoft.com/.default"]

def build_authority(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}"

def _map_msal_error(desc: str) -> AuthError:
    d = desc or ""
    if "AADSTS7000215" in d:  # invalid client secret
        return InvalidClientSecret("Invalid client secret.")
    if "AADSTS700016" in d:  # invalid client id
        return InvalidClientId("Invalid client ID or app not found.")
    if "invalid_tenant" in d or "AADSTS90002" in d:
        return InvalidTenantId("Invalid tenant ID or tenant not found.")
    if "AADSTS65001" in d or "consent_required" in d:
        return ConsentRequired("Admin consent required.")
    return AuthError(d)

def msal_acquire_token(client_id: str, client_secret: str, authority: str) -> str:
    try:
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )
        res = app.acquire_token_for_client(scopes=SCOPES)
    except requests.exceptions.RequestException as ex:
        raise NetworkError(str(ex))
    except Exception as ex:
        raise AuthError(str(ex))

    if "access_token" not in res:
        raise _map_msal_error(res.get("error_description", "Unknown error"))

    return res["access_token"]

def _http_get(url: str, headers: dict, timeout: float = 10.0, max_retries: int = 2):
    # tiny auth-only retry (we'll have a full http client for jobs later)
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            if r.status_code in (429, 502, 503, 504):
                ra = r.headers.get("Retry-After")
                sleep_s = int(ra) if ra and ra.isdigit() else min(2 ** attempt, 8)
                time.sleep(sleep_s)
                continue
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as ex:
            last_exc = ex
            # basic backoff
            if attempt < max_retries:
                time.sleep(min(2 ** attempt, 8))
            else:
                break
    raise NetworkError(str(last_exc) if last_exc else "HTTP error")

@dataclass
class OrgInfo:
    display_name: str
    domain_hint: str

def graph_get_org(token: str) -> OrgInfo:
    url = f"{GRAPH}/v1.0/organization?$select=id,displayName,verifiedDomains"
    r = _http_get(url, headers={"Authorization": f"Bearer {token}"})
    data = r.json()
    org = (data.get("value") or [{}])[0]
    name = org.get("displayName") or "Unknown Tenant"
    domains = org.get("verifiedDomains") or []
    domain_hint = domains[0]["name"] if domains else ""
    return OrgInfo(display_name=name, domain_hint=domain_hint)
