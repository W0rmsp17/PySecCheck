from __future__ import annotations
from dataclasses import dataclass

# Error classes (unchanged)
class AuthError(Exception):
    code = "auth_error"; hint = "Unknown error."
    def __init__(self, message: str = "", *, hint: str | None = None):
        super().__init__(message or self.__class__.__name__)
        if hint: self.hint = hint

class InvalidTenantId(AuthError):
    code = "invalid_tenant_id"; hint = "Tenant ID invalid or unreachable."
class InvalidClientId(AuthError):
    code = "invalid_client_id"; hint = "Client ID invalid."
class InvalidClientSecret(AuthError):
    code = "invalid_client_secret"; hint = "Client Secret rejected."
class NetworkError(AuthError):
    code = "network_error"; hint = "Network or timeout issue."
class ConsentRequired(AuthError):
    code = "consent_required"; hint = "Admin consent required for Graph permissions."

@dataclass
class TenantSummary:
    tenant_id: str
    display_name: str
    domain_hint: str
    token: str

def connect(creds: dict) -> TenantSummary:
    tenant_id = (creds.get("tenant_id") or "").strip()
    client_id = (creds.get("client_id") or "").strip()
    client_secret = (creds.get("client_secret") or "").strip()

    if not tenant_id: raise InvalidTenantId("Tenant ID required.")
    if not client_id: raise InvalidClientId("Client ID required.")
    if not client_secret: raise InvalidClientSecret("Client Secret required.")

    # helpers do the heavy lifting
    from tenantsec.core.auth_helpers import (
        build_authority, msal_acquire_token, graph_get_org
    )

    authority = build_authority(tenant_id)
    token = msal_acquire_token(client_id, client_secret, authority)
    try:
        org = graph_get_org(token)  
        display, domain = org.display_name, org.domain_hint
    except AuthError:
        display, domain = "Unknown Tenant", ""
    print(f"[AUTH] Tenant={tenant_id}, Client={client_id[:6]}..., attempting real MSAL connect")

    return TenantSummary(
        tenant_id=tenant_id,
        display_name=display,
        domain_hint=domain,
        token=token,
    )
