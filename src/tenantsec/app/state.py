class AppState:
    def __init__(self):
        self.credentials = {
            "tenant_id": "", "client_id": "", "client_secret": "", "auth_mode": "app-only",
        }
        self.tenant_name = ""
        self.token = None  # NEW: store MSAL access token for Graph
