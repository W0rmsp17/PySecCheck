# src/tenantsec/ui/panels/settings_panel.py
import tkinter as tk
from tkinter import ttk
from tenantsec.app import event_bus
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.prefs import load_display_prefs, save_display_prefs
from tenantsec.core.ai_prefs import load_ai_settings, save_ai_settings
from tenantsec.ai import client as ai_client
from tenantsec.app import job_runner
from tkinter import ttk, filedialog, messagebox

from tenantsec.ai.client import AIConfigError

class SettingsPanel(ttk.Frame):
    def __init__(self, master, event_bus_mod, app_state: "AppState"):
        super().__init__(master)
        self.event_bus = event_bus_mod
        self.app_state = app_state
        self._build_ai_section() 

        # checkbox state
        self._vars_org: dict[str, tk.BooleanVar] = {}
        self._vars_user: dict[str, tk.BooleanVar] = {}

        self._build()

        # rebuild options when data lands
        event_bus.subscribe("auth.connect.succeeded", self._on_connect_ok)
        event_bus.subscribe("auth.connect.failed", self._on_connect_fail)
        event_bus.subscribe("data.core.ready", self._on_data_ready)
        event_bus.subscribe("org.info.ready", self._on_data_ready)
        event_bus.subscribe("users.list.updated", self._on_data_ready)

    # ---------- UI build ----------
    def _build(self):
        self.columnconfigure(1, weight=1)

        # Connect section
        ttk.Label(self, text="Tenant Settings", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )
        ttk.Label(self, text="Tenant ID").grid(row=1, column=0, sticky="e", padx=(0, 8))
        self.ent_tenant = ttk.Entry(self); self.ent_tenant.grid(row=1, column=1, sticky="ew")

        ttk.Label(self, text="Client ID").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=(6, 0))
        self.ent_client = ttk.Entry(self); self.ent_client.grid(row=2, column=1, sticky="ew", pady=(6, 0))

        ttk.Label(self, text="Client Secret").grid(row=3, column=0, sticky="e", padx=(0, 8), pady=(6, 0))
        self.ent_secret = ttk.Entry(self, show="*"); self.ent_secret.grid(row=3, column=1, sticky="ew", pady=(6, 0))

        self.btn_connect = ttk.Button(self, text="Connect", command=self._on_connect)
        self.btn_connect.grid(row=4, column=1, sticky="e", pady=(10, 0))

        creds = self.app_state.credentials
        self.ent_tenant.insert(0, creds.get("tenant_id", ""))
        self.ent_client.insert(0, creds.get("client_id", ""))

        self.status = ttk.Label(self, text="", foreground="#666")
        self.status.grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 8))

        ttk.Separator(self, orient="horizontal").grid(row=6, column=0, columnspan=2, sticky="ew", pady=(6, 8))

        # Display preferences section
        lbl = ttk.Label(self, text="Display Preferences", font=("Segoe UI", 10, "bold"))
        lbl.grid(row=7, column=0, columnspan=2, sticky="w")

        # Two columns for checklists
        prefs_wrap = ttk.Frame(self)
        prefs_wrap.grid(row=8, column=0, columnspan=2, sticky="nsew")
        prefs_wrap.columnconfigure(0, weight=1)
        prefs_wrap.columnconfigure(1, weight=1)

        self.org_frame = ttk.LabelFrame(prefs_wrap, text="Organization fields")
        self.org_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))

        self.user_frame = ttk.LabelFrame(prefs_wrap, text="User fields")
        self.user_frame.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))

        # Action buttons
        btns = ttk.Frame(self)
        btns.grid(row=9, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(btns, text="Refresh Display", command=self._refresh_display).pack(side="right", padx=(6, 0))
        ttk.Button(btns, text="Save Preferences", command=self._save).pack(side="right")

        # First render of checklists
        self._rebuild_checklists()

    # ---------- Connect handlers ----------
    def _on_connect(self):
        creds = {
            "tenant_id": self.ent_tenant.get().strip(),
            "client_id": self.ent_client.get().strip(),
            "client_secret": self.ent_secret.get().strip(),
            "auth_mode": "app-only",
        }
        self.status.config(text="Connecting...")
        self.btn_connect.state(["disabled"])
        event_bus.publish("auth.connect.requested", creds)

    def _on_connect_ok(self, payload):
        def ui():
            self.status.config(text=f"Connected: {payload['display_name']} ({payload['domain']})")
            self.btn_connect.state(["!disabled"])
        self.after(0, ui)

    def _on_connect_fail(self, payload):
        def ui():
            self.status.config(text=f"Failed: {payload['message']}  Hint: {payload.get('hint','')}")
            self.btn_connect.state(["!disabled"])
        self.after(0, ui)

    # ---------- Data readiness → rebuild dynamic options ----------
    def _on_data_ready(self, _payload):
        self.after(0, self._rebuild_checklists)

    def _rebuild_checklists(self):
        # clear existing
        for f in (self.org_frame, self.user_frame):
            for w in f.winfo_children():
                w.destroy()
        self._vars_org.clear(); self._vars_user.clear()

        prefs = load_display_prefs()
        tenant_id = self.app_state.credentials.get("tenant_id")
        gw = DataGateway(tenant_id) if tenant_id else None

        # Org options = keys from org_summary.organization
        org_keys: list[str] = []
        if gw:
            org = (gw.get_org_summary() or {}).get("organization") or {}
            org_keys = sorted(org.keys())
        if not org_keys:
            # fall back to saved preferences as placeholders if nothing cached yet
            org_keys = list(prefs.get("org_fields", []))

        for i, key in enumerate(org_keys):
            var = tk.BooleanVar(value=(key in prefs.get("org_fields", [])))
            ttk.Checkbutton(self.org_frame, text=key, variable=var).grid(row=i, column=0, sticky="w", padx=8, pady=2)
            self._vars_org[key] = var

        # User options = users_index.fields
        user_keys: list[str] = []
        if gw:
            user_keys = sorted(set(gw.list_user_fields()))
        if not user_keys:
            user_keys = list(prefs.get("user_fields", []))

        for i, key in enumerate(user_keys):
            var = tk.BooleanVar(value=(key in prefs.get("user_fields", [])))
            ttk.Checkbutton(self.user_frame, text=key, variable=var).grid(row=i, column=0, sticky="w", padx=8, pady=2)
            self._vars_user[key] = var

    # ---------- Save & Refresh ----------
    def _save(self):
        prefs = {
            "org_fields": [k for k, v in self._vars_org.items() if v.get()],
            "user_fields": [k for k, v in self._vars_user.items() if v.get()],
        }
        save_display_prefs(prefs)
        # notify display to repaint with new prefs
        event_bus.publish("display.prefs.changed", {"tenant_id": self.app_state.credentials.get("tenant_id")})
        self.status.config(text="Preferences saved.")

    def _refresh_display(self):
        # Simply re-emit the same event; DisplayPanel can repaint boxes on this signal
        event_bus.publish("display.prefs.changed", {"tenant_id": self.app_state.credentials.get("tenant_id")})
        self.status.config(text="Display refreshed.")

    def list_subscribed_skus(graph, tenant_id: str) -> list[dict]:
        res = graph.get_json("/v1.0/subscribedSkus")
        items = res.get("value", [])
        gw = DataGateway(tenant_id)
        gw.set_subscribed_skus(items)
        event_bus.publish("org.skus.ready", {"tenant_id": tenant_id, "count": len(items)})
        return items



    def _build_ai_section(self):
        box = ttk.LabelFrame(self, text="AI / ChatGPT")
        box.grid(row=99, column=0, sticky="ew", padx=8, pady=8)  # pick row appropriately in your layout
        for i in range(2): box.columnconfigure(i, weight=1)

        s = load_ai_settings()

        ttk.Label(box, text="Provider").grid(row=0, column=0, sticky="w", padx=8, pady=(8,2))
        self.ai_provider = ttk.Combobox(box, values=["openai"], state="readonly")
        self.ai_provider.set(s.get("provider","openai"))
        self.ai_provider.grid(row=0, column=1, sticky="ew", padx=8, pady=(8,2))

        ttk.Label(box, text="Model").grid(row=1, column=0, sticky="w", padx=8, pady=2)
        self.ai_model = ttk.Entry(box)
        self.ai_model.insert(0, s.get("model","gpt-5"))
        self.ai_model.grid(row=1, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(box, text="API Key").grid(row=2, column=0, sticky="w", padx=8, pady=2)
        self.ai_key = ttk.Entry(box, show="*")
        self.ai_key.insert(0, s.get("api_key",""))
        self.ai_key.grid(row=2, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(box, text="Base URL (optional)").grid(row=3, column=0, sticky="w", padx=8, pady=2)
        self.ai_base = ttk.Entry(box)
        self.ai_base.insert(0, s.get("base_url",""))
        self.ai_base.grid(row=3, column=1, sticky="ew", padx=8, pady=2)

        btns = ttk.Frame(box)
        btns.grid(row=4, column=0, columnspan=2, sticky="e", padx=8, pady=(8,8))
        ttk.Button(btns, text="Save", command=self._ai_save).pack(side="right")
        ttk.Button(btns, text="Test Connection", command=self._ai_test).pack(side="right", padx=(0,8))

    def _ai_save(self):
        settings = {
            "provider": self.ai_provider.get(),
            "model": self.ai_model.get().strip(),
            "api_key": self.ai_key.get().strip(),
            "base_url": self.ai_base.get().strip(),
        }
        save_ai_settings(settings)
        messagebox.showinfo("Saved", "AI settings saved.")

    def _ai_test(self):
        self.event_generate("<<AiTestStart>>", when="tail")
        fut = job_runner.submit_job(ai_client.test_connection)

        def done():
            try:
                reply = fut.result()  # could be "OK", "PONG", etc.
                # normalize reply
                text = (str(reply) if reply is not None else "").strip().upper()
                if text in {"OK", "PONG", "SUCCESS"}:
                    messagebox.showinfo("AI Connection", "Connection OK.")
                else:
                    # still show what we got, but as info (not warning)
                    messagebox.showinfo("AI Connection", f"{reply or 'Connection OK.'}")
            except AIConfigError as e:
                messagebox.showwarning("AI Connection", f"{e}\n\nSet your API key in Settings.")
            except Exception as e:
                messagebox.showerror("AI Connection", str(e))
