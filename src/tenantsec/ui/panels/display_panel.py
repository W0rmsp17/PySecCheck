# src/tenantsec/ui/panels/display_panel.py
import tkinter as tk
from tkinter import ttk
from tenantsec.core.data_gateway import DataGateway
from tenantsec.core.prefs import load_display_prefs
from tenantsec.ui.presenters.render import render_org, render_user, render_skus
from tenantsec.ui.helpers import dialogs as dlg
from tenantsec.app import job_runner
from tenantsec.core.graph_client import GraphClient
from tenantsec.core import user_actions


class DisplayPanel(ttk.Frame):
    def __init__(self, master, event_bus_mod, app_state):
        super().__init__(master)
        self.event_bus = event_bus_mod
        self.app_state = app_state
        self._tenant_id = None
        self._gw: DataGateway | None = None

        self._build_layout()
        self._subscribe_events()

    # ---------- layout ----------
    def _build_layout(self):
        self.columnconfigure(0, weight=2)
        self.columnconfigure(1, weight=0)
        self.columnconfigure(2, weight=2)  # give right pane a bit more room
        self.rowconfigure(0, weight=1)

        # LEFT: user tree
        left = ttk.Frame(self)
        left.grid(row=0, column=0, sticky="nsew", padx=(8, 6), pady=8)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            left, columns=("upn", "job_title"), show="headings", selectmode="browse"
        )
        self.tree.heading("upn", text="User Principal Name")
        self.tree.heading("job_title", text="Job Title")
        self.tree.column("upn", width=280, anchor="w")
        self.tree.column("job_title", width=180, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        yscroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=1, sticky="ns")

        # SEPARATOR
        ttk.Separator(self, orient="vertical").grid(row=0, column=1, sticky="ns", padx=4)

        # RIGHT: 4 stacked boxes
        right = ttk.Frame(self)
        right.grid(row=0, column=2, sticky="nsew", padx=(6, 8), pady=8)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)  # Org
        right.rowconfigure(1, weight=1)  # Licenses
        right.rowconfigure(2, weight=1)  # User
        right.rowconfigure(3, weight=0)  # Interactive (no stretch)

        # --- Organization Detail ---
        self.org_box = ttk.LabelFrame(right, text="Organizational View")
        self.org_box.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        self._org_lbl = ttk.Label(self.org_box, text="—", justify="left", anchor="w")
        self._org_lbl.configure(wraplength=600)
        self._org_lbl.pack(anchor="w", padx=8, pady=8)

        # --- License View (NEW) ---
        self.lic_box = ttk.LabelFrame(right, text="License View")
        self.lic_box.grid(row=1, column=0, sticky="nsew", pady=8)
        self._lic_lbl = ttk.Label(self.lic_box, text="(No licenses yet)", justify="left", anchor="w")
        self._lic_lbl.configure(wraplength=600)
        self._lic_lbl.pack(anchor="w", padx=8, pady=8)

        # --- User Detail ---
        self.user_box = ttk.LabelFrame(right, text="User Detail View")
        self.user_box.grid(row=2, column=0, sticky="nsew", pady=8)
        self._user_lbl = ttk.Label(self.user_box, text="Select a user…", justify="left", anchor="w")
        self._user_lbl.configure(wraplength=600)
        self._user_lbl.pack(anchor="w", padx=8, pady=8)

        # --- Interactive (shrunk) ---
        self.act_box = ttk.LabelFrame(right, text="Interactive View")
        self.act_box.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        btn_row = ttk.Frame(self.act_box)
        btn_row.pack(anchor="w", padx=8, pady=8)

        self.btn_pw = ttk.Button(btn_row, text="Change Password", command=self._on_change_password)
        self.btn_pw.grid(row=0, column=0, padx=(0, 6))

        self.btn_tap = ttk.Button(btn_row, text="Generate TAP", command=self._on_generate_tap)
        self.btn_tap.grid(row=0, column=1, padx=6)

        ttk.Button(btn_row, text="Revoke Sessions").grid(row=0, column=2, padx=6)
        ttk.Button(btn_row, text="Reinitiate MFA").grid(row=0, column=3, padx=6)

        # start disabled until a user is selected
        self.btn_pw.state(["disabled"])
        self.btn_tap.state(["disabled"])

        self.tree.bind("<<TreeviewSelect>>", self._on_user_selected)

    def _subscribe_events(self):
        self.event_bus.subscribe("users.list.ready", self._on_users_ready)
        self.event_bus.subscribe("users.list.updated", self._on_users_updated)
        self.event_bus.subscribe("org.info.ready", self._on_org_ready)
        self.event_bus.subscribe("org.skus.ready", self._on_skus_ready)   
        self.event_bus.subscribe("data.core.ready", self._on_core_ready)
        self.event_bus.subscribe("display.prefs.changed", self._on_prefs_changed)

    #event handlering
    def _on_skus_ready(self, payload):
        if payload.get("tenant_id") == self._tenant_id:
            self.after(0, self._paint_licenses)



    def _on_users_ready(self, users):
        self._tenant_id = self.app_state.credentials.get("tenant_id")
        if not self._tenant_id:
            return
        if not self._gw:
            self._gw = DataGateway(self._tenant_id)
        self.after(0, lambda: self._populate_tree(users))
        self.after(50, self._repaint_all)

    def _on_users_updated(self, evt):
        if not self._tenant_id or evt.get("tenant_id") != self._tenant_id:
            return
        users = self._gw.get_users_index() if self._gw else []
        self.after(0, lambda: self._populate_tree(users))
        self.after(0, self._paint_user_box)

    def _on_org_ready(self, payload):
        if payload.get("tenant_id") == self._tenant_id:
            self.after(0, self._paint_org)

    def _on_core_ready(self, payload):
        if payload.get("tenant_id") == self._tenant_id:
            self.after(0, self._repaint_all)

    def _on_prefs_changed(self, payload):
        if payload.get("tenant_id") and payload["tenant_id"] != self._tenant_id:
            return
        self.after(0, self._repaint_all)

    # UI helpers
    def _populate_tree(self, users):
        self.tree.delete(*self.tree.get_children())
        for u in users or []:
            self.tree.insert("", "end", iid=u.get("id"), values=(u.get("upn", ""), u.get("job_title", "")))

    def _on_user_selected(self, _evt):
        has_sel = bool(self.tree.selection())
        for b in (self.btn_pw, self.btn_tap):
            b.state(["!disabled"] if has_sel else ["disabled"])
        self._paint_user_box()

    def _require_user(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            dlg.warn("No User Selected", "Please select a user first.")
            return None
        uid = sel[0]
        user = self._gw.get_user_by_id(uid) if self._gw else None
        if not user:
            dlg.error("Missing Data", "Could not locate selected user.")
            return None
        return user

    # ---------- interactive actions ----------
    def _on_change_password(self):
        user = self._require_user()
        if not user:
            return
        upn = user.get("upn", "")
        new_pw = dlg.ask_password(upn)
        if not new_pw:
            return
        if not dlg.confirm("Confirm Password Reset", f"Reset password for {upn}?"):
            return

        graph = GraphClient(lambda: self.app_state.token)
        fut = job_runner.submit_job(
            user_actions.change_password, graph, self._tenant_id, user["id"], new_password=new_pw
        )

        def done():
            try:
                fut.result()
                dlg.copyable("Password Reset", f"New password for {upn}", new_pw, parent=self)
            except Exception as e:
                dlg.error("Error", f"Password reset failed:\n{e}")

        fut.add_done_callback(lambda _f: self.after(0, done))

    def _on_generate_tap(self):
        user = self._require_user()
        if not user:
            return
        upn = user.get("upn", "")
        params = dlg.ask_tap_params(default_minutes=60)
        if not params:
            return
        if not dlg.confirm("Confirm", f"Generate TAP for {upn}?"):
            return

        graph = GraphClient(lambda: self.app_state.token)
        fut = job_runner.submit_job(
            user_actions.generate_tap,
            graph,
            self._tenant_id,
            user["id"],
            lifetime_in_minutes=params["lifetime_in_minutes"],
            is_usable_once=params["is_usable_once"],
        )

        def done():
            try:
                res = fut.result()
                tap = res.get("tap")
                if tap:
                    details = (
                        f"Lifetime: {res.get('lifetimeInMinutes')} min\n"
                        f"Usable once: {res.get('isUsableOnce')}\n"
                        f"Created: {res.get('createdDateTime') or '—'}"
                    )
                    dlg.copyable("Temporary Access Pass", f"TAP for {upn}", tap, details=details, parent=self)
                else:
                    dlg.warn("No TAP Returned", "TAP was created but no code returned.")
            except Exception as e:
                dlg.error("Error", f"TAP generation failed:\n{e}")

        fut.add_done_callback(lambda _f: self.after(0, done))



    # ---------- rendering ----------
    def _repaint_all(self):
        self._paint_org()
        self._paint_licenses()
        self._paint_user_box()

    def _paint_user_box(self):
        if not self._gw:
            self._user_lbl.config(text="Select a user…")
            return
        sel = self.tree.selection()
        if not sel:
            self._user_lbl.config(text="Select a user…")
            return

        user = self._gw.get_user_by_id(sel[0]) or {}
        prefs = load_display_prefs()
        rendered = render_user(user, prefs)
        text = "\n".join(rendered) if isinstance(rendered, list) else rendered
        self._user_lbl.config(text=text or "(No fields selected)")

    def _paint_org(self):
        if not self._gw:
            return
        org = (self._gw.get_org_summary().get("organization") or {})
        prefs = load_display_prefs()
        org_lines = render_org(org, prefs)
        org_text = "\n".join(org_lines) if isinstance(org_lines, list) else (org_lines or "")
        self._org_lbl.config(text=org_text or "(No fields selected)")

    def _paint_licenses(self):
        if not self._gw:
            self._lic_lbl.config(text="(No licenses yet)")
            return
        try:
            skus = self._gw.get_subscribed_skus()
        except Exception:
            skus = []
        if skus:
            lines = render_skus(skus)
            self._lic_lbl.config(text="\n".join(lines))
        else:
            self._lic_lbl.config(text="(No licenses found)")

    def _ensure_user_table(self):
        if getattr(self, "user_tbl", None): return
        self.user_tbl = ttk.Treeview(self, columns=("user","mfa","issues"), show="headings", height=12)
        for c,h in (("user","User (hashed/UPN)"),("mfa","MFA"),("issues","Issues")):
            self.user_tbl.heading(c, text=h); self.user_tbl.column(c, width=220, anchor="w")
        self.user_tbl.grid(row=9, column=0, columnspan=4, sticky="nsew", pady=6)

    def _on_ai_exec_ready(self, payload):
        data = payload or {}
        exec_json = data.get("exec_json") or {}
        users = (data.get("users_table") or [])
        # org header
        ov = exec_json.get("org_overview") or {}
        self.status.config(text=f"{ov.get('tenant_name','?')} • users={ov.get('user_count',len(users))} • score={exec_json.get('overall_score','?')}")
        # table
        self._ensure_user_table()
        for i in self.user_tbl.get_children(): self.user_tbl.delete(i)
        for u in users:
            upn = u.get("upn") or u.get("user_hash") or "unknown"
            mfa = "Yes" if u.get("mfa_enabled") else "No"
            issues = ", ".join(u.get("issues") or [])
            self.user_tbl.insert("", "end", values=(upn, mfa, issues))