from __future__ import annotations
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List
from tenantsec.core.findings import Finding
from tenantsec.app import event_bus
from tenantsec.ui.presenters.review_render import format_finding_to_text
from tenantsec.review.user_scanner import load_user_sheets
from tenantsec.review.user_scanner.sheets import load_user_sheets
from tenantsec.ui.presenters.user_report_render import render_user_report

class UserPanel(ttk.Frame):
    def __init__(self, master, event_bus_mod, app_state):
        super().__init__(master)
        self.event_bus = event_bus_mod
        self.app_state = app_state
        self._build_layout()

        # Subscribe once
        event_bus.subscribe("user.review.ready", self._on_user_review_ready)
        event_bus.subscribe("user.review.failed", self._on_user_review_failed)

    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))

        self.btn_run = ttk.Button(bar, text="Run User Checks", command=self._on_run)
        self.btn_run.pack(side="left")
        ttk.Button(bar, text="Copy", command=self._on_copy).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Save…", command=self._on_save).pack(side="left", padx=(6, 0))

        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="right")

        wrap = ttk.Frame(self)
        wrap.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.text = tk.Text(wrap, wrap="word", state="disabled")
        self.text.grid(row=0, column=0, sticky="nsew")

        try:
            self.text.configure(font="TkFixedFont")
        except Exception:
            self.text.configure(font=("Consolas", 10))

        sev_styles = {
            "CRITICAL": "#b71c1c",
            "HIGH":     "#d32f2f",
            "MEDIUM":   "#f57c00",
            "LOW":      "#1976d2",
            "INFO":     "#2e7d32",
        }
        for sev, col in sev_styles.items():
            self.text.tag_configure(f"sev-{sev}", foreground=col, font=("TkFixedFont", 10, "bold"))
            self.text.tag_raise(f"sev-{sev}")

        yscroll = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=1, sticky="ns")

    def _on_run(self):
        tenant_id = self.app_state.credentials.get("tenant_id")
        if not tenant_id:
            messagebox.showwarning("Not connected", "Connect to a tenant first.")
            return
        self.status.config(text="Scanning users…")
        self.btn_run.state(["disabled"])
        event_bus.publish(
            "jobs.callback.request",
            lambda: getattr(self.app_state, "orchestrator").start_user_review(tenant_id)
        )
        if not hasattr(self.app_state, "orchestrator"):
            messagebox.showerror("Setup error", "Orchestrator not attached to AppState.")
            return



    # replace BOTH definitions with this single one
    def _on_user_review_ready(self, payload):
        tid = payload.get("tenant_id")
        sheets = load_user_sheets(tid)
        u = len(sheets.get("users", {}).get("items", []))
        s = len(sheets.get("signins", {}).get("items", []))
        c = ((sheets.get("org", {}).get("organization") or {}).get("country") or "")
        self.status.config(text=f"users:{u} signins:{s} org_country:{c}")
        findings: List[Finding] = payload.get("findings", [])
        self._set_text(self._render_report(findings, tid))
        self.btn_run.state(["!disabled"])


    # src/tenantsec/ui/panels/user_panel.py
    def _on_user_review_failed(self, payload):
        print("[user_panel] user.review.failed:", payload)   # <— console
        messagebox.showerror("User scan failed", payload.get("error", "Unknown error"))
        self.status.config(text="User scan failed")
        self.btn_run.state(["!disabled"])


    def _set_text(self, s: str):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        if not s:
            self.text.config(state="disabled"); return
        if not s.endswith("\n"): s += "\n"
        self.text.insert("end", s)

        idx = "1.0"
        pattern = r'^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]'
        while True:
            pos = self.text.search(pattern, idx, stopindex="end", regexp=True)
            if not pos: break
            line_start = self.text.index(f"{pos} linestart")
            line_end   = self.text.index(f"{pos} lineend")
            line_text  = self.text.get(line_start, line_end)
            rbr = line_text.find("]")
            if rbr > 1:
                sev = line_text[1:rbr].strip().upper()
                if sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                    self.text.tag_add(f"sev-{sev}", line_start, line_end)
            idx = self.text.index(f"{line_end}+1c")
        self.text.config(state="disabled")

    def _on_copy(self):
        txt = self.text.get("1.0", "end-1c")
        if not txt.strip():
            self.status.config(text="Nothing to copy"); return
        try:
            self.clipboard_clear(); self.clipboard_append(txt)
            self.status.config(text="User report copied")
        except Exception as e:
            messagebox.showerror("Copy failed", str(e))

    def _on_save(self):
        txt = self.text.get("1.0", "end-1c")
        if not txt.strip():
            messagebox.showinfo("Nothing to save", "Run a user scan first."); return
        path = filedialog.asksaveasfilename(
            title="Save User Review", defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not path: return
        try:
            with open(path, "w", encoding="utf-8") as f: f.write(txt)
            self.status.config(text=f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _render_report(self, findings, tenant_id): 
        return render_user_report(tenant_id, findings)

