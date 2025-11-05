from __future__ import annotations
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Dict
from tenantsec.core.findings import Finding
from tenantsec.app import job_runner
from tenantsec.review.scanner import run_all_checks, org_rule_catalog, load_sheets_for_ai
from tenantsec.core.cache_manager import clear_all
from tenantsec.ui.presenters.review_render import format_finding_to_text
from tenantsec.ai.client import generate_exec_summary, generate_technical_report_md

# --- small utility to standardize async UI handoff ---
def _run_in_bg(self, fn, *args, on_done=None, on_error=None, finally_fn=None):
    fut = job_runner.submit_job(fn, *args)

    def _done():
        try:
            result = fut.result()
            if on_done:
                on_done(result)
        except Exception as e:
            if on_error:
                on_error(e)
            else:
                # Default error handler
                messagebox.showerror("Operation failed", str(e))
        finally:
            if finally_fn:
                finally_fn()

    self.after(0, lambda: fut.add_done_callback(lambda _f: self.after(0, _done)))

# --------------------- AI EXEC SUMMARY ---------------------

def _on_ai_exec(self):
    tenant_id = self.app_state.credentials.get("tenant_id")
    if not tenant_id:
        messagebox.showwarning("Not connected", "Connect to a tenant first.")
        return

    self.status.config(text="Generating executive summary…")
    self.btn_run.state(["disabled"])

    def on_done(out: dict):
        try:
            txt = self._render_exec_summary(out)
            self._set_text(txt)
            self.status.config(text="Executive summary ready")
        except NotImplementedError:
            messagebox.showinfo("AI not wired", "Wire tenantsec.ai.client.call_llm() to your LLM provider.")
            self.status.config(text="AI not configured")

    def on_error(e: Exception):
        if isinstance(e, NotImplementedError):
            messagebox.showinfo("AI not wired", "Wire tenantsec.ai.client.call_llm() to your LLM provider.")
            self.status.config(text="AI not configured")
        else:
            messagebox.showerror("AI summary failed", str(e))
            self.status.config(text="AI summary failed")

    _run_in_bg(self, self._do_ai_exec, tenant_id,
               on_done=on_done,
               on_error=on_error,
               finally_fn=lambda: self.btn_run.state(["!disabled"]))

def _do_ai_exec(self, tenant_id: str):
    sheets = load_sheets_for_ai(tenant_id)
    findings = run_all_checks(tenant_id)
    return generate_exec_summary(tenant_id, sheets, findings)

def _render_exec_summary(self, data: dict) -> str:
    lines = []
    lines.append("=== PySecCheck — AI Executive Summary ===")
    lines.append("")
    score = data.get("overall_score", 0)
    lines.append(f"Overall Score: {score}/100")
    lines.append("")

    def sec(title, items, fmt):
        if not items:
            return
        lines.append(title)
        for it in items:
            lines.append("  • " + fmt(it))
        lines.append("")

    sec("Headline Risks:",
        data.get("headline_risks", []),
        lambda r: f"[{r.get('priority','?')}] {r.get('id')}: {r.get('why')} (impact: {r.get('impact')})")

    sec("Quick Wins:",
        data.get("quick_wins", []),
        lambda q: f"{q.get('action')} — owner: {q.get('owner')}, ETA: {q.get('eta_days','?')}d")

    for road in data.get("roadmap", []):
        lines.append(f"Roadmap — {road.get('theme')}:")
        for it in road.get("items", []):
            lines.append(f"  • {it.get('action')} (ETA: {it.get('eta_days','?')}d)")
        lines.append("")
    return "\n".join(lines)

# --------------------- AI TECH REPORT ---------------------

def _on_ai_tech(self):
    tenant_id = self.app_state.credentials.get("tenant_id")
    if not tenant_id:
        messagebox.showwarning("Not connected", "Connect to a tenant first.")
        return

    self.status.config(text="Generating technical report…")
    self.btn_run.state(["disabled"])

    def on_done(md: str):
        self._set_text(md)
        self.status.config(text="Technical report ready")

    def on_error(e: Exception):
        if isinstance(e, NotImplementedError):
            messagebox.showinfo("AI not wired", "Wire tenantsec.ai.client.call_llm() to your LLM provider.")
            self.status.config(text="AI not configured")
        else:
            messagebox.showerror("AI report failed", str(e))
            self.status.config(text="AI report failed")

    _run_in_bg(self, self._do_ai_tech, tenant_id,
               on_done=on_done,
               on_error=on_error,
               finally_fn=lambda: self.btn_run.state(["!disabled"]))

def _do_ai_tech(self, tenant_id: str):
    sheets = load_sheets_for_ai(tenant_id)
    findings = run_all_checks(tenant_id)
    return generate_technical_report_md(tenant_id, sheets, findings)

# --------------------- REVIEW PANEL CLASS ---------------------

class ReviewPanel(ttk.Frame):
    def __init__(self, master, event_bus_mod, app_state):
        super().__init__(master)
        self.event_bus = event_bus_mod
        self.app_state = app_state
        self._build_layout()

    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        bar = ttk.Frame(self)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        self.btn_run = ttk.Button(bar, text="Run All Checks", command=self._on_run)
        self.btn_run.pack(side="left")

        ttk.Button(bar, text="Copy", command=self._on_copy).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Save…", command=self._on_save).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Clear Cache…", command=self._on_clear_cache).pack(side="left", padx=(12, 0))
        ttk.Button(bar, text="Export DOCX…", command=self._on_export_docx).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Export HTML…", command=self._on_export_html).pack(side="left", padx=(6, 0))

        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="right")

        wrap = ttk.Frame(self)
        wrap.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.text = tk.Text(wrap, wrap="word", state="disabled")
        self.text.grid(row=0, column=0, sticky="nsew")

        # Severity tag colors (safe to configure without try/except)
        self.text.tag_configure("sev-CRITICAL", foreground="#b71c1c")
        self.text.tag_configure("sev-HIGH",     foreground="#d32f2f")
        self.text.tag_configure("sev-MEDIUM",   foreground="#f57c00")
        self.text.tag_configure("sev-LOW",      foreground="#1976d2")
        self.text.tag_configure("sev-INFO",     foreground="#2e7d32")

        yscroll = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=1, sticky="ns")

    def _set_text(self, s: str):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")

        for line in s.splitlines():
            # capture start index *before* inserting
            start = self.text.index("end")
            self.text.insert("end", line + "\n")
            end = self.text.index("end-1c")

            tag = None
            if line.startswith("["):
                i = line.find("]")
                if i > 0:
                    sev = line[1:i].strip().upper()
                    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                        tag = f"sev-{sev}"
            if tag:
                self.text.tag_add(tag, start, end)

        self.text.config(state="disabled")

    def _on_run(self):
        tenant_id = self.app_state.credentials.get("tenant_id")
        if not tenant_id:
            messagebox.showwarning("Not connected", "Connect to a tenant first.")
            return

        self.status.config(text="Scanning…")
        self.btn_run.state(["disabled"])

        def on_done(findings: List[Finding]):
            report = self._render_report(findings, tenant_id)
            self._set_text(report)
            self.status.config(text=f"Scan completed — {len(findings)} findings")

        def on_error(e: Exception):
            messagebox.showerror("Scan failed", str(e))
            self.status.config(text="Scan failed")

        _run_in_bg(self, run_all_checks, tenant_id,
                   on_done=on_done,
                   on_error=on_error,
                   finally_fn=lambda: self.btn_run.state(["!disabled"]))

    # --- SINGLE source of truth for report rendering ---
    def _render_report(self, findings: List[Finding], tenant_id: str) -> str:
        header = [
            "=== PySecCheck — Organizational Security Review ===",
            f"Tenant: {tenant_id}",
            "",
        ]
        total_rules = len(org_rule_catalog())

        if not findings:
            footer = self._summary_footer(total_rules=total_rules, failed=0, sev_counts={})
            return "\n".join(header + ["No findings. ✅", "", footer])

        blocks = [f.as_text_block() for f in findings]

        failed = len(findings)
        sev_counts: Dict[str, int] = {}
        for f in findings:
            if getattr(f, "severity", None):
                sev_counts[f.severity.lower()] = sev_counts.get(f.severity.lower(), 0) + 1

        footer = self._summary_footer(total_rules=total_rules, failed=failed, sev_counts=sev_counts)
        return "\n".join(header + blocks + ["", footer])

    def _summary_footer(self, *, total_rules: int, failed: int, sev_counts: Dict[str, int]) -> str:
        passed = max(0, total_rules - failed)
        lines = [
            "---",
            f"Summary: Failed {failed} / Total {total_rules}  (Passed {passed})",
            "Findings by severity:",
            f"[CRITICAL] {sev_counts.get('critical', 0)}",
            f"[HIGH] {sev_counts.get('high', 0)}",
            f"[MEDIUM] {sev_counts.get('medium', 0)}",
            f"[LOW] {sev_counts.get('low', 0)}",
            f"[INFO] {sev_counts.get('info', 0)}",
        ]
        return "\n".join(lines)

    def _on_copy(self):
        txt = self.text.get("1.0", "end-1c")
        if not txt:
            self.status.config(text="Nothing to copy")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(txt)
            self.status.config(text="Report copied to clipboard")
        except Exception as e:
            messagebox.showerror("Copy failed", str(e))

    def _on_save(self):
        txt = self.text.get("1.0", "end-1c")
        if not txt.strip():
            messagebox.showinfo("Nothing to save", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Review Report",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            self.status.config(text=f"Saved: {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _on_clear_cache(self):
        tid = self.app_state.credentials.get("tenant_id")
        if not tid:
            messagebox.showwarning("Not connected", "Connect to a tenant first.")
            return
        if not messagebox.askyesno("Confirm", f"Clear all cached data for tenant:\n{tid}?"):
            return
        try:
            clear_all(tid)
            self._set_text("")  # clear current report view
            self.status.config(text="Cache cleared.")
        except Exception as e:
            messagebox.showerror("Clear Cache failed", str(e))

    # --- Export DOCX / HTML ---

    def _on_export_docx(self):
        tenant_id = self.app_state.credentials.get("tenant_id")
        if not tenant_id:
            messagebox.showwarning("Not connected", "Connect to a tenant first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save DOCX Report",
            defaultextension=".docx",
            filetypes=[("Word Document", "*.docx")]
        )
        if not path:
            return
        self.status.config(text="Building DOCX report…")

        def on_done(_res):
            self.status.config(text=f"Saved: {path}")

        def on_error(e: Exception):
            messagebox.showerror("Export failed", str(e))
            self.status.config(text="Export failed")

        _run_in_bg(self, self._do_export_docx, tenant_id, path, on_done=on_done, on_error=on_error)

    def _do_export_docx(self, tenant_id: str, path: str):
        from tenantsec.report.generator import generate_reports, build_docx_report
        exec_json, tech_md = generate_reports(tenant_id)
        tenant_name = exec_json.get("tenant_meta", {}).get("tenant_name") or "Tenant"
        build_docx_report(path, tenant_name, tenant_id, exec_json, tech_md)

    def _on_export_html(self):
        tenant_id = self.app_state.credentials.get("tenant_id")
        if not tenant_id:
            messagebox.showwarning("Not connected", "Connect to a tenant first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save HTML Report",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")]
        )
        if not path:
            return
        self.status.config(text="Building HTML report…")

        def on_done(_res):
            self.status.config(text=f"Saved: {path}")

        def on_error(e: Exception):
            messagebox.showerror("Export failed", str(e))
            self.status.config(text="Export failed")

        _run_in_bg(self, self._do_export_html, tenant_id, path, on_done=on_done, on_error=on_error)

    def _do_export_html(self, tenant_id: str, path: str):
        from tenantsec.report.generator import generate_reports, build_html_report
        exec_json, tech_md = generate_reports(tenant_id)
        tenant_name = exec_json.get("tenant_meta", {}).get("tenant_name") or "Tenant"
        html_doc = build_html_report(tenant_name, tenant_id, exec_json, tech_md)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
