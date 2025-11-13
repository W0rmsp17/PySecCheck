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
from tenantsec.ui.templates import list_themes


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

# --- replace _render_exec_summary with:
def _render_exec_summary(self, data: dict) -> str:
    ov = data.get("org_overview") or data.get("tenant_meta") or {}
    lines = [
        "=== PySecCheck — AI Executive Summary ===",
        "",
        f"Tenant: {ov.get('tenant_id','unknown')}  •  Name: {ov.get('tenant_name','Tenant')}  •  Users: {ov.get('user_count','?')}",
        f"Overall Score: {data.get('overall_score',0)}/100",
        ""
    ]
    def sec(title, items, fmt):
        if items: lines.append(title); [lines.append("  • " + fmt(x)) for x in items]; lines.append("")
    sec("Headline Risks:", data.get("headline_risks", []),
        lambda r: f"[{r.get('priority','?')}] {r.get('id')}: {r.get('why')} (impact: {r.get('impact')})")
    sec("Quick Wins:", data.get("quick_wins", []),
        lambda q: f"{q.get('action')} — owner: {q.get('owner')}, ETA: {q.get('eta_days','?')}d")
    for rd in data.get("roadmap", []):
        lines.append(f"Roadmap — {rd.get('theme')}:")
        for it in rd.get("items", []): lines.append(f"  • {it.get('action')} (ETA: {it.get('eta_days','?')}d)")
        lines.append("")
    # User table (from AI-injected user_findings_table)
    users = data.get("user_findings_table") or []
    if users:
        lines += ["User Findings:", "  (hashed) | MFA | Issues"]
        for u in users:
            name = u.get("user_hash","user#unknown")
            mfa = "Yes" if u.get("mfa_enabled") else "No"
            issues = ", ".join(u.get("issues") or [])
            lines.append(f"  {name} | {mfa} | {issues}")
        lines.append("")
    return "\n".join(lines)

# --- in _do_export_docx / _do_export_html, change tenant_name line to:
#tenant_name = (exec_json.get("org_overview") or exec_json.get("tenant_meta") or {}).get("tenant_name") or "Tenant"

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
        self._theme = "default"
        try:
            self._theme = (getattr(app_state, "prefs", {}) or {}).get("report_theme", "default")
        except Exception:
            pass
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

        # Theme picker
        try:
            themes = list_themes()
        except Exception:
            themes = ["default"]
        ttk.Label(bar, text="Theme:").pack(side="left", padx=(12, 4))
        self.cmb_theme = ttk.Combobox(bar, state="readonly", values=themes, width=12)
        idx = themes.index(self._theme) if self._theme in themes else 0
        self.cmb_theme.current(idx)
        self.cmb_theme.pack(side="left")
        def on_theme_changed(_evt=None):
            self._theme = self.cmb_theme.get()
            try:
                if hasattr(self.app_state, "prefs"):
                    self.app_state.prefs["report_theme"] = self._theme
            except Exception:
                pass
            self.status.config(text=f"Theme: {self._theme}")
        self.cmb_theme.bind("<<ComboboxSelected>>", on_theme_changed)

        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="right")

        wrap = ttk.Frame(self)
        wrap.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        # IMPORTANT: leave it enabled; we will block edits via bindings
        self.text = tk.Text(wrap, wrap="word")
        self.text.grid(row=0, column=0, sticky="nsew")

        # Read-only bindings (keeps selection, scrolling, etc.)
        for seq in ("<Key>", "<BackSpace>", "<Delete>", "<Control-v>", "<Control-x>",
                    "<Control-BackSpace>", "<Control-Delete>"):
            self.text.bind(seq, lambda e: "break")

        # Monospace so tables/evidence align
        try:
            self.text.configure(font="TkFixedFont")
        except Exception:
            self.text.configure(font=("Consolas", 10))

        # Configure severity tags once (color + bold), then raise them
        sev_styles = {
            "CRITICAL": "#b71c1c",
            "HIGH":     "#d32f2f",
            "MEDIUM":   "#f57c00",
            "LOW":      "#1976d2",
            "INFO":     "#2e7d32",
        }
        for sev, color in sev_styles.items():
            self.text.tag_configure(f"sev-{sev}", foreground=color, font=("TkFixedFont", 10, "bold"))
        for sev in sev_styles:
            self.text.tag_raise(f"sev-{sev}")

        # Scrollbar
        yscroll = ttk.Scrollbar(wrap, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.grid(row=0, column=1, sticky="ns")

        # Quick visual test
        self.after(500, lambda: self._set_text("[HIGH] Test line\n   [MEDIUM] Indented ok\n[LOW] Last"))



    def _set_text(self, s: str):
        # No state flipping required; widget is read-only via bindings
        self.text.delete("1.0", "end")

        if not s:
            return

        # Ensure trailing newline so last line has a lineend
        if not s.endswith("\n"):
            s += "\n"
        self.text.insert("end", s)

        # Iterate by row indexes (rock-solid, no regex or end math)
        total_rows = int(float(self.text.index("end-1c").split(".")[0]))
        for row in range(1, total_rows + 1):
            line_start = f"{row}.0"
            line_end   = f"{row}.end"
            line_text  = self.text.get(line_start, line_end)

            # allow leading spaces before '['
            stripped = line_text.lstrip()
            if not stripped.startswith("["):
                continue
            rbr = stripped.find("]")
            if rbr <= 1:
                continue
            sev = stripped[1:rbr].strip().upper()
            if sev not in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                continue

            # Tag the whole visible line so it POPS on all themes
            self.text.tag_add(f"sev-{sev}", line_start, line_end)



    def _debug_tags(self):
        for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            print(sev, self.text.tag_ranges(f"sev-{sev}"))




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

       # blocks = [f.as_text_block() for f in findings]
        blocks = [format_finding_to_text(f) for f in findings] 

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
        ov = (exec_json.get("org_overview") or exec_json.get("tenant_meta") or {})
        tenant_name = ov.get("tenant_name") or "Tenant"
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

        theme = getattr(self, "_theme", "default")

        def on_done(_res):
            self.status.config(text=f"Saved: {path}")

        def on_error(e: Exception):
            messagebox.showerror("Export failed", str(e))
            self.status.config(text="Export failed")

        _run_in_bg(self, self._do_export_html, tenant_id, path, theme, on_done=on_done, on_error=on_error)

    def _do_export_html(self, tenant_id: str, path: str, theme: str):
        from tenantsec.report.generator import generate_reports, build_html_report
        exec_json, tech_md = generate_reports(tenant_id)
        ov = (exec_json.get("org_overview") or exec_json.get("tenant_meta") or {})
        tenant_name = ov.get("tenant_name") or "Tenant"
        html_doc = build_html_report(tenant_name, tenant_id, exec_json, tech_md, theme=theme)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)


