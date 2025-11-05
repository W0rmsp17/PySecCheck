# src/tenantsec/main.py
import tkinter as tk
from tkinter import ttk

from tenantsec.app.state import AppState
from tenantsec.app import event_bus, job_runner
from tenantsec.ui.panels.display_panel import DisplayPanel
from tenantsec.ui.panels.settings_panel import SettingsPanel
from tenantsec.core import auth as core_auth
from tenantsec.app.orchestrator import Orchestrator
from tenantsec.ui.panels.review_panel import ReviewPanel

def _wire_handlers(root, app_state: AppState, orchestrator: Orchestrator):
    # Any callback published under "jobs.callback.request" runs on the UI thread.
    def _run_cb_on_ui(cb):
        root.after(0, cb)
    event_bus.subscribe("jobs.callback.request", _run_cb_on_ui)

    def on_connect_requested(creds):
        fut = job_runner.submit_job(core_auth.connect, creds)

        def done():
            try:
                summary = fut.result()
                app_state.credentials.update(creds)
                app_state.tenant_name = summary.display_name
                app_state.token = summary.token

                event_bus.publish("auth.connect.succeeded", {
                    "tenant_id": summary.tenant_id,
                    "display_name": summary.display_name,
                    "domain": summary.domain_hint,
                })

                # Kick orchestrator once (idempotent per tenant_id)
                root.after(0, lambda: orchestrator.start_after_connect(summary.tenant_id))

            except core_auth.AuthError as e:
                event_bus.publish("auth.connect.failed", {
                    "code": getattr(e, "code", "auth_error"),
                    "message": str(e),
                    "hint": getattr(e, "hint", ""),
                })
            except Exception as e:
                event_bus.publish("auth.connect.failed", {
                    "code": "unexpected",
                    "message": str(e),
                    "hint": "Unexpected error.",
                })

        fut.add_done_callback(lambda _f: root.after(0, done))

    event_bus.subscribe("auth.connect.requested", on_connect_requested)


def main():
    root = tk.Tk()
    root.title("PySecCheck")
    root.geometry("1000x720")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    app_state = AppState()
    orchestrator = Orchestrator(app_state)

    nb = ttk.Notebook(root)
    nb.grid(row=0, column=0, sticky="nsew")

    display_tab = DisplayPanel(nb, event_bus, app_state)
    settings_tab = SettingsPanel(nb, event_bus, app_state)
    review_tab = ReviewPanel(nb, event_bus, app_state) 
    nb.add(display_tab, text="Display")
    nb.add(settings_tab, text="Settings")
    nb.add(review_tab, text="Review")   

    _wire_handlers(root, app_state, orchestrator)

    def _on_close():
        try:
            # Fast shutdown; set wait=True if you want graceful drain.
            job_runner._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
