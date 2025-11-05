# src/tenantsec/ui/helpers/dialogs.py
import tkinter as tk
import tkinter.simpledialog as sd
from tkinter import messagebox
from typing import Optional, Dict

# === Simple prompts ===

def ask_password(who: str) -> Optional[str]:
    return sd.askstring("Change Password", f"Enter new password for:\n{who}", show="*")

def confirm(title: str, msg: str) -> bool:
    return messagebox.askyesno(title, msg)

def ask_tap_params(default_minutes: int = 60) -> Optional[Dict[str, object]]:
    lifetime = sd.askinteger(
        "Generate TAP",
        "Lifetime (minutes):",
        initialvalue=default_minutes,
        minvalue=10,
        maxvalue=43200
    )
    if not lifetime:
        return None
    one_time = messagebox.askyesno("TAP Usage", "Should this TAP be one-time use only?")
    return {"lifetime_in_minutes": int(lifetime), "is_usable_once": bool(one_time)}

def info(title: str, msg: str) -> None:
    messagebox.showinfo(title, msg)

def warn(title: str, msg: str) -> None:
    messagebox.showwarning(title, msg)

def error(title: str, msg: str) -> None:
    messagebox.showerror(title, msg)

# === Copyable result dialog (password / TAP) ===

def copyable(
    title: str,
    field_label: str,
    value: str,
    details: Optional[str] = None,
    parent: Optional[tk.Widget] = None,
) -> None:
    """
    Shows a centered, copy-friendly dialog:
      - Starts topmost (dropped after 250ms) so it doesn’t get lost behind the main window
      - Grabs focus (non-blocking) and selects all for quick Ctrl/Cmd+C
      - Enter copies, Esc closes
    """
    # Figure a good parent (prefer a real widget)
    toplevel_parent = parent.winfo_toplevel() if parent else None

    # Create hidden, then show after layout to prevent flicker
    win = tk.Toplevel(master=toplevel_parent or parent)
    win.withdraw()
    win.title(title)

    # Briefly force-on-top & focus so it shows reliably on Windows
    try:
        win.attributes("-topmost", True)
    except Exception:
        pass
    if toplevel_parent:
        try:
            win.transient(toplevel_parent)
        except Exception:
            pass
    try:
        win.grab_set()
    except Exception:
        pass

    outer = tk.Frame(win, padx=12, pady=12)
    outer.pack(fill="both", expand=True)

    if field_label:
        tk.Label(outer, text=field_label).pack(anchor="w", pady=(0, 4))

    var = tk.StringVar(value=value or "")
    entry = tk.Entry(outer, textvariable=var, width=64)
    entry.pack(fill="x")
    entry.focus_set()
    entry.select_range(0, tk.END)

    def do_copy():
        try:
            win.clipboard_clear()
            win.clipboard_append(var.get())
        except Exception:
            pass

    btns = tk.Frame(outer)
    btns.pack(fill="x", pady=(10, 0))
    tk.Button(btns, text="Copy", command=do_copy).pack(side="left")
    tk.Button(btns, text="Close", command=win.destroy).pack(side="right")

    if details:
        tk.Label(outer, text=details, justify="left").pack(anchor="w", pady=(10, 0))

    # Key bindings
    win.bind("<Return>", lambda _e: do_copy())
    win.bind("<Escape>", lambda _e: win.destroy())

    # Show & center
    win.deiconify()
    win.update_idletasks()
    try:
        p = toplevel_parent or win.master or win
        px, py = p.winfo_rootx(), p.winfo_rooty()
        pw, ph = p.winfo_width(), p.winfo_height()
        ww, wh = win.winfo_width(), win.winfo_height()
        x, y = px + (pw - ww) // 2, py + (ph - wh) // 2
        win.geometry(f"+{x}+{y}")
    except Exception:
        pass

    # Ensure it surfaces, then drop topmost so it behaves like a normal dialog
    try:
        win.lift()
        win.focus_force()
        win.after(250, lambda: win.attributes("-topmost", False))
    except Exception:
        pass
