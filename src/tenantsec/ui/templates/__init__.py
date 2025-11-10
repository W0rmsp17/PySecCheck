# src/tenantsec/ui/templates/__init__.py
from __future__ import annotations
from typing import List
import importlib.resources as pkg
import os

# Directory layout:
# tenantsec/ui/templates/css/default.css
# tenantsec/ui/templates/css/slate.css
# tenantsec/ui/templates/css/midnight.css

def list_themes() -> List[str]:
    """Return available CSS theme names (without .css)."""
    try:
        css_pkg = __package__ + ".css"
        names = []
        for res in pkg.files(css_pkg).iterdir():
            if res.is_file() and res.name.endswith(".css"):
                names.append(os.path.splitext(res.name)[0])
        return sorted(names)
    except Exception:
        # Fallback if package metadata isn’t available (editable installs, etc.)
        return ["default"]

def get_css(theme: str = "default") -> str:
    """Load a CSS theme’s contents. Falls back to 'default' and a built-in minimal style."""
    css_pkg = __package__ + ".css"
    filename = f"{theme}.css"
    try:
        with pkg.as_file(pkg.files(css_pkg) / filename) as p:
            return p.read_text(encoding="utf-8")
    except Exception:
        # Try default
        if theme != "default":
            try:
                with pkg.as_file(pkg.files(css_pkg) / "default.css") as p:
                    return p.read_text(encoding="utf-8")
            except Exception:
                pass
        # Hard fallback (never break export)
        return """
:root { --ink:#222; --muted:#666; --brand:#003366; --hair:#e6e8eb; --bg:#fafafa; --card:#fff; }
body { font-family: "Segoe UI", Roboto, -apple-system, Arial, sans-serif; color: var(--ink); background: var(--bg);
       margin: 24px auto; max-width: 1024px; line-height: 1.38; }
.cover { background: var(--card); border:1px solid var(--hair); padding:24px; margin:24px 0; border-radius:8px; }
h1, h2, h3 { color: var(--brand); margin: .6em 0 .3em; }
h2 { border-bottom: 2px solid #00336622; padding-bottom: 6px; margin-top: 1.2em; }
table.grid { width:100%; border-collapse: collapse; margin: 8px 0 16px; background: var(--card); }
.grid th, .grid td { border:1px solid var(--hair); padding:8px 10px; text-align:left; vertical-align:top; }
.grid th { background:#f7f9fc; font-weight:700; }
.grid tbody tr:nth-child(even) td { background:#fbfcfe; }
.kpi { display:inline-block; background: #f2f4f7; padding: 10px 14px; border-radius: 8px; margin:6px 12px 0 0; font-weight:600; }
"""
