# src/tenantsec/app/main_app.py
import tkinter as tk
from tkinter import ttk

def main():
    root = tk.Tk()
    root.title("PySecCheck")
    root.geometry("900x600")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True)

    # Placeholder tabs for the FRAME aspect
    display = ttk.Frame(nb)
    settings = ttk.Frame(nb)
    nb.add(display, text="Display")
    nb.add(settings, text="Settings")

    root.mainloop()
