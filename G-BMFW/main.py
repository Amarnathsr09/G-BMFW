import tkinter as tk
from tkinter import messagebox, ttk
import threading
from packet_filter import start_packet_filtering
from proxy_services import (
    start_forward_proxy, stop_forward_proxy,
    start_reverse_proxy, stop_reverse_proxy,
    start_ssl_proxy, stop_ssl_proxy
)
from logger import log_event
from PIL import Image, ImageTk

# Theme Colors (VS Code Dark+)
BG_COLOR = "#1e1e1e"
SIDEBAR_COLOR = "#252526"
TEXT_COLOR = "#d4d4d4"
BUTTON_COLOR = "#0e639c"

# Description and status update functions
active_proxies = []

def update_status():
    status_text = "Active Proxies:\n"
    if not active_proxies:
        status_text += "None"
    else:
        for proxy in active_proxies:
            status_text += f"- {proxy}\n"
    status_label.config(text=status_text)

def display_description(text):
    global desc_label
    for widget in top_frame.winfo_children():
        widget.destroy()
    desc_label = tk.Label(top_frame, text=text, font=("Arial", 11),
                          bg=BG_COLOR, fg=TEXT_COLOR, wraplength=350, justify="left")
    desc_label.pack(padx=10, pady=10)

def launch_packet_filter():
    log_event("Packet Filtering Enabled", module="Packet Filter")
    display_description("Packet Filtering started. This module filters packets based on predefined rules.")
    threading.Thread(target=start_packet_filtering, daemon=True).start()

def quit_application():
    if forward_proxy_enabled.get():
        stop_forward_proxy()
    if reverse_proxy_enabled.get():
        stop_reverse_proxy()
    if ssl_proxy_enabled.get():
        stop_ssl_proxy()
    app.destroy()

app = tk.Tk()
app.title("G-BMFW: Modular Firewall System")
app.geometry("800x500")
app.configure(bg=BG_COLOR)

sidebar = tk.Frame(app, width=180, bg=SIDEBAR_COLOR)
sidebar.pack(side="left", fill="y")

main_area = tk.Frame(app, bg=BG_COLOR)
main_area.pack(side="right", expand=True, fill="both")

top_frame = tk.Frame(main_area, bg=BG_COLOR, height=200)
top_frame.pack(fill="both", expand=True)

bottom_frame = tk.Frame(main_area, bg=BG_COLOR)
bottom_frame.pack(fill="both", expand=True)

def open_live_log_viewer():
    viewer = tk.Toplevel(app)
    viewer.title("Live Log Viewer")
    viewer.geometry("600x400")
    viewer.configure(bg=BG_COLOR)

    filter_frame = tk.Frame(viewer, bg=SIDEBAR_COLOR)
    filter_frame.pack(fill="x", padx=5, pady=5)

    tk.Label(filter_frame, text="Filter by module:", bg=SIDEBAR_COLOR, fg=TEXT_COLOR).pack(side="left")
    module_filter = tk.Entry(filter_frame, bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
    module_filter.pack(side="left", padx=5)

    tk.Label(filter_frame, text="Level:", bg=SIDEBAR_COLOR, fg=TEXT_COLOR).pack(side="left")
    level_filter = tk.Entry(filter_frame, bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
    level_filter.pack(side="left", padx=5)

    log_display = tk.Text(viewer, wrap="word", state="disabled", bg=BG_COLOR, fg=TEXT_COLOR)
    log_display.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_logs():
        try:
            with open("data/logs.txt", "r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            lines = []

        module = module_filter.get().strip().upper()
        level = level_filter.get().strip().upper()

        filtered = []
        for line in lines:
            if module and f"[{module}]" not in line:
                continue
            if level and f"[{level}]" not in line:
                continue
            filtered.append(line)

        log_display.config(state="normal")
        log_display.delete(1.0, tk.END)
        log_display.insert(tk.END, "".join(filtered))
        log_display.config(state="disabled")
        viewer.after(2000, refresh_logs)

    refresh_logs()

# Sidebar Content
tk.Label(sidebar, text="FUNCTIONS", font=("Arial", 14, "bold"), bg=SIDEBAR_COLOR, fg=TEXT_COLOR).pack(pady=(20, 10))

style = ttk.Style()
style.theme_use("default")
style.configure("TButton", foreground=TEXT_COLOR, background=BUTTON_COLOR)
style.map("TButton", background=[("active", "#1177bb")])
style.configure("TCheckbutton", foreground=TEXT_COLOR, background=SIDEBAR_COLOR)

ttk.Button(sidebar, text="PACKET FILTERING", command=launch_packet_filter, width=20).pack(pady=5)
ttk.Button(sidebar, text="LIVE LOG VIEWER", command=open_live_log_viewer, width=20).pack(pady=5)

# Forward Proxy toggle
forward_proxy_enabled = tk.BooleanVar()
def toggle_forward_proxy():
    if forward_proxy_enabled.get():
        log_event("Forward Proxy Enabled", module="Forward Proxy")
        threading.Thread(target=start_forward_proxy, daemon=True).start()
        if "Forward Proxy (8888)" not in active_proxies:
            active_proxies.append("Forward Proxy (8888)")
        update_status()
        display_description("Forward Proxy enabled. It routes client requests to remote servers.")
    else:
        log_event("Forward Proxy Disabled", module="Forward Proxy")
        stop_forward_proxy()
        if "Forward Proxy (8888)" in active_proxies:
            active_proxies.remove("Forward Proxy (8888)")
        update_status()
        display_description("Forward Proxy disabled.")

ttk.Checkbutton(sidebar, text="FORWARD PROXY", variable=forward_proxy_enabled,
                command=toggle_forward_proxy).pack(pady=5)

# Reverse Proxy toggle
reverse_proxy_enabled = tk.BooleanVar()
def toggle_reverse_proxy():
    if reverse_proxy_enabled.get():
        log_event("Reverse Proxy Enabled", module="Reverse Proxy")
        threading.Thread(target=start_reverse_proxy, daemon=True).start()
        if "Reverse Proxy (8080)" not in active_proxies:
            active_proxies.append("Reverse Proxy (8080)")
        update_status()
        display_description("Reverse Proxy enabled. It receives requests on behalf of servers.")
    else:
        log_event("Reverse Proxy Disabled", module="Reverse Proxy")
        stop_reverse_proxy()
        if "Reverse Proxy (8080)" in active_proxies:
            active_proxies.remove("Reverse Proxy (8080)")
        update_status()
        display_description("Reverse Proxy disabled.")

ttk.Checkbutton(sidebar, text="REVERSE PROXY", variable=reverse_proxy_enabled,
                command=toggle_reverse_proxy).pack(pady=5)

# SSL Proxy toggle
ssl_proxy_enabled = tk.BooleanVar()
def toggle_ssl_proxy():
    if ssl_proxy_enabled.get():
        log_event("SSL Proxy Enabled", module="SSL Proxy")
        threading.Thread(target=start_ssl_proxy, daemon=True).start()
        if "SSL Proxy (8443)" not in active_proxies:
            active_proxies.append("SSL Proxy (8443)")
        update_status()
        display_description("SSL Proxy enabled. Secures connections via SSL encryption.")
    else:
        log_event("SSL Proxy Disabled", module="SSL Proxy")
        stop_ssl_proxy()
        if "SSL Proxy (8443)" in active_proxies:
            active_proxies.remove("SSL Proxy (8443)")
        update_status()
        display_description("SSL Proxy disabled.")

ttk.Checkbutton(sidebar, text="SSL PROXY", variable=ssl_proxy_enabled,
                command=toggle_ssl_proxy).pack(pady=5)

ttk.Button(sidebar, text="VIEW LOGS", command=lambda: view_logs(), width=20).pack(pady=5)

# Quit button with image
try:
    quit_img = Image.open("quit_icon.jpg").resize((40, 40), Image.LANCZOS)
    quit_icon = ImageTk.PhotoImage(quit_img)
    quit_btn = tk.Button(sidebar, image=quit_icon, command=quit_application, bg=SIDEBAR_COLOR, borderwidth=0)
    quit_btn.pack(pady=(30, 5))
except:
    ttk.Button(sidebar, text="QUIT", command=quit_application, width=20).pack(pady=(30, 5))

# Top Frame - Description
desc_label = tk.Label(top_frame, text="Welcome to G-BMFW\nSelect a function from the left panel.",
                      font=("Arial", 12), bg=BG_COLOR, fg=TEXT_COLOR, wraplength=500, justify="left")
desc_label.pack(pady=20, padx=20, anchor="w")

# About Section
def show_about():
    display_description("G-BMFW is a GUI-based modular firewall system that offers packet filtering, forward/reverse/SSL proxy services, and logging capabilities for enhanced network security.")

ttk.Button(sidebar, text="ABOUT", command=show_about, width=20).pack(pady=(20, 5))

# Bottom Status Frame
status_label = tk.Label(bottom_frame, text="Active Proxies:\nNone", font=("Arial", 10),
                        bg=BG_COLOR, fg=TEXT_COLOR, anchor="nw", justify="left")
status_label.pack(padx=20, pady=10, anchor="nw")

def view_logs():
    try:
        with open("data/logs.txt", "r") as file:
            logs = file.read()
        messagebox.showinfo("Logs", logs)
    except FileNotFoundError:
        messagebox.showerror("Error", "Log file not found.")

app.mainloop()
