import os
import sys
import time
import socket
import threading
import queue
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# Ensure project root is in path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from config.settings import APP_NAME, VERSION
from modules.reconnaissance.network import discover_hosts, get_network_hosts
from modules.reconnaissance.ports import assess_ports
from modules.reconnaissance.osint import collect_osint
from utils.formatter import (
    format_osint_report,
    get_hostname,
    get_mac_address,
)
from utils.report_export import save_pdf, save_txt
from utils.validators import is_domain_target, parse_network_target, parse_single_ip


# -------------------------------------------------------------
# Well-known Port Definitions
# -------------------------------------------------------------
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Mail)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Server)",
    110: "POP3 (Post Office Protocol)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    443: "HTTPS (Encrypted Web)",
    445: "SMB (Direct Host)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL (Microsoft SQL)",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Desktop",
    6379: "Redis Key-Value Store",
    8080: "HTTP-Alt / Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt / Web",
    9000: "SonarQube / Web",
    27017: "MongoDB Database",
}


# -------------------------------------------------------------
# Color Palette & Theme Configuration
# -------------------------------------------------------------
THEME = {
    "bg_dark": "#0B0F19",        # Deep navy/obsidian
    "bg_card": "#111827",        # Dark slate card
    "bg_input": "#1F2937",       # Input background
    "bg_hover": "#374151",       # Hover state
    "accent_cyan": "#00F2FE",    # Glowing cyan
    "accent_blue": "#3B82F6",    # Electric blue
    "accent_green": "#10B981",   # Emerald green
    "accent_red": "#EF4444",     # Alert red
    "accent_purple": "#8B5CF6",  # Modern purple
    "text_bright": "#F9FAFB",    # High-contrast white
    "text_dim": "#9CA3AF",       # Muted gray
    "text_highlight": "#38BDF8", # Sky blue
    "border": "#1E293B",         # Card border
    "table_alt": "#162032"       # Alternating row
}


class ModernReconGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} Reconnaissance Suite v{VERSION} - Custom GUI")
        self.geometry("1100x750")
        self.minsize(950, 650)
        self.configure(bg=THEME["bg_dark"])

        self.active_scan_thread = None
        self.stop_requested = False
        self.log_queue = queue.Queue()
        self.current_osint_report = None

        self._apply_styles()
        self._build_ui()
        self._start_log_consumer()

    def _apply_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Global base styling
        self.style.configure(".",
                             background=THEME["bg_dark"],
                             foreground=THEME["text_bright"],
                             font=("Segoe UI", 10))

        # Notebook (Tabs) styling
        self.style.configure("TNotebook",
                             background=THEME["bg_dark"],
                             borderwidth=0)
        self.style.configure("TNotebook.Tab",
                             background=THEME["bg_card"],
                             foreground=THEME["text_dim"],
                             padding=[18, 10],
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0)
        self.style.map("TNotebook.Tab",
                       background=[("selected", THEME["bg_input"]), ("active", THEME["bg_hover"])],
                       foreground=[("selected", THEME["accent_cyan"]), ("active", THEME["text_bright"])])

        # Treeview (Modern Dark Tables)
        self.style.configure("Treeview",
                             background=THEME["bg_card"],
                             foreground=THEME["text_bright"],
                             fieldbackground=THEME["bg_card"],
                             rowheight=28,
                             borderwidth=0,
                             font=("Segoe UI", 9))
        self.style.map("Treeview",
                       background=[("selected", THEME["accent_blue"])],
                       foreground=[("selected", THEME["text_bright"])])

        self.style.configure("Treeview.Heading",
                             background=THEME["bg_input"],
                             foreground=THEME["text_highlight"],
                             font=("Segoe UI", 10, "bold"),
                             borderwidth=0,
                             relief="flat")
        self.style.map("Treeview.Heading",
                       background=[("active", THEME["bg_hover"])])

        # Modern Progressbar
        self.style.configure("Horizontal.TProgressbar",
                             troughcolor=THEME["bg_input"],
                             background=THEME["accent_cyan"],
                             thickness=6,
                             borderwidth=0)

    def _build_ui(self):
        # 1. Header Banner
        header = tk.Frame(self, bg=THEME["bg_card"], height=65)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        header_content = tk.Frame(header, bg=THEME["bg_card"])
        header_content.pack(fill="both", expand=True, padx=20, pady=10)

        title_lbl = tk.Label(header_content,
                             text=f"⚡ {APP_NAME.upper()}",
                             font=("Segoe UI", 16, "bold"),
                             fg=THEME["accent_cyan"],
                             bg=THEME["bg_card"])
        title_lbl.pack(side="left")

        sub_lbl = tk.Label(header_content,
                           text="Advanced Reconnaissance & Security Assessment Framework",
                           font=("Segoe UI", 10),
                           fg=THEME["text_dim"],
                           bg=THEME["bg_card"])
        sub_lbl.pack(side="left", padx=(12, 0), pady=(4, 0))

        status_box = tk.Frame(header_content, bg=THEME["bg_card"])
        status_box.pack(side="right")

        self.engine_status = tk.Label(status_box,
                                      text="● IDLE",
                                      font=("Segoe UI", 9, "bold"),
                                      fg=THEME["accent_green"],
                                      bg=THEME["bg_card"])
        self.engine_status.pack(side="right", padx=(5, 0))

        # 2. Main Tabbed Navigation
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=15, pady=10)

        # Tab Frames
        self.tab_network = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.tab_ports = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.tab_osint = tk.Frame(self.notebook, bg=THEME["bg_dark"])
        self.tab_reports = tk.Frame(self.notebook, bg=THEME["bg_dark"])

        self.notebook.add(self.tab_network, text="  🌐 Network Discovery  ")
        self.notebook.add(self.tab_ports, text="  🔌 Port Scanner  ")
        self.notebook.add(self.tab_osint, text="  🔍 OSINT Recon  ")
        self.notebook.add(self.tab_reports, text="  📄 Logs & Exports  ")

        self._build_network_tab()
        self._build_ports_tab()
        self._build_osint_tab()
        self._build_reports_tab()

        # 3. Status Bar
        status_bar = tk.Frame(self, bg=THEME["bg_card"], height=28)
        status_bar.pack(fill="x", side="bottom")

        self.status_lbl = tk.Label(status_bar,
                                   text="Ready for authorized scanning operations.",
                                   font=("Segoe UI", 9),
                                   fg=THEME["text_dim"],
                                   bg=THEME["bg_card"])
        self.status_lbl.pack(side="left", padx=15)

        self.progress_bar = ttk.Progressbar(status_bar,
                                           style="Horizontal.TProgressbar",
                                           mode="determinate",
                                           length=200)
        self.progress_bar.pack(side="right", padx=15, pady=4)

    # -------------------------------------------------------------
    # TAB 1: Network Discovery
    # -------------------------------------------------------------
    def _build_network_tab(self):
        top_panel = tk.Frame(self.tab_network, bg=THEME["bg_card"], padx=15, pady=15)
        top_panel.pack(fill="x", padx=5, pady=5)

        lbl = tk.Label(top_panel, text="Target IP or CIDR Subnet:",
                       font=("Segoe UI", 10, "bold"), fg=THEME["text_bright"], bg=THEME["bg_card"])
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.net_target_entry = tk.Entry(top_panel, width=35, font=("Consolas", 11),
                                         bg=THEME["bg_input"], fg=THEME["accent_cyan"],
                                         insertbackground="white", relief="flat")
        self.net_target_entry.insert(0, "192.168.1.1")
        self.net_target_entry.grid(row=0, column=1, sticky="w", padx=(0, 15))

        btn_scan = tk.Button(top_panel, text="▶ Start Discovery",
                             command=self._start_network_scan,
                             bg=THEME["accent_blue"], fg="white",
                             font=("Segoe UI", 9, "bold"), padx=15, pady=4, relief="flat", cursor="hand2")
        btn_scan.grid(row=0, column=2, padx=5)

        btn_stop = tk.Button(top_panel, text="⏹ Stop",
                             command=self._stop_scan,
                             bg=THEME["bg_input"], fg=THEME["accent_red"],
                             font=("Segoe UI", 9, "bold"), padx=12, pady=4, relief="flat", cursor="hand2")
        btn_stop.grid(row=0, column=3, padx=5)

        help_lbl = tk.Label(top_panel, text="Example: 192.168.1.10 (Single Host) or 192.168.1.0/24 (CIDR Range)",
                            font=("Segoe UI", 8), fg=THEME["text_dim"], bg=THEME["bg_card"])
        help_lbl.grid(row=1, column=1, sticky="w", pady=(5, 0))

        # Results Table
        table_container = tk.Frame(self.tab_network, bg=THEME["bg_dark"])
        table_container.pack(fill="both", expand=True, padx=5, pady=10)

        cols = ("ip", "status", "hostname", "latency")
        self.net_tree = ttk.Treeview(table_container, columns=cols, show="headings", selectmode="browse")
        self.net_tree.heading("ip", text="IP Address")
        self.net_tree.heading("status", text="Status")
        self.net_tree.heading("hostname", text="Hostname / Resolved Name")
        self.net_tree.heading("latency", text="Response")

        self.net_tree.column("ip", width=180, anchor="center")
        self.net_tree.column("status", width=120, anchor="center")
        self.net_tree.column("hostname", width=380, anchor="w")
        self.net_tree.column("latency", width=120, anchor="center")

        scroll = ttk.Scrollbar(table_container, orient="vertical", command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=scroll.set)
        self.net_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Double click to scan ports
        self.net_tree.bind("<Double-1>", self._on_net_row_double_click)

    def _on_net_row_double_click(self, event):
        item = self.net_tree.selection()
        if item:
            ip = self.net_tree.item(item[0], "values")[0]
            self.port_target_entry.delete(0, tk.END)
            self.port_target_entry.insert(0, ip)
            self.notebook.select(self.tab_ports)
            self.log(f"Transferred target {ip} to Port Scanner tab.")

    # -------------------------------------------------------------
    # TAB 2: Port Assessment
    # -------------------------------------------------------------
    def _build_ports_tab(self):
        top_panel = tk.Frame(self.tab_ports, bg=THEME["bg_card"], padx=15, pady=15)
        top_panel.pack(fill="x", padx=5, pady=5)

        lbl = tk.Label(top_panel, text="Target Host / IP:",
                       font=("Segoe UI", 10, "bold"), fg=THEME["text_bright"], bg=THEME["bg_card"])
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.port_target_entry = tk.Entry(top_panel, width=28, font=("Consolas", 11),
                                          bg=THEME["bg_input"], fg=THEME["accent_cyan"],
                                          insertbackground="white", relief="flat")
        self.port_target_entry.insert(0, "127.0.0.1")
        self.port_target_entry.grid(row=0, column=1, sticky="w", padx=(0, 15))

        lbl_ports = tk.Label(top_panel, text="Ports (comma separated or ranges):",
                             font=("Segoe UI", 10, "bold"), fg=THEME["text_bright"], bg=THEME["bg_card"])
        lbl_ports.grid(row=0, column=2, sticky="w", padx=(0, 10))

        self.port_list_entry = tk.Entry(top_panel, width=32, font=("Consolas", 11),
                                        bg=THEME["bg_input"], fg=THEME["accent_cyan"],
                                        insertbackground="white", relief="flat")
        self.port_list_entry.insert(0, "21,22,25,53,80,110,135,139,443,445,3306,3389,8080")
        self.port_list_entry.grid(row=0, column=3, sticky="w", padx=(0, 15))

        btn_scan = tk.Button(top_panel, text="▶ Scan Ports",
                             command=self._start_port_scan,
                             bg=THEME["accent_blue"], fg="white",
                             font=("Segoe UI", 9, "bold"), padx=15, pady=4, relief="flat", cursor="hand2")
        btn_scan.grid(row=0, column=4, padx=5)

        # Quick Port Presets
        presets_bar = tk.Frame(self.tab_ports, bg=THEME["bg_dark"], padx=5, pady=6)
        presets_bar.pack(fill="x")

        tk.Label(presets_bar, text="Quick Presets:", font=("Segoe UI", 9, "bold"),
                 fg=THEME["text_dim"], bg=THEME["bg_dark"]).pack(side="left", padx=(5, 10))

        presets = [
            ("Top 20 Common", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,8080,8443"),
            ("Web Services", "80,443,8000,8080,8443,8888,9000"),
            ("Database Ports", "1433,1521,3306,5432,6379,27017"),
            ("Remote Access", "22,23,3389,5900,5901"),
        ]

        for name, port_str in presets:
            btn = tk.Button(presets_bar, text=name,
                            command=lambda p=port_str: self._set_ports(p),
                            bg=THEME["bg_card"], fg=THEME["accent_cyan"],
                            font=("Segoe UI", 8), relief="flat", padx=8, pady=2, cursor="hand2")
            btn.pack(side="left", padx=4)

        # Results Table
        table_container = tk.Frame(self.tab_ports, bg=THEME["bg_dark"])
        table_container.pack(fill="both", expand=True, padx=5, pady=5)

        cols = ("port", "state", "service", "protocol")
        self.port_tree = ttk.Treeview(table_container, columns=cols, show="headings", selectmode="browse")
        self.port_tree.heading("port", text="Port")
        self.port_tree.heading("state", text="State")
        self.port_tree.heading("service", text="Identified Service")
        self.port_tree.heading("protocol", text="Protocol")

        self.port_tree.column("port", width=120, anchor="center")
        self.port_tree.column("state", width=140, anchor="center")
        self.port_tree.column("service", width=360, anchor="w")
        self.port_tree.column("protocol", width=140, anchor="center")

        scroll = ttk.Scrollbar(table_container, orient="vertical", command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=scroll.set)
        self.port_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _set_ports(self, port_str):
        self.port_list_entry.delete(0, tk.END)
        self.port_list_entry.insert(0, port_str)

    # -------------------------------------------------------------
    # TAB 3: OSINT Domain Reconnaissance
    # -------------------------------------------------------------
    def _build_osint_tab(self):
        top_panel = tk.Frame(self.tab_osint, bg=THEME["bg_card"], padx=15, pady=15)
        top_panel.pack(fill="x", padx=5, pady=5)

        lbl = tk.Label(top_panel, text="Target Domain Name:",
                       font=("Segoe UI", 10, "bold"), fg=THEME["text_bright"], bg=THEME["bg_card"])
        lbl.grid(row=0, column=0, sticky="w", padx=(0, 10))

        self.osint_target_entry = tk.Entry(top_panel, width=35, font=("Consolas", 11),
                                          bg=THEME["bg_input"], fg=THEME["accent_cyan"],
                                          insertbackground="white", relief="flat")
        self.osint_target_entry.insert(0, "example.com")
        self.osint_target_entry.grid(row=0, column=1, sticky="w", padx=(0, 15))

        btn_scan = tk.Button(top_panel, text="▶ Run Full OSINT",
                             command=self._start_osint_scan,
                             bg=THEME["accent_purple"], fg="white",
                             font=("Segoe UI", 9, "bold"), padx=15, pady=4, relief="flat", cursor="hand2")
        btn_scan.grid(row=0, column=2, padx=5)

        btn_export_pdf = tk.Button(top_panel, text="💾 Save PDF",
                                   command=self._export_osint_pdf,
                                   bg=THEME["bg_input"], fg=THEME["accent_cyan"],
                                   font=("Segoe UI", 9), padx=10, pady=4, relief="flat", cursor="hand2")
        btn_export_pdf.grid(row=0, column=3, padx=4)

        btn_export_txt = tk.Button(top_panel, text="📄 Save TXT",
                                   command=self._export_osint_txt,
                                   bg=THEME["bg_input"], fg=THEME["text_bright"],
                                   font=("Segoe UI", 9), padx=10, pady=4, relief="flat", cursor="hand2")
        btn_export_txt.grid(row=0, column=4, padx=4)

        # OSINT Text Output Area
        content_frame = tk.Frame(self.tab_osint, bg=THEME["bg_dark"])
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)

        self.osint_text = scrolledtext.ScrolledText(content_frame, wrap="word",
                                                   font=("Consolas", 10),
                                                   bg=THEME["bg_card"],
                                                   fg=THEME["text_bright"],
                                                   insertbackground="white",
                                                   relief="flat", padx=15, pady=15)
        self.osint_text.pack(fill="both", expand=True)

        # Setup custom syntax tags for OSINT report
        self.osint_text.tag_config("header", foreground=THEME["accent_cyan"], font=("Consolas", 11, "bold"))
        self.osint_text.tag_config("success", foreground=THEME["accent_green"])
        self.osint_text.tag_config("warning", foreground=THEME["accent_red"])
        self.osint_text.tag_config("dim", foreground=THEME["text_dim"])

    # -------------------------------------------------------------
    # TAB 4: Reports & Logs
    # -------------------------------------------------------------
    def _build_reports_tab(self):
        btn_bar = tk.Frame(self.tab_reports, bg=THEME["bg_dark"], padx=5, pady=8)
        btn_bar.pack(fill="x")

        tk.Label(btn_bar, text="Console Output & Audit Log",
                 font=("Segoe UI", 10, "bold"), fg=THEME["text_bright"],
                 bg=THEME["bg_dark"]).pack(side="left")

        btn_clear = tk.Button(btn_bar, text="Clear Log",
                              command=self._clear_logs,
                              bg=THEME["bg_card"], fg=THEME["text_dim"],
                              font=("Segoe UI", 8), relief="flat", padx=10, pady=2, cursor="hand2")
        btn_clear.pack(side="right", padx=5)

        btn_open_folder = tk.Button(btn_bar, text="Open Reports Folder",
                                    command=self._open_reports_folder,
                                    bg=THEME["bg_card"], fg=THEME["accent_cyan"],
                                    font=("Segoe UI", 8), relief="flat", padx=10, pady=2, cursor="hand2")
        btn_open_folder.pack(side="right", padx=5)

        self.log_text = scrolledtext.ScrolledText(self.tab_reports, wrap="word",
                                                 font=("Consolas", 9),
                                                 bg=THEME["bg_card"],
                                                 fg=THEME["text_dim"],
                                                 insertbackground="white",
                                                 relief="flat", padx=10, pady=10)
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_text.tag_config("info", foreground=THEME["accent_cyan"])
        self.log_text.tag_config("success", foreground=THEME["accent_green"])
        self.log_text.tag_config("error", foreground=THEME["accent_red"])

    # -------------------------------------------------------------
    # Scan Execution Logic (Multi-Threaded)
    # -------------------------------------------------------------
    def _start_network_scan(self):
        target = self.net_target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target IP or CIDR block.")
            return

        self._set_scanning_state(True, f"Scanning network target: {target}...")
        self.net_tree.delete(*self.net_tree.get_children())

        def task():
            try:
                self.log(f"Initiating network discovery on {target}...", "info")
                is_cidr = "/" in target

                if is_cidr:
                    hosts = get_network_hosts(target)
                    self.log(f"Enumerating {len(hosts)} potential hosts in range...", "info")
                    results = discover_hosts(target)
                else:
                    hosts = [target]
                    results = discover_hosts(target)

                # Populate tree
                for host, online in results.items():
                    if self.stop_requested:
                        break
                    status_text = "🟢 ONLINE" if online else "🔴 OFFLINE"
                    hostname = get_hostname(host) if online else "-"
                    latency = "Active" if online else "No response"

                    self.net_tree.insert("", "end", values=(host, status_text, hostname, latency))

                active_count = sum(1 for status in results.values() if status)
                self.log(f"Scan complete. {active_count}/{len(results)} hosts active.", "success")
                self.set_status(f"Discovery complete: {active_count} active hosts found.")

            except Exception as e:
                self.log(f"Network discovery error: {e}", "error")
                messagebox.showerror("Scan Error", str(e))
            finally:
                self._set_scanning_state(False)

        self.active_scan_thread = threading.Thread(target=task, daemon=True)
        self.active_scan_thread.start()

    def _start_port_scan(self):
        host = self.port_target_entry.get().strip()
        ports_raw = self.port_list_entry.get().strip()

        if not host:
            messagebox.showwarning("Input Required", "Please specify a target host.")
            return

        # Parse ports
        ports_to_scan = []
        try:
            for part in ports_raw.split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    ports_to_scan.extend(range(start, end + 1))
                else:
                    ports_to_scan.append(int(part))
        except ValueError:
            messagebox.showerror("Invalid Ports", "Please enter valid comma-separated port numbers or ranges.")
            return

        if not ports_to_scan:
            messagebox.showwarning("Input Required", "No valid ports specified.")
            return

        self._set_scanning_state(True, f"Assessing {len(ports_to_scan)} ports on {host}...")
        self.port_tree.delete(*self.port_tree.get_children())

        def task():
            try:
                self.log(f"Starting port assessment on {host} ({len(ports_to_scan)} ports)...", "info")
                results = assess_ports(host, ports_to_scan)

                open_count = 0
                for port, is_open in results.items():
                    if self.stop_requested:
                        break
                    state_str = "🟢 OPEN" if is_open else "⚪ CLOSED"
                    service_name = PORT_SERVICES.get(port, "Unknown / Custom")
                    if is_open:
                        open_count += 1
                        self.port_tree.insert("", 0, values=(port, state_str, service_name, "TCP"))
                    else:
                        self.port_tree.insert("", "end", values=(port, state_str, service_name, "TCP"))

                self.log(f"Port scan finished. Found {open_count} OPEN ports.", "success")
                self.set_status(f"Port scan complete: {open_count} open ports found.")

            except Exception as e:
                self.log(f"Port scan error: {e}", "error")
                messagebox.showerror("Port Error", str(e))
            finally:
                self._set_scanning_state(False)

        self.active_scan_thread = threading.Thread(target=task, daemon=True)
        self.active_scan_thread.start()

    def _start_osint_scan(self):
        domain = self.osint_target_entry.get().strip()
        if not domain:
            messagebox.showwarning("Input Required", "Please enter a target domain.")
            return

        self._set_scanning_state(True, f"Collecting OSINT intelligence for {domain}...")
        self.osint_text.delete("1.0", tk.END)
        self.osint_text.insert(tk.END, f"[*] Gathering public OSINT intelligence for: {domain}\n\n", "header")

        def task():
            try:
                self.log(f"Starting comprehensive OSINT investigation for {domain}...", "info")
                data = collect_osint(domain)
                self.current_osint_report = data

                formatted_report = format_osint_report(data)

                # Insert report text into viewer
                self.osint_text.delete("1.0", tk.END)
                self.osint_text.insert(tk.END, formatted_report)
                self.log(f"OSINT intelligence collection for {domain} complete.", "success")
                self.set_status(f"OSINT analysis completed for {domain}.")

            except Exception as e:
                self.log(f"OSINT collection failed: {e}", "error")
                messagebox.showerror("OSINT Error", str(e))
            finally:
                self._set_scanning_state(False)

        self.active_scan_thread = threading.Thread(target=task, daemon=True)
        self.active_scan_thread.start()

    def _stop_scan(self):
        self.stop_requested = True
        self.log("Stopping running task...", "warning")
        self.set_status("Scan aborted by user.")

    def _set_scanning_state(self, is_scanning, status_msg="Scanning..."):
        self.stop_requested = False
        if is_scanning:
            self.engine_status.config(text="● RUNNING", fg=THEME["accent_cyan"])
            self.progress_bar.start(10)
            self.set_status(status_msg)
        else:
            self.engine_status.config(text="● IDLE", fg=THEME["accent_green"])
            self.progress_bar.stop()

    def _export_osint_pdf(self):
        if not self.current_osint_report:
            messagebox.showwarning("No Data", "Please run an OSINT scan before exporting.")
            return
        domain = self.osint_target_entry.get().strip() or "target"
        try:
            path = save_pdf(domain, self.current_osint_report)
            messagebox.showinfo("Export Success", f"Report saved to:\n{path}")
            self.log(f"Saved PDF report to {path}", "success")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def _export_osint_txt(self):
        if not self.current_osint_report:
            messagebox.showwarning("No Data", "Please run an OSINT scan before exporting.")
            return
        domain = self.osint_target_entry.get().strip() or "target"
        try:
            path = save_txt(domain, self.current_osint_report)
            messagebox.showinfo("Export Success", f"Report saved to:\n{path}")
            self.log(f"Saved TXT report to {path}", "success")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def _open_reports_folder(self):
        rep_dir = Path("reports").resolve()
        rep_dir.mkdir(parents=True, exist_ok=True)
        os.startfile(rep_dir)

    def _clear_logs(self):
        self.log_text.delete("1.0", tk.END)

    def log(self, message, level="info"):
        self.log_queue.put((message, level))

    def set_status(self, text):
        self.status_lbl.config(text=text)

    def _start_log_consumer(self):
        def check():
            while not self.log_queue.empty():
                msg, level = self.log_queue.get_nowait()
                timestamp = time.strftime("[%H:%M:%S]")
                self.log_text.insert(tk.END, f"{timestamp} {msg}\n", level)
                self.log_text.see(tk.END)
            self.after(100, check)
        self.after(100, check)


def launch_gui():
    app = ModernReconGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
