import os
import sqlite3
import pandas as pd
import shutil
import hashlib
import psutil
import re
import json
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timezone, timedelta
import platform


# --- Helper Functions ---

def get_os_type():
    return "Windows" if os.name == 'nt' else "macOS"


def get_browser_base_path(browser):
    """Return Chromium user data base path for Chrome/Edge."""
    user_home = os.path.expanduser("~")
    if get_os_type() == "Windows":
        if browser == "Chrome":
            return os.path.join(user_home, "AppData", "Local", "Google", "Chrome", "User Data")
        return os.path.join(user_home, "AppData", "Local", "Microsoft", "Edge", "User Data")

    if browser == "Chrome":
        return os.path.join(user_home, "Library", "Application Support", "Google", "Chrome")
    return os.path.join(user_home, "Library", "Application Support", "Microsoft Edge")


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def webkit_to_datetime(webkit_timestamp):
    """Convert WebKit timestamp to readable local datetime"""
    if webkit_timestamp and webkit_timestamp > 0:
        try:
            utc_dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=webkit_timestamp)
            local_dt = utc_dt.astimezone()
            return local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid Date"
    return "N/A"


def get_ram_usage(browser_name):
    """Capture RAM usage for the specified browser"""
    search_terms = ["chrome", "google chrome"] if "chrome" in browser_name.lower() else ["msedge", "microsoft edge"]
    ram_data = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            p_name = proc.info['name'].lower()
            if any(term in p_name for term in search_terms):
                ram_data.append({
                    'PID': proc.info['pid'],
                    'Process_Name': proc.info['name'],
                    'Memory_Usage_MB': round(proc.info['memory_info'].rss / (1024 * 1024), 2)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            continue
    return pd.DataFrame(ram_data)


def analyze_internal_slack(file_path):
    """
    SMART FORENSIC CARVING:
    Scans binary data of DB and WAL files for URLs, then subtracts ACTIVE URLs
    to isolate genuinely deleted/slack artifacts.
    """
    carved_links = set()
    files_to_scan = [file_path]

    # Check if WAL file exists and add it to the scan
    wal_path = file_path + "-wal"
    if os.path.exists(wal_path):
        files_to_scan.append(wal_path)

    # 1. Carve ALL URLs from binary
    for fp in files_to_scan:
        try:
            with open(fp, 'rb') as f:
                raw_data = f.read()
                # Advanced regex to find standard web URLs in binary blobs
                links = re.findall(b'https?://[a-zA-Z0-9./\-_?=&%]+', raw_data)
                for link in links:
                    try:
                        decoded = link.decode('utf-8', errors='ignore').strip()
                        if len(decoded) > 10:
                            carved_links.add(decoded)
                    except:
                        continue
        except:
            pass

    # 2. Extract ACTIVE URLs using standard SQL queries
    active_urls = set()
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url FROM urls")
        for row in cursor.fetchall():
            active_urls.add(row[0])
        conn.close()
    except:
        pass

    # 3. Find the difference (Carved - Active) = Deleted/Slack Data
    deleted_links = carved_links - active_urls

    # Convert to DataFrame, removing duplicates and limiting to 250 rows to prevent bloat
    return pd.DataFrame(list(deleted_links)[:250], columns=['Recovered_Deleted_Artifacts'])


def find_browser_profiles(browser):
    """Find all possible History database locations for a browser"""
    profiles = []
    base_path = get_browser_base_path(browser)

    if not os.path.exists(base_path):
        return []

    # Check Default and Profile folders
    for item in os.listdir(base_path):
        if item in ["Default", "Profile 1", "Profile 2", "System Profile"] or item.startswith("Profile "):
            history_path = os.path.join(base_path, item, "History")
            if os.path.exists(history_path):
                profiles.append({
                    'Browser': browser,
                    'Profile': item,
                    'History_Path': history_path,
                    'Exists': True
                })
    return profiles


def get_browser_version(browser):
    """Best-effort browser version from Chromium Local State."""
    base_path = get_browser_base_path(browser)
    local_state = os.path.join(base_path, "Local State")
    if not os.path.exists(local_state):
        return "Unknown"

    try:
        with open(local_state, "r", encoding="utf-8") as f:
            data = json.load(f)
        return (
                data.get("browser", {}).get("last_version")
                or data.get("last_version")
                or "Unknown"
        )
    except Exception:
        return "Unknown"


def build_artifact_location_table(browser, profile):
    """Tabulate key potential evidence locations per browser/profile."""
    base = get_browser_base_path(browser)
    profile_base = os.path.join(base, profile)
    candidates = [
        ("History", os.path.join(profile_base, "History")),
        ("Cookies", os.path.join(profile_base, "Cookies")),
        ("Login_Data", os.path.join(profile_base, "Login Data")),
        ("Web_Data", os.path.join(profile_base, "Web Data")),
        ("Top_Sites", os.path.join(profile_base, "Top Sites")),
        ("Favicons", os.path.join(profile_base, "Favicons")),
        ("Shortcuts", os.path.join(profile_base, "Shortcuts")),
        ("Visited_Links", os.path.join(profile_base, "Visited Links")),
        ("Network_Cookies", os.path.join(profile_base, "Network", "Cookies")),
        ("Cache", os.path.join(profile_base, "Cache")),
        ("Code_Cache", os.path.join(profile_base, "Code Cache")),
        ("Sessions", os.path.join(profile_base, "Sessions")),
    ]

    rows = []
    for artifact_name, artifact_path in candidates:
        exists = os.path.exists(artifact_path)
        rows.append({
            "Browser": browser,
            "Profile": profile,
            "Artifact": artifact_name,
            "Path": artifact_path,
            "Exists": "Yes" if exists else "No",
            "Last_Modified": datetime.fromtimestamp(os.path.getmtime(artifact_path)).strftime("%Y-%m-%d %H:%M:%S")
            if exists else "N/A",
        })
    return pd.DataFrame(rows)


def build_comparative_artifact_matrix(chrome_profiles, edge_profiles):
    """Build one-row-per-artifact forensic comparison."""

    def collect(browser, profiles):
        frames = [build_artifact_location_table(browser, p["Profile"]) for p in profiles]
        if not frames:
            return pd.DataFrame(columns=["Browser", "Profile", "Artifact", "Path", "Exists", "Last_Modified"])
        return pd.concat(frames, ignore_index=True)

    def aggregate(df, browser_label):
        if df.empty:
            return pd.DataFrame(columns=[
                "Artifact",
                f"{browser_label}_Path_Example",
                f"{browser_label}_Exists_In_Any_Profile",
                f"{browser_label}_Profiles_With_Artifact"
            ])

        grouped = df.groupby("Artifact")
        rows = []
        for artifact, g in grouped:
            exists_rows = g[g["Exists"] == "Yes"]
            path_example = exists_rows["Path"].iloc[0] if not exists_rows.empty else g["Path"].iloc[0]
            rows.append({
                "Artifact": artifact,
                f"{browser_label}_Path_Example": path_example,
                f"{browser_label}_Exists_In_Any_Profile": "Yes" if not exists_rows.empty else "No",
                f"{browser_label}_Profiles_With_Artifact": f"{len(exists_rows)}/{g['Profile'].nunique()}"
            })
        return pd.DataFrame(rows)

    chrome_detail = collect("Chrome", chrome_profiles)
    edge_detail = collect("Edge", edge_profiles)

    chrome_agg = aggregate(chrome_detail, "Chrome")
    edge_agg = aggregate(edge_detail, "Edge")

    matrix = pd.merge(chrome_agg, edge_agg, on="Artifact", how="outer").sort_values(by="Artifact")
    return matrix, chrome_detail, edge_detail


# --- Main GUI Application ---

class ForensicApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SEC-435: Chromium Browser Forensic Analyzer")
        self.root.geometry("1080x780")
        self.root.minsize(980, 700)
        self.root.configure(bg="#0f172a")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("App.TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#111827")
        style.configure("Title.TLabel", background="#0f172a", foreground="#f8fafc", font=("Segoe UI", 24, "bold"))
        style.configure("Subtitle.TLabel", background="#0f172a", foreground="#93c5fd", font=("Segoe UI", 11, "italic"))
        style.configure("Status.TLabel", background="#0f172a", foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=10)
        style.map("Primary.TButton", background=[("active", "#1d4ed8"), ("!active", "#2563eb")],
                  foreground=[("!disabled", "white")])
        style.configure("Secondary.TButton", font=("Segoe UI", 10, "bold"), padding=10)
        style.map("Secondary.TButton", background=[("active", "#0f766e"), ("!active", "#0d9488")],
                  foreground=[("!disabled", "white")])

        main_frame = ttk.Frame(root, style="App.TFrame", padding=(24, 18))
        main_frame.pack(fill="both", expand=True)

        # Header
        ttk.Label(main_frame, text="Chromium Browser Forensic Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(main_frame, text="Developed by Sulaiman Alhabsi and Ameen Almenhali | SEC-435",
                  style="Subtitle.TLabel").pack(anchor="w", pady=(2, 14))

        status_text = f"Platform: {get_os_type()} ({platform.platform()})"
        ttk.Label(main_frame, text=status_text, style="Status.TLabel").pack(anchor="w", pady=(0, 14))

        # Console Card
        log_card = ttk.Frame(main_frame, style="Card.TFrame", padding=12)
        log_card.pack(fill="both", expand=True)

        self.log_area = tk.Text(
            log_card,
            height=24,
            state='disabled',
            bg="#020617",
            fg="#22c55e",
            font=("Consolas", 10),
            borderwidth=0,
            relief="flat",
            insertbackground="#22c55e",
            wrap="none"
        )
        log_scroll_y = ttk.Scrollbar(log_card, orient="vertical", command=self.log_area.yview)
        self.log_area.configure(yscrollcommand=log_scroll_y.set)
        self.log_area.pack(side="left", fill="both", expand=True)
        log_scroll_y.pack(side="right", fill="y")

        # Buttons
        btn_frame = ttk.Frame(main_frame, style="App.TFrame")
        btn_frame.pack(fill="x", pady=(14, 0))

        ttk.Button(btn_frame, text="Analyze Chrome",
                   command=lambda: self.run_investigation("Chrome"),
                   style="Primary.TButton").grid(row=0, column=0, padx=(0, 10))
        ttk.Button(btn_frame, text="Analyze Edge",
                   command=lambda: self.run_investigation("Edge"),
                   style="Primary.TButton").grid(row=0, column=1, padx=(0, 10))
        ttk.Button(btn_frame, text="Comparative Analysis",
                   command=self.run_comparative_analysis,
                   style="Secondary.TButton").grid(row=0, column=2)

        # Initial Logs
        self.log("[*] SEC-435 Advanced Browser Forensic Tool Initialized")
        self.log(f"[*] Operating System: {get_os_type()} ({platform.platform()})")
        self.log("[*] Investigators: Sulaiman Alhabsi & Ameen Almenhali")
        self.log("[*] Objective: Comparative Analysis of Chrome & Edge Evidence Locations")
        self.log("[*] Forensic Soundness Criteria:")
        self.log("    1) Read-only source handling where feasible")
        self.log("    2) Source and working-copy SHA-256 hashing")
        self.log("    3) Repeatable extraction with timestamped metadata")
        self.log("    4) Explicit caveat: RAM and slack outputs are indicative, not full acquisition\n")

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.config(state='disabled')
        self.log_area.see(tk.END)
        self.root.update_idletasks()

    def run_investigation(self, browser):
        self.log(f"\n{'=' * 80}")
        self.log(f"STARTING TARGETED ANALYSIS: {browser.upper()}")
        self.log(f"{'=' * 80}")

        profiles = find_browser_profiles(browser)
        if not profiles:
            self.log(f"[-] No {browser} profiles found.")
            messagebox.showwarning("Not Found", f"No {browser} History database found.")
            return

        saved_reports = []
        failed_profiles = []
        for profile in profiles:
            report_path = self.analyze_single_profile(profile)
            if report_path:
                saved_reports.append(report_path)
            else:
                failed_profiles.append(profile.get("Profile", "Unknown"))

        self.log(f"[*] {browser} Analysis Completed.")
        if saved_reports:
            message = (
                f"{browser} analysis completed successfully.\n\n"
                "Report(s) saved on Desktop."
            )
            if failed_profiles:
                failed_text = ", ".join(failed_profiles)
                message += f"\n\nSome profiles failed: {failed_text}"
                messagebox.showwarning(f"{browser} Analysis Completed (Partial)", message)
            else:
                messagebox.showinfo(f"{browser} Analysis Completed", message)
        else:
            messagebox.showerror(
                f"{browser} Analysis Failed",
                f"No {browser} report was generated. Please check logs for details."
            )

    def analyze_single_profile(self, profile_info):
        browser = profile_info['Browser']
        profile = profile_info['Profile']
        path = profile_info['History_Path']

        self.log(f"\n[+] Analyzing {browser} - Profile: {profile}")

        try:
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            temp_db = os.path.join(desktop_path, f"temp_{browser}_{profile}_forensic.db")
            browser_version = get_browser_version(browser)
            investigation_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Forensic Copy + hash provenance
            src_hash = calculate_sha256(path)
            shutil.copy2(path, temp_db)
            copy_hash = calculate_sha256(temp_db)
            self.log(f"    Browser Version (best effort): {browser_version}")
            self.log(f"    Source SHA-256: {src_hash}")
            self.log(f"    Copy SHA-256  : {copy_hash}")

            # COPY WAL FILE FOR RECOVERY OF RECENTLY DELETED ITEMS
            wal_path = path + "-wal"
            temp_wal = temp_db + "-wal"
            if os.path.exists(wal_path):
                shutil.copy2(wal_path, temp_wal)
                self.log("    [*] WAL File detected and copied. Enhanced recovery enabled.")

            # RAM Analysis (process memory usage only; not memory image carving)
            df_ram = get_ram_usage(browser)

            # SMART SLACK RECOVERY: Run before deleting temp files
            self.log("    [*] Scanning binary slack space for deleted URLs...")
            df_slack = analyze_internal_slack(temp_db)

            df_locations = build_artifact_location_table(browser, profile)

            # Database Extraction (Active Records)
            conn = sqlite3.connect(temp_db)

            df_hist = pd.read_sql_query(
                "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC", conn)
            df_hist['last_visit_time'] = df_hist['last_visit_time'].apply(webkit_to_datetime)

            try:
                df_search = pd.read_sql_query("""
                                              SELECT term, urls.last_visit_time
                                              FROM keyword_search_terms
                                                       JOIN urls ON keyword_search_terms.url_id = urls.id
                                              """, conn)
                df_search['last_visit_time'] = df_search['last_visit_time'].apply(webkit_to_datetime)
            except Exception:
                df_search = pd.DataFrame(columns=["term", "last_visit_time"])

            try:
                df_down = pd.read_sql_query(
                    "SELECT target_path, total_bytes, start_time, tab_url FROM downloads", conn)
                df_down['start_time'] = df_down['start_time'].apply(webkit_to_datetime)
            except Exception:
                df_down = pd.DataFrame(columns=["target_path", "total_bytes", "start_time", "tab_url"])

            try:
                df_visits = pd.read_sql_query("""
                                              SELECT urls.url, visits.visit_time, visits.from_visit, visits.transition
                                              FROM visits
                                                       JOIN urls ON visits.url = urls.id
                                              ORDER BY visits.visit_time DESC
                                              """, conn)
                df_visits['visit_time'] = df_visits['visit_time'].apply(webkit_to_datetime)
            except Exception:
                df_visits = pd.DataFrame(columns=["url", "visit_time", "from_visit", "transition"])

            conn.close()

            # Clean up temp files safely
            if os.path.exists(temp_db):
                os.remove(temp_db)
            if os.path.exists(temp_wal):
                os.remove(temp_wal)

            # Summary
            summary = {
                'Forensic_Metric': ['Investigators', 'Profile', 'Investigation_Time', 'SHA256_Hash',
                                    'Source_SHA256', 'Copy_SHA256', 'Hash_Match', 'Browser_Version',
                                    'Total_Active_URLs', 'Total_Visits', 'Total_Search_Terms',
                                    'Total_Download_Records', 'Recovered_DELETED_URLs', 'Known_Artifact_Locations'],
                'Value': ['Sulaiman Alhabsi & Ameen Almenhali', profile, investigation_time, copy_hash[:64],
                          src_hash[:64], copy_hash[:64],
                          'Yes' if src_hash == copy_hash else 'No', browser_version,
                          len(df_hist), len(df_visits), len(df_search), len(df_down),
                          len(df_slack), len(df_locations)]
            }
            df_summary = pd.DataFrame(summary)

            # Export Report
            report_name = os.path.join(desktop_path, f"Forensic_Report_{browser}_{profile}.xlsx")

            with pd.ExcelWriter(report_name) as writer:
                df_summary.to_excel(writer, sheet_name="Summary", index=False)
                df_locations.to_excel(writer, sheet_name="Evidence_Locations", index=False)
                df_ram.to_excel(writer, sheet_name="RAM_Process_Usage", index=False)
                df_slack.to_excel(writer, sheet_name="Deleted_Artifacts", index=False)
                df_search.to_excel(writer, sheet_name="Search_Terms", index=False)
                df_hist.to_excel(writer, sheet_name="Visit_History", index=False)
                df_visits.to_excel(writer, sheet_name="Visit_Events", index=False)
                df_down.to_excel(writer, sheet_name="Downloads", index=False)

            self.log(f"    Report saved: {os.path.basename(report_name)}")
            return report_name

        except Exception as e:
            self.log(f"    [!] Error analyzing profile {profile}: {str(e)}")
            return None

    def run_comparative_analysis(self):
        """Performs comparative analysis between Chrome and Edge"""
        self.log(f"\n{'=' * 90}")
        self.log("PERFORMING COMPARATIVE FORENSIC ANALYSIS: CHROME vs EDGE")
        self.log(f"{'=' * 90}")

        chrome_profiles = find_browser_profiles("Chrome")
        edge_profiles = find_browser_profiles("Edge")
        if not chrome_profiles and not edge_profiles:
            self.log("[-] No Chrome or Edge profiles were found for comparative analysis.")
            messagebox.showwarning(
                "No Profiles Found",
                "No Chrome or Edge profiles were found on this system."
            )
            return

        df_matrix, df_chrome_detail, df_edge_detail = build_comparative_artifact_matrix(
            chrome_profiles, edge_profiles
        )
        df_comparison = pd.concat([df_chrome_detail, df_edge_detail], ignore_index=True)
        chrome_version = get_browser_version("Chrome")
        edge_version = get_browser_version("Edge")

        # Save Comparative Report
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        comp_report = os.path.join(desktop, "Comparative_Analysis_Chrome_vs_Edge.xlsx")

        with pd.ExcelWriter(comp_report) as writer:
            # Primary assignment-aligned output: one row per artifact type.
            df_matrix.to_excel(writer, sheet_name="Artifact_Comparison", index=False)

            # Supporting detailed view by profile.
            df_comparison.to_excel(writer, sheet_name="Evidence_Locations_Detail", index=False)

            # Add summary sheet
            summary = pd.DataFrame({
                'Investigators': ['Sulaiman Alhabsi & Ameen Almenhali', 'Sulaiman Alhabsi & Ameen Almenhali'],
                'Browser': ['Chrome', 'Edge'],
                'Version': [chrome_version, edge_version],
                'Profiles_Found': [len(chrome_profiles), len(edge_profiles)],
                'Profiles_With_History': [len(chrome_profiles), len(edge_profiles)],
                'Artifacts_Compared': [len(df_matrix), len(df_matrix)]
            })
            summary.to_excel(writer, sheet_name="Summary", index=False)

        self.log(f"[+] Comparative Analysis Report Generated:")
        self.log(f"    → {comp_report}")
        self.log(f"    Chrome Profiles Found : {len(chrome_profiles)}")
        self.log(f"    Edge Profiles Found   : {len(edge_profiles)}")

        messagebox.showinfo("Comparative Analysis Complete",
                            f"Comparative report saved to Desktop.\n\n"
                            f"Chrome Profiles: {len(chrome_profiles)}\n"
                            f"Edge Profiles: {len(edge_profiles)}")

        # Print concise forensic-style matrix in console
        self.log("\nComparative Artifact Matrix (one row per artifact):")
        if df_matrix.empty:
            self.log("No artifact rows generated (no compatible browser profiles found).")
        else:
            self.log(df_matrix.to_string(index=False))


if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicApp(root)
    root.mainloop()
