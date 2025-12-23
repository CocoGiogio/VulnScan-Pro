import os
import sys
import subprocess
import socket
import datetime
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATION ---
TARGETS = [
    "example.com", "beta.example.com"
]
MAX_THREADS = 4
NMAP_CMD = ["nmap", "-sV", "-O", "--top-ports", "50", "--script", "vulners"]

# Sensitive directories to test
FUZZ_PATHS = [
    ".git", ".env", "admin", "config", "backup", "db", "phpinfo.php", 
    "webmail", "zimbra", ".htaccess", "server-status", "api/v1"
]

class ProfessionalReport(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.set_text_color(44, 62, 80)
        self.cell(0, 10, "EXECUTIVE SUMMARY OFFENSIVE AUDIT REPORT", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(5)

    def draw_highlight_box(self, title, items, color_rgb):
        """Displays a colored box for critical findings"""
        if not items: return
        self.set_font("helvetica", "B", 11)
        self.set_text_color(*color_rgb)
        self.cell(0, 8, f"ALERTS: {title}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font("helvetica", "", 10)
        for item in items:
            self.cell(0, 6, f" > {item}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)
        self.set_text_color(0, 0, 0)

def clean_text(text):
    """Encodes text to latin-1 to avoid FPDF crashes with Unicode characters"""
    if not text: return ""
    return text.encode("latin-1", "ignore").decode("latin-1")

def fuzz_directories(base_url):
    """Tests for the existence of sensitive directories"""
    found = []
    for path in FUZZ_PATHS:
        url = f"{base_url}/{path}"
        try:
            res = requests.get(url, timeout=2, verify=False, allow_redirects=False)
            if res.status_code in [200, 301, 403]:
                found.append(f"/{path} (Status: {res.status_code})")
        except:
            continue
    return found

def run_advanced_scan(target):
    print(f"[*] Audit in progress: {target}")
    try:
        ip = socket.gethostbyname(target)
    except:
        return None

    # Web Analysis & Fuzzing
    base_url = f"https://{target}"
    fuzz_results = fuzz_directories(base_url)
    
    # Nmap Scan
    try:
        nmap_proc = subprocess.run(NMAP_CMD + [ip], capture_output=True, text=True, timeout=300)
        raw_output = clean_text(nmap_proc.stdout)
        
        # Extracting key information from Nmap output
        vulns = [line.strip() for line in raw_output.split('\n') if "CVE-" in line or "*EXPLOIT*" in line]
        open_ports = [line.strip() for line in raw_output.split('\n') if "/tcp" in line and "open" in line]

        return {
            "target": target, "ip": ip, 
            "fuzz": fuzz_results, "vulns": vulns[:10], "ports": open_ports,
            "raw": raw_output
        }
    except Exception as e:
        print(f"[!] Error scanning {target}: {e}")
        return None

def main():
    if os.getuid() != 0:
        print("[!] Error: Root privileges (sudo) required for OS detection and NSE scripts.") ; sys.exit(1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(run_advanced_scan, TARGETS))

    pdf = ProfessionalReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    for res in results:
        if not res: continue
        pdf.add_page()
        
        # Target Title
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(0, 10, f"TARGET: {res['target']} ({res['ip']})", border="B", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)
        
        # --- HIGHLIGHTS SECTION ---
        # 1. Sensitive Files and Directories (Red)
        pdf.draw_highlight_box("SENSITIVE DIRECTORIES DETECTED", res['fuzz'], (192, 57, 43))
        
        # 2. Critical Vulnerabilities (Orange)
        pdf.draw_highlight_box("CVE VULNERABILITIES & EXPLOITS", res['vulns'], (211, 84, 0))
        
        # 3. Open Ports (Blue)
        pdf.draw_highlight_box("ACTIVE SERVICES DETECTED", res['ports'], (41, 128, 185))

        # --- TECHNICAL LOGS ---
        pdf.ln(5)
        pdf.set_font("helvetica", "B", 11)
        pdf.cell(0, 7, "FULL NMAP TECHNICAL LOGS:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("courier", "", 7)
        pdf.multi_cell(0, 3.5, res['raw'])

    output_file = "Prioritized_Pentest_Report.pdf"
    pdf.output(output_file)
    print(f"\n[+] Audit Complete! Report generated: {output_file}")

if __name__ == "__main__":
    main()
