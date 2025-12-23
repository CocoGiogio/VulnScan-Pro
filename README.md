


____   ____    .__           _________                             __________                
\   \ /   /_ __|  |   ____  /   _____/ ____ _____    ____          \______   \_______  ____  
 \   Y   /  |  \  |  /    \ \_____  \_/ ___\\__  \  /    \   ______ |     ___/\_  __ \/  _ \ 
  \     /|  |  /  |_|   |  \/        \  \___ / __ \|   |  \ /_____/ |    |     |  | \(  <_> )
   \___/ |____/|____/___|  /_______  /\___  >____  /___|  /         |____|     |__|   \____/ 
                         \/        \/     \/     \/     \/                                   


🛡️ VunScan-Pro
VunScan-Pro is an advanced, multi-threaded reconnaissance and vulnerability assessment tool. It combines the power of Nmap for network discovery with a specialized Web Fuzzer to identify sensitive directories, all while generating a prioritized, executive-level PDF report.

🚀 Key Features
- Multi-Threaded Scanning: Processes multiple targets simultaneously using ThreadPoolExecutor for maximum efficiency.
- Deep Infrastructure Discovery: Utilizes Nmap for service versioning (-sV) and OS fingerprinting (-O).
- Vulnerability Mapping: Automatically correlates detected service versions with known CVEs using the vulners NSE script.
- Offensive Web Fuzzing: Probes for 12+ sensitive paths (e.g., /.git, /.env, /admin) and reports HTTP status codes .
- Prioritized Reporting: Generates a professional PDF where critical findings (Sensitive Files, CVEs, Open Ports) are highlighted in color-coded alert boxes before the technical logs.
- Unicode Safety: Built-in text cleaning to ensure PDF generation never crashes due to special characters in web titles or Nmap headers.

📋 Prerequisites
Ensure you have the following installed on your system:
- Python 3.13+
- Nmap (must be in your system PATH)
- Sudo privileges (required for Nmap OS detection and raw packet crafting)
