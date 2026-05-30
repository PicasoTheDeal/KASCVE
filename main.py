import sys
from core.path_discovery import discover_seclist_paths
from core.passive_recon import gather_subdomains_passively, check_robots_metadata
from core.structural_audit import audit_web_surfaces
from core.osv_api import look_up_remediation

# Terminal ANSI Color Escape Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def display_banner():
    print(CYAN + r"""
                  /¯¯\          
                  \__/          
                   ||           
                   ||           
                  |  |          
                  |  |          █   █   ███   ███   ███   █   █  ███
                  |  |          █ / █  █   █  █     █     █   █  █  
                  |  |          ████   █████  ███   █     █   █  ███
                  |  |          █ \ █  █   █    █   █     \   /  █  
                  |  |          █  \█  █   █  ███   ███    \_/   ███
              .--.----.--.       --  --- --  ---  ---     --   --- 
            .-----\__/-----.    --------------------------------------------------------
 ___---¯¯////¯¯|\/|¯¯\\\\¯¯---___
/¯¯ __O_--////   |  |   \\\\--_O__ ¯¯\    KERNEL ASSET SURFACE & CVE EVALUATOR FRAMEWORK
| O?¯     ¯¯¯    |  |    ¯¯¯     ¯?O | 
|  '    _.-.      |  |      .-._    '  |    [+] Deployment Architecture Hardening Engine
|O|    ?..?      ./  \.      ?..?    |O|
| |     '?. .-.  | /\ |  .-. .?'     | |    --------------------------------------------------------
| ---__  ¯?__?  /|\¯¯/|\  ?__?¯  __--- |
|O     \         ||\/ |         /     O|
|       \  /¯?_  ||   |  _?¯\  /       |
|       / /    - ||   | -    \ \       |
|O    __/  | __   ||   |   __ |  \__    O|
| ---     |/  -_/||   |\_-  \|     --- | 
|O|            \ ||   | /    made by   |O|  
\ '              ||   | PicasoTheDealer /
 \O\    _-¯?.    ||   |    .?¯-_    /O/
  \ \  /  /¯¯¯?  ||   |  ?¯¯¯\  \  / /
   \O\/   |      ||   |      |   \/O/
    \     |      ||   |      |     /
     '.O  |_     ||   |     _|  O.'
        '._O'.__/||   |\__.'O_.'
           '._ O ||   | O _.'
              '._||   |_.'
                 ||   |
                 ||   |
                 | \/ |
                 |  | |
                  \ |/
                   \/"
    """ + RESET)

def print_disclaimer():
    print(YELLOW + "=" * 90 + RESET)
    print(RED + "[!] LEGAL WARNING: FOR AUTHORIZED SECURITY AUDITING ONLY [!]" + RESET)
    print(" This tool is engineered strictly for educational purposes, authorized")
    print(" penetration testing, and defensive system hardening.")
    print(" Running KASCVE against unauthorized targets is strictly illegal.")
    print(" The developer assumes zero liability for misuse, damage, or legal risk.")
    print(YELLOW + "=" * 90 + RESET + "\n")

def display_menu():
    print(CYAN + "Select Audit Operating Module Options:" + RESET)
    print(" [1] Baseline Passive Scan (Default Component & CVE Audit)")
    print(" [2] Advanced Authentication Surface Audit (SQLi & CSRF Evaluation)")
    print(" [3] File Upload Integrity Audit (Trojan & Execution Prevention)")
    print(" [4] Complete Stack Evaluation (Execute All Modules Simultaneously)")
    print("-" * 90)
    
    while True:
        try:
            choice = input(CYAN + "Enter option number [1-4]: " + RESET).strip()
            if choice in ["1", "2", "3", "4"]:
                return choice
            print(RED + "[!] Invalid input. Please enter a correct option number between 1 and 4." + RESET)
        except (KeyboardInterrupt, EOFError):
            print(RED + "\n[-] Operation canceled by user." + RESET)
            sys.exit(0)

def display_fuzzing_depth_menu():
    print(CYAN + "\nSelect SecLists Directory Fuzzing Range Depth:" + RESET)
    print(" [1] Light-Speed Sweep (Top 150 Most-Common High-Signal Targets)")
    print(" [2] Balanced Common Sweep (Full SecLists common.txt Directory - ~4.5k entries)")
    print(" [3] Brutal Fuzz Run (SecLists raft-medium-directories.txt - Large Runtime)")
    print("-" * 90)
    
    while True:
        try:
            choice = input(CYAN + "Enter selection [1-3]: " + RESET).strip()
            if choice in ["1", "2", "3"]:
                return choice
            print(RED + "[!] Invalid input. Please enter a correct option number between 1 and 3." + RESET)
        except (KeyboardInterrupt, EOFError):
            print(RED + "\n[-] Operation canceled." + RESET)
            sys.exit(0)

def analyze_forgotten_assets(working_paths):
    """
    Examines directory tracking data arrays and alerts the user to 
    forgotten development paths, structural components, or source exposure leaks.
    """
    sensitive_patterns = {
        ".git": ("CRITICAL", "Exposed Git Source Repository Structure", "Completely remove the internal project '.git' directory or include 'deny all;' context rules within production routes."),
        "test": ("HIGH", "Forgotten Verification Sandbox Path Located", "Delete sandbox deployment structures or enforce strict local server access IP validation controls."),
        "dev": ("HIGH", "Active Development/Staging Resource Interface", "Isolate development infrastructure away from public-facing DNS structures entirely."),
        "backup": ("CRITICAL", "Compressed Archival/Backup Storage Leak", "Instantly delete old zip/tar archive files from the web root folder to thwart target reverse-engineering attempts."),
        ".env": ("CRITICAL", "Exposed Local Application Environment Credentials", "Isolate environment property text files out of public directory layers immediately."),
        "config": ("HIGH", "Visible Pipeline Architecture Mapping", "Configure custom server authorization blocks to deny directory reads or restrict index permissions.")
    }
    
    found_issues = False
    print(f"\n{YELLOW}[* MODULE] UNINTENDED DIRECTORY EXPOSURE & FORGOTTEN ASSET SCANNER{RESET}")
    print("-" * 90)
    
    for url in working_paths:
        for keyword, (severity, detail, fix) in sensitive_patterns.items():
            if keyword in url.lower() and url.rstrip('/') != url.split('//')[-1]:
                found_issues = True
                color = RED if severity == "CRITICAL" else YELLOW
                print(f" {color}[{severity}]{RESET} Exposed Asset Identified: {url}")
                print(f"    ├── Impact Context: {detail}")
                print(f"    └── {BLUE}Remediation Plan:{RESET} {fix}\n")
                
    if not found_issues:
        print(f"{GREEN}[+] Zero residual sandbox systems or exposed backup resources located over scanned paths.{RESET}")

def print_security_header_matrix(missing_headers):
    """
    Calculates exact technical severities, pinpointing configurations needing repair.
    """
    header_vulnerability_data = {
        "Content-Security-Policy": {
            "severity": "HIGH",
            "impact": "Exposes application endpoints to cross-site scripting (XSS) injection arrays.",
            "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\";",
            "apache": "Header set Content-Security-Policy \"default-src 'self';\"",
            "laravel": "Deploy an explicit middleware stack or integrate security management libraries like 'spatie/laravel-csp'."
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "impact": "Allows client-side application browsers to perform dangerous execution via MIME-sniffing exploits.",
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header set X-Content-Type-Options \"nosniff\"",
            "laravel": "Inject missing properties via 'App\\Http\\Middleware\\TrustProxies.php' runtime handling."
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "impact": "Leaves deployment vulnerable to UI-redressing and framing clicks (Clickjacking attacks).",
            "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "apache": "Header set X-Frame-Options \"SAMEORIGIN\"",
            "laravel": "Ensure framework returns appropriate parameters via backend layout wrapper configurations."
        }
    }

    print(f"\n{YELLOW}[* CONFIGURATION HARDENING ADVISORY MATRIX]{RESET}")
    print("-" * 90)
    
    for h in missing_headers:
        if h in header_vulnerability_data:
            meta = header_vulnerability_data[h]
            severity_color = RED if meta["severity"] in ["CRITICAL", "HIGH"] else YELLOW
            
            print(f" {severity_color}[{meta['severity']} VULNERABILITY]{RESET} Missing Protocol Header: `{h}`")
            print(f"    ├── Threat Context:   {meta['impact']}")
            print(f"    └── {BLUE}Explicit Configuration Instructions:{RESET}")
            print(f"        ├── For Nginx Configuration [Edit: /etc/nginx/nginx.conf or sites-available/]:")
            print(f"        │   └── \033[92m{meta['nginx']}\033[0m")
            print(f"        ├── For Apache Deployment   [Edit: .htaccess or httpd.conf]:")
            print(f"        │   └── \033[92m{meta['apache']}\033[0m")
            print(f"        └── For Laravel Framework   [Edit Middleware Layers]:")
            print(f"            └── \033[92m{meta['laravel']}\033[0m\n")

def print_remediation_card(tech, findings):
    if not findings:
        print(f"{GREEN}[+] {tech:<15} | Current Version Verified Secure{RESET}")
        return
    print(f"{RED}[!] {tech:<15} | UNPATCHED VULNERABILITY DETECTED{RESET}")
    for f in findings:
        print(f"    ├── CVE Reference: {f['cve']}")
        print(f"    ├── Risk Context:  {f['summary']}")
        print(f"    └── {BLUE}Required Action:{RESET} {f['fix']}")

def main():
    display_banner()
    print_disclaimer()
    
    if len(sys.argv) < 2:
        print(RED + "Usage: KASCVE <domain.com>" + RESET)
        sys.exit(1)

    target_domain = sys.argv[1].replace("https://", "").replace("http://", "").split("/")[0]
    
    user_choice = display_menu()
    fuzz_depth = display_fuzzing_depth_menu()

    print(CYAN + "\n" + "="*90)
    print(f"   KASCVE SYSTEM AUDIT ENGAGED FOR: {target_domain}")
    print("="*90 + RESET)

    run_passive = True
    run_auth = user_choice in ["2", "4"]
    run_uploads = user_choice in ["3", "4"]

    # 1. Engage Depth-Controlled SecList Wordlist Discovery
    print(f"\n{BLUE}[*] Launching SecLists Endpoint Discovery Protocol...{RESET}")
    working_paths = discover_seclist_paths(target_domain, fuzz_depth)
    print(f"{GREEN}[+] Path analysis complete. Found {len(working_paths)} operational deployment surfaces.{RESET}")

    # 2. Run Forgotten/Exposed Assets Analysis Block
    analyze_forgotten_assets(working_paths)

    # 3. Extract component structure mapping over all working directory instances
    print(f"\n{BLUE}[*] Auditing layout components across identified paths...{RESET}")
    surface_map = audit_web_surfaces(working_paths)

    # ------------------------------------------------------------
    # PILLAR 1: Passive Baseline Security Assessment
    # ------------------------------------------------------------
    if run_passive:
        print(f"\n{BLUE}[*] Gathering Public Asset Intelligence Records...{RESET}")
        subs = gather_subdomains_passively(target_domain)
        paths = check_robots_metadata(target_domain)
        print(f"{GREEN}[+] Passive OSINT complete. Found {len(subs)} subdomains and {len(paths)} paths.{RESET}")

        print(f"\n{BLUE}[*] Evaluating Component Ecosystem Patch Signatures...{RESET}")
        laravel_findings = look_up_remediation("laravel", "8.0.0")
        print_remediation_card("laravel", laravel_findings)

    # ------------------------------------------------------------
    # PILLAR 2: Authentication Surface Configuration Check
    # ------------------------------------------------------------
    if run_auth or (user_choice == "1" and surface_map["login_forms_found"]):
        print(f"\n{YELLOW}[* MODULE] ADVANCED AUTHENTICATION SURFACE AUDIT ACTIVE{RESET}")
        print("-" * 90)
        
        if surface_map["login_forms_found"]:
            print(f"{RED}[CRITICAL] Exposed Authentication Input Portals Discovered:{RESET}")
            
            for form in surface_map["login_forms_found"]:
                print(f"\n {YELLOW}● Target Location:{RESET} {form['action_url']}")
                print(f"   ├── Form ID context: {form['id']}")
                print(f"   ├── Input parameter: name='{form['field_name']}'")
                
                if form["method"] == "get":
                    print(f"   ├── {RED}[HIGH VULNERABILITY] Submits data via unencrypted HTTP GET parameters.{RESET}")
                    print(f"   │   └── Fix Advisory: Change form attributes to method='POST' immediately.")
                else:
                    print(f"   ├── {GREEN}[SECURE] Submits data via isolated HTTP POST parameter payload.{RESET}")
                    
                if not form["has_csrf"]:
                    print(f"   └── {RED}[HIGH VULNERABILITY] Missing structural Anti-CSRF verification tokens.{RESET}")
                    print(f"       └── Fix Advisory: Include framework-level security tokens (e.g., @csrf in Laravel).")
                else:
                    print(f"   └── {GREEN}[SECURE] Verification tokens configured correctly inside form parameters.{RESET}")
        else:
            print(f"{GREEN}[+] Zero active authentication forms located across tested SecList boundaries.{RESET}")

    # ------------------------------------------------------------
    # PILLAR 3: Content Upload Integrity Validation
    # ------------------------------------------------------------
    if run_uploads or (user_choice == "1" and surface_map["upload_forms_found"]):
        print(f"\n{YELLOW}[* MODULE] FILE UPLOAD INTEGRITY AND SANITIZATION AUDIT ACTIVE{RESET}")
        print("-" * 90)
        
        if surface_map["upload_forms_found"]:
            print(f"{RED}[CRITICAL] Active Content Upload Pathways Discovered:{RESET}")
            
            for form in surface_map["upload_forms_found"]:
                print(f"\n {YELLOW}● Upload Endpoint:{RESET} {form['action_url']}")
                print(f"   ├── Form ID context: {form['id']}")
                
                if form["missing_accept"]:
                    print(f"   └── {RED}[MEDIUM VULNERABILITY] HTML input does not specify client-side file-type filters.{RESET}")
                    print(f"       └── Fix Advisory: Restrict options explicitly on the frontend (e.g., accept='image/png').")
                else:
                    print(f"   └── {GREEN}[SECURE] Client-side layout restrictions present on file selection field.{RESET}")
        else:
            print(f"{GREEN}[+] Zero active file selection forms located across tested SecList boundaries.{RESET}")

    # ------------------------------------------------------------
    # PILLAR 4: Highly Prioritized Configuration Hardening Matrix
    # ------------------------------------------------------------
    if surface_map["missing_security_headers"]:
        print_security_header_matrix(surface_map["missing_security_headers"])

    print(f"\n{CYAN}============================================================{RESET}")
    print(f"{CYAN}   AUDIT COMPLETE: DEFENSIVE HARDENING BLUEPRINT GENERATED{RESET}")
    print(f"{CYAN}============================================================{RESET}\n")

if __name__ == "__main__":
    main()
