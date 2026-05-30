# KASCVE: Kernel Asset Surface & CVE Evaluator Framework

KASCVE is an automated, lightweight defensive hardening and security architecture audit engine written in Python. It is engineered to map public attack surfaces, discover forgotten staging paths or configuration artifacts via dynamic **SecLists** integrations, and generate prioritized remediation matrices for missing protocol wrappers.

```text
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
              .--.----.--.       --  --- --  ---  ---    --   --- 
            .-----\__/-----.    --------------------------------------------------------
```
<img width="716" height="499" alt="image" src="https://github.com/user-attachments/assets/ccdb9605-1080-48a8-b17f-2b0f10ab4492" />


## Core Features

* **Dynamic SecLists Pipeline:** Features multi-tier directory fuzzing tracking ranging from lightweight sweeps (150 words) to intense structural audits leveraging standard enterprise path wordlists (`raft-medium-directories`).

* **Forgotten Asset Analysis Engine:** Automatically identifies residual staging files, unlinked user directories (`/~admin`), exposed source code hubs (`.git`), and unpurged database/backup archives (`.env`, `backup.zip`).

* **Prioritized Severity Hardening Matrix:** Classifies configuration errors into clear structural severity vectors (**Low, Medium, High**) accompanied by explicit, copy-pasteable configuration directives for **Nginx**, **Apache**, and the **Laravel Framework**.

* **Ecosystem Component Patch Matching:** Evaluates running application platform signatures directly against open-source vulnerability documentation indices to map underlying risks.

---

## File System Architecture

```text
KASCVE/
├── main.py                     # Primary controller orchestrator & interface console
├── requirements.txt            # System dependency manifest references
├── install.sh                  # Automated deployment engine script
├── .gitignore                  # Development environment cache filters
└── core/
    ├── path_discovery.py       # Multi-tier SecLists streaming dictionary interface
    ├── structural_audit.py     # Component form processing layer
    ├── passive_recon.py        # Passive sub-domain metadata analyzer
    └── osv_api.py              # Framework vulnerability signature match check
```

---

## Installation & Global Deployment

The system contains an automated installer that handles necessary Python packages and establishes a global environment symbolic execution wrapper in `/usr/local/bin/KASCVE`, allowing you to execute audits from any active folder route.

```bash
# Clone the core framework repository
git clone https://github.com/PicasoTheDeal/KASCVE.git
cd KASCVE

# Execute the automated system configuration wrapper script
sudo ./install.sh
```

---

## Technical Usage Manual

Once initialized, call the tool globally passing any target domain asset as the first tracking index parameter:

```bash
KASCVE example.com
```

### Module Routine Options

1. **Baseline Passive Scan:** Collects passive subdomain layouts and maps third-party framework patch versions.
2. **Advanced Authentication Surface Audit:** Isolates login endpoint vectors, evaluating parameters for insecure `GET` handshakes or missing Anti-CSRF verification tokens.
3. **File Upload Integrity Audit:** Inspects multi-part file handlers to enforce strict binary validation requirements.
4. **Complete Stack Evaluation:** Fires every analysis module concurrently against the selected targets.

---

## Defensive Remediations Applied

When vulnerabilities are discovered, KASCVE outputs direct production layout file patches:
* **Nginx Server Configurations:** Directly logs specific `add_header` parameters matching required security scopes.
* **Apache Overlays:** Dictates appropriate `.htaccess` rule arrays.
* **Modern Framework Middleware:** Provides direct paths to safely isolate variables out of executable roots.

---
**Developer:** PicasoTheDealer
_Licensed under the MIT License._
