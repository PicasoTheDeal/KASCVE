#!/bin/bash

# Terminal UI Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "  [+] Launching KASCVE Framework Installer..."
echo "  [+] Engineering Global Shell Environment Links..."
echo -e "${RESET}"

# 1. Verify the script is running with appropriate permissions to link globally
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[- ] Error: Please execute the installer using sudo privileges.${RESET}"
    echo -e "${YELLOW}    Usage: sudo ./install.sh${RESET}"
    exit 1
fi

# 2. Check for core requirements
echo -e "${BLUE}[*] Checking for system Python 3 ecosystem...${RESET}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Error: Python 3 is missing from this system host.${RESET}"
    echo -e "    Please install it using your system package manager (apt, pacman, etc) and rerun."
    exit 1
fi

if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo -e "${YELLOW}[*] pip missing. Attempting to install core python3-pip module...${RESET}"
    if command -v apt &> /dev/null; then
        apt update && apt install -y python3-pip
    elif command -v pacman &> /dev/null; then
        pacman -Syu --noconfirm python-pip
    fi
fi

# 3. Resolve Pip command wrapper variant
PIP_EXEC="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_EXEC="pip"
fi

# 4. Install Python manifest dependencies safely
echo -e "${BLUE}[*] Provisioning required Python libraries...${RESET}"
$PIP_EXEC install -r requirements.txt --break-system-packages 2>/dev/null || $PIP_EXEC install -r requirements.txt

# 5. Extract absolute deployment path folder
INSTALL_DIR=$(pwd)
WRAPPER_PATH="/usr/local/bin/KASCVE"

echo -e "${BLUE}[*] Compiling global executable wrapper link at ${WRAPPER_PATH}...${RESET}"

# Generate an atomic executable block linking back to your main architecture routing folder
cat << EOF > $WRAPPER_PATH
#!/bin/bash
python3 ${INSTALL_DIR}/main.py "\$@"
EOF

# Grant system execution permissions
chmod +x $WRAPPER_PATH
chmod +x main.py

echo -e "\n${GREEN}[+ ] KASCVE FRAMEWORK INSTALLATION SUCCESSFUL!${RESET}"
echo -e "${CYAN}    You can now audit targets from anywhere on the system using:${RESET}"
echo -e "${YELLOW}    KASCVE <target_domain.com>${RESET}\n"
