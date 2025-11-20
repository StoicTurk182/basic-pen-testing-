#!/bin/bash

# VPS Security Toolkit - Automated Tool Installer
# Installs all required tools for security assessment
# For Kali Linux / Debian-based systems

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════╗
║   VPS Security Toolkit - Tool Installer      ║
║   Installing required security tools...      ║
╚═══════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root (use sudo)${NC}"
    exit 1
fi

log() {
    echo -e "${2}[$(date +'%H:%M:%S')] $1${NC}"
}

check_tool() {
    if command -v "$1" &> /dev/null; then
        log "[✓] $1 is already installed" "$GREEN"
        return 0
    else
        log "[ ] $1 not found, will install..." "$YELLOW"
        return 1
    fi
}

log "Updating package lists..." "$BLUE"
apt update -qq

log "" ""
log "=== Core Scanning Tools ===" "$BLUE"

# Nmap
if ! check_tool nmap; then
    log "[+] Installing nmap..." "$GREEN"
    apt install -y nmap > /dev/null 2>&1 && log "[✓] nmap installed" "$GREEN"
fi

# Netcat
if ! check_tool nc; then
    log "[+] Installing netcat..." "$GREEN"
    apt install -y netcat-traditional > /dev/null 2>&1 && log "[✓] netcat installed" "$GREEN"
fi

# Curl
if ! check_tool curl; then
    log "[+] Installing curl..." "$GREEN"
    apt install -y curl > /dev/null 2>&1 && log "[✓] curl installed" "$GREEN"
fi

# Wget
if ! check_tool wget; then
    log "[+] Installing wget..." "$GREEN"
    apt install -y wget > /dev/null 2>&1 && log "[✓] wget installed" "$GREEN"
fi

log "" ""
log "=== Web Scanning Tools ===" "$BLUE"

# Nikto
if ! check_tool nikto; then
    log "[+] Installing nikto..." "$GREEN"
    apt install -y nikto > /dev/null 2>&1 && log "[✓] nikto installed" "$GREEN"
fi

# Gobuster
if ! check_tool gobuster; then
    log "[+] Installing gobuster..." "$GREEN"
    apt install -y gobuster > /dev/null 2>&1 && log "[✓] gobuster installed" "$GREEN"
fi

# Dirb
if ! check_tool dirb; then
    log "[+] Installing dirb..." "$GREEN"
    apt install -y dirb > /dev/null 2>&1 && log "[✓] dirb installed" "$GREEN"
fi

# WhatWeb
if ! check_tool whatweb; then
    log "[+] Installing whatweb..." "$GREEN"
    apt install -y whatweb > /dev/null 2>&1 && log "[✓] whatweb installed" "$GREEN"
fi

# Wafw00f
if ! check_tool wafw00f; then
    log "[+] Installing wafw00f..." "$GREEN"
    apt install -y wafw00f > /dev/null 2>&1 && log "[✓] wafw00f installed" "$GREEN"
fi

log "" ""
log "=== SSL/TLS Testing Tools ===" "$BLUE"

# SSLScan
if ! check_tool sslscan; then
    log "[+] Installing sslscan..." "$GREEN"
    apt install -y sslscan > /dev/null 2>&1 && log "[✓] sslscan installed" "$GREEN"
fi

# TestSSL
if ! check_tool testssl.sh; then
    log "[+] Installing testssl.sh..." "$GREEN"
    if [ -f "/usr/bin/testssl" ] || [ -f "/usr/bin/testssl.sh" ]; then
        apt install -y testssl.sh > /dev/null 2>&1 && log "[✓] testssl.sh installed" "$GREEN"
    else
        log "[!] testssl.sh not in repos, installing from GitHub..." "$YELLOW"
        cd /opt
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git > /dev/null 2>&1
        ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
        chmod +x /opt/testssl.sh/testssl.sh
        log "[✓] testssl.sh installed from source" "$GREEN"
        cd - > /dev/null
    fi
fi

log "" ""
log "=== Authentication Testing Tools ===" "$BLUE"

# Hydra
if ! check_tool hydra; then
    log "[+] Installing hydra..." "$GREEN"
    apt install -y hydra > /dev/null 2>&1 && log "[✓] hydra installed" "$GREEN"
fi

log "" ""
log "=== DNS Tools ===" "$BLUE"

# Dig
if ! check_tool dig; then
    log "[+] Installing dnsutils..." "$GREEN"
    apt install -y dnsutils > /dev/null 2>&1 && log "[✓] dnsutils installed" "$GREEN"
fi

# Host
if ! check_tool host; then
    log "[+] Installing host..." "$GREEN"
    apt install -y host > /dev/null 2>&1 && log "[✓] host installed" "$GREEN"
fi

log "" ""
log "=== Database Tools ===" "$BLUE"

# MySQL Client
if ! check_tool mysql; then
    log "[+] Installing mysql-client..." "$GREEN"
    apt install -y mysql-client > /dev/null 2>&1 && log "[✓] mysql-client installed" "$GREEN"
fi

log "" ""
log "=== Optional Advanced Tools ===" "$BLUE"

# SQLmap
if ! check_tool sqlmap; then
    log "[+] Installing sqlmap..." "$YELLOW"
    apt install -y sqlmap > /dev/null 2>&1 && log "[✓] sqlmap installed" "$GREEN"
fi

# SSH-Audit
if ! check_tool ssh-audit; then
    log "[+] Installing ssh-audit..." "$YELLOW"
    if apt install -y ssh-audit > /dev/null 2>&1; then
        log "[✓] ssh-audit installed" "$GREEN"
    else
        log "[!] ssh-audit not available in repos, installing via pip..." "$YELLOW"
        apt install -y python3-pip > /dev/null 2>&1
        pip3 install ssh-audit > /dev/null 2>&1 && log "[✓] ssh-audit installed via pip" "$GREEN"
    fi
fi

# Masscan (for very fast scanning)
if ! check_tool masscan; then
    log "[+] Installing masscan..." "$YELLOW"
    apt install -y masscan > /dev/null 2>&1 && log "[✓] masscan installed" "$GREEN"
fi

log "" ""
log "=== Installing Wordlists ===" "$BLUE"

# SecLists
if [ ! -d "/usr/share/wordlists/seclists" ]; then
    log "[+] Installing SecLists..." "$GREEN"
    apt install -y seclists > /dev/null 2>&1 && log "[✓] SecLists installed" "$GREEN"
fi

# Check if dirb wordlists exist
if [ ! -d "/usr/share/wordlists/dirb" ]; then
    log "[!] Dirb wordlists not found, installing..." "$YELLOW"
    apt install -y dirb > /dev/null 2>&1
fi

log "" ""
log "=== Verification ===" "$BLUE"

MISSING_TOOLS=()
REQUIRED_TOOLS=(nmap nc curl nikto gobuster sslscan hydra dig)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
        log "[✗] $tool is still missing!" "$RED"
    else
        log "[✓] $tool verified" "$GREEN"
    fi
done

log "" ""
if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
    log "=== Installation Complete! ===" "$GREEN"
    log "All required tools are installed and ready to use." "$GREEN"
    log "" ""
    log "You can now run:" "$BLUE"
    log "  ./vps_security_audit.sh YOUR_VPS_IP" "$BLUE"
    log "" ""
else
    log "=== Installation Incomplete ===" "$YELLOW"
    log "The following tools are still missing:" "$YELLOW"
    for tool in "${MISSING_TOOLS[@]}"; do
        log "  - $tool" "$RED"
    done
    log "" ""
    log "Try installing them manually:" "$YELLOW"
    log "  sudo apt install ${MISSING_TOOLS[*]}" "$YELLOW"
fi

# Display tool versions
log "" ""
log "=== Installed Tool Versions ===" "$BLUE"
echo "Nmap: $(nmap --version 2>/dev/null | head -n1)"
echo "Nikto: $(nikto -Version 2>/dev/null | grep 'Nikto' | head -n1)"
echo "Hydra: $(hydra -V 2>/dev/null | head -n1)"
echo "SSLScan: $(sslscan --version 2>/dev/null | head -n1)"
echo "Gobuster: $(gobuster version 2>/dev/null | head -n1)"

log "" ""
log "=== Next Steps ===" "$BLUE"
cat << EOF
1. Review the README.md file for usage instructions
2. Test the toolkit: ./vps_security_audit.sh --help
3. Run a scan: ./vps_security_audit.sh YOUR_VPS_IP
4. Analyze results: ./analyze_results.sh OUTPUT_DIRECTORY

For help, see: cat README.md
EOF

log "" ""
log "Installation script completed!" "$GREEN"
