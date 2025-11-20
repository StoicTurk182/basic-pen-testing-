#!/bin/bash

# VPS Security Assessment Script
# Comprehensive security analysis with detailed logging
# Usage: ./vps_security_audit.sh <target-ip>

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if target IP is provided
if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <target-ip>${NC}"
    exit 1
fi

TARGET=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="security_audit_${TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/audit_log.txt"

# Logging function
log() {
    echo -e "${2}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "   VPS SECURITY ASSESSMENT TOOL"
    echo "   Target: $TARGET"
    echo "   Time: $(date)"
    echo "=========================================="
    echo -e "${NC}"
}

banner | tee "$LOG_FILE"

# 1. NETWORK RECONNAISSANCE
log "=== PHASE 1: NETWORK RECONNAISSANCE ===" "$BLUE"

log "[+] Running initial host discovery..." "$GREEN"
ping -c 3 "$TARGET" > "$OUTPUT_DIR/01_ping.txt" 2>&1
if [ $? -eq 0 ]; then
    log "[✓] Host is reachable" "$GREEN"
else
    log "[!] Host may be down or blocking ICMP" "$YELLOW"
fi

log "[+] Performing comprehensive port scan..." "$GREEN"
nmap -sV -sC -O -T4 -p- "$TARGET" -oN "$OUTPUT_DIR/02_full_port_scan.txt" -oX "$OUTPUT_DIR/02_full_port_scan.xml" 2>&1 | tee -a "$LOG_FILE"

log "[+] Running aggressive scan with OS detection..." "$GREEN"
nmap -A -T4 "$TARGET" -oN "$OUTPUT_DIR/03_aggressive_scan.txt" 2>&1 | tee -a "$LOG_FILE"

log "[+] Checking for common ports..." "$GREEN"
nmap -sV -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443 "$TARGET" -oN "$OUTPUT_DIR/04_common_ports.txt" 2>&1 | tee -a "$LOG_FILE"

log "[+] UDP scan (top 100 ports)..." "$GREEN"
nmap -sU --top-ports 100 "$TARGET" -oN "$OUTPUT_DIR/05_udp_scan.txt" 2>&1 | tee -a "$LOG_FILE"

# 2. VULNERABILITY SCANNING
log "=== PHASE 2: VULNERABILITY SCANNING ===" "$BLUE"

log "[+] Running Nmap vulnerability scripts..." "$GREEN"
nmap --script vuln "$TARGET" -oN "$OUTPUT_DIR/06_vulnerability_scan.txt" 2>&1 | tee -a "$LOG_FILE"

log "[+] Checking for common CVEs..." "$GREEN"
nmap --script vulners "$TARGET" -oN "$OUTPUT_DIR/07_cve_check.txt" 2>&1 | tee -a "$LOG_FILE"

log "[+] SMB vulnerability check..." "$GREEN"
nmap --script smb-vuln* -p 445 "$TARGET" -oN "$OUTPUT_DIR/08_smb_vulns.txt" 2>&1 | tee -a "$LOG_FILE"

# 3. SSH SECURITY ANALYSIS
log "=== PHASE 3: SSH SECURITY ANALYSIS ===" "$BLUE"

if nc -zv -w 3 "$TARGET" 22 2>&1 | grep -q succeeded; then
    log "[+] SSH port is open, analyzing..." "$GREEN"
    
    log "[+] SSH banner grabbing..." "$GREEN"
    nc -v -w 3 "$TARGET" 22 2>&1 | head -n 1 > "$OUTPUT_DIR/09_ssh_banner.txt"
    cat "$OUTPUT_DIR/09_ssh_banner.txt" | tee -a "$LOG_FILE"
    
    log "[+] SSH configuration analysis..." "$GREEN"
    nmap --script ssh2-enum-algos,ssh-auth-methods "$TARGET" -p 22 -oN "$OUTPUT_DIR/10_ssh_config.txt" 2>&1 | tee -a "$LOG_FILE"
    
    log "[+] Checking SSH host keys..." "$GREEN"
    nmap --script ssh-hostkey "$TARGET" -p 22 -oN "$OUTPUT_DIR/11_ssh_hostkey.txt" 2>&1 | tee -a "$LOG_FILE"
    
    # Check if ssh-audit is installed
    if command -v ssh-audit &> /dev/null; then
        log "[+] Running ssh-audit..." "$GREEN"
        ssh-audit "$TARGET" > "$OUTPUT_DIR/12_ssh_audit.txt" 2>&1
        cat "$OUTPUT_DIR/12_ssh_audit.txt" | tee -a "$LOG_FILE"
    else
        log "[!] ssh-audit not installed, skipping detailed SSH analysis" "$YELLOW"
    fi
else
    log "[!] SSH port (22) not accessible" "$YELLOW"
fi

# 4. WEB SERVER ANALYSIS
log "=== PHASE 4: WEB SERVER ANALYSIS ===" "$BLUE"

check_web_port() {
    PORT=$1
    PROTOCOL=$2
    
    if nc -zv -w 3 "$TARGET" "$PORT" 2>&1 | grep -q succeeded; then
        log "[+] $PROTOCOL service detected on port $PORT" "$GREEN"
        
        # HTTP headers
        log "[+] Grabbing HTTP headers..." "$GREEN"
        curl -I -s -L --max-time 10 "$PROTOCOL://$TARGET:$PORT" > "$OUTPUT_DIR/13_http_headers_${PORT}.txt" 2>&1
        cat "$OUTPUT_DIR/13_http_headers_${PORT}.txt" | tee -a "$LOG_FILE"
        
        # Nikto scan
        if command -v nikto &> /dev/null; then
            log "[+] Running Nikto web scanner on port $PORT..." "$GREEN"
            nikto -h "$PROTOCOL://$TARGET:$PORT" -o "$OUTPUT_DIR/14_nikto_${PORT}.txt" 2>&1 | tee -a "$LOG_FILE"
        else
            log "[!] Nikto not installed, skipping" "$YELLOW"
        fi
        
        # Directory enumeration
        if command -v gobuster &> /dev/null; then
            log "[+] Running directory enumeration on port $PORT..." "$GREEN"
            gobuster dir -u "$PROTOCOL://$TARGET:$PORT" -w /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/15_gobuster_${PORT}.txt" -q 2>&1 | tee -a "$LOG_FILE"
        elif command -v dirb &> /dev/null; then
            log "[+] Running dirb on port $PORT..." "$GREEN"
            dirb "$PROTOCOL://$TARGET:$PORT" /usr/share/wordlists/dirb/common.txt -o "$OUTPUT_DIR/15_dirb_${PORT}.txt" 2>&1 | tee -a "$LOG_FILE"
        else
            log "[!] No directory enumeration tool found" "$YELLOW"
        fi
        
        # WAF detection
        if command -v wafw00f &> /dev/null; then
            log "[+] Detecting WAF on port $PORT..." "$GREEN"
            wafw00f "$PROTOCOL://$TARGET:$PORT" > "$OUTPUT_DIR/16_waf_detect_${PORT}.txt" 2>&1
            cat "$OUTPUT_DIR/16_waf_detect_${PORT}.txt" | tee -a "$LOG_FILE"
        fi
        
        # Web application enumeration
        log "[+] Running whatweb on port $PORT..." "$GREEN"
        if command -v whatweb &> /dev/null; then
            whatweb -a 3 "$PROTOCOL://$TARGET:$PORT" > "$OUTPUT_DIR/17_whatweb_${PORT}.txt" 2>&1
            cat "$OUTPUT_DIR/17_whatweb_${PORT}.txt" | tee -a "$LOG_FILE"
        fi
        
        return 0
    fi
    return 1
}

check_web_port 80 "http"
check_web_port 443 "https"
check_web_port 8080 "http"
check_web_port 8443 "https"

# 5. SSL/TLS SECURITY
log "=== PHASE 5: SSL/TLS SECURITY ANALYSIS ===" "$BLUE"

check_ssl() {
    PORT=$1
    
    if nc -zv -w 3 "$TARGET" "$PORT" 2>&1 | grep -q succeeded; then
        log "[+] Checking SSL/TLS on port $PORT..." "$GREEN"
        
        if command -v sslscan &> /dev/null; then
            log "[+] Running sslscan..." "$GREEN"
            sslscan "$TARGET:$PORT" > "$OUTPUT_DIR/18_sslscan_${PORT}.txt" 2>&1
            cat "$OUTPUT_DIR/18_sslscan_${PORT}.txt" | tee -a "$LOG_FILE"
        fi
        
        if command -v testssl.sh &> /dev/null; then
            log "[+] Running testssl.sh (this may take a while)..." "$GREEN"
            testssl.sh --fast "$TARGET:$PORT" > "$OUTPUT_DIR/19_testssl_${PORT}.txt" 2>&1
            grep -E "VULNERABLE|HIGH|CRITICAL" "$OUTPUT_DIR/19_testssl_${PORT}.txt" | tee -a "$LOG_FILE"
        fi
        
        # OpenSSL certificate check
        log "[+] Checking SSL certificate..." "$GREEN"
        echo | openssl s_client -connect "$TARGET:$PORT" -servername "$TARGET" 2>/dev/null | openssl x509 -noout -text > "$OUTPUT_DIR/20_ssl_cert_${PORT}.txt" 2>&1
        
        # Extract key info
        echo "=== Certificate Details ===" | tee -a "$LOG_FILE"
        grep -E "Issuer:|Subject:|Not Before|Not After" "$OUTPUT_DIR/20_ssl_cert_${PORT}.txt" | tee -a "$LOG_FILE"
    fi
}

check_ssl 443
check_ssl 8443

# 6. DATABASE SECURITY
log "=== PHASE 6: DATABASE SECURITY ===" "$BLUE"

# MySQL/MariaDB
if nc -zv -w 3 "$TARGET" 3306 2>&1 | grep -q succeeded; then
    log "[+] MySQL/MariaDB detected on port 3306" "$GREEN"
    nmap --script mysql-* -p 3306 "$TARGET" -oN "$OUTPUT_DIR/21_mysql_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# PostgreSQL
if nc -zv -w 3 "$TARGET" 5432 2>&1 | grep -q succeeded; then
    log "[+] PostgreSQL detected on port 5432" "$GREEN"
    nmap --script pgsql-brute -p 5432 "$TARGET" -oN "$OUTPUT_DIR/22_pgsql_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# MongoDB
if nc -zv -w 3 "$TARGET" 27017 2>&1 | grep -q succeeded; then
    log "[+] MongoDB detected on port 27017" "$GREEN"
    nmap --script mongodb-* -p 27017 "$TARGET" -oN "$OUTPUT_DIR/23_mongodb_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# Redis
if nc -zv -w 3 "$TARGET" 6379 2>&1 | grep -q succeeded; then
    log "[+] Redis detected on port 6379" "$GREEN"
    nmap --script redis-info -p 6379 "$TARGET" -oN "$OUTPUT_DIR/24_redis_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# 7. DNS ENUMERATION
log "=== PHASE 7: DNS ENUMERATION ===" "$BLUE"

log "[+] DNS resolution..." "$GREEN"
host "$TARGET" > "$OUTPUT_DIR/25_dns_lookup.txt" 2>&1
cat "$OUTPUT_DIR/25_dns_lookup.txt" | tee -a "$LOG_FILE"

log "[+] Reverse DNS lookup..." "$GREEN"
dig -x "$TARGET" > "$OUTPUT_DIR/26_reverse_dns.txt" 2>&1
cat "$OUTPUT_DIR/26_reverse_dns.txt" | tee -a "$LOG_FILE"

if nc -zv -w 3 "$TARGET" 53 2>&1 | grep -q succeeded; then
    log "[+] DNS server detected, enumerating..." "$GREEN"
    nmap --script dns-* -p 53 "$TARGET" -oN "$OUTPUT_DIR/27_dns_enum.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# 8. ADDITIONAL SERVICES
log "=== PHASE 8: ADDITIONAL SERVICE CHECKS ===" "$BLUE"

# FTP
if nc -zv -w 3 "$TARGET" 21 2>&1 | grep -q succeeded; then
    log "[+] FTP detected on port 21" "$GREEN"
    nmap --script ftp-* -p 21 "$TARGET" -oN "$OUTPUT_DIR/28_ftp_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# SMTP
if nc -zv -w 3 "$TARGET" 25 2>&1 | grep -q succeeded; then
    log "[+] SMTP detected on port 25" "$GREEN"
    nmap --script smtp-* -p 25 "$TARGET" -oN "$OUTPUT_DIR/29_smtp_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# RDP
if nc -zv -w 3 "$TARGET" 3389 2>&1 | grep -q succeeded; then
    log "[+] RDP detected on port 3389" "$GREEN"
    nmap --script rdp-* -p 3389 "$TARGET" -oN "$OUTPUT_DIR/30_rdp_scan.txt" 2>&1 | tee -a "$LOG_FILE"
fi

# 9. MALWARE & BACKDOOR DETECTION
log "=== PHASE 9: MALWARE & BACKDOOR DETECTION ===" "$BLUE"

log "[+] Scanning for common backdoor ports..." "$GREEN"
nmap -p 1337,4444,5555,6666,31337,12345 "$TARGET" -oN "$OUTPUT_DIR/31_backdoor_ports.txt" 2>&1 | tee -a "$LOG_FILE"

log "[+] Checking for unusual open ports..." "$GREEN"
nmap -p- --open "$TARGET" -oN "$OUTPUT_DIR/32_all_open_ports.txt" 2>&1 | tee -a "$LOG_FILE"

# 10. SUMMARY REPORT
log "=== PHASE 10: GENERATING SUMMARY REPORT ===" "$BLUE"

SUMMARY="$OUTPUT_DIR/00_SUMMARY_REPORT.txt"

cat > "$SUMMARY" << EOF
=====================================
VPS SECURITY ASSESSMENT SUMMARY
=====================================
Target: $TARGET
Scan Date: $(date)
Scan Duration: ${SECONDS}s

EOF

echo "=== OPEN PORTS ===" >> "$SUMMARY"
grep "open" "$OUTPUT_DIR/02_full_port_scan.txt" | grep -v "filtered" >> "$SUMMARY" 2>/dev/null
echo "" >> "$SUMMARY"

echo "=== DETECTED SERVICES ===" >> "$SUMMARY"
grep "Service Info:" "$OUTPUT_DIR/02_full_port_scan.txt" >> "$SUMMARY" 2>/dev/null
echo "" >> "$SUMMARY"

echo "=== CRITICAL FINDINGS ===" >> "$SUMMARY"
for file in "$OUTPUT_DIR"/*.txt; do
    grep -iE "CRITICAL|VULNERABLE|HIGH RISK|CVE-[0-9]+" "$file" >> "$SUMMARY" 2>/dev/null
done
echo "" >> "$SUMMARY"

echo "=== RECOMMENDATIONS ===" >> "$SUMMARY"
cat >> "$SUMMARY" << EOF

1. Close unnecessary ports and services
2. Update all software to latest versions
3. Implement strong authentication (SSH keys only)
4. Enable and configure firewall (ufw/iptables)
5. Install fail2ban or similar IDS/IPS
6. Use strong SSL/TLS configurations
7. Regular security updates and monitoring
8. Implement log monitoring and alerting
9. Use non-standard ports where possible
10. Regular backup procedures

EOF

cat "$SUMMARY" | tee -a "$LOG_FILE"

# Final output
log "=== ASSESSMENT COMPLETE ===" "$GREEN"
log "Results saved to: $OUTPUT_DIR" "$GREEN"
log "Summary report: $SUMMARY" "$GREEN"
log "Full log: $LOG_FILE" "$GREEN"

echo -e "${BLUE}"
echo "=========================================="
echo "   SCAN COMPLETED SUCCESSFULLY"
echo "   Total time: ${SECONDS}s"
echo "=========================================="
echo -e "${NC}"

# Create a quick reference file
cat > "$OUTPUT_DIR/QUICK_REFERENCE.txt" << EOF
Quick Reference - Important Files:
====================================
00_SUMMARY_REPORT.txt - Executive summary
audit_log.txt - Complete scan log
02_full_port_scan.txt - All open ports
06_vulnerability_scan.txt - Vulnerabilities found
14_nikto_*.txt - Web vulnerabilities
18_sslscan_*.txt - SSL/TLS issues

Run this command to view all HIGH/CRITICAL issues:
grep -riE "CRITICAL|HIGH|VULNERABLE" $OUTPUT_DIR/

EOF

log "[+] Quick reference guide created" "$GREEN"
