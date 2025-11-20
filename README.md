# VPS Security Assessment Toolkit
## Comprehensive Security Analysis with Detailed Logging

---

## 📋 Overview

This toolkit provides a comprehensive security assessment suite for analyzing your own VPS infrastructure. It includes automated scanning, vulnerability detection, authentication testing, and detailed reporting with full logging capabilities.

---

## 🚀 Quick Start

### Basic Usage
```bash
# 1. Run the main security audit
./vps_security_audit.sh YOUR_VPS_IP

# 2. (Optional) Run authentication testing
./auth_testing.sh YOUR_VPS_IP ./security_audit_YOUR_VPS_IP_TIMESTAMP

# 3. Analyze and generate reports
./analyze_results.sh ./security_audit_YOUR_VPS_IP_TIMESTAMP
```

### Example
```bash
# Scan VPS at 192.168.1.100
./vps_security_audit.sh 192.168.1.100

# This creates: security_audit_192.168.1.100_20241107_153045/
# Then analyze:
./analyze_results.sh security_audit_192.168.1.100_20241107_153045/
```

---

## 📦 Prerequisites

### Required Tools (Install on Kali Linux)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install required tools
sudo apt install -y nmap nikto gobuster sslscan hydra \
    curl wget netcat-traditional dnsutils \
    whatweb wafw00f dirb

# Optional but recommended
sudo apt install -y testssl.sh ssh-audit sqlmap \
    masscan exploitdb
```

### Verify Installation
```bash
# Check all tools are installed
which nmap nikto gobuster sslscan hydra curl
```

---

## 📁 Toolkit Components

### 1. vps_security_audit.sh
**Main comprehensive security scanner**

**What it does:**
- Network reconnaissance and port scanning
- Service detection and version identification
- Vulnerability scanning (CVE detection)
- SSH security analysis
- Web server analysis (headers, directories, WAF detection)
- SSL/TLS security testing
- Database security checks
- DNS enumeration
- Additional service testing (FTP, SMTP, RDP, etc.)
- Malware and backdoor detection
- Automated summary report generation

**Output Files:**
- `00_SUMMARY_REPORT.txt` - Executive summary
- `audit_log.txt` - Complete timestamped log
- `01_ping.txt` - Host reachability test
- `02_full_port_scan.txt` - Complete port scan results
- `06_vulnerability_scan.txt` - Vulnerability findings
- `10_ssh_config.txt` - SSH configuration analysis
- `14_nikto_*.txt` - Web vulnerability scans
- `18_sslscan_*.txt` - SSL/TLS analysis
- And many more detailed scan files...

**Runtime:** 15-30 minutes depending on target

### 2. auth_testing.sh
**Authentication and credential testing**

**What it does:**
- SSH brute force testing (limited attempts)
- Web admin panel discovery
- Database default credential testing
- FTP anonymous access testing
- Common password testing

**⚠️ Warning:** This script performs active authentication testing. Use responsibly!

**Output Files:**
- `auth_testing.log` - Complete authentication test log
- `ssh_auth_test.txt` - SSH authentication results
- `admin_panels.txt` - Discovered admin interfaces
- `mysql_anon_test.txt` - MySQL access test results

**Runtime:** 5-10 minutes

### 3. analyze_results.sh
**Results analyzer and report generator**

**What it does:**
- Parses all scan results
- Extracts and categorizes findings by severity
- Generates prioritized vulnerability list
- Creates HTML and text reports
- Provides actionable recommendations
- Security hardening checklist

**Output Files:**
- `ANALYZED_FINDINGS.html` - Beautiful HTML report (open in browser)
- `ANALYZED_FINDINGS.txt` - Text summary report

**Runtime:** < 1 minute

---

## 🎯 Scan Phases Explained

### Phase 1: Network Reconnaissance
- Host discovery (ICMP ping)
- Full TCP port scan (all 65535 ports)
- Service version detection
- OS fingerprinting
- UDP scan (top 100 ports)

**Log Example:**
```
[2024-11-07 15:30:45] === PHASE 1: NETWORK RECONNAISSANCE ===
[2024-11-07 15:30:45] [+] Running initial host discovery...
[2024-11-07 15:30:48] [✓] Host is reachable
[2024-11-07 15:30:48] [+] Performing comprehensive port scan...
```

### Phase 2: Vulnerability Scanning
- Nmap NSE vulnerability scripts
- CVE database matching
- SMB vulnerability checks
- Known exploit detection

**Log Example:**
```
[2024-11-07 15:35:12] === PHASE 2: VULNERABILITY SCANNING ===
[2024-11-07 15:35:12] [+] Running Nmap vulnerability scripts...
[2024-11-07 15:38:45] [!] Found potential vulnerability: CVE-2024-1234
```

### Phase 3: SSH Security Analysis
- Banner grabbing
- Supported algorithms enumeration
- Weak cipher detection
- Host key analysis
- Configuration audit

**Log Example:**
```
[2024-11-07 15:40:01] === PHASE 3: SSH SECURITY ANALYSIS ===
[2024-11-07 15:40:01] [+] SSH port is open, analyzing...
[2024-11-07 15:40:05] [!] WARNING: Weak encryption algorithm detected
```

### Phase 4: Web Server Analysis
- HTTP header analysis
- Directory enumeration
- WAF detection
- Web technology fingerprinting
- Common vulnerability scanning

**Log Example:**
```
[2024-11-07 15:45:20] === PHASE 4: WEB SERVER ANALYSIS ===
[2024-11-07 15:45:20] [+] http service detected on port 80
[2024-11-07 15:45:25] [+] Running Nikto web scanner on port 80...
[2024-11-07 15:50:12] [!] Found: /admin/ directory (Status: 200)
```

### Phase 5: SSL/TLS Security
- Certificate validation
- Protocol version support
- Cipher suite analysis
- Known SSL/TLS vulnerabilities
- Certificate expiration check

**Log Example:**
```
[2024-11-07 15:55:00] === PHASE 5: SSL/TLS SECURITY ANALYSIS ===
[2024-11-07 15:55:00] [+] Checking SSL/TLS on port 443...
[2024-11-07 15:55:45] [!] Certificate expires in 15 days
```

### Phase 6: Database Security
- MySQL/MariaDB detection
- PostgreSQL checks
- MongoDB security
- Redis configuration
- Default credential testing

### Phase 7: DNS Enumeration
- DNS resolution
- Reverse DNS lookup
- Zone transfer attempts
- DNS server enumeration

### Phase 8: Additional Services
- FTP security
- SMTP configuration
- RDP detection
- And more...

### Phase 9: Malware & Backdoor Detection
- Common backdoor port scanning
- Unusual port detection
- Suspicious service identification

### Phase 10: Summary Generation
- Consolidates all findings
- Generates recommendations
- Creates quick reference guide

---

## 📊 Understanding the Output

### Directory Structure
```
security_audit_192.168.1.100_20241107_153045/
├── 00_SUMMARY_REPORT.txt          # Start here!
├── audit_log.txt                   # Complete log with timestamps
├── QUICK_REFERENCE.txt             # Important files guide
├── 01_ping.txt                     # Connectivity test
├── 02_full_port_scan.txt          # All ports
├── 03_aggressive_scan.txt          # OS + service details
├── 06_vulnerability_scan.txt       # Vulnerabilities found
├── 10_ssh_config.txt              # SSH security
├── 14_nikto_80.txt                # Web vulnerabilities
├── 18_sslscan_443.txt             # SSL/TLS security
├── ANALYZED_FINDINGS.html          # Beautiful report (after analysis)
└── ANALYZED_FINDINGS.txt           # Text summary
```

### Log Format
Every entry includes:
- **Timestamp:** When the action occurred
- **Color coding:** Red (critical), Yellow (warning), Green (success), Blue (info)
- **Prefix:** [+] Action, [✓] Success, [!] Warning/Finding

Example:
```
[2024-11-07 15:30:45] [+] Running initial host discovery...
[2024-11-07 15:30:48] [✓] Host is reachable
[2024-11-07 15:35:12] [!] Found potential vulnerability: CVE-2024-1234
```

### Finding Severity Levels
- **CRITICAL** 🔴 - Immediate action required
- **HIGH** 🟠 - Address within 24-48 hours
- **MEDIUM** 🟡 - Address within 1 week
- **LOW** 🟢 - Address during next maintenance
- **INFO** 🔵 - Informational only

---

## 🔍 Quick Analysis Commands

### View All Critical Issues
```bash
grep -riE "CRITICAL|HIGH|VULNERABLE" security_audit_*/
```

### Count Open Ports
```bash
grep -c "open" security_audit_*/02_full_port_scan.txt
```

### List All Vulnerabilities
```bash
cat security_audit_*/06_vulnerability_scan.txt | grep -E "VULNERABLE|CVE"
```

### Check SSL/TLS Issues
```bash
cat security_audit_*/18_sslscan_*.txt | grep -i weak
```

### View Web Vulnerabilities
```bash
cat security_audit_*/14_nikto_*.txt | grep -E "OSVDB|CVE"
```

---

## ⚠️ Important Warnings

### Legal Considerations
1. **Only scan systems you own or have explicit permission to test**
2. **Notify your hosting provider before scanning** (some may flag aggressive scans)
3. **Authentication testing may trigger account lockouts**
4. **Keep logs secure** - they contain sensitive information

### Best Practices
1. Run scans during maintenance windows
2. Start with non-intrusive scans first
3. Monitor your VPS during scanning
4. Keep scan results confidential
5. Don't run scans from production systems

### Resource Usage
- Scans can be CPU and bandwidth intensive
- May trigger rate limiting or IDS alerts
- Can take 15-45 minutes for full scan
- Consider scanning during low-traffic periods

---

## 🛠️ Customization

### Modify Scan Intensity
Edit `vps_security_audit.sh`:

```bash
# Change from aggressive (-T4) to slower (-T2)
nmap -T2 "$TARGET" ...

# Scan fewer ports for faster results
nmap -p 21,22,80,443,3306 "$TARGET" ...

# Skip certain phases by commenting out
# log "=== PHASE 4: WEB SERVER ANALYSIS ===" "$BLUE"
```

### Add Custom Checks
Add your own tests to the script:

```bash
# Add after Phase 10
log "=== PHASE 11: CUSTOM CHECKS ===" "$BLUE"
log "[+] Running custom security check..." "$GREEN"
# Your custom commands here
```

### Adjust Authentication Testing
Edit `auth_testing.sh` to modify password lists or attempt limits:

```bash
# Add more common passwords
cat > /tmp/custom_passwords.txt << EOF
your_custom_passwords_here
EOF

# Reduce hydra threads (slower but stealthier)
hydra -t 2 -w 60 "$TARGET" ssh
```

---

## 📈 Interpreting Results

### Priority Actions Based on Findings

#### If you find open port 22 (SSH):
1. Change to key-only authentication
2. Change to non-standard port
3. Install fail2ban
4. Limit access by IP

#### If you find open database ports (3306, 5432):
1. Bind to localhost only
2. Use firewall to restrict access
3. Change default credentials
4. Enable SSL/TLS

#### If you find weak SSL/TLS:
1. Disable SSLv3, TLSv1.0, TLSv1.1
2. Use strong cipher suites only
3. Enable HSTS
4. Check certificate expiration

#### If you find web vulnerabilities:
1. Update web server and applications
2. Remove unnecessary files/directories
3. Implement WAF
4. Add security headers

---

## 🎓 Advanced Usage

### Continuous Monitoring
Set up automated weekly scans:

```bash
# Add to crontab (runs every Sunday at 2 AM)
0 2 * * 0 /path/to/vps_security_audit.sh YOUR_IP >> /var/log/security_scans.log 2>&1
```

### Compare Scans Over Time
```bash
# Compare two scan results
diff security_audit_IP_DATE1/00_SUMMARY_REPORT.txt \
     security_audit_IP_DATE2/00_SUMMARY_REPORT.txt
```

### Export Results
```bash
# Create PDF report (requires wkhtmltopdf)
wkhtmltopdf security_audit_*/ANALYZED_FINDINGS.html security_report.pdf

# Email results
mail -s "VPS Security Scan Results" you@example.com < security_audit_*/00_SUMMARY_REPORT.txt
```

### Integration with Other Tools
```bash
# Import nmap results into Metasploit
db_import security_audit_*/02_full_port_scan.xml

# Use with OpenVAS
# Import the host list for deeper scanning
```

---

## 🐛 Troubleshooting

### "Permission denied"
```bash
chmod +x *.sh
```

### "Command not found"
```bash
# Install missing tools
sudo apt install -y tool-name
```

### "Connection timeout"
```bash
# Check network connectivity
ping YOUR_VPS_IP

# Try with longer timeout
nmap -Pn --host-timeout 30m YOUR_VPS_IP
```

### Scans taking too long
```bash
# Use faster timing (-T4 instead of -T3)
# Scan fewer ports
# Skip resource-intensive phases
```

### No results in output files
```bash
# Check if target is reachable
# Verify you have write permissions
# Check available disk space: df -h
```

---

## 📚 Additional Resources

### Learning Resources
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- Nmap Documentation: https://nmap.org/book/
- PTES Technical Guidelines: http://www.pentest-standard.org/

### Security Tools
- Metasploit Framework
- Burp Suite
- OWASP ZAP
- Wireshark

### CVE Databases
- https://cve.mitre.org/
- https://nvd.nist.gov/
- https://www.exploit-db.com/

---

## 🔐 Post-Scan Hardening

After running scans, use these commands to harden your VPS:

### SSH Hardening
```bash
# Disable password authentication
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Change SSH port
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Restart SSH
sudo systemctl restart sshd
```

### Firewall Setup
```bash
# Install and enable UFW
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp  # SSH on custom port
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### Install Fail2ban
```bash
sudo apt install -y fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### Update System
```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
```

---

## 📝 Report Templates

### Executive Summary Template
```
Security Assessment Summary
Target: [IP Address]
Date: [Scan Date]
Severity: [Critical/High/Medium/Low]

Key Findings:
1. [Finding 1]
2. [Finding 2]
3. [Finding 3]

Immediate Actions Required:
1. [Action 1]
2. [Action 2]

Risk Level: [Low/Medium/High/Critical]
```

---

## 🤝 Support and Contributing

### Getting Help
- Review the audit_log.txt for detailed error messages
- Check tool installation: `which tool-name`
- Verify network connectivity
- Review scan output files

### Improving the Toolkit
Customize scripts for your specific needs:
1. Add additional security checks
2. Integrate with your monitoring tools
3. Customize reporting format
4. Add notification mechanisms

---

## ⏱️ Scan Duration Estimates

| Scan Type | Duration | Thoroughness |
|-----------|----------|--------------|
| Quick Scan (top 1000 ports) | 5-10 min | Basic |
| Standard Scan | 15-20 min | Good |
| Full Scan (all ports) | 30-45 min | Comprehensive |
| Full + Authentication Test | 45-60 min | Thorough |

---

## 🎯 Success Metrics

After implementing recommendations, re-run scans to verify:
- [ ] Reduced number of open ports
- [ ] No critical vulnerabilities
- [ ] Strong SSL/TLS configuration (A+ rating)
- [ ] No default credentials
- [ ] Firewall properly configured
- [ ] All services updated
- [ ] Security monitoring enabled

---

## 📞 Emergency Response

If you discover active exploitation:
1. **Isolate** the system immediately
2. **Document** everything (don't modify logs)
3. **Analyze** the breach scope
4. **Remediate** vulnerabilities
5. **Restore** from clean backups if necessary
6. **Monitor** for continued suspicious activity

---

**Remember:** Security is a continuous process, not a one-time task. Regular scanning and updates are essential for maintaining a secure VPS!

**Stay Safe! 🛡️**
