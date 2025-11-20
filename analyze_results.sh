#!/bin/bash

# Security Assessment Results Analyzer
# Parses scan results and generates prioritized findings
# Usage: ./analyze_results.sh <scan-directory>

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ -z "$1" ]; then
    echo -e "${RED}[!] Usage: $0 <scan-directory>${NC}"
    exit 1
fi

SCAN_DIR=$1
REPORT="$SCAN_DIR/ANALYZED_FINDINGS.html"

if [ ! -d "$SCAN_DIR" ]; then
    echo -e "${RED}[!] Directory not found: $SCAN_DIR${NC}"
    exit 1
fi

echo -e "${BLUE}[+] Analyzing security assessment results...${NC}"

# Create HTML report
cat > "$REPORT" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VPS Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        h2 { color: #555; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 30px; }
        .critical { background: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }
        .high { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }
        .medium { background: #fff9c4; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        .low { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 10px; margin: 10px 0; }
        .info { background: #e3f2fd; border-left: 4px solid #2196f3; padding: 10px; margin: 10px 0; }
        .stat { display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #f0f0f0; border-radius: 5px; }
        .stat-label { font-size: 12px; color: #666; }
        .stat-value { font-size: 24px; font-weight: bold; color: #333; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 3px; font-family: monospace; overflow-x: auto; }
        .recommendation { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 10px 0; }
        .timestamp { color: #999; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 VPS Security Assessment Report</h1>
        <p class="timestamp">Generated: DATE_PLACEHOLDER</p>
        <p><strong>Target:</strong> TARGET_PLACEHOLDER</p>
EOF

# Add statistics
cat >> "$REPORT" << EOF
        <div style="margin: 20px 0;">
            <div class="stat">
                <div class="stat-label">Open Ports</div>
                <div class="stat-value" style="color: #2196f3;">OPEN_PORTS_COUNT</div>
            </div>
            <div class="stat">
                <div class="stat-label">Critical Issues</div>
                <div class="stat-value" style="color: #f44336;">CRITICAL_COUNT</div>
            </div>
            <div class="stat">
                <div class="stat-label">High Issues</div>
                <div class="stat-value" style="color: #ff9800;">HIGH_COUNT</div>
            </div>
            <div class="stat">
                <div class="stat-label">Services Detected</div>
                <div class="stat-value" style="color: #4caf50;">SERVICES_COUNT</div>
            </div>
        </div>

        <h2>🎯 Executive Summary</h2>
        <div class="info">
EOF

# Count findings
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
OPEN_PORTS=0
SERVICES=0

# Extract information
if [ -f "$SCAN_DIR/02_full_port_scan.txt" ]; then
    OPEN_PORTS=$(grep -c "open" "$SCAN_DIR/02_full_port_scan.txt" 2>/dev/null || echo "0")
    SERVICES=$(grep -c "Service Info:" "$SCAN_DIR/02_full_port_scan.txt" 2>/dev/null || echo "0")
fi

# Count critical issues
CRITICAL_COUNT=$(grep -riE "CRITICAL|VULNERABLE.*HIGH" "$SCAN_DIR" 2>/dev/null | wc -l)
HIGH_COUNT=$(grep -riE "HIGH RISK|CVE-[0-9]{4}-[0-9]+" "$SCAN_DIR" 2>/dev/null | wc -l)

# Update statistics in report
sed -i "s/OPEN_PORTS_COUNT/$OPEN_PORTS/" "$REPORT"
sed -i "s/CRITICAL_COUNT/$CRITICAL_COUNT/" "$REPORT"
sed -i "s/HIGH_COUNT/$HIGH_COUNT/" "$REPORT"
sed -i "s/SERVICES_COUNT/$SERVICES/" "$REPORT"
sed -i "s/DATE_PLACEHOLDER/$(date)/" "$REPORT"

# Get target from directory name
TARGET=$(echo "$SCAN_DIR" | grep -oP 'security_audit_\K[^_]+' || echo "Unknown")
sed -i "s/TARGET_PLACEHOLDER/$TARGET/" "$REPORT"

cat >> "$REPORT" << EOF
            <p>Security assessment completed with $OPEN_PORTS open ports identified and $SERVICES services detected.</p>
            <p><strong>Critical Findings:</strong> $CRITICAL_COUNT | <strong>High Risk:</strong> $HIGH_COUNT</p>
        </div>

        <h2>🚨 Critical Findings</h2>
EOF

# Extract critical findings
echo '<div class="critical">' >> "$REPORT"
grep -riE "CRITICAL|VULNERABLE.*HIGH" "$SCAN_DIR" 2>/dev/null | head -20 | while read -r line; do
    echo "<p>• $(echo "$line" | cut -d: -f2-)</p>" >> "$REPORT"
done
if [ $CRITICAL_COUNT -eq 0 ]; then
    echo "<p>✓ No critical vulnerabilities detected</p>" >> "$REPORT"
fi
echo '</div>' >> "$REPORT"

# High risk findings
cat >> "$REPORT" << EOF
        <h2>⚠️ High Risk Findings</h2>
        <div class="high">
EOF

grep -riE "HIGH|CVE-[0-9]{4}" "$SCAN_DIR" 2>/dev/null | grep -v "CRITICAL" | head -20 | while read -r line; do
    echo "<p>• $(echo "$line" | cut -d: -f2-)</p>" >> "$REPORT"
done
if [ $HIGH_COUNT -eq 0 ]; then
    echo "<p>✓ No high-risk issues detected</p>" >> "$REPORT"
fi
echo '</div>' >> "$REPORT"

# Open Ports table
cat >> "$REPORT" << EOF
        <h2>🔓 Open Ports and Services</h2>
        <table>
            <tr>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
EOF

if [ -f "$SCAN_DIR/02_full_port_scan.txt" ]; then
    grep "open" "$SCAN_DIR/02_full_port_scan.txt" | while read -r line; do
        PORT=$(echo "$line" | awk '{print $1}')
        STATE=$(echo "$line" | awk '{print $2}')
        SERVICE=$(echo "$line" | awk '{print $3}')
        VERSION=$(echo "$line" | cut -d' ' -f4-)
        echo "<tr><td>$PORT</td><td>$STATE</td><td>$SERVICE</td><td>$VERSION</td></tr>" >> "$REPORT"
    done
fi

cat >> "$REPORT" << EOF
        </table>

        <h2>🔐 SSL/TLS Security</h2>
EOF

if [ -f "$SCAN_DIR"/18_sslscan_*.txt ]; then
    echo '<div class="info">' >> "$REPORT"
    grep -iE "TLS|SSL|Protocol|Cipher" "$SCAN_DIR"/18_sslscan_*.txt | head -15 | while read -r line; do
        echo "<p>$line</p>" >> "$REPORT"
    done
    echo '</div>' >> "$REPORT"
else
    echo '<div class="info"><p>No SSL/TLS services detected</p></div>' >> "$REPORT"
fi

# Recommendations
cat >> "$REPORT" << 'EOF'
        <h2>✅ Security Recommendations</h2>
        
        <div class="recommendation">
            <h3>Immediate Actions (Critical Priority)</h3>
            <ol>
                <li><strong>Close unnecessary ports:</strong> Only keep essential services exposed</li>
                <li><strong>Update all software:</strong> Apply security patches immediately</li>
                <li><strong>Strong authentication:</strong> Implement SSH key-only access, disable password auth</li>
                <li><strong>Firewall configuration:</strong> Use ufw/iptables with default-deny policy</li>
            </ol>
        </div>

        <div class="recommendation">
            <h3>Short-term Actions (Within 1 week)</h3>
            <ol>
                <li><strong>Install fail2ban:</strong> Protect against brute-force attacks</li>
                <li><strong>SSL/TLS hardening:</strong> Disable weak protocols and ciphers</li>
                <li><strong>Change default ports:</strong> Move SSH to non-standard port</li>
                <li><strong>Regular updates:</strong> Enable automatic security updates</li>
                <li><strong>Monitoring:</strong> Set up log monitoring and alerting</li>
            </ol>
        </div>

        <div class="recommendation">
            <h3>Long-term Security Posture</h3>
            <ol>
                <li><strong>Regular audits:</strong> Run security scans monthly</li>
                <li><strong>Backup strategy:</strong> Automated, encrypted, off-site backups</li>
                <li><strong>IDS/IPS:</strong> Deploy intrusion detection systems</li>
                <li><strong>WAF implementation:</strong> Web Application Firewall for web services</li>
                <li><strong>Security headers:</strong> Implement HSTS, CSP, X-Frame-Options</li>
                <li><strong>Least privilege:</strong> Run services with minimal required permissions</li>
                <li><strong>Security training:</strong> Keep team updated on security best practices</li>
            </ol>
        </div>

        <h2>📋 Detailed Scan Files</h2>
        <div class="info">
            <p>Complete scan results are available in the following files:</p>
            <ul>
                <li><strong>00_SUMMARY_REPORT.txt</strong> - Quick overview</li>
                <li><strong>audit_log.txt</strong> - Complete execution log</li>
                <li><strong>02_full_port_scan.txt</strong> - All port scan results</li>
                <li><strong>06_vulnerability_scan.txt</strong> - Vulnerability details</li>
                <li><strong>14_nikto_*.txt</strong> - Web vulnerability scans</li>
                <li><strong>18_sslscan_*.txt</strong> - SSL/TLS analysis</li>
            </ul>
        </div>

        <h2>🛡️ Security Hardening Checklist</h2>
        <table>
            <tr>
                <th>Item</th>
                <th>Status</th>
                <th>Priority</th>
            </tr>
            <tr><td>SSH key-only authentication</td><td>⬜ To Do</td><td>Critical</td></tr>
            <tr><td>Firewall configured and active</td><td>⬜ To Do</td><td>Critical</td></tr>
            <tr><td>Fail2ban or similar IPS installed</td><td>⬜ To Do</td><td>High</td></tr>
            <tr><td>All services up-to-date</td><td>⬜ To Do</td><td>Critical</td></tr>
            <tr><td>Strong SSL/TLS configuration</td><td>⬜ To Do</td><td>High</td></tr>
            <tr><td>Non-standard SSH port</td><td>⬜ To Do</td><td>Medium</td></tr>
            <tr><td>Automated backups configured</td><td>⬜ To Do</td><td>High</td></tr>
            <tr><td>Log monitoring enabled</td><td>⬜ To Do</td><td>Medium</td></tr>
            <tr><td>Unnecessary services disabled</td><td>⬜ To Do</td><td>High</td></tr>
            <tr><td>Security updates automated</td><td>⬜ To Do</td><td>High</td></tr>
        </table>

        <div style="margin-top: 50px; padding: 20px; background: #f9f9f9; border-radius: 5px; text-align: center;">
            <p style="color: #666;">Security is a continuous process, not a one-time event.</p>
            <p style="color: #666;">Regular monitoring and updates are essential for maintaining security.</p>
        </div>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}[+] Analysis complete!${NC}"
echo -e "${GREEN}[+] HTML report generated: $REPORT${NC}"

# Generate text summary as well
TEXT_SUMMARY="$SCAN_DIR/ANALYZED_FINDINGS.txt"
cat > "$TEXT_SUMMARY" << EOF
=====================================
VPS SECURITY ASSESSMENT ANALYSIS
=====================================
Generated: $(date)
Target: $TARGET

STATISTICS:
-----------
Open Ports: $OPEN_PORTS
Services: $SERVICES
Critical Issues: $CRITICAL_COUNT
High Risk Issues: $HIGH_COUNT

CRITICAL FINDINGS:
------------------
EOF

grep -riE "CRITICAL|VULNERABLE.*HIGH" "$SCAN_DIR" 2>/dev/null | head -20 >> "$TEXT_SUMMARY"

cat >> "$TEXT_SUMMARY" << EOF

HIGH RISK FINDINGS:
-------------------
EOF

grep -riE "HIGH|CVE-[0-9]{4}" "$SCAN_DIR" 2>/dev/null | grep -v "CRITICAL" | head -20 >> "$TEXT_SUMMARY"

cat >> "$TEXT_SUMMARY" << EOF

IMMEDIATE ACTIONS REQUIRED:
---------------------------
1. Review all CRITICAL findings above
2. Close unnecessary open ports
3. Update all software to latest versions
4. Implement SSH key-only authentication
5. Configure and enable firewall

For complete details, see: $REPORT
EOF

echo -e "${GREEN}[+] Text summary: $TEXT_SUMMARY${NC}"
echo -e "${BLUE}[+] Open the HTML report in a browser for best viewing experience${NC}"
