#!/bin/bash

# Advanced Authentication Testing Script
# Tests for weak credentials and authentication bypass
# Usage: ./auth_testing.sh <target-ip> <output-dir>

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -z "$1" ] || [ -z "$2" ]; then
    echo -e "${RED}[!] Usage: $0 <target-ip> <output-dir>${NC}"
    exit 1
fi

TARGET=$1
OUTPUT_DIR=$2
LOG_FILE="$OUTPUT_DIR/auth_testing.log"

log() {
    echo -e "${2}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

log "=== AUTHENTICATION SECURITY TESTING ===" "$GREEN"

# SSH Brute Force Testing (limited attempts)
if nc -zv -w 3 "$TARGET" 22 2>&1 | grep -q succeeded; then
    log "[+] Testing SSH authentication..." "$GREEN"
    
    # Create a small test wordlist with common passwords
    cat > /tmp/common_passwords.txt << EOF
admin
password
123456
root
toor
admin123
password123
changeme
EOF

    log "[+] Testing common usernames with weak passwords..." "$YELLOW"
    
    if command -v hydra &> /dev/null; then
        # Test very limited attempts to avoid account lockout
        hydra -L /tmp/common_passwords.txt -P /tmp/common_passwords.txt -t 4 -w 30 "$TARGET" ssh -o "$OUTPUT_DIR/ssh_auth_test.txt" 2>&1 | tee -a "$LOG_FILE"
    else
        log "[!] Hydra not installed, skipping SSH brute force" "$YELLOW"
    fi
    
    rm /tmp/common_passwords.txt
fi

# Web Form Authentication Testing
for PORT in 80 443 8080 8443; do
    if nc -zv -w 3 "$TARGET" "$PORT" 2>&1 | grep -q succeeded; then
        PROTOCOL="http"
        [ "$PORT" = "443" ] || [ "$PORT" = "8443" ] && PROTOCOL="https"
        
        log "[+] Checking for admin panels on port $PORT..." "$GREEN"
        
        # Common admin panel paths
        ADMIN_PATHS=(
            "/admin"
            "/administrator"
            "/wp-admin"
            "/phpmyadmin"
            "/cpanel"
            "/webmail"
            "/login"
            "/admin.php"
            "/wp-login.php"
        )
        
        for PATH in "${ADMIN_PATHS[@]}"; do
            STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PROTOCOL://$TARGET:$PORT$PATH" --max-time 5)
            if [ "$STATUS" = "200" ] || [ "$STATUS" = "301" ] || [ "$STATUS" = "302" ]; then
                log "[!] Found: $PROTOCOL://$TARGET:$PORT$PATH (Status: $STATUS)" "$YELLOW"
                echo "$PROTOCOL://$TARGET:$PORT$PATH" >> "$OUTPUT_DIR/admin_panels.txt"
            fi
        done
    fi
done

# Database Authentication Testing
if nc -zv -w 3 "$TARGET" 3306 2>&1 | grep -q succeeded; then
    log "[+] Testing MySQL default credentials..." "$GREEN"
    
    # Try common MySQL credentials
    mysql -h "$TARGET" -u root -p'' -e "SELECT VERSION();" > "$OUTPUT_DIR/mysql_anon_test.txt" 2>&1
    if [ $? -eq 0 ]; then
        log "[!] CRITICAL: MySQL allows anonymous root access!" "$RED"
    fi
fi

# FTP Anonymous Access
if nc -zv -w 3 "$TARGET" 21 2>&1 | grep -q succeeded; then
    log "[+] Testing FTP anonymous access..." "$GREEN"
    
    if command -v ftp &> /dev/null; then
        echo "anonymous
anonymous
ls
bye" | ftp -n "$TARGET" > "$OUTPUT_DIR/ftp_anon_test.txt" 2>&1
        
        if grep -q "230" "$OUTPUT_DIR/ftp_anon_test.txt"; then
            log "[!] WARNING: FTP allows anonymous access!" "$RED"
        fi
    fi
fi

log "[+] Authentication testing complete" "$GREEN"
log "[+] Results saved to: $OUTPUT_DIR" "$GREEN"
