#!/bin/bash
# Comprehensive AI-Powered Security Scanner
# Uses Llama 3.1 70B for deep security analysis

set -e

MODEL="${OLLAMA_MODEL:-llama3.1:70b}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
REPORT_DIR="/home/ubuntu/security-reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
REPORT_FILE="$REPORT_DIR/security_analysis_$TIMESTAMP.md"

echo "================================================" | tee -a "$REPORT_FILE"
echo "  COMPREHENSIVE AI SECURITY SCAN" | tee -a "$REPORT_FILE"
echo "================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "# AI Security Analysis Report" >> "$REPORT_FILE"
echo "Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT_FILE"
echo "System Time: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$REPORT_FILE"
echo "Report File: $REPORT_FILE" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Function to query the AI
query_ai() {
    local prompt="$1"
    local section="$2"
    
    echo "## $section" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Analyzing: $section..."
    
    response=$(curl -s "$OLLAMA_HOST/api/generate" -d "{
        \"model\": \"$MODEL\",
        \"prompt\": \"$prompt\",
        \"stream\": false,
        \"options\": {
            \"temperature\": 0.3,
            \"top_p\": 0.9
        }
    }" | jq -r '.response')
    
    echo "$response" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# 1. System Security Audit
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Running System Security Audit..." | tee -a "$REPORT_FILE"
SYSTEM_INFO=$(cat <<EOF
Server Hostname: $(hostname)
Kernel Version: $(uname -r)
OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Uptime: $(uptime -p)

Listening Ports: $(ss -tulpn 2>/dev/null | grep LISTEN)

Active Services: $(systemctl list-units --type=service --state=running)

Firewall Status: $(ufw status verbose 2>/dev/null || iptables -L -n -v 2>/dev/null)

User Accounts: $(cat /etc/passwd | grep -v nologin | grep -v false)

Sudo Users: $(grep -Po '^sudo.+:\K.*$' /etc/group)

Recent Logins: $(last -n 50)

Failed Login Attempts: $(lastb -n 50 2>/dev/null || echo "No failed logins or no access")

Cron Jobs: $(for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done)
EOF
)

query_ai "You are a cybersecurity expert. Analyze this Linux server configuration for security vulnerabilities, misconfigurations, and suspicious activity. Provide specific, actionable recommendations:

$SYSTEM_INFO

Focus on:
1. Exposed services and ports
2. Unnecessary running services
3. Firewall configuration gaps
4. User account security
5. Login anomalies
6. Privilege escalation risks" "1. System Security Analysis"

# 2. Web Server Security
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing Web Server Security..." | tee -a "$REPORT_FILE"
WEB_CONFIGS=$(find /etc/nginx /etc/apache2 /etc/httpd -name "*.conf" 2>/dev/null | head -5)
if [ -n "$WEB_CONFIGS" ]; then
    WEB_DATA=""
    for conf in $WEB_CONFIGS; do
        WEB_DATA="$WEB_DATA\n\nFile: $conf\n$(cat "$conf" 2>/dev/null | head -100)"
    done
    
    query_ai "Analyze these web server configurations for security issues:

$WEB_DATA

Check for:
1. Missing security headers
2. SSL/TLS misconfigurations
3. Directory traversal risks
4. Information disclosure
5. Rate limiting
6. Authentication weaknesses" "2. Web Server Security"
fi

# 3. SSH Security
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing SSH Configuration..." | tee -a "$REPORT_FILE"
SSH_CONFIG=$(cat /etc/ssh/sshd_config 2>/dev/null || echo "SSH config not accessible")
SSH_KEYS=$(find /home -name "authorized_keys" 2>/dev/null | xargs cat 2>/dev/null | head -20)

query_ai "Analyze this SSH configuration for security risks:

SSH Config:
$SSH_CONFIG

Authorized Keys Found:
$SSH_KEYS

Evaluate:
1. Authentication methods
2. Root login settings
3. Password policies
4. Key management
5. Protocol versions
6. Port configuration" "3. SSH Security Analysis"

# 4. File System Security
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing File System Security..." | tee -a "$REPORT_FILE"
FILE_PERMS=$(find /home /var/www /etc -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -30)
WORLD_WRITABLE=$(find /var/www /home -type f -perm -002 2>/dev/null | head -20)

query_ai "Analyze these file system security findings:

SUID/SGID Files:
$FILE_PERMS

World-Writable Files:
$WORLD_WRITABLE

Assess:
1. Risky SUID/SGID binaries
2. World-writable file risks
3. Permission misconfigurations
4. Potential backdoors
5. Unusual file locations" "4. File System Security"

# 5. Network Security
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing Network Security..." | tee -a "$REPORT_FILE"
NETWORK_INFO=$(cat <<EOF
Active Connections: $(ss -tunap 2>/dev/null | head -30)

Routing Table: $(ip route)

DNS Configuration: $(cat /etc/resolv.conf)

Open Ports: $(ss -tulpn | grep LISTEN)
EOF
)

query_ai "Analyze this network configuration for security issues:

$NETWORK_INFO

Look for:
1. Suspicious connections
2. Unusual listening services
3. DNS security risks
4. Network exposure
5. Routing vulnerabilities" "5. Network Security Analysis"

# 6. Application Security
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing Applications..." | tee -a "$REPORT_FILE"
DOCKER_CONTAINERS=$(docker ps -a 2>/dev/null || echo "Docker not running")
NODE_APPS=$(find /home -name "package.json" 2>/dev/null | head -10)
PYTHON_APPS=$(find /home -name "requirements.txt" 2>/dev/null | head -10)

query_ai "Analyze the security of applications running on this server:

Docker Containers:
$DOCKER_CONTAINERS

Node.js Applications Found:
$NODE_APPS

Python Applications Found:
$PYTHON_APPS

Check for:
1. Container security
2. Exposed management interfaces
3. Dependency vulnerabilities
4. Configuration issues
5. Update requirements" "6. Application Security"

# 7. Log Analysis
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Analyzing Security Logs..." | tee -a "$REPORT_FILE"
AUTH_LOGS=$(tail -100 /var/log/auth.log 2>/dev/null || tail -100 /var/log/secure 2>/dev/null || echo "Auth logs not accessible")
SYSLOG=$(tail -50 /var/log/syslog 2>/dev/null || tail -50 /var/log/messages 2>/dev/null || echo "Syslog not accessible")

query_ai "Analyze these system logs for security incidents and anomalies:

Authentication Logs:
$AUTH_LOGS

System Logs:
$SYSLOG

Identify:
1. Brute force attempts
2. Unauthorized access
3. Privilege escalation
4. Suspicious commands
5. Error patterns
6. Potential compromises" "7. Log Analysis"

# 8. Generate Executive Summary
echo "[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] Generating Executive Summary..." | tee -a "$REPORT_FILE"
query_ai "Based on all the security analysis above, provide:

1. CRITICAL ISSUES - Immediate action required
2. HIGH PRIORITY - Fix within 24 hours
3. MEDIUM PRIORITY - Address this week
4. SECURITY SCORE - Rate overall security 1-10
5. QUICK WINS - Easy fixes with high impact
6. LONG-TERM RECOMMENDATIONS

Be specific with commands and configurations needed." "8. Executive Summary & Recommendations"

echo ""
echo "================================================" | tee -a "$REPORT_FILE"
echo "  SECURITY SCAN COMPLETE" | tee -a "$REPORT_FILE"
echo "================================================" | tee -a "$REPORT_FILE"
echo "Completed: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"
echo "View report: cat $REPORT_FILE"
echo "Or open with: nano $REPORT_FILE"
echo ""
echo "Latest reports:"
ls -lht "$REPORT_DIR"/security_analysis_*.md | head -5
