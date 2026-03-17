# AI Security Scanner for Windows
# Comprehensive security analysis using local AI

#Requires -RunAsAdministrator

$MODEL = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "llama3.1:70b" }
$OLLAMA_HOST = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST.TrimEnd('/') } else { "http://localhost:11434" }
$REPORT_DIR = "$env:USERPROFILE\Documents\SecurityReports"
New-Item -ItemType Directory -Force -Path $REPORT_DIR | Out-Null

$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$REPORT_FILE = "$REPORT_DIR\security_analysis_$TIMESTAMP.md"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  COMPREHENSIVE AI SECURITY SCAN" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Initialize report
@"
# AI Security Analysis Report - Windows

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC") UTC
System Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Computer: $env:COMPUTERNAME
Report File: $REPORT_FILE

"@ | Out-File -FilePath $REPORT_FILE -Encoding UTF8

# Function to query AI
function Query-AI {
    param(
        [string]$Prompt,
        [string]$Section
    )
    
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing: $Section..." -ForegroundColor Yellow
    
    "`n## $Section`n" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
    
    $body = @{
        model = $MODEL
        prompt = $Prompt
        stream = $false
        options = @{
            temperature = 0.3
            top_p = 0.9
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        $response = Invoke-RestMethod -Uri "$OLLAMA_HOST/api/generate" -Method Post -Body $body -ContentType "application/json"
        $response.response | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
    } catch {
        "Error: Unable to get AI response. Is Ollama running?" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
        Write-Host "Error querying AI: $_" -ForegroundColor Red
    }
    
    "`n---`n" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
}

# 1. System Security Audit
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Running System Security Audit..." -ForegroundColor Yellow

$systemInfo = @"
Computer Name: $env:COMPUTERNAME
OS Version: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
OS Build: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)
Architecture: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)
Last Boot: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)

Listening Ports: 
$(Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize | Out-String)

Running Services:
$(Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, StartType | Format-Table -AutoSize | Out-String)

Firewall Status:
$(Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize | Out-String)

Local Users:
$(Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordRequired | Format-Table -AutoSize | Out-String)

Administrator Group Members:
$(Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource | Format-Table -AutoSize | Out-String)

Recent Security Events (Last 50):
$(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List | Out-String)

Scheduled Tasks:
$(Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName, TaskPath, State | Format-Table -AutoSize | Out-String)
"@

$prompt = @"
You are a cybersecurity expert. Analyze this Windows server configuration for security vulnerabilities, misconfigurations, and suspicious activity. Provide specific, actionable recommendations:

$systemInfo

Focus on:
1. Exposed services and ports
2. Unnecessary running services
3. Firewall configuration gaps
4. User account security
5. Failed login attempts and anomalies
6. Privilege escalation risks
7. Scheduled task security
"@

Query-AI -Prompt $prompt -Section "1. System Security Analysis"

# 2. Web Server Security (IIS)
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Web Server Security..." -ForegroundColor Yellow

if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
    $iisInfo = @"
IIS Service Status:
$(Get-Service W3SVC | Select-Object Name, Status, StartType | Format-List | Out-String)

IIS Sites:
$(Import-Module WebAdministration -ErrorAction SilentlyContinue; Get-Website | Select-Object Name, State, PhysicalPath, Bindings | Format-List | Out-String)

IIS Application Pools:
$(Get-IISAppPool | Select-Object Name, State, StartMode | Format-Table -AutoSize | Out-String)
"@

    $prompt = @"
Analyze this Windows IIS web server configuration for security issues:

$iisInfo

Check for:
1. Missing security headers
2. SSL/TLS misconfigurations
3. Directory browsing enabled
4. Anonymous authentication risks
5. Application pool isolation
6. Request filtering
"@

    Query-AI -Prompt $prompt -Section "2. Web Server Security (IIS)"
}

# 3. Remote Access Security
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Remote Access Security..." -ForegroundColor Yellow

$remoteInfo = @"
RDP Status:
$(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue)

RDP Port:
$(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -ErrorAction SilentlyContinue)

RDP Network Level Authentication:
$(Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -ErrorAction SilentlyContinue)

Windows Remote Management:
$(Get-Service WinRM | Select-Object Name, Status, StartType | Format-List | Out-String)

SSH Server (OpenSSH):
$(Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-List | Out-String)
"@

$prompt = @"
Analyze this Windows remote access configuration for security risks:

$remoteInfo

Evaluate:
1. RDP security settings
2. Network Level Authentication
3. Port configuration
4. WinRM exposure
5. SSH configuration if present
6. Multi-factor authentication
"@

Query-AI -Prompt $prompt -Section "3. Remote Access Security"

# 4. File System Security
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing File System Security..." -ForegroundColor Yellow

$fileInfo = @"
World-Writable Directories in System:
$(Get-ChildItem -Path "C:\Windows" -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSIsContainer} | Get-Acl | Where-Object {$_.AccessToString -match "Everyone.*Allow.*FullControl"} | Select-Object -First 20)

Executable Files with Everyone Access:
$(Get-ChildItem -Path "C:\Program Files" -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | Get-Acl | Where-Object {$_.AccessToString -match "Everyone"} | Select-Object -First 20)

System32 Directory Permissions:
$(Get-Acl "C:\Windows\System32" | Format-List | Out-String)
"@

$prompt = @"
Analyze these Windows file system security findings:

$fileInfo

Assess:
1. Excessive permissions
2. World-writable directories in system paths
3. Everyone group access risks
4. System directory protections
5. Potential privilege escalation paths
"@

Query-AI -Prompt $prompt -Section "4. File System Security"

# 5. Network Security
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Network Security..." -ForegroundColor Yellow

$networkInfo = @"
Active Network Connections:
$(Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize | Out-String)

Network Adapters:
$(Get-NetAdapter | Select-Object Name, Status, LinkSpeed, MacAddress | Format-Table -AutoSize | Out-String)

DNS Servers:
$(Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize | Out-String)

Network Shares:
$(Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize | Out-String)

SMB Version:
$(Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | Format-List | Out-String)
"@

$prompt = @"
Analyze this Windows network configuration for security issues:

$networkInfo

Look for:
1. Suspicious established connections
2. Exposed network shares
3. SMBv1 enabled (security risk)
4. DNS security
5. Network adapter security
6. Unusual listening services
"@

Query-AI -Prompt $prompt -Section "5. Network Security Analysis"

# 6. Windows Defender & Antivirus
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Antivirus Security..." -ForegroundColor Yellow

$avInfo = @"
Windows Defender Status:
$(Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, LastQuickScanTime, LastFullScanTime | Format-List | Out-String)

Windows Defender Exclusions:
$(Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess | Format-List | Out-String)

Windows Update Status:
$(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String)
"@

$prompt = @"
Analyze this Windows Defender and update configuration:

$avInfo

Check for:
1. Antivirus protection status
2. Real-time protection enabled
3. Scan frequency
4. Suspicious exclusions
5. Update status
6. Missing critical updates
"@

Query-AI -Prompt $prompt -Section "6. Antivirus & Windows Updates"

# 7. Application Security
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Applications..." -ForegroundColor Yellow

$appInfo = @"
Installed Applications:
$(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize | Out-String)

Running Processes (Top 20 by CPU):
$(Get-Process | Sort-Object CPU -Descending | Select-Object -First 20 | Select-Object Name, Id, CPU, WorkingSet, Path | Format-Table -AutoSize | Out-String)

Auto-start Programs:
$(Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize | Out-String)
"@

$prompt = @"
Analyze the security of applications on this Windows system:

$appInfo

Check for:
1. Outdated software
2. Unknown/suspicious publishers
3. High-risk applications
4. Auto-start security
5. Resource-intensive processes
6. Update requirements
"@

Query-AI -Prompt $prompt -Section "7. Application Security"

# 8. Event Log Analysis
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Analyzing Security Logs..." -ForegroundColor Yellow

$logInfo = @"
Failed Login Attempts (Last 50):
$(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List | Out-String)

Successful Logins (Last 20):
$(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message | Format-List | Out-String)

System Errors (Last 20):
$(Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Message | Format-List | Out-String)

Application Errors (Last 20):
$(Get-WinEvent -FilterHashtable @{LogName='Application';Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue | Select-Object TimeCreated, ProviderName, Message | Format-List | Out-String)
"@

$prompt = @"
Analyze these Windows event logs for security incidents and anomalies:

$logInfo

Identify:
1. Brute force attempts
2. Unauthorized access
3. Privilege escalation
4. Suspicious error patterns
5. Security policy violations
6. Potential compromises
"@

Query-AI -Prompt $prompt -Section "8. Event Log Analysis"

# 9. Generate Executive Summary
Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Generating Executive Summary..." -ForegroundColor Yellow

$prompt = @"
Based on all the Windows security analysis above, provide:

1. CRITICAL ISSUES - Immediate action required
2. HIGH PRIORITY - Fix within 24 hours
3. MEDIUM PRIORITY - Address this week
4. SECURITY SCORE - Rate overall security 1-10
5. QUICK WINS - Easy fixes with high impact
6. LONG-TERM RECOMMENDATIONS

Be specific with PowerShell commands and configurations needed for Windows.
"@

Query-AI -Prompt $prompt -Section "9. Executive Summary & Recommendations"

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  SECURITY SCAN COMPLETE" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "Report saved to: $REPORT_FILE" -ForegroundColor Yellow
Write-Host ""
Write-Host "View report: notepad `"$REPORT_FILE`"" -ForegroundColor Yellow
Write-Host ""
Write-Host "Latest reports:" -ForegroundColor Yellow
Get-ChildItem -Path $REPORT_DIR -Filter "security_analysis_*.md" | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | Format-Table Name, Length, LastWriteTime -AutoSize
