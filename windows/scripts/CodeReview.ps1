# AI-Powered Code Security Review for Windows

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetPath
)

$MODEL = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "llama3.1:70b" }
$OLLAMA_HOST = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST.TrimEnd('/') } else { "http://localhost:11434" }

if (-not (Test-Path $TargetPath)) {
    Write-Host "Error: Path not found: $TargetPath" -ForegroundColor Red
    exit 1
}

$REPORT_DIR = "$env:USERPROFILE\Documents\SecurityReports"
New-Item -ItemType Directory -Force -Path $REPORT_DIR | Out-Null

$REPORT_FILE = "$REPORT_DIR\code_review_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"

Write-Host "# Code Security Review" | Out-File -FilePath $REPORT_FILE -Encoding UTF8
Write-Host "Target: $TargetPath" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
Write-Host "Date: $(Get-Date)" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
Write-Host "" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8

# Find code files
$extensions = @('*.ps1', '*.cs', '*.js', '*.py', '*.php', '*.java', '*.cpp', '*.c')
$files = Get-ChildItem -Path $TargetPath -Recurse -Include $extensions -ErrorAction SilentlyContinue | Select-Object -First 20

if ($files.Count -eq 0) {
    Write-Host "No code files found in $TargetPath" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($files.Count) code files to analyze..." -ForegroundColor Yellow
Write-Host ""

foreach ($file in $files) {
    Write-Host "Analyzing: $($file.FullName)" -ForegroundColor Yellow
    
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content.Length -gt 50000) {
        $content = $content.Substring(0, 50000)
    }
    
    $lineCount = (Get-Content $file.FullName | Measure-Object -Line).Lines
    
    "`n## File: $($file.FullName) ($lineCount lines)`n" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
    
    $prompt = @"
Perform a security code review of this file. Identify vulnerabilities like:
- SQL injection
- XSS (Cross-site scripting)
- Command injection
- Path traversal
- Hardcoded secrets/credentials
- Insecure authentication
- Cryptographic weaknesses
- Input validation issues
- Buffer overflows
- CSRF vulnerabilities

File content:
$content

Provide specific line numbers and fix recommendations.
"@

    $body = @{
        model = $MODEL
        prompt = $prompt
        stream = $false
        options = @{
            temperature = 0.3
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        $response = Invoke-RestMethod -Uri "$OLLAMA_HOST/api/generate" -Method Post -Body $body -ContentType "application/json"
        $response.response | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
    } catch {
        "Error: Unable to analyze file. Is Ollama running?" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
        Write-Host "Error: $_" -ForegroundColor Red
    }
    
    "`n---`n" | Out-File -FilePath $REPORT_FILE -Append -Encoding UTF8
}

Write-Host ""
Write-Host "Code review complete!" -ForegroundColor Green
Write-Host "Report: $REPORT_FILE" -ForegroundColor Yellow
Write-Host ""
Write-Host "View with: notepad `"$REPORT_FILE`"" -ForegroundColor Cyan
