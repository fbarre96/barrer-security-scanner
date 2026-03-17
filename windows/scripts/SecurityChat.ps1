# Interactive AI Security Assistant for Windows

$MODEL = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { "llama3.1:70b" }
$OLLAMA_HOST = if ($env:OLLAMA_HOST) { $env:OLLAMA_HOST.TrimEnd('/') } else { "http://localhost:11434" }

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   AI Security Assistant (Llama 3.1 70B)" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Ask any Windows security questions. Type 'exit' to quit." -ForegroundColor Yellow
Write-Host ""

$systemContext = "You are an expert cybersecurity consultant specializing in Windows Server security, Active Directory, PowerShell security, IIS security, and Windows threat detection. Provide detailed, actionable security advice specific to Windows environments."

while ($true) {
    Write-Host "Security Question: " -NoNewline -ForegroundColor Green
    $question = Read-Host
    
    if ($question -eq "exit" -or $question -eq "quit") {
        Write-Host "Goodbye!" -ForegroundColor Yellow
        break
    }
    
    if ([string]::IsNullOrWhiteSpace($question)) {
        continue
    }
    
    Write-Host ""
    Write-Host "AI Response:" -ForegroundColor Cyan
    Write-Host "---" -ForegroundColor Gray
    
    $body = @{
        model = $MODEL
        prompt = "$systemContext`n`nQuestion: $question`n`nAnswer:"
        stream = $false
        options = @{
            temperature = 0.4
            top_p = 0.9
        }
    } | ConvertTo-Json -Depth 10
    
    try {
        $response = Invoke-RestMethod -Uri "$OLLAMA_HOST/api/generate" -Method Post -Body $body -ContentType "application/json"
        Write-Host $response.response -ForegroundColor White
    } catch {
        Write-Host "Error: Unable to get AI response. Is Ollama running?" -ForegroundColor Red
        Write-Host "Start Ollama with: ollama serve" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "---" -ForegroundColor Gray
    Write-Host ""
}
