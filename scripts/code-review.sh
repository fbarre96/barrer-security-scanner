#!/bin/bash
# AI-Powered Code Security Review
# Scans code for vulnerabilities

MODEL="${OLLAMA_MODEL:-llama3.1:70b}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

if [ -z "$1" ]; then
    echo "Usage: $0 <file_or_directory>"
    echo "Example: $0 /home/ubuntu/webhost-panel/"
    exit 1
fi

TARGET="$1"
REPORT_FILE="/home/ubuntu/security-reports/code_review_$(date +%Y%m%d_%H%M%S).md"

echo "# Code Security Review" > "$REPORT_FILE"
echo "Target: $TARGET" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Find code files
FILES=$(find "$TARGET" -type f \( -name "*.js" -o -name "*.py" -o -name "*.php" -o -name "*.sh" -o -name "*.java" \) 2>/dev/null | head -20)

for file in $FILES; do
    echo "Analyzing: $file"
    
    CONTENT=$(cat "$file" 2>/dev/null | head -500)
    FILE_SIZE=$(wc -l < "$file")
    
    echo "## File: $file ($FILE_SIZE lines)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    ANALYSIS=$(curl -s "$OLLAMA_HOST/api/generate" -d "{
        \"model\": \"$MODEL\",
        \"prompt\": \"Perform a security code review of this file. Identify vulnerabilities like SQL injection, XSS, command injection, hardcoded secrets, insecure authentication, path traversal, and other security issues:\n\n$CONTENT\n\nProvide specific line numbers and fix recommendations.\",
        \"stream\": false,
        \"options\": {\"temperature\": 0.3}
    }" | jq -r '.response')
    
    echo "$ANALYSIS" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
done

echo ""
echo "Code review complete!"
echo "Report: $REPORT_FILE"
