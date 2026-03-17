#!/bin/bash
# Interactive AI Security Assistant
# Chat with the AI about security questions

MODEL="${OLLAMA_MODEL:-llama3.1:70b}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

echo "================================================"
echo "   AI Security Assistant (Llama 3.1 70B)"
echo "================================================"
echo "Ask any security questions. Type 'exit' to quit."
echo ""

SYSTEM_CONTEXT="You are an expert cybersecurity consultant specializing in Linux server security, web application security, network security, and threat detection. Provide detailed, actionable security advice."

while true; do
    echo -n "Security Question: "
    read -r QUESTION
    
    if [ "$QUESTION" = "exit" ] || [ "$QUESTION" = "quit" ]; then
        echo "Goodbye!"
        break
    fi
    
    if [ -z "$QUESTION" ]; then
        continue
    fi
    
    echo ""
    echo "AI Response:"
    echo "---"
    
    curl -s "$OLLAMA_HOST/api/generate" -d "{
        \"model\": \"$MODEL\",
        \"prompt\": \"$SYSTEM_CONTEXT\n\nQuestion: $QUESTION\n\nAnswer:\",
        \"stream\": false,
        \"options\": {
            \"temperature\": 0.4,
            \"top_p\": 0.9
        }
    }" | jq -r '.response'
    
    echo ""
    echo "---"
    echo ""
done
