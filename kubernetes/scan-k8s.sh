#!/bin/bash

###################################################
# AI Security Scanner - Kubernetes Security Audit
# Comprehensive K8s cluster security scan
###################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="$HOME/security-reports/kubernetes_security_$(date +%Y%m%d_%H%M%S).md"
TEMP_DIR="/tmp/k8s-security-scan-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Ollama configuration (override via environment variables)
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3.1:8b}"

# Check dependencies
check_dependencies() {
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}❌ kubectl not installed${NC}"
        echo "Install: https://kubernetes.io/docs/tasks/tools/"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo -e "${YELLOW}⚠️  jq not installed - some features limited${NC}"
    fi
}

# Check cluster access
check_cluster_access() {
    if ! kubectl cluster-info &>/dev/null; then
        echo -e "${RED}❌ Cannot connect to Kubernetes cluster${NC}"
        echo "Configure kubectl: kubectl config use-context <context>"
        exit 1
    fi
    
    local context=$(kubectl config current-context 2>/dev/null)
    local cluster=$(kubectl config view -o jsonpath='{.current-context}' 2>/dev/null)
    
    echo -e "${GREEN}✅ Connected to cluster: $context${NC}"
}

# Initialize report
init_report() {
    mkdir -p "$(dirname "$REPORT_FILE")"
    mkdir -p "$TEMP_DIR"
    
    local context=$(kubectl config current-context 2>/dev/null)
    
    cat > "$REPORT_FILE" << EOF
# Kubernetes Security Analysis Report
Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Cluster: $context

## Table of Contents
- [Pod Security](#pod-security)
- [RBAC Analysis](#rbac-analysis)
- [Network Policies](#network-policies)
- [Secrets Management](#secrets-management)
- [Resource Quotas](#resource-quotas)
- [Container Security](#container-security)
- [Service Accounts](#service-accounts)
- [Recommendations](#recommendations)

---

EOF
}

# Scan Pod Security
scan_pods() {
    echo -e "${BLUE}🔍 Scanning Pods...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Pod Security

### Pod Overview
EOF
    
    kubectl get pods --all-namespaces -o json > "$TEMP_DIR/pods.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        local total_pods=$(jq -r '.items | length' "$TEMP_DIR/pods.json" 2>/dev/null || echo "0")
        echo "- **Total Pods:** $total_pods" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Privileged Pods" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.spec.containers[].securityContext.privileged == true) | 
            "- 🚨 **\(.metadata.name)** in namespace **\(.metadata.namespace)** - Running privileged"' \
            "$TEMP_DIR/pods.json" 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Pods Running as Root" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.spec.containers[].securityContext.runAsUser == 0 or 
                   (.spec.containers[].securityContext.runAsUser == null and 
                    .spec.securityContext.runAsUser == null)) | 
            "- ⚠️  **\(.metadata.name)** in namespace **\(.metadata.namespace)** - Running as root"' \
            "$TEMP_DIR/pods.json" 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Pods Without Resource Limits" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.spec.containers[].resources.limits == null) | 
            "- ⚠️  **\(.metadata.name)** in namespace **\(.metadata.namespace)** - No resource limits"' \
            "$TEMP_DIR/pods.json" 2>/dev/null >> "$REPORT_FILE" || echo "All pods have limits" >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan RBAC
scan_rbac() {
    echo -e "${BLUE}🔍 Scanning RBAC...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## RBAC Analysis

### Cluster Roles
EOF
    
    kubectl get clusterrolebindings -o json > "$TEMP_DIR/clusterrolebindings.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        echo "" >> "$REPORT_FILE"
        echo "### Cluster-Admin Bindings" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.roleRef.name == "cluster-admin") | 
            "- ⚠️  **\(.metadata.name)** - cluster-admin role bound to: \(.subjects[].name)"' \
            "$TEMP_DIR/clusterrolebindings.json" 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Service Accounts with Cluster Roles" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.subjects[].kind == "ServiceAccount") | 
            "- \(.metadata.name) - Role: \(.roleRef.name) - SA: \(.subjects[].name)"' \
            "$TEMP_DIR/clusterrolebindings.json" 2>/dev/null | head -10 >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan Network Policies
scan_network_policies() {
    echo -e "${BLUE}🔍 Scanning Network Policies...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Network Policies

### Network Policy Status
EOF
    
    kubectl get networkpolicies --all-namespaces -o json > "$TEMP_DIR/networkpolicies.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        local policy_count=$(jq -r '.items | length' "$TEMP_DIR/networkpolicies.json" 2>/dev/null || echo "0")
        
        if [[ "$policy_count" -eq 0 ]]; then
            echo "- 🚨 **CRITICAL: No network policies configured**" >> "$REPORT_FILE"
        else
            echo "- ✅ Network policies found: $policy_count" >> "$REPORT_FILE"
            
            echo "" >> "$REPORT_FILE"
            echo "### Configured Policies" >> "$REPORT_FILE"
            
            jq -r '.items[] | 
                "- **\(.metadata.name)** in namespace **\(.metadata.namespace)**"' \
                "$TEMP_DIR/networkpolicies.json" >> "$REPORT_FILE"
        fi
        
        echo "" >> "$REPORT_FILE"
        echo "### Namespaces Without Network Policies" >> "$REPORT_FILE"
        
        kubectl get namespaces -o json > "$TEMP_DIR/namespaces.json"
        local namespaces=$(jq -r '.items[].metadata.name' "$TEMP_DIR/namespaces.json")
        
        for ns in $namespaces; do
            if ! kubectl get networkpolicies -n "$ns" 2>/dev/null | grep -q "."; then
                echo "- ⚠️  **$ns** - No network policies" >> "$REPORT_FILE"
            fi
        done
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan Secrets
scan_secrets() {
    echo -e "${BLUE}🔍 Scanning Secrets...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Secrets Management

### Secrets Overview
EOF
    
    kubectl get secrets --all-namespaces -o json > "$TEMP_DIR/secrets.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        local secret_count=$(jq -r '.items | length' "$TEMP_DIR/secrets.json" 2>/dev/null || echo "0")
        echo "- **Total Secrets:** $secret_count" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Secrets in Default Namespace" >> "$REPORT_FILE"
        
        local default_secrets=$(jq -r '.items[] | 
            select(.metadata.namespace == "default") | 
            .metadata.name' "$TEMP_DIR/secrets.json" 2>/dev/null | wc -l)
        
        if [[ "$default_secrets" -gt 0 ]]; then
            echo "- ⚠️  **$default_secrets secrets** in default namespace (should be avoided)" >> "$REPORT_FILE"
        else
            echo "- ✅ No secrets in default namespace" >> "$REPORT_FILE"
        fi
        
        echo "" >> "$REPORT_FILE"
        echo "### External Secret Management" >> "$REPORT_FILE"
        
        if kubectl get crd externalsecrets.external-secrets.io &>/dev/null; then
            echo "- ✅ External Secrets Operator installed" >> "$REPORT_FILE"
        else
            echo "- ℹ️  Consider using External Secrets Operator for better secret management" >> "$REPORT_FILE"
        fi
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan Resource Quotas
scan_quotas() {
    echo -e "${BLUE}🔍 Scanning Resource Quotas...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Resource Quotas

### Quota Configuration
EOF
    
    kubectl get resourcequotas --all-namespaces -o json > "$TEMP_DIR/quotas.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        local quota_count=$(jq -r '.items | length' "$TEMP_DIR/quotas.json" 2>/dev/null || echo "0")
        
        if [[ "$quota_count" -eq 0 ]]; then
            echo "- ⚠️  No resource quotas configured" >> "$REPORT_FILE"
        else
            echo "- ✅ Resource quotas configured: $quota_count" >> "$REPORT_FILE"
            
            echo "" >> "$REPORT_FILE"
            echo "### Configured Quotas" >> "$REPORT_FILE"
            
            jq -r '.items[] | 
                "- **\(.metadata.name)** in namespace **\(.metadata.namespace)**"' \
                "$TEMP_DIR/quotas.json" >> "$REPORT_FILE"
        fi
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan Container Images
scan_images() {
    echo -e "${BLUE}🔍 Scanning Container Images...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Container Security

### Image Analysis
EOF
    
    if command -v jq &>/dev/null; then
        echo "" >> "$REPORT_FILE"
        echo "### Images Using :latest Tag" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            .spec.containers[] | 
            select(.image | endswith(":latest")) | 
            "- ⚠️  **\(.image)** - Using :latest tag (not recommended)"' \
            "$TEMP_DIR/pods.json" 2>/dev/null >> "$REPORT_FILE" || echo "None found" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Images from Public Registries" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            .spec.containers[] | 
            select(.image | startswith("docker.io/") or startswith("gcr.io/") or (contains("/") | not)) | 
            "- ℹ️  **\(.image)**"' \
            "$TEMP_DIR/pods.json" 2>/dev/null | sort -u | head -10 >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# Scan Service Accounts
scan_serviceaccounts() {
    echo -e "${BLUE}🔍 Scanning Service Accounts...${NC}"
    
    cat >> "$REPORT_FILE" << EOF
## Service Accounts

### Service Account Usage
EOF
    
    kubectl get serviceaccounts --all-namespaces -o json > "$TEMP_DIR/serviceaccounts.json" 2>/dev/null || true
    
    if command -v jq &>/dev/null; then
        local sa_count=$(jq -r '.items | length' "$TEMP_DIR/serviceaccounts.json" 2>/dev/null || echo "0")
        echo "- **Total Service Accounts:** $sa_count" >> "$REPORT_FILE"
        
        echo "" >> "$REPORT_FILE"
        echo "### Pods Using Default Service Account" >> "$REPORT_FILE"
        
        jq -r '.items[] | 
            select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | 
            "- ⚠️  **\(.metadata.name)** in namespace **\(.metadata.namespace)** - Using default SA"' \
            "$TEMP_DIR/pods.json" 2>/dev/null | head -10 >> "$REPORT_FILE"
    fi
    
    echo "" >> "$REPORT_FILE"
}

# AI Analysis
ai_analysis() {
    if ! curl -sf "$OLLAMA_HOST/api/tags" -o /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  Skipping AI analysis - Ollama not reachable at $OLLAMA_HOST${NC}"
        return
    fi

    echo -e "${BLUE}🤖 Running AI security analysis...${NC}"

    cat >> "$REPORT_FILE" << EOF
## AI Security Analysis

EOF

    local analysis_input=$(cat "$REPORT_FILE")

    local ai_response=$(curl -s "$OLLAMA_HOST/api/generate" -d "{
        \"model\": \"$OLLAMA_MODEL\",
        \"prompt\": \"You are a Kubernetes security expert. Analyze this K8s security audit report and provide:\\n1. Top 3 critical security issues\\n2. Pod security best practices violations\\n3. RBAC concerns\\n4. Security score (1-10)\\n\\nReport:\\n$analysis_input\\n\\nProvide a concise analysis.\",
        \"stream\": false,
        \"options\": {\"temperature\": 0.3}
    }" | jq -r '.response' 2>/dev/null | head -100)

    echo "$ai_response" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Generate recommendations
generate_recommendations() {
    cat >> "$REPORT_FILE" << EOF

## Recommendations

### High Priority
1. Configure network policies for all namespaces
2. Avoid running pods as root or privileged
3. Set resource limits for all containers
4. Use specific image tags instead of :latest
5. Implement Pod Security Standards (restricted)

### Medium Priority
1. Review and minimize cluster-admin bindings
2. Use dedicated service accounts (not default)
3. Configure resource quotas per namespace
4. Enable audit logging
5. Implement admission controllers

### Best Practices
1. Use Pod Security Admission Controller
2. Scan images for vulnerabilities (Trivy, Snyk)
3. Implement External Secrets Operator
4. Use OPA/Gatekeeper for policy enforcement
5. Regular security audits with kube-bench

### Tools to Consider
- **kube-bench** - CIS Kubernetes Benchmark
- **Trivy** - Container vulnerability scanning
- **Falco** - Runtime security monitoring
- **OPA Gatekeeper** - Policy enforcement
- **External Secrets** - Secret management

---

**Report generated by AI Security Scanner**
EOF
}

# Main function
main() {
    echo -e "${GREEN}🛡️  Kubernetes Security Scanner${NC}\n"
    
    # Checks
    check_dependencies
    check_cluster_access
    
    echo ""
    echo -e "${BLUE}Starting Kubernetes security audit...${NC}\n"
    
    # Initialize
    init_report
    
    # Run scans
    scan_pods
    scan_rbac
    scan_network_policies
    scan_secrets
    scan_quotas
    scan_images
    scan_serviceaccounts
    
    # AI analysis
    ai_analysis
    
    # Recommendations
    generate_recommendations
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    
    echo ""
    echo -e "${GREEN}✅ Kubernetes security audit complete!${NC}"
    echo -e "${BLUE}📄 Report: $REPORT_FILE${NC}\n"
    
    # Display summary
    echo -e "${CYAN}Summary:${NC}"
    grep -E "^- \*\*|^- 🚨|^- ⚠️|^- ✅" "$REPORT_FILE" | head -20
}

# Run
main "$@"
