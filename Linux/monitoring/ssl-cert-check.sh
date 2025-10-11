#!/bin/bash

# SSL Certificate Expiry Check
# Checks certificates in k8s-platform repo and K8s secrets
# Based on k8s-platform deployment scripts security checks

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

K8S_PLATFORM_REPO="${K8S_PLATFORM_REPO:-/opt/k8s-platform}"
WARN_DAYS=30
CRITICAL_DAYS=7

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --warn-days)
            WARN_DAYS="$2"
            shift 2
            ;;
        --critical-days)
            CRITICAL_DAYS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --warn-days DAYS       Warn if cert expires within N days (default: 30)"
            echo "  --critical-days DAYS   Critical if expires within N days (default: 7)"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          SSL Certificate Expiry Check                    ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

ISSUES=0
WARNINGS=0

# Check certificates in k8s-platform repo
if [[ -d "$K8S_PLATFORM_REPO" ]]; then
    echo -e "${BLUE}=== Checking Certificates in k8s-platform Repo ===${NC}"

    # Look for cert files
    CERT_FILES=$(find "$K8S_PLATFORM_REPO" -name "*.crt" -o -name "*.pem" 2>/dev/null || true)

    if [[ -n "$CERT_FILES" ]]; then
        echo "$CERT_FILES" | while read cert; do
            if [[ -f "$cert" ]]; then
                # Check if it's a valid certificate
                if openssl x509 -in "$cert" -noout -text &>/dev/null; then
                    EXPIRY_DATE=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
                    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)
                    NOW_EPOCH=$(date +%s)
                    DAYS_REMAINING=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

                    CERT_NAME=$(basename "$cert")

                    if [[ $DAYS_REMAINING -le 0 ]]; then
                        echo -e "${RED}[-] $CERT_NAME: EXPIRED${NC}"
                        ISSUES=$((ISSUES + 1))
                    elif [[ $DAYS_REMAINING -le $CRITICAL_DAYS ]]; then
                        echo -e "${RED}[-] $CERT_NAME: expires in $DAYS_REMAINING days (CRITICAL)${NC}"
                        ISSUES=$((ISSUES + 1))
                    elif [[ $DAYS_REMAINING -le $WARN_DAYS ]]; then
                        echo -e "${YELLOW}[!] $CERT_NAME: expires in $DAYS_REMAINING days${NC}"
                        WARNINGS=$((WARNINGS + 1))
                    else
                        echo -e "${GREEN}[+] $CERT_NAME: expires in $DAYS_REMAINING days${NC}"
                    fi
                fi
            fi
        done
    else
        echo -e "${YELLOW}[!] No certificate files found in k8s-platform repo${NC}"
    fi
    echo ""
fi

# Check K8s TLS secrets
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

if kubectl cluster-info &>/dev/null; then
    echo -e "${BLUE}=== Checking K8s TLS Secrets ===${NC}"

    # Get all TLS secrets
    TLS_SECRETS=$(kubectl get secrets --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.type=="kubernetes.io/tls") | "\(.metadata.namespace)/\(.metadata.name)"' || true)

    if [[ -n "$TLS_SECRETS" ]]; then
        echo "$TLS_SECRETS" | while IFS=/ read namespace secret_name; do
            # Extract certificate
            CERT_DATA=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.data.tls\.crt}' 2>/dev/null | base64 -d 2>/dev/null || echo "")

            if [[ -n "$CERT_DATA" ]]; then
                EXPIRY_DATE=$(echo "$CERT_DATA" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "")

                if [[ -n "$EXPIRY_DATE" ]]; then
                    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)
                    NOW_EPOCH=$(date +%s)
                    DAYS_REMAINING=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

                    if [[ $DAYS_REMAINING -le 0 ]]; then
                        echo -e "${RED}[-] $namespace/$secret_name: EXPIRED${NC}"
                        ISSUES=$((ISSUES + 1))
                    elif [[ $DAYS_REMAINING -le $CRITICAL_DAYS ]]; then
                        echo -e "${RED}[-] $namespace/$secret_name: expires in $DAYS_REMAINING days (CRITICAL)${NC}"
                        ISSUES=$((ISSUES + 1))
                    elif [[ $DAYS_REMAINING -le $WARN_DAYS ]]; then
                        echo -e "${YELLOW}[!] $namespace/$secret_name: expires in $DAYS_REMAINING days${NC}"
                        WARNINGS=$((WARNINGS + 1))
                    else
                        echo -e "${GREEN}[+] $namespace/$secret_name: expires in $DAYS_REMAINING days${NC}"
                    fi
                fi
            fi
        done
    else
        echo -e "${YELLOW}[!] No TLS secrets found in cluster${NC}"
    fi
    echo ""
fi

# Summary
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    Summary                               ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

if [[ $ISSUES -gt 0 ]]; then
    echo -e "${RED}[-] Found $ISSUES critical certificate issue(s)${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}[!] Found $WARNINGS certificate(s) expiring soon${NC}"
    exit 1
else
    echo -e "${GREEN}[+] All certificates valid for >$WARN_DAYS days${NC}"
    exit 0
fi
