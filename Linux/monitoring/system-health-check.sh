#!/bin/bash

# System Health Check Script for Ubuntu Lab Server
# Monitors: CPU, RAM, GPU, Disk, K3s cluster, running services
# Can be run manually or via cron for monitoring
# Based on k8s-platform repo health checks

set -euo pipefail

# ========================================
# Configuration
# ========================================
K8S_PLATFORM_REPO="${K8S_PLATFORM_REPO:-/opt/k8s-platform}"
LOG_DIR="${LOG_DIR:-~/logs}"
SAVE_LOG="${SAVE_LOG:-false}"
VERBOSE="${VERBOSE:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ========================================
# Helper Functions
# ========================================
section() {
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    printf "${CYAN}║${NC} %-62s ${CYAN}║${NC}\n" "$1"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

info() { echo -e "${BLUE}[i]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

check_status() {
    if [ $? -eq 0 ]; then
        success "$1"
        return 0
    else
        error "$1"
        return 1
    fi
}

# ========================================
# Parse Arguments
# ========================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --save-log)
            SAVE_LOG=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --verbose,-v   Show detailed output"
            echo "  --save-log     Save output to log file"
            echo "  --help,-h      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ========================================
# Header
# ========================================
print_header() {
    echo -e "${MAGENTA}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║        Ubuntu Lab Server - System Health Check                ║"
    echo "║        Hermes Medical Solutions AB                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${CYAN}📅 Timestamp:${NC} $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo -e "${CYAN}🖥️  Hostname:${NC} $(hostname)"
    echo -e "${CYAN}👤 User:${NC} $(whoami)"
    echo -e "${CYAN}📂 k8s-platform Repo:${NC} $K8S_PLATFORM_REPO"
}

# ========================================
# System Resources
# ========================================
check_system_resources() {
    section "System Resources"

    # Uptime
    local uptime_info=$(uptime -p 2>/dev/null || uptime)
    info "Uptime: $uptime_info"

    # Load average
    local load=$(uptime | grep -oP 'load average: \K.*')
    info "Load Average: $load"

    # CPU info
    local cpu_count=$(nproc)
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    info "CPU: $cpu_count cores (${cpu_usage}% used)"

    # Memory
    if command -v free &>/dev/null; then
        local mem_total=$(free -h | awk 'NR==2{print $2}')
        local mem_used=$(free -h | awk 'NR==2{print $3}')
        local mem_percent=$(free | awk 'NR==2{printf "%.0f", $3/$2*100}')

        if [[ $mem_percent -lt 80 ]]; then
            success "Memory: $mem_used / $mem_total (${mem_percent}%)"
        elif [[ $mem_percent -lt 90 ]]; then
            warning "Memory: $mem_used / $mem_total (${mem_percent}%)"
        else
            error "Memory: $mem_used / $mem_total (${mem_percent}%) - CRITICAL"
        fi
    fi

    # Disk space
    local disk_total=$(df -h / | awk 'NR==2{print $2}')
    local disk_used=$(df -h / | awk 'NR==2{print $3}')
    local disk_percent=$(df / | awk 'NR==2{print $5}' | tr -d '%')

    if [[ $disk_percent -lt 80 ]]; then
        success "Disk Space: $disk_used / $disk_total (${disk_percent}%)"
    elif [[ $disk_percent -lt 90 ]]; then
        warning "Disk Space: $disk_used / $disk_total (${disk_percent}%)"
    else
        error "Disk Space: $disk_used / $disk_total (${disk_percent}%) - CRITICAL"
    fi

    # GPU Status (NVIDIA)
    if command -v nvidia-smi &>/dev/null; then
        local gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null)
        local gpu_mem_total=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null)
        local gpu_mem_used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits 2>/dev/null)
        local gpu_temp=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null)

        if [[ -n "$gpu_name" ]]; then
            success "GPU: $gpu_name"
            info "  → VRAM: ${gpu_mem_used}MB / ${gpu_mem_total}MB"
            info "  → Temperature: ${gpu_temp}°C"
        fi
    fi
}

# ========================================
# K3s Cluster Health
# ========================================
check_k3s_cluster() {
    section "K3s Cluster Status"

    # Set kubeconfig
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

    # Check K3s service
    if systemctl is-active --quiet k3s 2>/dev/null; then
        success "K3s service: running"
    else
        error "K3s service: not running"
        return 1
    fi

    # Check cluster connectivity
    if kubectl cluster-info &>/dev/null; then
        success "Cluster: accessible"

        # Check node status
        local node_status=$(kubectl get nodes --no-headers 2>/dev/null | awk '{print $2}')
        if [[ "$node_status" == "Ready" ]]; then
            success "Node status: $node_status"
        else
            error "Node status: $node_status"
        fi

        # Check namespaces
        local ns_count=$(kubectl get namespaces --no-headers 2>/dev/null | wc -l)
        info "Namespaces: $ns_count"

        # Check pods in docker-services namespace
        if kubectl get namespace docker-services &>/dev/null; then
            local total_pods=$(kubectl get pods -n docker-services --no-headers 2>/dev/null | wc -l)
            local running_pods=$(kubectl get pods -n docker-services --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
            local failed_pods=$(kubectl get pods -n docker-services --field-selector=status.phase=Failed --no-headers 2>/dev/null | wc -l)

            info "Pods in docker-services: $total_pods total, $running_pods running"

            if [[ $failed_pods -gt 0 ]]; then
                warning "Failed pods: $failed_pods"
                if [[ "$VERBOSE" == "true" ]]; then
                    kubectl get pods -n docker-services --field-selector=status.phase=Failed
                fi
            fi

            # List running services
            if [[ "$VERBOSE" == "true" ]]; then
                echo ""
                info "Running deployments:"
                kubectl get deployments -n docker-services --no-headers 2>/dev/null | while read name ready uptodate available age; do
                    echo "  → $name: $ready"
                done
            fi
        else
            warning "Namespace docker-services not found"
        fi
    else
        error "Cluster: not accessible (kubectl failed)"
        return 1
    fi
}

# ========================================
# Service Health Checks
# ========================================
check_services() {
    section "Service Health"

    local services=(
        "http://localhost:31869:DefectDojo"
        "http://localhost:32213:Ollama"
        "http://localhost:32574:Open-WebUI"
    )

    for service_info in "${services[@]}"; do
        IFS=: read -r url name <<< "$service_info:$(echo $service_info | cut -d: -f3-)"

        if timeout 3 curl -sf "$url" >/dev/null 2>&1; then
            success "$name: responding ($url)"
        else
            warning "$name: not responding ($url)"
        fi
    done
}

# ========================================
# k8s-platform Repository Status
# ========================================
check_k8s_platform_repo() {
    section "k8s-platform Repository"

    if [[ -d "$K8S_PLATFORM_REPO" ]]; then
        success "k8s-platform repo found: $K8S_PLATFORM_REPO"

        # Check git status
        if [[ -d "$K8S_PLATFORM_REPO/.git" ]]; then
            cd "$K8S_PLATFORM_REPO"
            local branch=$(git branch --show-current 2>/dev/null)
            local status=$(git status --porcelain 2>/dev/null | wc -l)

            info "Git branch: $branch"
            if [[ $status -eq 0 ]]; then
                success "Git status: clean"
            else
                warning "Git status: $status uncommitted changes"
            fi
        fi
    else
        error "k8s-platform repo not found at: $K8S_PLATFORM_REPO"
    fi
}

# ========================================
# System Updates
# ========================================
check_updates() {
    section "System Updates"

    local updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)

    if [[ $updates -eq 1 ]]; then
        success "System is up to date"
    elif [[ $updates -lt 10 ]]; then
        info "$updates packages can be upgraded"
    else
        warning "$updates packages can be upgraded (consider updating soon)"
    fi

    # Check for security updates
    if command -v unattended-upgrade &>/dev/null; then
        if [[ -f /var/run/reboot-required ]]; then
            warning "System reboot required"
        fi
    fi
}

# ========================================
# Log Directory Sizes
# ========================================
check_log_sizes() {
    section "Log Directory Sizes"

    local large_logs=$(du -sh /var/log/* 2>/dev/null | sort -rh | head -5)

    echo "$large_logs" | while read size path; do
        local size_mb=$(echo $size | grep -oP '\d+' || echo 0)
        local unit=$(echo $size | grep -oP '[A-Z]')

        if [[ "$unit" == "G" ]] || [[ "$unit" == "M" && "$size_mb" -gt 100 ]]; then
            warning "$path: $size"
        else
            info "$path: $size"
        fi
    done
}

# ========================================
# Summary
# ========================================
print_summary() {
    section "Health Summary"

    local issues=0

    # Check critical services
    systemctl is-active --quiet k3s || issues=$((issues + 1))
    kubectl cluster-info &>/dev/null || issues=$((issues + 1))

    # Check disk space
    local disk_percent=$(df / | awk 'NR==2{print $5}' | tr -d '%')
    [[ $disk_percent -gt 90 ]] && issues=$((issues + 1))

    # Check memory
    local mem_percent=$(free | awk 'NR==2{printf "%.0f", $3/$2*100}')
    [[ $mem_percent -gt 90 ]] && issues=$((issues + 1))

    if [[ $issues -eq 0 ]]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        printf "${GREEN}║${NC} %-40s ${GREEN}%-21s║${NC}\n" "Overall Status:" "HEALTHY ✓"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    elif [[ $issues -le 2 ]]; then
        echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
        printf "${YELLOW}║${NC} %-40s ${YELLOW}%-21s║${NC}\n" "Overall Status:" "DEGRADED ⚠"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
        warning "Detected $issues potential issues - review details above"
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
        printf "${RED}║${NC} %-40s ${RED}%-21s║${NC}\n" "Overall Status:" "UNHEALTHY ✗"
        echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
        error "Detected $issues critical issues - immediate attention required"
    fi
}

# ========================================
# Main Execution
# ========================================
main() {
    # Setup logging if requested
    if [[ "$SAVE_LOG" == "true" ]]; then
        mkdir -p "$LOG_DIR"
        local log_file="$LOG_DIR/health-check-$(date +%Y%m%d-%H%M%S).log"
        exec > >(tee "$log_file")
        exec 2>&1
        info "Logging to: $log_file"
    fi

    print_header
    check_system_resources
    check_k3s_cluster
    check_services
    check_k8s_platform_repo
    check_updates
    check_log_sizes
    print_summary

    echo ""
    info "💡 Tips:"
    echo "   • Run with --verbose for detailed output"
    echo "   • Run with --save-log to save results"
    echo "   • Check K8s pods: kubectl get pods -A"
    echo "   • View logs: journalctl -u k3s -f"
}

# Run main
main
