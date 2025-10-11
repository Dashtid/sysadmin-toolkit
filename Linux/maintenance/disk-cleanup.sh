#!/bin/bash

# Disk Cleanup Script for Ubuntu Lab Server
# Cleans: old logs, journal files, Docker images, apt cache
# Safe mode: dry-run by default

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

DRY_RUN=true  # Safe default
CLEAN_LOGS=false
CLEAN_DOCKER=false
CLEAN_APT=false
CLEAN_JOURNAL=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --execute)
            DRY_RUN=false
            shift
            ;;
        --logs)
            CLEAN_LOGS=true
            shift
            ;;
        --docker)
            CLEAN_DOCKER=true
            shift
            ;;
        --apt)
            CLEAN_APT=true
            shift
            ;;
        --journal)
            CLEAN_JOURNAL=true
            shift
            ;;
        --all)
            CLEAN_LOGS=true
            CLEAN_DOCKER=true
            CLEAN_APT=true
            CLEAN_JOURNAL=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --execute     Execute cleanup (default is dry-run)"
            echo "  --logs        Clean old log files (>30 days)"
            echo "  --docker      Clean Docker images and containers"
            echo "  --apt         Clean apt cache"
            echo "  --journal     Clean systemd journal (keep last 7 days)"
            echo "  --all         Clean everything"
            echo "  -h, --help    Show this help"
            echo ""
            echo "Example:"
            echo "  $0 --all              # Preview what would be cleaned"
            echo "  $0 --all --execute    # Actually perform cleanup"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            Disk Cleanup Utility                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
    echo -e "${YELLOW}Add --execute flag to perform actual cleanup${NC}"
    echo ""
fi

# Initial disk usage
echo -e "${BLUE}=== Current Disk Usage ===${NC}"
df -h / | awk 'NR==1 || NR==2'
echo ""

SPACE_FREED=0

# Clean old logs
if [[ "$CLEAN_LOGS" == "true" ]]; then
    echo -e "${BLUE}=== Cleaning Old Log Files (>30 days) ===${NC}"

    # Find old logs
    OLD_LOGS=$(find /var/log -type f -name "*.log.*" -mtime +30 2>/dev/null || true)

    if [[ -n "$OLD_LOGS" ]]; then
        LOG_SIZE=$(du -ch $(echo "$OLD_LOGS") 2>/dev/null | tail -1 | cut -f1 || echo "0")
        echo "Found old log files: $LOG_SIZE"

        if [[ "$DRY_RUN" == "false" ]]; then
            if [[ $EUID -ne 0 ]]; then
                echo -e "${RED}[-] Need root privileges to clean logs${NC}"
            else
                echo "$OLD_LOGS" | xargs rm -f
                echo -e "${GREEN}[+] Cleaned old log files${NC}"
            fi
        else
            echo -e "${YELLOW}[DRY RUN] Would remove:${NC}"
            echo "$OLD_LOGS" | head -10
            [[ $(echo "$OLD_LOGS" | wc -l) -gt 10 ]] && echo "  ... and more"
        fi
    else
        echo -e "${GREEN}[+] No old log files found${NC}"
    fi
    echo ""
fi

# Clean journal logs
if [[ "$CLEAN_JOURNAL" == "true" ]]; then
    echo -e "${BLUE}=== Cleaning Systemd Journal (keep 7 days) ===${NC}"

    JOURNAL_SIZE=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.\d+[A-Z]' || echo "unknown")
    echo "Current journal size: $JOURNAL_SIZE"

    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}[-] Need root privileges to clean journal${NC}"
        else
            journalctl --vacuum-time=7d
            NEW_SIZE=$(journalctl --disk-usage 2>/dev/null | grep -oP '\d+\.\d+[A-Z]' || echo "unknown")
            echo -e "${GREEN}[+] Cleaned journal (new size: $NEW_SIZE)${NC}"
        fi
    else
        echo -e "${YELLOW}[DRY RUN] Would run: journalctl --vacuum-time=7d${NC}"
    fi
    echo ""
fi

# Clean Docker
if [[ "$CLEAN_DOCKER" == "true" ]]; then
    echo -e "${BLUE}=== Cleaning Docker ===${NC}"

    if command -v docker &>/dev/null; then
        # Show Docker disk usage
        if docker info &>/dev/null; then
            echo "Current Docker usage:"
            docker system df 2>/dev/null || echo "Unable to get Docker disk usage"
            echo ""

            if [[ "$DRY_RUN" == "false" ]]; then
                # Clean stopped containers
                STOPPED=$(docker ps -aq -f status=exited 2>/dev/null || echo "")
                if [[ -n "$STOPPED" ]]; then
                    echo "Removing stopped containers..."
                    docker rm $STOPPED
                fi

                # Clean dangling images
                echo "Removing dangling images..."
                docker image prune -f

                # Clean build cache
                echo "Cleaning build cache..."
                docker builder prune -f

                echo -e "${GREEN}[+] Docker cleanup complete${NC}"
                echo ""
                echo "New Docker usage:"
                docker system df
            else
                echo -e "${YELLOW}[DRY RUN] Would run Docker cleanup:${NC}"
                echo "  - Remove stopped containers"
                echo "  - Remove dangling images"
                echo "  - Clean build cache"
            fi
        else
            echo -e "${YELLOW}[!] Docker daemon not accessible${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Docker not installed${NC}"
    fi
    echo ""
fi

# Clean APT cache
if [[ "$CLEAN_APT" == "true" ]]; then
    echo -e "${BLUE}=== Cleaning APT Cache ===${NC}"

    APT_CACHE_SIZE=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "unknown")
    echo "Current APT cache size: $APT_CACHE_SIZE"

    if [[ "$DRY_RUN" == "false" ]]; then
        if [[ $EUID -ne 0 ]]; then
            echo -e "${RED}[-] Need root privileges to clean APT cache${NC}"
        else
            apt clean
            apt autoclean
            NEW_SIZE=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "unknown")
            echo -e "${GREEN}[+] Cleaned APT cache (new size: $NEW_SIZE)${NC}"
        fi
    else
        echo -e "${YELLOW}[DRY RUN] Would run: apt clean && apt autoclean${NC}"
    fi
    echo ""
fi

# Final disk usage
echo -e "${BLUE}=== Final Disk Usage ===${NC}"
df -h / | awk 'NR==1 || NR==2'
echo ""

# Summary
if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║          Dry Run Complete - No Changes Made             ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "To execute cleanup, run with --execute flag"
else
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Cleanup Complete                            ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
fi
