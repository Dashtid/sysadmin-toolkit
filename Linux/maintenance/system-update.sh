#!/bin/bash

# System Update Script for Ubuntu Lab Server
# Updates system packages, cleans up old packages, and checks for reboot requirement
# Safe to run - asks for confirmation before major changes

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

DRY_RUN=false
AUTO_YES=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dry-run    Show what would be done without making changes"
            echo "  -y, --yes    Skip confirmation prompts"
            echo "  -h, --help   Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         Ubuntu System Update & Maintenance              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
    echo ""
fi

# Check if running as root
if [[ $EUID -ne 0 ]] && [[ "$DRY_RUN" == "false" ]]; then
    echo -e "${RED}[-] This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Update package lists
echo -e "${BLUE}=== Updating Package Lists ===${NC}"
if [[ "$DRY_RUN" == "false" ]]; then
    apt update
    echo -e "${GREEN}[+] Package lists updated${NC}"
else
    echo -e "${YELLOW}[DRY RUN] Would run: apt update${NC}"
fi
echo ""

# Check for available updates
echo -e "${BLUE}=== Checking for Available Updates ===${NC}"
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0)

if [[ $UPDATES -eq 1 ]]; then
    echo -e "${GREEN}[+] System is up to date${NC}"
    echo ""
else
    echo -e "${YELLOW}Found $UPDATES packages to upgrade${NC}"
    echo ""

    # Show upgradable packages
    echo "Upgradable packages:"
    apt list --upgradable 2>/dev/null | tail -n +2
    echo ""

    # Confirm upgrade
    if [[ "$AUTO_YES" == "false" ]] && [[ "$DRY_RUN" == "false" ]]; then
        read -p "Proceed with upgrade? (y/N) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Upgrade cancelled"
            exit 0
        fi
    fi

    # Perform upgrade
    echo -e "${BLUE}=== Upgrading Packages ===${NC}"
    if [[ "$DRY_RUN" == "false" ]]; then
        apt upgrade -y
        echo -e "${GREEN}[+] Packages upgraded${NC}"
    else
        echo -e "${YELLOW}[DRY RUN] Would run: apt upgrade -y${NC}"
    fi
    echo ""
fi

# Clean up
echo -e "${BLUE}=== Cleaning Up ===${NC}"
if [[ "$DRY_RUN" == "false" ]]; then
    apt autoremove -y
    apt autoclean
    echo -e "${GREEN}[+] Cleanup complete${NC}"
else
    echo -e "${YELLOW}[DRY RUN] Would run: apt autoremove -y && apt autoclean${NC}"
fi
echo ""

# Check for reboot requirement
echo -e "${BLUE}=== Checking Reboot Requirement ===${NC}"
if [[ -f /var/run/reboot-required ]]; then
    echo -e "${YELLOW}[!] System reboot required${NC}"
    if [[ -f /var/run/reboot-required.pkgs ]]; then
        echo "Packages requiring reboot:"
        cat /var/run/reboot-required.pkgs
    fi
    echo ""
    echo "Reboot with: sudo reboot"
else
    echo -e "${GREEN}[+] No reboot required${NC}"
fi
echo ""

# Disk space check
echo -e "${BLUE}=== Disk Space ===${NC}"
df -h / | awk 'NR==1 || NR==2'
echo ""

# Summary
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Update Complete                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
