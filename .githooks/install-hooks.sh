#!/usr/bin/env bash
#
# Install Git hooks for this repository
# Run this script once after cloning the repository
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[i] Installing Git hooks..."

# Configure Git to use .githooks directory
cd "$REPO_ROOT"
git config core.hooksPath .githooks

echo "[+] Git hooks configured successfully"
echo "[i] Hooks directory: .githooks"
echo ""
echo "Available hooks:"
ls -1 .githooks/pre-* 2>/dev/null | sed 's/^/  - /'
echo ""
echo "[+] Setup complete! Pre-commit checks will run automatically."
