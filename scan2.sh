#!/usr/bin/env bash
# Axios Supply-Chain Scanner - GTIG/UNC1069
# Based on this report : https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
FOUND_ISSUES=0
REPORT_FILE="axios_forensic_$(date +%s).json"
OS="$(uname -s)"

# IOCs from April 2026
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
MALICIOUS_HASH="e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09" # SILKBELL setup.js

found() { echo -e "${RED}[!!!] FOUND: $1${NC}"; FOUND_ISSUES=$((FOUND_ISSUES + 1)); }

section() { echo -e "\n${CYAN}[*] $1${NC}"; }

section "1. Filesystem IOCs (UNC1069 Specific)"
# Check for original package backup (Artifact setup.js)
find "$1" -maxdepth 8 -name "package.md" 2>/dev/null | while read -r f; do
    found "Shadow backup file found: $f (Indicates postinstall manipulation)"
done

# Check for Windows PowerShell Masquerading
if [[ -f "/mnt/c/ProgramData/wt.exe" ]]; then
    # If wt.exe is actually powershell.exe
    if strings "/mnt/c/ProgramData/wt.exe" 2>/dev/null | grep -q "PowerShell"; then
        found "Malicious wt.exe detected (PowerShell masquerading as Windows Terminal)"
    fi
fi

# Linux/macOS Stage 2 Backdoors (WAVESHAPER.V2)
FILES=("/tmp/ld.py" "/Library/Caches/com.apple.act.mond" "/tmp/6202033.ps1" "/tmp/6202033.vbs")
for f in "${FILES[@]}"; do
    if [[ -f "$f" ]]; then
        found "WAVESHAPER.V2 Payload detected: $f"
        [[ -f "$f" ]] && sha256sum "$f" 2>/dev/null || true
    fi
done

section "2. Persistence & Registry (WAVESHAPER.V2)"
if [[ "$OS" == "Linux" ]]; then
    if [[ -f "/etc/systemd/system/MicrosoftUpdate.service" ]] || crontab -l 2>/dev/null | grep -q "6202033"; then
        found "Persistence entry found in Systemd/Cron"
    fi
fi
# Windows Persistence (Check via /mnt/c on WSL Aul)
if [[ -d "/mnt/c" ]]; then
    if [[ -f "/mnt/c/ProgramData/system.bat" ]]; then
        found "Windows Persistence Script found: %PROGRAMDATA%\\system.bat"
    fi
fi

section "3. Network Beaconing & DNS"
# Check for C2 resolution
if command -v dig &>/dev/null; then
    RESOLVED=$(dig +short $C2_DOMAIN 2>/dev/null || true)
    if [[ "$RESOLVED" == "$C2_IP" ]]; then
        warn "DNS Resolution matches UNC1069 Infrastructure ($C2_IP)"
    fi
fi

section "4. Deep Lockfile Audit"
# Look for the dropper hash and the specific malicious version 4.2.1
find "$1" -maxdepth 8 -name "package-lock.json" -exec grep -l "plain-crypto-js" {} + | while read -r lock; do
    if grep -q "4.2.1" "$lock"; then
        found "Confirmed Malicious plain-crypto-js v4.2.1 in $lock"
    fi
done

echo -e "\n--- SUMMARY ---"
if [[ $FOUND_ISSUES -gt 0 ]]; then
    echo -e "${RED}${BOLD}SYSTEM COMPROMISED.${NC} Segera isolasi host ini."
    echo -e "Lakukan rotasi credentials (API Keys, SSH, Tokens) karena WAVESHAPER.V2 memiliki fitur exfiltration"
else
    echo -e "${GREEN}No specific IOCs from April 2026 report found.${NC}"
fi
