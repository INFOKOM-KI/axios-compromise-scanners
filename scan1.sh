#!/usr/bin/env bash
# Axios Supply-Chain Scanner
# Author : NAuliajati (csirt@tangerangkota.go.id)
# Based on this report : https://cloud.google.com/blog/topics/threat-intelligence/north-korea-threat-actor-targets-axios-npm-package

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

FOUND_ISSUES=0
SCAN_DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
REPORT_FILE="scan_report_$(date +%Y%m%d_%H%M%S).json"

# Initialize JSON Report
echo "{\"scan_date\": \"$SCAN_DATE\", \"platform\": \"$(uname -s)\", \"issues\": []}" > "$REPORT_FILE"

banner() {
  echo -e "${BOLD} Axios Scanner ${NC}"
}

section() {
  echo -e "\n${CYAN}[*] $1${NC}"
  echo -e "${CYAN}$(printf '%.0s-' {1..50})${NC}"
}

found() {
  echo -e "${RED}[!!!] FOUND: $1${NC}"
  FOUND_ISSUES=$((FOUND_ISSUES + 1))
  
  # JSON report
  local msg=$(echo "$1" | sed 's/"/\\"/g')
  if [[ "$OS" == "Darwin" ]]; then
      # macOS sed compatible
      sed -i '' "s/ ]}/, {\"issue\": \"$msg\"} ]}/" "$REPORT_FILE" 2>/dev/null || \
      sed -i '' "s/\]}/, {\"issue\": \"$msg\"}]}/" "$REPORT_FILE"
  else
      # Linux sed
      sed -i "s/\]}/, {\"issue\": \"$msg\"}]}/" "$REPORT_FILE"
  fi
}

warn() { echo -e "${YELLOW}[!] WARNING: $1${NC}"; }
safe() { echo -e "${GREEN}[✓] $1${NC}"; }
info() { echo -e "    $1"; }

# Determine scan root
SCAN_ROOT="${1:-$HOME}"
OS="$(uname -s)"

banner
info "Platform:    $OS"
info "Scan Root:   $SCAN_ROOT"
info "Report:      $REPORT_FILE"

section "Checking Environment Integrity"
if [[ -n "${NODE_OPTIONS:-}" ]]; then
  if echo "$NODE_OPTIONS" | grep -q "--require"; then
    found "NODE_OPTIONS contains --require: $NODE_OPTIONS (Preload Attack)"
  fi
fi

if echo "$PATH" | grep -qE "/tmp|/dev/shm|/var/tmp"; then
  warn "PATH contains writable directories: $PATH (Binary Hijacking Risk)"
fi
safe "Environment check complete"

section "Checking for Persistence Mechanisms"
if [[ "$OS" == "Darwin" ]]; then
  SUS_LA=$(ls ~/Library/LaunchAgents/ 2>/dev/null | grep -iE "com.apple.act|mond|axios" || true)
  [[ -n "$SUS_LA" ]] && found "Suspicious LaunchAgent: $SUS_LA"
fi

if [[ "$OS" == "Linux" ]]; then
  # Systemd User Units
  if [[ -d "$HOME/.config/systemd/user" ]]; then
    if grep -rEi "ld.py|sfrclak|python.*tmp" "$HOME/.config/systemd/user" 2>/dev/null; then
      found "Suspicious Systemd user unit detected"
    fi
  fi
  # Crontab
  if crontab -l 2>/dev/null | grep -qiE "ld.py|sfrclak|curl|wget"; then
    found "Suspicious crontab entry detected"
  fi
fi
safe "Persistence check complete"

section "Checking for stage-2 payload IOCs"
IOC_FILES=("/Library/Caches/com.apple.act.mond" "/tmp/ld.py" "/tmp/6202033.vbs" "/tmp/6202033.ps1")
for f in "${IOC_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    found "Malicious payload file found: $f"
    # Anti-evasion: Check Hash (ld.py)
    [[ "$f" == "/tmp/ld.py" ]] && info "SHA256: $(sha256sum "$f" 2>/dev/null || echo 'N/A')"
  fi
done

section "Checking for active C2 connections (sfrclak.com)"
NET_CMD=""
command -v ss &>/dev/null && NET_CMD="ss -tunap" || command -v netstat &>/dev/null && NET_CMD="netstat -anp"

if [[ -n "$NET_CMD" ]]; then
  if $NET_CMD 2>/dev/null | grep -qi "sfrclak"; then
    found "Active connection to C2 domain detected"
  else
    safe "No active C2 connections found"
  fi
fi

section "Scanning Project Files"
# Scan Lockfiles
find "$SCAN_ROOT" -maxdepth 6 \
  \( -path "*/node_modules" -o -path "*/.git" -o -path "*/.cache" -o -path "*/Library" \) -prune \
  -o \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print0 2>/dev/null | \
  xargs -0 grep -lE "plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4" 2>/dev/null | while read -r hit; do
    found "Compromised entry in lockfile: $hit"
done

# Scan node_modules for malicious directory
find "$SCAN_ROOT" -maxdepth 5 -type d -name "plain-crypto-js" 2>/dev/null | while read -r dir; do
  found "Malicious package directory: $dir"
done

section "Checking Global Packages"
for mgr in "npm" "yarn" "pnpm"; do
  if command -v $mgr &>/dev/null; then
    OUT=$($mgr list -g --depth=0 2>/dev/null || true)
    if echo "$OUT" | grep -qE "axios@(1\.14\.1|0\.30\.4)|plain-crypto-js"; then
      found "Compromised package in global $mgr"
    fi
  fi
done

echo -e "\n${BOLD}================================================${NC}"
if [[ $FOUND_ISSUES -gt 0 ]]; then
  echo -e "${RED}${BOLD}$FOUND_ISSUES ISSUE(S) FOUND - SYSTEM COMPROMISED${NC}"
  echo -e "Report saved to: $REPORT_FILE"
else
  echo -e "${GREEN}${BOLD}No indicators of compromise found.${NC}"
fi
echo -e "${BOLD}================================================${NC}\n"
