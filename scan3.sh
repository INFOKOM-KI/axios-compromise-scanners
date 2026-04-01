#!/usr/bin/env bash
# Axios Scanner - © TangerangKota-CSIRT (GTIG/UNC1069)

set -euo pipefail

OS_TYPE=$(uname -s)
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
MALICIOUS_VERSIONS=("1.14.1" "0.30.4")
C2_DOMAIN="sfrclak.com"
C2_IP="142.11.206.73"
FINDINGS=0
SEARCH_ROOT="${1:-$HOME}" # Default ke Dir Home

banner() {
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║      Axios Scanner - ©TangerangKota-CSIRT                    ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
  echo -e "  Target Root : ${BOLD}${SEARCH_ROOT}${RESET}"
  echo -e "  Platform    : ${BOLD}${OS_TYPE}${RESET}\n"
}

step() { echo -e "\n${BOLD}${CYAN}[*] $1${RESET}"; echo -e "${CYAN}--------------------------------------------------${RESET}"; }
hit() { echo -e "  ${RED}[!] DETECTED:${RESET} $*"; FINDINGS=$((FINDINGS + 1)); }
ok()  { echo -e "  ${GREEN}[✓] CLEAN:${RESET} $*"; }
info() { echo -e "  ${CYAN}[i] INFO:${RESET} $*"; }

# Forensic
check_version() {
  local file="$1"
  grep -m1 '"version"' "$file" | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' 2>/dev/null || echo "unknown"
}

# Main Execution
banner

# Filesystem Scan
step "Scanning Filesystem IOC & Artifacts"
start_time=$(date +%s)

# Mencari package-lock, node_modules, dan file shadow package.md
while IFS= read -r -d '' entry; do
  # Check axios version
  if [[ "$entry" == *"/node_modules/axios/package.json" ]]; then
    ver=$(check_version "$entry")
    for bad in "${MALICIOUS_VERSIONS[@]}"; do
      if [[ "$ver" == "$bad" ]]; then
        hit "Compromised axios@$ver found at: $(dirname "$entry")"
      fi
    done
  fi

  # Check plain-crypto-js (Dropper)
  if [[ "$entry" == *"/node_modules/plain-crypto-js" ]]; then
    hit "Malicious package 'plain-crypto-js' found: $entry"
  fi

  # Check Anti-Forensic Artifact (package.md)
  if [[ "$entry" == *"package.md" ]]; then
    hit "Shadow backup 'package.md' found at: $entry (Indicates payload execution)"
  fi

  # Check Lockfile poisoning
  if [[ "$entry" == *"package-lock.json" || "$entry" == *"yarn.lock" ]]; then
    if grep -qE "plain-crypto-js|axios@1\.14\.1|axios@0\.30\.4" "$entry" 2>/dev/null; then
      hit "Poisoned lockfile detected: $entry"
    fi
  fi
done < <(find "$SEARCH_ROOT" \
  \( -path "/proc" -o -path "/sys" -o -path "/dev" -o -path "/run" -o -path "/snap" -o -path "/var/lib/docker" \) -prune -o \
  \( -name "package.json" -o -name "package.md" -o -name "package-lock.json" -o -name "yarn.lock" -o -path "*/node_modules/plain-crypto-js" \) \
  -print0 2>/dev/null)

# Stage 2 Payload Check (WAVESHAPER.V2)
step "Checking for Active Backdoor Payloads"
IOC_FILES=("/tmp/ld.py" "/Library/Caches/com.apple.act.mond" "/tmp/6202033.ps1" "/tmp/6202033.vbs")
for f in "${IOC_FILES[@]}"; do
  if [[ -f "$f" ]]; then
    hit "WAVESHAPER.V2 Payload present: $f"
  fi
done

# Masquerade Detection (Windows OS)
if [[ -d "/mnt/c" ]]; then
  step "Analyzing Windows Masquerading (wt.exe)"
  WT_PATH="/mnt/c/ProgramData/wt.exe"
  if [[ -f "$WT_PATH" ]]; then
    # Deep inspect: Is it Windows Terminal or PowerShell?
    if strings "$WT_PATH" 2>/dev/null | grep -iq "PowerShell"; then
      hit "Fake wt.exe found! It is actually PowerShell (UNC1069 Tactic)"
    else
      ok "wt.exe exists but looks legitimate"
    fi
  fi
fi

# Network & Persistence
step "Checking Network & Persistence"
# DNS Check
if command -v dig &>/dev/null; then
  RES=$(dig +short $C2_DOMAIN 2>/dev/null || true)
  [[ "$RES" == "$C2_IP" ]] && hit "Local DNS resolves $C2_DOMAIN to malicious IP $C2_IP"
fi

# Persistence Check
if [[ "$OS_TYPE" == "Linux" ]]; then
  if crontab -l 2>/dev/null | grep -qiE "ld.py|sfrclak"; then
    hit "Persistence found in Crontab"
  fi
fi

# Summary
end_time=$(date +%s)
duration=$((end_time - start_time))

echo -e "\n${BOLD}==================================================${RESET}"
echo -e "Scan Duration : $duration seconds"
if [[ $FINDINGS -gt 0 ]]; then
  echo -e "${RED}${BOLD}RESULT        : $FINDINGS ISSUES DETECTED!${RESET}"
  echo -e "${YELLOW}Action Required:${RESET}"
  echo -e "  1. Rotate ALL ENV secrets & API Keys segera"
  echo -e "  2. Hapus payload yang ditemukan"
  echo -e "  3. Re-install axios ke versi 1.13.2 atau 1.14.0"
else
  echo -e "${GREEN}${BOLD}RESULT        : SYSTEM APPEARS CLEAN${RESET}"
fi
echo -e "${BOLD}==================================================${RESET}\n"
