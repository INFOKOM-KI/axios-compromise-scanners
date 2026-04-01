# Axios Supply-Chain Scanner

Scanning tools for detecting indicators of compromise related to the axios npm package supply chain attack.

## Background

These scanners are based on the report from Google Cloud Threat Intelligence about a North Korean threat actor (UNC1069/GTIG) that targeted the axios npm package. The attack involved malicious packages like `plain-crypto-js` and specific compromised versions of axios.

## Usage

### Basic Scan (`scan1.sh`)

Performs a general security scan checking for:
- Environment integrity issues (NODE_OPTIONS, PATH manipulation)
- Persistence mechanisms (LaunchAgents, Systemd units, crontab entries)
- Stage 2 payload files
- Active C2 connections to `sfrclak.com`
- Malicious entries in package lockfiles
- Global npm/yarn/pnpm packages

```bash
./scan1.sh [path axios]
```

Default path is `$HOME`. The script generates a JSON report (`scan_report_YYYYMMDD_HHMMSS.json`) in the current directory.

### Forensic Scan (`scan2.sh`)

Performs a forensic scan targeting specific UNC1069 indicators:
- Shadow backup files (`package.md`)
- PowerShell masquerading as Windows Terminal (`wt.exe`)
- WAVESHAPER.V2 backdoor payloads
- Windows/Linux persistence mechanisms
- DNS resolution to C2 infrastructure
- Deep lockfile audit for `plain-crypto-js` v4.2.1

```bash
./scan2.sh [path axios]
```

## Requirements

- Linux or macOS
- Bash shell
- Common utilities: `grep`, `find`, `sed`, `xargs`, `sha256sum`
- Optional: `ss` or `netstat` (for connection checking), `dig` (for DNS checks)

## Output

Both scripts display colored output to the terminal:
- `[!!!]` = Found issue (red)
- `[!]` = Warning (yellow)
- `[✓]` = Safe/clear (green)

`scan1.sh` additionally creates a JSON report file with all detected issues.

## Indicators of Compromise Detected

| IOC Type | Description |
|----------|-------------|
| Malicious packages | `plain-crypto-js`, `axios@1.14.1`, `axios@0.30.4` |
| C2 Domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| Payload files | `/tmp/ld.py`, `/Library/Caches/com.apple.act.mond`, `/tmp/6202033.*` |
| Persistence | `MicrosoftUpdate.service`, `system.bat`, suspicious LaunchAgents |

## Response Actions

If issues are found:
1. Isolate the affected host from the network
2. Remove malicious packages: `npm uninstall plain-crypto-js`
3. Delete suspicious files and persistence mechanisms
4. Rotate all credentials (API keys, SSH keys, tokens)
5. Review audit logs for lateral movement

## Author

NAuliajati (csirt@tangerangkota.go.id)
