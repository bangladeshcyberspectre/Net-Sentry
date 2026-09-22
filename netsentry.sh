#!/usr/bin/env bash
#
# NetSentry (shell edition) - Port & Vulnerability Scanner
#
# Scans a target host for a curated list of commonly-exploited ports,
# reports what's open, and grabs a quick service banner where possible.
#
# Author / Credit: Ochena Gamer
# License: MIT (see LICENSE)
#
# IMPORTANT: Use this tool only on hosts you own or are explicitly
# authorized to test. It only detects and reports open ports/banners -
# it does not exploit or attempt to gain access to anything.
#
# Usage:
#   ./netsentry.sh <target> [-p port1,port2,...] [-o report.json] [-t timeout]
#
set -uo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Common ports checked, with a short note on why each matters.
# ---------------------------------------------------------------------------
declare -A COMMON_PORTS=(
  [21]="FTP - often allows anonymous or unencrypted login"
  [22]="SSH - check for outdated versions / weak auth"
  [23]="Telnet - unencrypted, should not be exposed"
  [25]="SMTP - mail relay, check for open relay"
  [53]="DNS - can be abused for amplification if misconfigured"
  [80]="HTTP - check for outdated server banners / missing HTTPS"
  [110]="POP3 - unencrypted mail retrieval"
  [139]="NetBIOS - legacy Windows file sharing"
  [143]="IMAP - unencrypted mail retrieval"
  [443]="HTTPS - check certificate validity separately"
  [445]="SMB - frequent target for lateral movement, keep patched"
  [3306]="MySQL - should not be exposed to the internet"
  [3389]="RDP - frequent brute-force target"
  [5900]="VNC - often weak/no auth by default"
  [8080]="HTTP-alt - common admin panel port"
)

TIMEOUT=1
OUTPUT=""
TARGET=""
PORTS_ARG=""

usage() {
  echo "NetSentry v${VERSION} (shell edition) - Port & Vulnerability Scanner"
  echo
  echo "Usage: $0 <target> [-p port1,port2,...] [-o report.json] [-t timeout_seconds]"
  echo
  echo "  <target>            Hostname or IP address to scan"
  echo "  -p ports             Comma-separated list of ports (default: common ports)"
  echo "  -o report.json        Save results as a JSON report"
  echo "  -t timeout_seconds    Per-port connect timeout (default: 1)"
  exit 1
}

[ $# -eq 0 ] && usage

TARGET="$1"; shift
[[ "$TARGET" == -* ]] && usage

while getopts ":p:o:t:" opt; do
  case "$opt" in
    p) PORTS_ARG="$OPTARG" ;;
    o) OUTPUT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    *) usage ;;
  esac
done

echo "  _   _      _   ____             _   _              _  "
echo " | \\ | | ___| |_/ ___|  ___ _ __ | |_(_)_ __   ___ | | "
echo " |  \\| |/ _ \\ __\\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\| | "
echo " | |\\  |  __/ |_ ___) |  __/ | | | |_| | | | |  __/|_| "
echo " |_| \\_|\\___|\\__|____/ \\___|_| |_|\\__|_|_| |_|\\___(_)_| "
echo
echo "        NetSentry v${VERSION} (shell edition) - Vulnerability Scanner"
echo

# Resolve target to an IP for display purposes (best effort; falls back to name)
IP=$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1}' | head -n1)
[ -z "$IP" ] && IP="$TARGET"

# Build the list of ports to check
if [ -n "$PORTS_ARG" ]; then
  IFS=',' read -ra PORTS <<< "$PORTS_ARG"
else
  PORTS=("${!COMMON_PORTS[@]}")
fi

# Sort ports numerically
IFS=$'\n' PORTS=($(sort -n <<<"${PORTS[*]}")); unset IFS

echo "[*] Scanning ${TARGET} (${IP}) — ${#PORTS[@]} port(s)..."
echo

OPEN_COUNT=0
JSON_FINDINGS="[]"

for port in "${PORTS[@]}"; do
  note="${COMMON_PORTS[$port]:-unknown service}"

  if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${TARGET}/${port}" 2>/dev/null; then
    OPEN_COUNT=$((OPEN_COUNT + 1))
    banner=""

    # Try a quick banner grab (best effort, ignore failures)
    if [ "$port" = "80" ] || [ "$port" = "8080" ]; then
      banner=$(timeout "$TIMEOUT" bash -c \
        "exec 3<>/dev/tcp/${TARGET}/${port}; printf 'HEAD / HTTP/1.0\r\n\r\n' >&3; head -n1 <&3" \
        2>/dev/null | tr -d '\r')
    else
      banner=$(timeout "$TIMEOUT" bash -c \
        "exec 3<>/dev/tcp/${TARGET}/${port}; head -n1 <&3" 2>/dev/null | tr -d '\r')
    fi

    printf "  [OPEN] port %-6s %s\n" "$port" "$note"
    [ -n "$banner" ] && printf "         banner: %s\n" "$banner"

    exec 3<&- 2>/dev/null
    exec 3>&- 2>/dev/null

    if [ -n "$OUTPUT" ]; then
      esc_note=$(printf '%s' "$note" | sed 's/"/\\"/g')
      esc_banner=$(printf '%s' "$banner" | sed 's/"/\\"/g')
      entry="{\"port\": ${port}, \"note\": \"${esc_note}\", \"banner\": \"${esc_banner}\"}"
      if [ "$JSON_FINDINGS" = "[]" ]; then
        JSON_FINDINGS="[${entry}]"
      else
        JSON_FINDINGS="${JSON_FINDINGS%]}, ${entry}]"
      fi
    fi
  fi
done

if [ "$OPEN_COUNT" -eq 0 ]; then
  echo "  No commonly-flagged ports were found open."
fi

echo
echo "[*] Scan complete: ${OPEN_COUNT} open port(s) found."

if [ -n "$OUTPUT" ]; then
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  cat > "$OUTPUT" <<EOF
{
  "tool": "NetSentry v${VERSION} (shell edition)",
  "type": "vuln_scan",
  "target": "${TARGET}",
  "ip": "${IP}",
  "generated_at": "${timestamp}",
  "findings": ${JSON_FINDINGS}
}
EOF
  echo "[*] Report saved to ${OUTPUT}"
fi
