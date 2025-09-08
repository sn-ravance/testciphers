#!/usr/bin/env bash
# tls_sweeper.sh
# Liveness + TLS protocol policy check (TLS 1.2+ only) for IPs/DNS.
# Author: Rob Vance
#
# To Do:
# Fix the Discovery logic function. It currently does not scan and find any open ports with encryption 

set -euo pipefail

# -------- Defaults --------
PRIMARY_PORT="${PORT:-443}"           # Back-compat with PORT env
FALLBACK_PORTS="8443,4443,3389"       # When primary isn't listening
ALSO_SCAN_ALTS=0                      # -A to scan alts even if primary is open
CONCURRENCY="${CONCURRENCY:-8}"
OUTPUT_FILE="scan_results_$(date +%Y%m%d_%H%M%S).csv"
NMAP_TIMEOUT="7s"
SCRIPT_TIMEOUT="8s"
PING_TIMEOUT_MS="1000"                # macOS ping -W is ms
QUIET=0
HOSTS_FILE=""
DETAILS=0                    # -E to save HTML reports for FAIL
DETAILS_DIR=""

# -------- Discovery (new) --------
DISCOVER=0                   # -D to enable
TOP_PORTS="${TOP_PORTS:-2000}"   # -t N (only used with -D)
PORT_RANGE=""                # -R "1-65535" or "443,8443,..." (overrides -t)
DISCOVER_TIMEOUT="45s"       # nmap host-timeout for discovery


# -------- Colors/Icons --------
if [ -t 1 ]; then
  BOLD='\033[1m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; GRAY='\033[90m'; NC='\033[0m'
else
  BOLD=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; GRAY=''; NC=''
fi
ICON_OK="✅"; ICON_FAIL="❌"; ICON_WARN="⚠️"; ICON_WAIT="⏳"; ICON_INFO="ℹ️"

# -------- Utilities --------
usage() {
  cat <<EOF
Usage:
  $0 [options] host1 [host2 ...]
  $0 [options] -f hosts.txt

e.g.,
  $0 -f targets.txt -D -R "1-65535" -c 16
  $0 -f i1497.txt -P 443,8443,3389 -c 16

Options:
  -f FILE        File with hosts (one DNS/IP per line; '#' comments allowed)
  -p PORT        Primary port to test (default: ${PRIMARY_PORT})
  -P LIST        Fallback ports (CSV) if primary not open (default: ${FALLBACK_PORTS})
  -A             Also scan fallback ports even if primary is open
  -c N           Concurrency across hosts (default: ${CONCURRENCY})
  -o FILE        Output CSV (default: ${OUTPUT_FILE})
  -q             Quiet mode (less stdout)
  -D             Discovery mode: find open ports first, then test TLS on them
  -E             Save detailed HTML reports (testssl.sh) for FAIL results
  -t N           With -D, scan top N TCP ports (default: ${TOP_PORTS})
  -R SPEC        With -D, scan a specific port set (e.g., "1-65535" or "80,443,3389");
                 overrides -t
  -h             Help

Behavior:
  • Liveness: ping, then nmap ping if ICMP blocked.
  • Per-host scanning:
      - Check primary port. If closed -> try fallback ports (8443,4443,3389 by default).
      - Use -A to always scan alternates as well.
  • TLS check: testssl.sh (-p protocols) -> nmap ssl-enum-ciphers -> openssl s_client.
  • PASS = only TLS1.2/1.3. FAIL = any SSLv2/3 or TLS1.0/1.1. NO_TLS = speaks TCP but not TLS on that port.
  • CSV rows are per host:port with fields:
      timestamp,host,port,alive,tls_status,versions,tool,details
Keyboard controls (interactive runs):
  p = pause, r = resume, q = quit (graceful)
EOF
}

# When -E is enabled, generate an HTML report with testssl.sh for FAIL cases
ensure_details_dir() {
  [ "$DETAILS" -eq 1 ] || return 0
  if [ -z "$DETAILS_DIR" ]; then
    local base
    base="${OUTPUT_FILE%.csv}"
    DETAILS_DIR="details/${base}"
    mkdir -p "$DETAILS_DIR" 2>/dev/null || true
  fi
}

save_testssl_report() {
  [ "$DETAILS" -eq 1 ] || return 0
  [ "$HAVE_TESTSSL" -eq 1 ] || { log warn "${ICON_WARN} Details requested but testssl.sh not found"; return 0; }
  local host="$1" port="$2"
  ensure_details_dir
  local target="$host"
  [ -n "$port" ] && [ "$port" != "-" ] && target="${host}:${port}"
  local safe_name
  safe_name="${host}_${port:-dash}"
  safe_name="${safe_name//[:\/*?\"<>| ]/_}"
  # Build absolute paths to avoid CWD confusion across subshells
  local abs_details_dir
  abs_details_dir="$(cd "$DETAILS_DIR" 2>/dev/null && pwd)"
  [ -z "$abs_details_dir" ] && abs_details_dir="$DETAILS_DIR"  # fallback
  local html_out="${abs_details_dir}/${safe_name}.html"
  local log_out="${abs_details_dir}/${safe_name}.log"
  log info "${ICON_INFO} Saving detailed testssl report: ${html_out}"
  # --html creates index.html by default; prefer --htmlfile when available
  if testssl.sh -h 2>&1 | grep -q -- '--htmlfile'; then
    LC_ALL=C testssl.sh --htmlfile "$html_out" --hints -4 -s -p -f -E -R -U "$target" >"$log_out" 2>&1 || true
  else
    # Fallback: run in a temp dir and move index.html
    local tmpd
    tmpd=$(mktemp -d "/tmp/testssl_html.XXXXXX")
    ( cd "$tmpd" && LC_ALL=C testssl.sh --html --hints -4 -s -p -f -E -R -U "$target" >"$log_out" 2>&1 || true )
    # Move the first HTML report we find (testssl versions vary: index*.html or <host>_p<port>-<ts>.html)
    local produced
    produced=$(ls -1 "$tmpd"/index*.html 2>/dev/null | head -n 1 || true)
    if [ -z "$produced" ]; then
      produced=$(ls -1t "$tmpd"/*.html 2>/dev/null | head -n 1 || true)
    fi
    if [ -n "$produced" ]; then
      mv "$produced" "$html_out" 2>/dev/null || true
    fi
    rm -rf "$tmpd" 2>/dev/null || true
  fi
  # Verify output exists; if not, attempt one more time via temp dir regardless of htmlfile support
  if [ ! -s "$html_out" ]; then
    local tmpd2 produced2
    tmpd2=$(mktemp -d "/tmp/testssl_html.XXXXXX")
    ( cd "$tmpd2" && LC_ALL=C testssl.sh --html --hints -4 -s -p -f -E -R -U "$target" >>"$log_out" 2>&1 || true )
    produced2=$(ls -1 "$tmpd2"/index*.html 2>/dev/null | head -n 1 || true)
    if [ -z "$produced2" ]; then
      produced2=$(ls -1t "$tmpd2"/*.html 2>/dev/null | head -n 1 || true)
    fi
    if [ -n "$produced2" ]; then
      mv "$produced2" "$html_out" 2>/dev/null || true
    fi
    rm -rf "$tmpd2" 2>/dev/null || true
  fi
  # If still no HTML, try a minimal-flag retry which is more compatible across versions
  if [ ! -s "$html_out" ]; then
    if testssl.sh -h 2>&1 | grep -q -- '--htmlfile'; then
      LC_ALL=C testssl.sh --htmlfile "$html_out" -U "$target" >>"$log_out" 2>&1 || true
    else
      local tmpd3 produced3
      tmpd3=$(mktemp -d "/tmp/testssl_html.XXXXXX")
      ( cd "$tmpd3" && LC_ALL=C testssl.sh --html -U "$target" >>"$log_out" 2>&1 || true )
      produced3=$(ls -1 "$tmpd3"/index*.html 2>/dev/null | head -n 1 || true)
      if [ -z "$produced3" ]; then
        produced3=$(ls -1t "$tmpd3"/*.html 2>/dev/null | head -n 1 || true)
      fi
      if [ -n "$produced3" ]; then
        mv "$produced3" "$html_out" 2>/dev/null || true
      fi
      rm -rf "$tmpd3" 2>/dev/null || true
    fi
  fi
  # As a last resort, some testssl versions write to CWD with pattern <host>_p<port>-<ts>.html
  if [ ! -s "$html_out" ]; then
    local cwd_html
    cwd_html=$(ls -1t *"${host}"*p"${port}"-*.html 2>/dev/null | head -n 1 || true)
    if [ -n "$cwd_html" ] && [ -s "$cwd_html" ]; then
      mv "$cwd_html" "$html_out" 2>/dev/null || true
    fi
  fi
  # If still nothing, save a textual fallback so the user has evidence
  if [ ! -s "$html_out" ]; then
    local txt_out="${DETAILS_DIR}/${safe_name}.txt"
    log warn "${ICON_WARN} testssl HTML not produced; saving text output instead: ${txt_out} (see ${log_out} for details)"
    LC_ALL=C testssl.sh --hints -4 -s -p -f -E -R -U "$target" > "$txt_out" 2>>"$log_out" || true
  fi
}

# -------- Global Discovery (new workflow) --------
# Produces:
#   - ACTIVE_FILE: one host per line, active hosts only
#   - PORTS_FILE: CSV lines "host,port" for each open port observed on active hosts
#   - GLOBAL_PORTS_CSV: comma-separated unique open ports across all active hosts
#   - Sets GLOBAL_DISCOVERY_DONE=1 when complete

GLOBAL_DISCOVERY_DONE=0
TEMP_DIR=""
ACTIVE_FILE=""
PORTS_FILE=""
GLOBAL_PORTS_CSV=""

setup_temp_dir() {
  TEMP_DIR=$(mktemp -d "/tmp/tls_sweeper.XXXXXXXX")
  ACTIVE_FILE="$TEMP_DIR/active.txt"
  PORTS_FILE="$TEMP_DIR/ports.txt"
  : > "$ACTIVE_FILE"
  : > "$PORTS_FILE"
}

cleanup_temp_dir() {
  [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR" 2>/dev/null || true
}

trap 'cleanup_temp_dir' EXIT

run_global_discovery() {
  local port_spec=""
  if [ -n "${PORT_RANGE:-}" ]; then
    port_spec="-p $PORT_RANGE"
  else
    port_spec="--top-ports $TOP_PORTS"
  fi

  setup_temp_dir
  log info "${ICON_INFO} Global discovery: temp dir = ${TEMP_DIR}"
  log info "${ICON_INFO} Step 1/3: finding active hosts..."

  # Step 1: Active hosts (reuse is_alive to honor local environment)
  local h
  for h in "${HOSTS[@]}"; do
    if is_alive "$h"; then
      echo "$h" >> "$ACTIVE_FILE"
    fi
  done

  if [ ! -s "$ACTIVE_FILE" ]; then
    log warn "${ICON_WARN} Global discovery: no active hosts detected"
    GLOBAL_PORTS_CSV=""
    GLOBAL_DISCOVERY_DONE=1
    return
  fi

  log ok "${ICON_OK} Active hosts file: ${ACTIVE_FILE}"
  log info "${ICON_INFO} Step 2/3: scanning open ports on active hosts..."

  # Step 2: For each active host, enumerate open ports (fast connect scan)
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    # Use -sT unprivileged TCP connect; no -sV here for speed/reliability
    local out
    out="$(nmap -Pn -n --open $port_spec -sT -T4 --host-timeout "$DISCOVER_TIMEOUT" "$h" 2>/dev/null || true)"
    # Parse lines like: "443/tcp open https"
    echo "$out" | awk -v host="$h" '/^[0-9]+\/tcp[[:space:]]+open/ {split($1,p,"/"); printf("%s,%s\n", host, p[1])}' >> "$PORTS_FILE"
  done < "$ACTIVE_FILE"

  if [ ! -s "$PORTS_FILE" ]; then
    log warn "${ICON_WARN} Global discovery: no open ports found on active hosts"
    GLOBAL_PORTS_CSV=""
    GLOBAL_DISCOVERY_DONE=1
    return
  fi

  log ok "${ICON_OK} Ports file: ${PORTS_FILE}"
  log info "${ICON_INFO} Step 3/3: computing unique open ports across hosts..."

  # Step 3: Unique ports across all active hosts
  GLOBAL_PORTS_CSV="$(awk -F, '{print $2}' "$PORTS_FILE" | sort -n | uniq | paste -sd, -)"
  GLOBAL_DISCOVERY_DONE=1
  log ok "${ICON_OK} Unique open ports: ${GLOBAL_PORTS_CSV}"
}

log() {
  local level="$1"; shift
  local msg="$*"
  if [ "$QUIET" -eq 1 ] && [ "$level" = "info" ]; then return 0; fi
  case "$level" in
    info)  printf "%b%b%b\n" "$GRAY" "$msg" "$NC" ;;
    ok)    printf "%b%b%b\n" "$GREEN" "$msg" "$NC" ;;
    warn)  printf "%b%b%b\n" "$YELLOW" "$msg" "$NC" ;;
    err)   printf "%b%b%b\n" "$RED" "$msg" "$NC" ;;
    *)     printf "%s\n" "$msg" ;;
  esac
}

csv_escape() { local s="$1"; s=${s//\"/\"\"}; printf "\"%s\"" "$s"; }

format_target() {
  local host="$1" port="$2"
  if [[ "$host" == *:* ]] && [[ "$host" != \[*\]* ]]; then
    printf "[%s]:%s" "$host" "$port"
  else
    printf "%s:%s" "$host" "$port"
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# -------- Tool detection --------
HAVE_NMAP=0; HAVE_TESTSSL=0; HAVE_OPENSSL=0; HAVE_NC=0
have_cmd nmap && HAVE_NMAP=1
have_cmd testssl.sh && HAVE_TESTSSL=1
have_cmd openssl && HAVE_OPENSSL=1
have_cmd nc && HAVE_NC=1

# -------- Args --------
while getopts ":f:p:P:c:o:At:R:qhDE" opt; do
  case "$opt" in
    f) HOSTS_FILE="$OPTARG" ;;
    p) PRIMARY_PORT="$OPTARG" ;;
    P) FALLBACK_PORTS="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    A) ALSO_SCAN_ALTS=1 ;;
    D) DISCOVER=1 ;;
    t) TOP_PORTS="$OPTARG" ;;
    R) PORT_RANGE="$OPTARG" ;;
    q) QUIET=1 ;;
    E) DETAILS=1 ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG (use -h for help; details flag is -E or --details)" >&2; usage; exit 2 ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND-1))

HOSTS=()

# Pre-parse long options (strip them before getopts). Currently supports: --details
if [ "$#" -gt 0 ]; then
  NEWARGS=()
  for arg in "$@"; do
    case "$arg" in
      --details)
        DETAILS=1
        ;;
      *)
        NEWARGS+=("$arg")
        ;;
    esac
  done
  # reset positional parameters
  set -- "${NEWARGS[@]}"
fi

if [ -n "$HOSTS_FILE" ]; then
  [ -f "$HOSTS_FILE" ] || { echo "Host file not found: $HOSTS_FILE" >&2; exit 2; }
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && HOSTS+=("$line")
  done < "$HOSTS_FILE"
fi
if [ "$#" -gt 0 ]; then HOSTS+=("$@"); fi
[ "${#HOSTS[@]}" -gt 0 ] || { usage; exit 2; }

# -------- CSV header --------
echo "timestamp,host,port,alive,tls_status,versions,tool,details" > "$OUTPUT_FILE"

# -------- Interrupt handling (Ctrl-C) --------
stop_background_jobs() {
  local pids
  pids=$(jobs -rp || true)
  if [ -n "${pids:-}" ]; then
    kill $pids 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}

cleanup_and_exit() {
  log warn "${ICON_WARN} Interrupt received — stopping scans and summarizing results..."
  stop_background_jobs
  summarize_results 130
}

# Trap SIGINT (Ctrl-C) and SIGTERM
trap 'cleanup_and_exit' INT TERM

# -------- Pause/Resume (SIGUSR1/SIGUSR2) --------
PAUSED=0
pause_scans() {
  PAUSED=1
  log warn "${ICON_WARN} Pause requested — halting scheduling and stopping background scans..."
  local pids
  pids=$(jobs -rp || true)
  if [ -n "${pids:-}" ]; then
    kill -STOP $pids 2>/dev/null || true
  fi
  start_status_ticker
}

resume_scans() {
  if [ "$PAUSED" -eq 1 ]; then
    log info "${ICON_INFO} Resuming scans..."
  fi
  PAUSED=0
  local pids
  pids=$(jobs -rp || true)
  if [ -n "${pids:-}" ]; then
    kill -CONT $pids 2>/dev/null || true
  fi
  stop_status_ticker
}

trap 'pause_scans' USR1
trap 'resume_scans' USR2

# -------- Keyboard input listener (p=pause, r=resume, q=quit) --------
INPUT_LISTENER_PID=""
STATUS_TICK_PID=""

start_status_ticker() {
  # Only show ticker if stdout is a TTY
  [ -t 1 ] || return 0
  (
    set +e
    while :; do
      [ "${PAUSED:-0}" -eq 1 ] || break
      log warn "${ICON_WARN} PAUSED — press 'r' to resume, 'q' to quit"
      sleep 2
    done
  ) &
  STATUS_TICK_PID=$!
}

stop_status_ticker() {
  if [ -n "${STATUS_TICK_PID:-}" ] && kill -0 "$STATUS_TICK_PID" 2>/dev/null; then
    kill "$STATUS_TICK_PID" 2>/dev/null || true
    wait "$STATUS_TICK_PID" 2>/dev/null || true
  fi
  STATUS_TICK_PID=""
}
stop_input_listener() {
  if [ -n "${INPUT_LISTENER_PID:-}" ] && kill -0 "$INPUT_LISTENER_PID" 2>/dev/null; then
    kill "$INPUT_LISTENER_PID" 2>/dev/null || true
    wait "$INPUT_LISTENER_PID" 2>/dev/null || true
  fi
  stop_status_ticker
}

start_input_listener() {
  # Run in a subshell with -e disabled so read errors don't kill the script
  (
    set +e
    while :; do
      # -s silent, -n 1 one char; if stdin isn't a TTY, this will likely exit
      read -r -s -n 1 key || break
      case "$key" in
        p|P) pause_scans ;;
        r|R) resume_scans ;;
        q|Q) cleanup_and_exit ;;
        *) ;;  # ignore other keys
      esac
    done
  ) &
  INPUT_LISTENER_PID=$!
}

# Ensure the listener is stopped on script exit
trap 'stop_input_listener' EXIT

# -------- Checks --------
is_alive() {
  local host="$1"
  if ping -c 1 -W "$PING_TIMEOUT_MS" "$host" >/dev/null 2>&1; then return 0; fi
  if [ "$HAVE_NMAP" -eq 1 ]; then
    nmap -n -sn -PE -PA80,443,22 --host-timeout "$NMAP_TIMEOUT" "$host" 2>/dev/null | grep -q "Host is up" && return 0
  fi
  return 1
}

port_open() {
  local host="$1" port="$2"
  # Prefer fast netcat check
  if [ "$HAVE_NC" -eq 1 ]; then
    # macOS nc supports -z (scan) and -G (timeout in seconds)
    nc -z -G 1 "$host" "$port" >/dev/null 2>&1 && return 0
  fi
  # Fallback to nmap single-port check
  if [ "$HAVE_NMAP" -eq 1 ]; then
    local out
    out="$(nmap -Pn -n -p "$port" --host-timeout "$NMAP_TIMEOUT" "$host" 2>/dev/null || true)"
    echo "$out" | grep -qE "$port/(open|open\\|filtered)" && return 0
  fi
  # No tool -> assume closed
  return 1
}

# (Legacy) Per-host discovery retained but not used in new global discovery path
discover_candidate_ports() {
  local host="$1"
  [ "$HAVE_NMAP" -eq 1 ] || { echo ""; return; }

  local port_spec=""
  if [ -n "$PORT_RANGE" ]; then
    port_spec="-p $PORT_RANGE"
  else
    port_spec="--top-ports $TOP_PORTS"
  fi

  # Strategy:
  #  - For large ranges (e.g., "1-65535"), prefer a fast connect scan without -sV first, then TLS-check.
  #  - For smaller/curated sets, use -sV to glean service hints.
  local out=""
  local all_open
  if [[ "$PORT_RANGE" == *-* ]]; then
    # Large range fast path (no logging here; caller will log)
    local out_fast
    out_fast="$(nmap -Pn -n --open $port_spec -sT -T4 --host-timeout "$DISCOVER_TIMEOUT" "$host" 2>/dev/null || true)"
    all_open="$(echo "$out_fast" | awk '/^[0-9]+\/tcp[[:space:]]+open/ {split($1,p,"/"); print p[1]}' | sort -n | uniq | paste -sd, -)"
    DISCOVER_LAST_OPEN="$all_open"
    DISCOVER_LAST_TLS=""  # not applicable in fast path
    echo "$all_open"
    return
  fi

  # Default path with minimal version probing so TLS probe is included but noise is low.
  # Use -sT (TCP connect) to avoid needing elevated privileges for SYN scan.
  # ssl-enum-ciphers can be run in this same pass, but we keep it separate to reuse existing parsing and keep timeouts tight.
  out="$(nmap -Pn -n --open $port_spec -sT -sV --version-intensity 1 \
         --host-timeout "$DISCOVER_TIMEOUT" "$host" 2>/dev/null || true)"  # [1](https://security.stackexchange.com/questions/55997/nmap-ssl-service-detection-how-to-check-all-open-ports-only-for-ssl-service)

  # Extract all open TCP ports (baseline)
  all_open="$(echo "$out" | awk '/^[0-9]+\/tcp[[:space:]]+open/ {split($1,p,"/"); print p[1]}' | sort -n | uniq | paste -sd, -)"
  # If none found (e.g., version scan timed out or filtered), fall back to a faster, no -sV sweep
  if [ -z "$all_open" ]; then
    local out_fast
    out_fast="$(nmap -Pn -n --open $port_spec -sT -T4 --host-timeout "$DISCOVER_TIMEOUT" "$host" 2>/dev/null || true)"
    all_open="$(echo "$out_fast" | awk '/^[0-9]+\/tcp[[:space:]]+open/ {split($1,p,"/"); print p[1]}' | sort -n | uniq | paste -sd, -)"
    # No logging here; caller will log
    # Reuse the last output for TLS-capable heuristics below if needed
    [ -z "$out" ] && out="$out_fast"
    # If still nothing, probe primary + fallbacks directly to avoid missing common TLS ports
    if [ -z "$all_open" ]; then
      local quick_ports_csv
      quick_ports_csv="${PRIMARY_PORT}${FALLBACK_PORTS:+,${FALLBACK_PORTS}}"
      local quick_ports=()
      IFS=',' read -r -a quick_ports <<< "$quick_ports_csv"
      local qp open_list=()
      for qp in "${quick_ports[@]:-}"; do
        [[ -z "$qp" ]] && continue
        if port_open "$host" "$qp"; then
          open_list+=("$qp")
        fi
      done
      if [ "${#open_list[@]}" -gt 0 ]; then
        # Dedup and join
        local seen_list=()
        local v s exists
        for v in "${open_list[@]}"; do
          exists=0
          for s in "${seen_list[@]:-}"; do
            [ "$s" = "$v" ] && { exists=1; break; }
          done
          [ $exists -eq 0 ] && seen_list+=("$v")
        done
        local joined=""
        for v in "${seen_list[@]}"; do
          joined="${joined}${joined:+,}${v}"
        done
        DISCOVER_LAST_OPEN="$joined"
        DISCOVER_LAST_TLS=""
        echo "$joined"
        return
      fi
    fi
  fi

  # Extract open TCP ports that are likely TLS/SSL-capable based on service detection
  # Match criteria (case-insensitive):
  #  - service names commonly TLS-only (https, imaps, pop3s, ldaps, smtps, ftps, nntps, rdp/ms-wbt-server)
  #  - or any indication of "ssl"/"tls" in the service/version/tunnel description
  # Example lines: "443/tcp open https", "993/tcp open imaps", "3389/tcp open ms-wbt-server"
  local tls_ports
  tls_ports="$(echo "$out" \
    | awk 'BEGIN{IGNORECASE=1} \
      /^[0-9]+\/tcp[[:space:]]+open/ { \
        line=$0; split($1,p,"/"); port=p[1]; \
        # Fields: port/proto open SERVICE ... [VERSION INFO]
        svc=$3; \
        if (svc ~ /^(https|imaps|pop3s|ldaps|smtps|ftps|nntps|ms-wbt-server|rdp)$/) { \
          print port; next; \
        } \
        # Heuristic: any mention of ssl/tls in the rest of the line
        if (line ~ /ssl|tls/) { print port; next; } \
      }' \
    | sort -n | uniq \
    | paste -sd, -)"
  # Persist for logging at the caller level
  DISCOVER_LAST_OPEN="$all_open"
  DISCOVER_LAST_TLS="$tls_ports"
  # If no TLS-candidate ports were identified, fall back to all open ports so we still attempt TLS detection
  if [ -z "$tls_ports" ] || [ "$tls_ports" = "" ]; then
    echo "$all_open"
  else
    echo "$tls_ports"
  fi
}

check_tls_versions_testssl() {
  local host="$1" port="$2" target out versions=""
  target="$(format_target "$host" "$port")"
  # Force English for reliable parsing; limit to protocols; no color
  out="$(LC_ALL=C testssl.sh -p -q --color 0 "$target" 2>/dev/null || true)"

  # Only add protocols where the line contains 'offered' AND NOT 'not offered'
  # Examples we account for:
  #   "SSLv2      not offered (OK)"
  #   "TLS 1.2    offered (OK)"
  #   "TLS 1      not offered"
  while IFS= read -r line; do
    # Normalize CR if present
    line="${line%$'\r'}"
    # Skip non-protocol lines fast
    [[ "$line" =~ SSLv2|SSLv3|TLS\ 1|TLS\ 1\.0|TLS\ 1\.1|TLS\ 1\.2|TLS\ 1\.3 ]] || continue
    # Must say 'offered' but NOT 'not offered'
    echo "$line" | grep -q "offered" || continue
    echo "$line" | grep -q "not offered" && continue

    case "$line" in
      *"SSLv2"*)   versions="${versions}${versions:+,}SSLv2" ;;
      *"SSLv3"*)   versions="${versions}${versions:+,}SSLv3" ;;
      *"TLS 1.0"*) versions="${versions}${versions:+,}TLS1.0" ;;
      *"TLS 1.1"*) versions="${versions}${versions:+,}TLS1.1" ;;
      *"TLS 1.2"*) versions="${versions}${versions:+,}TLS1.2" ;;
      *"TLS 1.3"*) versions="${versions}${versions:+,}TLS1.3" ;;
      # Some testssl versions show "TLS 1 " for TLS 1.0
      *"TLS 1 "*)  versions="${versions}${versions:+,}TLS1.0" ;;
    esac
  done <<<"$out"

  echo "$versions"
}

# Specialized: RDP TLS version detection via nmap rdp-enum-encryption
check_tls_versions_rdp_nmap() {
  local host="$1" port="$2" out versions=""
  [ "$HAVE_NMAP" -eq 1 ] || { echo ""; return; }
  out="$(nmap -Pn -n -p "$port" --script rdp-enum-encryption --host-timeout "$NMAP_TIMEOUT" --script-timeout "$SCRIPT_TIMEOUT" "$host" 2>/dev/null || true)"
  # Look for a line like: "SSL/TLS supported versions: TLSv1.0 TLSv1.1 TLSv1.2"
  local line
  line="$(echo "$out" | awk -F: '/SSL\/TLS supported versions/ {sub(/^ */,"",$2); print $2; exit}')"
  [ -z "$line" ] && { echo ""; return; }
  # Normalize space-separated tokens -> comma-separated TLS1.x
  for tok in $line; do
    case "$tok" in
      TLSv1.0) versions="${versions}${versions:+,}TLS1.0" ;;
      TLSv1.1) versions="${versions}${versions:+,}TLS1.1" ;;
      TLSv1.2) versions="${versions}${versions:+,}TLS1.2" ;;
      TLSv1.3) versions="${versions}${versions:+,}TLS1.3" ;;
    esac
  done
  echo "$versions"
}

check_tls_versions_nmap() {
  local host="$1" port="$2" out versions=""
  out="$(nmap -Pn -p "$port" --script ssl-enum-ciphers --host-timeout "$NMAP_TIMEOUT" --script-timeout "$SCRIPT_TIMEOUT" "$host" 2>/dev/null || true)"
  echo "$out" | grep -E "TLSv1\.[0-3]:" >/dev/null 2>&1 || { echo ""; return; }
  while IFS= read -r line; do
    case "$line" in
      *"TLSv1.0:"*) versions="${versions}${versions:+,}TLS1.0" ;;
      *"TLSv1.1:"*) versions="${versions}${versions:+,}TLS1.1" ;;
      *"TLSv1.2:"*) versions="${versions}${versions:+,}TLS1.2" ;;
      *"TLSv1.3:"*) versions="${versions}${versions:+,}TLS1.3" ;;
    esac
  done <<<"$(echo "$out")"
  echo "$versions"
}

check_tls_versions_openssl() {
  local host="$1" port="$2"
  [ "$HAVE_OPENSSL" -eq 1 ] || { echo ""; return; }

  local versions=""
  # Map: display label | s_client flag | normalized token
  # We'll infer the 'Protocol' line match from the normalized token.
  local entries=(
    "SSLv3:-ssl3:SSLv3"
    "TLS1.0:-tls1:TLS1.0"
    "TLS1.1:-tls1_1:TLS1.1"
    "TLS1.2:-tls1_2:TLS1.2"
    "TLS1.3:-tls1_3:TLS1.3"
  )

  # Only treat as supported if the s_client output shows the negotiated protocol,
  # e.g. "Protocol  : TLSv1.2" (OpenSSL) or "SSL-Protocol: TLSv1.2" (LibreSSL)
  for entry in "${entries[@]}"; do
    IFS=':' read -r label flag norm <<<"$entry"

    # Skip flags not supported by the local openssl build
    openssl s_client -help 2>&1 | grep -q -- "$flag" || continue

    # Run handshake attempt (quiet input)
    local out
    out="$(echo | openssl s_client -servername "$host" -connect "$(format_target "$host" "$port")" "$flag" 2>/dev/null || true)"

    # Convert "TLS1.2" -> "TLSv1.2" for matching; SSLv3 stays SSLv3
    local want="${norm/TLS/TLSv}"

    if echo "$out" | grep -qiE '^( *Protocol *:| *SSL-Protocol:) *'"$want" ; then
      versions="${versions}${versions:+,}${norm}"
    fi
  done

  echo "$versions"
}

evaluate_tls_policy() {
  local versions="$1"
  if [ -z "$versions" ]; then echo "NO_TLS"; return; fi
  echo "$versions" | grep -qE "SSLv2|SSLv3|TLS1\.0|TLS1\.1" && { echo "FAIL"; return; }
  echo "$versions" | grep -qE "TLS1\.2|TLS1\.3" && { echo "PASS"; return; }
  echo "NO_TLS"
}

# Return only the weak protocols from a comma-separated list
weak_versions_only() {
  local versions="$1"
  local out=""
  IFS=',' read -r -a arr <<< "$versions"
  local x
  for x in "${arr[@]:-}"; do
    case "$x" in
      SSLv2|SSLv3|TLS1.0|TLS1.1)
        out="${out}${out:+,}${x}"
        ;;
    esac
  done
  echo "$out"
}

sem_wait() {
  local max="$1"
  while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$max" ]; do sleep 0.05; done
}

write_csv() {
  local ts="$1" host="$2" port="$3" alive="$4" tls_status="$5" versions="$6" tool="$7" details="$8"
  printf "%s,%s,%s,%s,%s,%s,%s,%s\n" \
    "$ts" \
    "$(csv_escape "$host")" \
    "$(csv_escape "$port")" \
    "$(csv_escape "$alive")" \
    "$(csv_escape "$tls_status")" \
    "$(csv_escape "$versions")" \
    "$(csv_escape "$tool")" \
    "$(csv_escape "$details")" >> "$OUTPUT_FILE"
}

# Print the summary (counts are computed from the CSV). If an exit code is provided,
# exit with that code, otherwise return.
summarize_results() {
  # -------- Summary (per host:port rows + host-level tallies) --------

  # Per host:port tallies from the CSV
  PASS_CNT=$(awk -F, 'NR>1 && $5=="\"PASS\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  FAIL_CNT=$(awk -F, 'NR>1 && $5=="\"FAIL\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  NOTLS_CNT=$(awk -F, 'NR>1 && $5=="\"NO_TLS\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  PORTC_CNT=$(awk -F, 'NR>1 && $5=="\"PORT_CLOSED\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  NOSVC_CNT=$(awk -F, 'NR>1 && $5=="\"NO_SERVICE\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  INACT_ROWS_CNT=$(awk -F, 'NR>1 && $4=="\"inactive\"" {c++} END{print c+0}' "$OUTPUT_FILE")
  OPEN_CNT=$(awk -F, 'NR>1 && ($5=="\"PASS\"" || $5=="\"FAIL\"" || $5=="\"NO_TLS\"") {c++} END{print c+0}' "$OUTPUT_FILE")
  OPEN_PORTS_UNIQ=$(awk -F, 'NR>1 && ($5=="\"PASS\"" || $5=="\"FAIL\"" || $5=="\"NO_TLS\"") {gsub(/"/,"",$3); p[$3]=1} END{for (k in p) print k}' "$OUTPUT_FILE" | sort -n | paste -sd, -)

  # Host-level tallies (unique hosts)
  # - HOSTS_TESTED: unique hostnames seen in the CSV
  # - ACTIVE_HOSTS: unique hosts with at least one row where alive=="alive"
  # - INACTIVE_HOSTS: unique hosts with at least one row where alive=="inactive" (i.e., liveness failed)
  HOSTS_TESTED=$(awk -F, 'NR>1 {gsub(/"/,"",$2); h[$2]=1} END{print length(h)}' "$OUTPUT_FILE")
  ACTIVE_HOSTS=$(awk -F, 'NR>1 && $4=="\"alive\"" {gsub(/"/,"",$2); a[$2]=1} END{print length(a)}' "$OUTPUT_FILE")
  INACTIVE_HOSTS=$(awk -F, 'NR>1 && $4=="\"inactive\"" {gsub(/"/,"",$2); i[$2]=1} END{print length(i)}' "$OUTPUT_FILE")

  echo
  log info "==================== Summary ===================="
  log info "HOSTS tested: ${HOSTS_TESTED} | ACTIVE: ${ACTIVE_HOSTS} | INACTIVE: ${INACTIVE_HOSTS}"
  log ok   "PASS:        ${PASS_CNT}"
  log err  "FAIL:        ${FAIL_CNT}"
  log warn "NO_TLS:      ${NOTLS_CNT}"
  log info "PORT_OPEN:   ${OPEN_CNT}"
  log info "OPEN PORTS:  ${OPEN_PORTS_UNIQ:-<none>}"
  log info "==============================================="
  log info "${ICON_INFO}  Detailed results: $OUTPUT_FILE"

  if [ -n "${1-}" ]; then
    exit "$1"
  fi
}

scan_port_tls() {
  local host="$1" port="$2" ts="$3"
  local versions="" tool="" tls_status="" details=""
  # Try tools in order
  # Special-case RDP first: general TLS scripts often don't apply
  if [ "$port" = "3389" ]; then
    if [ "$HAVE_NMAP" -eq 1 ]; then
      versions="$(check_tls_versions_rdp_nmap "$host" "$port")"
      [ -n "$versions" ] && tool="nmap rdp-enum-encryption"
    fi
  fi
  if [ "$HAVE_TESTSSL" -eq 1 ] && [ -z "$versions" ]; then
    versions="$(check_tls_versions_testssl "$host" "$port")"
    [ -n "$versions" ] && tool="testssl.sh"
  fi
  if [ -z "$versions" ] && [ "$HAVE_NMAP" -eq 1 ]; then
    versions="$(check_tls_versions_nmap "$host" "$port")"
    [ -n "$versions" ] && tool="nmap ssl-enum-ciphers"
  fi
  if [ -z "$versions" ] && [ "$HAVE_OPENSSL" -eq 1 ]; then
    versions="$(check_tls_versions_openssl "$host" "$port")"
    [ -n "$versions" ] && tool="openssl s_client"
  fi
  tls_status="$(evaluate_tls_policy "$versions")"
  case "$tls_status" in
    PASS) details="Only TLS1.2/1.3 detected"; log ok   "[${host}:${port}] ${ICON_OK} TLS: PASS (${versions})" ;;
    FAIL) weak="$(weak_versions_only "$versions")"; details="Weaker protocol(s) detected: ${weak}"; log err  "[${host}:${port}] ${ICON_FAIL} TLS: FAIL (${weak:-$versions})"; save_testssl_report "$host" "$port" ;;
    NO_TLS) details="No TLS detected on this port or detection failed"; log warn "[${host}:${port}] ${ICON_WARN} TLS: NO_TLS" ;;
  esac
  write_csv "$ts" "$host" "$port" "alive" "$tls_status" "$versions" "$tool" "$details"
}

process_host() {
  local host="$1" ts alive="inactive"
  ts="$(date -Iseconds)"

  # ---- Liveness -------------------------------------------------------------
  log info "[${host}] ${ICON_WAIT} Checking liveness..."
  if is_alive "$host"; then
    alive="alive"
    log ok "[${host}] ${ICON_OK} Host is alive"
  else
    # Record one row to indicate host inactive (port is informational here)
    write_csv "$ts" "$host" "$PRIMARY_PORT" "inactive" "N/A" "" "" \
      "No ICMP response; nmap ping (if available) did not confirm host up"
    log err "[${host}] ${ICON_FAIL} Host is inactive"
    return
  fi

  # ---- Discovery mode: use global unique open ports and per-host open list ---
  if [ "${DISCOVER:-0}" -eq 1 ] && [ "${GLOBAL_DISCOVERY_DONE:-0}" -eq 1 ]; then
    # Per-host open ports (for logging) from ports file
    local host_open
    if [ -n "${PORTS_FILE:-}" ] && [ -f "${PORTS_FILE:-}" ]; then
      host_open="$(awk -F, -v h="$host" '($1==h){print $2}' "$PORTS_FILE" | sort -n | paste -sd, -)"
    fi
    if [ -z "$host_open" ]; then
      write_csv "$ts" "$host" "-" "alive" "NO_SERVICE" "" "" "No open ports found by discovery"
      log warn "[${host}] ${ICON_WARN} No open ports found (discovery)"
      return
    fi

    log info "[${host}] ${ICON_INFO} Open ports: ${host_open}"

    # Ports to TLS-check = global unique open ports across all hosts
    local discovered="${GLOBAL_PORTS_CSV:-}"
    if [ -z "$discovered" ]; then
      write_csv "$ts" "$host" "-" "alive" "NO_SERVICE" "" "" "No global ports found by discovery"
      log warn "[${host}] ${ICON_WARN} No global ports found (discovery)"
      return
    fi
    log ok "[${host}] ${ICON_OK} Ports to TLS-check: ${discovered}"

    IFS=',' read -r -a ports_to_scan <<< "$discovered"

    # TLS checks for each port in the global set; verify open on this host
    local port
    local checks=0
    for port in "${ports_to_scan[@]:-}"; do
      [[ -z "$port" ]] && continue
      if port_open "$host" "$port"; then
        log info "[${host}:${port}] ${ICON_WAIT} Checking TLS protocols..."
        scan_port_tls "$host" "$port" "$ts"
        checks=$((checks+1))
      else
        write_csv "$ts" "$host" "$port" "alive" "PORT_CLOSED" "" "" "No listener / filtered"
        log info "[${host}] ${ICON_INFO} ${port} closed"
      fi
    done
    log info "[${host}] ${ICON_INFO} TLS check targets: ${checks} port(s)"
    return
  fi

  # ---- Non-discovery path: primary + fallback ports -------------------------
  IFS=',' read -r -a alt_ports <<< "${FALLBACK_PORTS:-}"
  local ports_to_scan=()
  local primary_open=0
  local open_ports=()

  log info "[${host}] ${ICON_WAIT} Checking primary port ${PRIMARY_PORT}..."
  if port_open "$host" "$PRIMARY_PORT"; then
    primary_open=1
    ports_to_scan+=("$PRIMARY_PORT")
    open_ports+=("$PRIMARY_PORT")
    log ok "[${host}] ${ICON_OK} ${PRIMARY_PORT} is OPEN"
  else
    # Log primary closed and continue to alternates
    write_csv "$ts" "$host" "$PRIMARY_PORT" "$alive" "PORT_CLOSED" "" "" "No listener / filtered"
    log warn "[${host}] ${ICON_WARN} ${PRIMARY_PORT} appears CLOSED"
  fi

  # Scan alternates when primary is closed or when -A is set
  if [ "$primary_open" -eq 0 ] || [ "${ALSO_SCAN_ALTS:-0}" -eq 1 ]; then
    local p
    for p in "${alt_ports[@]}"; do
      [[ -z "$p" ]] && continue
      [[ "$p" = "$PRIMARY_PORT" ]] && continue  # avoid duplication
      if port_open "$host" "$p"; then
        # Add only if not already in the list
        local exists=0
        local q
        for q in "${ports_to_scan[@]:-}"; do
          [ "$q" = "$p" ] && { exists=1; break; }
        done
        [ $exists -eq 0 ] && ports_to_scan+=("$p")
        open_ports+=("$p")
        log ok "[${host}] ${ICON_OK} ${p} is OPEN"
      else
        write_csv "$ts" "$host" "$p" "$alive" "PORT_CLOSED" "" "" "No listener / filtered"
        log info "[${host}] ${ICON_INFO} ${p} closed"
      fi
    done
  fi

  # Nothing to scan?
  if [ "${#ports_to_scan[@]}" -eq 0 ]; then
    write_csv "$ts" "$host" "-" "$alive" "NO_SERVICE" "" "" \
      "No candidate ports open (${PRIMARY_PORT}${FALLBACK_PORTS:+,${FALLBACK_PORTS}})"
    log warn "[${host}] ${ICON_WARN} No candidate ports open (${PRIMARY_PORT}${FALLBACK_PORTS:+,${FALLBACK_PORTS}})"
    return
  fi

  # ---- TLS checks for each open candidate port ------------------------------
  # Deduplicate defensively (in case caller added duplicates)
  local scanned=()
  local port exists
  for port in "${ports_to_scan[@]:-}"; do
    exists=0
    for q in "${scanned[@]:-}"; do
      [ "$q" = "$port" ] && { exists=1; break; }
    done
    [ $exists -eq 1 ] && continue
    scanned+=("$port")

    log info "[${host}:${port}] ${ICON_WAIT} Checking TLS protocols..."
    scan_port_tls "$host" "$port" "$ts"
  done
}

# -------- Execution --------
log info "${ICON_INFO} Output CSV: ${BOLD}$OUTPUT_FILE${NC}"
if [ "$HAVE_TESTSSL" -eq 0 ]; then
  log warn "${ICON_WARN} testssl.sh not found — using nmap/openssl fallback. Install: brew install testssl"
fi
if [ "$HAVE_NMAP" -eq 0 ]; then
  log warn "${ICON_WARN} nmap not found — port checks & TLS enum may be limited. Install: brew install nmap"
fi
if [ "$HAVE_NC" -eq 0 ]; then
  log warn "${ICON_WARN} nc (netcat) not found — port-open checks will rely on nmap only."
fi

total="${#HOSTS[@]}"
log info "${ICON_INFO} Targets: $total | Primary: $PRIMARY_PORT | Fallbacks: ${FALLBACK_PORTS:-<none>} | Also scan alts: $ALSO_SCAN_ALTS | Concurrency: $CONCURRENCY"

# If discovery mode, perform a single global discovery pass
if [ "${DISCOVER:-0}" -eq 1 ]; then
  if [ "$HAVE_NMAP" -eq 0 ]; then
    log warn "${ICON_WARN} Discovery requested but nmap not found; falling back to primary/fallback behavior."
  else
    run_global_discovery
  fi
fi

# Start keyboard listener for interactive runs (TTY stdin)
if [ -t 0 ]; then
  start_input_listener
fi

count=0
for host in "${HOSTS[@]}"; do
  count=$((count+1))
  log info "$(printf "[%s/%s] %s %s" "$count" "$total" "$host" "$ICON_INFO")"
  # If paused, wait here until resumed
  while [ "${PAUSED:-0}" -eq 1 ]; do sleep 0.1; done
  # Throttle based on safe, numeric concurrency and running job count
  while :; do
    # Number of running background jobs (default 0 if empty)
    running_jobs=$(jobs -rp | wc -l | tr -d ' ')
    running_jobs=${running_jobs:-0}
    # Concurrency ceiling (default 8; coerce to 1 if non-numeric)
    max_conc="${CONCURRENCY:-8}"
    if ! [[ "$max_conc" =~ ^[0-9]+$ ]]; then max_conc=1; fi
    # Proceed when below limit
    if [ "$running_jobs" -lt "$max_conc" ]; then break; fi
    sleep 0.05
  done
  process_host "$host" &
done
wait

# Print summarized results after all jobs complete
summarize_results 0

