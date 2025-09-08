# Quick Start: see the [Installation](#installation) and [Workflow](#workflow) sections below to get set up and run your first scan.

# TLS Sweeper

TLS Sweeper (`tls_sweeper.sh`) is a fast, portable Bash tool for liveness checks and TLS protocol policy validation across many hosts. It can operate in two modes:

- Manual scanning of a primary port plus fallbacks (e.g., 443 and 8443,4443,3389)
- Discovery-driven scanning that first finds active hosts, enumerates their open ports, then runs TLS checks on the relevant ports

The script writes a CSV with per host:port results and prints a concise, colorized summary.

---

## Key Features

- Liveness detection with `ping`, then fallback to `nmap` host discovery
- Port openness detection via `nc` (netcat) when available, with `nmap` fallback
- TLS protocol detection using a tiered approach:
  - `testssl.sh` (preferred)
  - `nmap --script ssl-enum-ciphers`
  - `openssl s_client`
- Discovery mode (-D):
  - Step 1: Identify active hosts
  - Step 2: Enumerate open ports on those hosts (fast connect scan)
  - Step 3: Compute unique ports across all hosts and use them for TLS checks per host (re-validating port openness per host)
- RDP (3389) aware: detects TLS versions via `nmap --script rdp-enum-encryption`
- Concurrency across hosts with a simple background job semaphore
- Robust CSV output + summary footer with PASS/FAIL/NO_TLS counts and unique open ports
- Interactive controls (pause/resume/quit) and signal handling
- Optional detailed HTML reports for FAIL results via `-E` (uses testssl.sh)

---

## Requirements

- macOS or Linux with Bash (tested on macOS’s Bash 3.2)
- Tools (auto-detected):
  - `nmap` (recommended for discovery and TLS enumeration)
  - `testssl.sh` (recommended for fast protocol checks)
  - `openssl`
  - `nc` (netcat)

Install on macOS (Homebrew examples):

```bash
brew install nmap
brew install testssl
# openssl and nc are typically bundled; install as needed
```

---

## Installation

Use the cross-platform installer to set up all required tools (nmap, testssl.sh, openssl, nc):

```bash
chmod +x install.sh
./install.sh
```

- On macOS, this runs `install_macos_tools.sh` (Homebrew-based).
- On Linux, this runs `install_linux_tools.sh` (apt/dnf/yum/zypper based, with a fallback GitHub clone for `testssl.sh`).

After installation, verify tools with:

```bash
which nmap testssl.sh openssl nc || true
```

---

## Run with Docker

You can run the tool inside a container instead of installing dependencies locally.

Build the image and start the compose service:

```bash
docker compose build
docker compose run --rm tls-sweeper ./tls_sweeper.sh -h
```

Examples:

```bash
# Manual mode with details (-E)
docker compose run --rm tls-sweeper \
  ./tls_sweeper.sh -f raw_hosts_sorted.txt -p 443 -P 8443,4443,3389 -c 16 -E

# Discovery mode with a full range
docker compose run --rm tls-sweeper \
  ./tls_sweeper.sh -f raw_hosts_sorted.txt -D -R "1-65535" -c 16 -E
```

Notes:

- The `docker-compose.yml` mounts the repo into `/work` so outputs (CSV, details/) appear on your host.
- On Linux, the service uses `network_mode: host` for speed and fidelity. On macOS, Docker Desktop doesn’t support host networking; default bridge networking still works for scanning external hosts.
- If ICMP `ping` is blocked in your environment, the script already falls back to `nmap` host discovery.

---

## Usage

Basic help:

```bash
./tls_sweeper.sh -h
```

---

## Workflow

Use this quick workflow when you have a pasted, unstructured host list and want to produce a clean TLS assessment with separated outputs for PASS/FAIL/INACTIVE.

1) Clean your host list

- If your file contains bullets, dashes, or other list characters, clean and sort it first with `cleaup.sh` (note the filename):

```bash
./cleaup.sh -i raw_hosts.txt
# Produces raw_hosts_sorted.txt
```

2) Run the TLS assessment

- Use the cleaned list as input to `tls_sweeper.sh`.
- Example: manual mode with common HTTPS alternates and details (HTML) on FAIL:

```bash
./tls_sweeper.sh -f raw_hosts_sorted.txt -p 443 -P 8443,4443,3389 -c 16 -E
# Output CSV: scan_results_YYYYMMDD_HHMMSS.csv
# Optional detailed reports when -E is used: details/scan_results_YYYYMMDD_HHMMSS/
```

- Example: discovery mode over a port range:

```bash
./tls_sweeper.sh -f raw_hosts_sorted.txt -D -R "1-65535" -c 16 -E
```

3) Parse results into PASS/FAIL/INACTIVE files

- Use `parse_scan.sh` to separate results into three CSVs and optionally organize them into a folder named after your prefix (e.g., an initiative ID):

```bash
# Parse in-place
./parse_scan.sh -i scan_results_YYYYMMDD_HHMMSS.csv -f i1497

# Or create a folder named i1497 and move/parse inside it
./parse_scan.sh -i scan_results_YYYYMMDD_HHMMSS.csv -f i1497 -o
```

This produces (with header rows retained):

- i1497_active_pass_hosts.csv
- i1497_fail_hosts.csv
- i1497_inactive_hosts.csv

Notes

- If your terminal is attached (interactive), you can press `p` (pause), `r` (resume), or `q` (quit) while `tls_sweeper.sh` is running.
- Use `-E` (or `--details`) to save per-FAIL testssl reports. Reports and logs are placed under `details/scan_results_YYYYMMDD_HHMMSS/`.
- If you need discovery to be narrower, use `-t 2000` or a curated `-R "443,8443,3389"`.

Manual mode (primary + fallbacks):

```bash
# Scan 443. If closed, try 8443,4443,3389
./tls_sweeper.sh -f targets.txt -p 443 -P 8443,4443,3389 -c 16
```

Save detailed HTML reports for FAIL findings (uses `-E`):

```bash
# For each FAIL, produce an HTML report in details/scan_results_YYYYMMDD_HHMMSS/
./tls_sweeper.sh -f targets.txt -p 443 -P 8443,4443,3389 -c 16 -E
```

Discovery mode (large range):

```bash
# Find active hosts, enumerate open ports across 1-65535, TLS-check the unique ports on each active host
./tls_sweeper.sh -f targets.txt -D -R "1-65535" -c 16
```

Discovery + detailed HTML reports on FAIL:

```bash
./tls_sweeper.sh -f targets.txt -D -R "1-65535" -c 16 -E
```

Discovery mode (top-N ports):

```bash
# Use top 2000 TCP ports (default if -R not provided)
./tls_sweeper.sh -f targets.txt -D -t 2000 -c 16
```

Another example:

```bash
./tls_sweeper.sh -f i1497.txt -P 443,8443,3389 -c 16
```

Run with `-E` to save HTML reports for FAIL results:

```bash
./tls_sweeper.sh -f i1497.txt -P 443,8443,3389 -c 16 -E
```

Output file:

- A timestamped CSV is written to the current directory, e.g. `scan_results_YYYYMMDD_HHMMSS.csv`.

---

## CSV Columns

```
timestamp,host,port,alive,tls_status,versions,tool,details
```

- `alive`: "alive" or "inactive"
- `tls_status`: one of
  - `PASS` — Only TLS1.2 and/or TLS1.3 detected
  - `FAIL` — Any weak protocol detected (SSLv2, SSLv3, TLS1.0, TLS1.1)
  - `NO_TLS` — TCP service responded but TLS negotiation not detected
  - `PORT_CLOSED` — Port not open on that host
  - `NO_SERVICE` — No candidate ports to check
- `versions`: Comma-separated list (e.g., `SSLv3,TLS1.0,TLS1.1,TLS1.2`)
- `tool`: Which detector produced the versions (`testssl.sh`, `nmap ssl-enum-ciphers`, `openssl s_client`, or `nmap rdp-enum-encryption` for 3389)

The summary footer also prints:

- `PASS`, `FAIL`, `NO_TLS` counts
- `PORT_OPEN`: total ports that responded to TLS checks (PASS|FAIL|NO_TLS)
- `OPEN PORTS`: unique port numbers observed open across all hosts

When `-E` is used, additional HTML reports are saved per FAIL finding under:

```
details/scan_results_YYYYMMDD_HHMMSS/<host>_<port>.html
```

Examples of the underlying command the script runs on FAIL:

```
# For default port when not explicitly 3389:
testssl.sh --html -4 -e -R -U <host>

# For explicit port, e.g., RDP 3389:
testssl.sh --html -4 -e -R -U <host>:3389
```

---

## Discovery Mode Details (-D)

Global discovery (done once per run):

1. Active hosts
   - Uses `is_alive()` (ping, then nmap host discovery) to filter the input list
   - Writes active hosts to a temp file: `/tmp/tls_sweeper.XXXXXXXX/active.txt`
2. Open ports on active hosts
   - For each active host, runs `nmap -Pn -n --open -sT -T4` over your selected range (`-R` or `-t`)
   - Appends `host,port` lines to `/tmp/tls_sweeper.XXXXXXXX/ports.txt`
3. Unique ports across all hosts
   - Extracts a unique, sorted, comma-separated port list for the TLS-check phase

Per-host TLS checks:

- Logs that host’s discovered open ports
- TLS-checks the global unique port set, validating `port_open` for the specific host before attempting TLS
- Writes `PORT_CLOSED` rows for global ports not open on that host

Temp files are cleaned on exit. If you need to inspect them, copy them before the run finishes.

Note: `-D` in this script refers to Discovery mode. The details/HTML reports feature uses `-E` to avoid a flag conflict.

---

## Keyboard Controls and Signals

Interactive keys (when the script is run in a terminal):

- `p` — Pause (halts scheduling, SIGSTOPs running background scans)
- `r` — Resume (re-enables scheduling, SIGCONT to paused jobs)
- `q` — Quit gracefully (stops jobs, prints summary)

Signals:

- `INT`/Ctrl-C — Graceful stop, print summary
- `TERM` — Graceful stop, print summary
- `USR1` — Pause (same as `p`)
- `USR2` — Resume (same as `r`)

---

## Tuning and Environment

- Concurrency: `-c N` (default: 8)
- Timeouts:
  - `DISCOVER_TIMEOUT` (default: 45s) — host-level discovery scans
  - `NMAP_TIMEOUT` (default: 7s) — single port checks and scripts
  - `SCRIPT_TIMEOUT` (default: 8s) — nmap script timeout
- You can override these by exporting environment variables before the run, e.g.:

```bash
DISCOVER_TIMEOUT=90s NMAP_TIMEOUT=15s SCRIPT_TIMEOUT=20s \
  ./tls_sweeper.sh -f targets.txt -D -R "1-65535" -c 16
```

---

## Examples

Scan common HTTPS alternatives with concurrency:

```bash
./tls_sweeper.sh -f targets.txt -p 443 -P 8443,4443,3389 -c 32
```

Full-port-range discovery followed by TLS checks:

```bash
./tls_sweeper.sh -f targets.txt -D -R "1-65535" -c 16
```

Limit discovery to top 2000 ports:

```bash
./tls_sweeper.sh -f targets.txt -D -t 2000 -c 16
```

Quiet mode for minimal stdout:

```bash
./tls_sweeper.sh -f targets.txt -q
```

---

## Troubleshooting

- No open ports found (discovery):
  - Verify `nmap` is installed and on PATH
  - Increase `DISCOVER_TIMEOUT` and `-T`/timing to accommodate slow networks
  - Try a smaller set/range first (`-t 2000` or `-R "80,443,3389"`)
- TLS shows `NO_TLS` on expected services:
  - The service might require SNI/ALPN or not speak TLS on that port
  - Ensure `testssl.sh` is installed; it often yields better protocol detection
- Summary shows `OPEN PORTS: <none>`:
  - Means no ports produced TLS checks (PASS|FAIL|NO_TLS). Check logs to ensure discovery found open ports and host ports were validated with `port_open()`.

---

## Notes

- This script is designed to run safely and portably without root by using `-sT` where possible.
- CSV output is the source of truth; the summary is computed from it at the end (or on graceful interrupt).

---

## License

This project is provided as-is without warranty. Review and adapt for your environment and policies.
