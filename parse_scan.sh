#!/usr/bin/env bash
set -euo pipefail

# Defaults
INPUT_FILE=""
PREFIX=""
CREATE_DIR="no"

usage() {
  cat <<EOF
Usage: $0 -i <input_file> -f <prefix> [-o]
  -i : Input CSV file name (e.g., scan.csv)
  -f : Prefix (also used as folder name when -o is provided) (e.g., i506)
  -o : Create folder named <prefix>, verify it exists, and parse input at <prefix>/<input_file>
       - If <input_file> exists in the current directory, it will be moved to <prefix>/<input_file> before parsing.
Examples:
  $0 -i scan_results_20250908_084128.csv -f i506
  $0 -i scan_results_20250908_092149.csv -f i1497 -o
EOF
  exit 1
}

# Parse args
while getopts ":i:f:o" opt; do
  case "$opt" in
    i) INPUT_FILE="$OPTARG" ;;
    f) PREFIX="$OPTARG" ;;
    o) CREATE_DIR="yes" ;;
    *) usage ;;
  esac
done

# Validate args
[[ -z "$INPUT_FILE" || -z "$PREFIX" ]] && usage

# Handle output directory and input path resolution
OUTDIR="."
INPUT_PATH="$INPUT_FILE"

if [[ "$CREATE_DIR" == "yes" ]]; then
  # 1) Create and verify folder
  mkdir -p "$PREFIX"
  if [[ ! -d "$PREFIX" ]]; then
    echo "ERROR: Failed to create folder: $PREFIX" >&2
    exit 2
  fi

  OUTDIR="$PREFIX"
  INPUT_PATH="$PREFIX/$(basename "$INPUT_FILE")"

  # 2) Ensure the input file is at <prefix>/<input_file>
  if [[ ! -f "$INPUT_PATH" ]]; then
    if [[ -f "$INPUT_FILE" ]]; then
      mv "$INPUT_FILE" "$INPUT_PATH"
      echo "Moved input file to: $INPUT_PATH"
    else
      echo "ERROR: Input file not found at either:"
      echo "  - $INPUT_PATH"
      echo "  - $(pwd)/$INPUT_FILE"
      exit 3
    fi
  fi
else
  # No -o: parse input from current path
  if [[ ! -f "$INPUT_PATH" ]]; then
    echo "ERROR: Input file not found: $(pwd)/$INPUT_PATH" >&2
    exit 3
  fi
fi

# Output files (placed in OUTDIR; names keep the prefix)
ACTIVE_PASS="${OUTDIR}/${PREFIX}_active_pass_hosts.csv"
INACTIVE="${OUTDIR}/${PREFIX}_inactive_hosts.csv"
FAIL="${OUTDIR}/${PREFIX}_fail_hosts.csv"

# Extract header from the input file
HEADER=$(head -n 1 "$INPUT_PATH")

# Write headers to all outputs
printf "%s\n" "$HEADER" > "$ACTIVE_PASS"
printf "%s\n" "$HEADER" > "$INACTIVE"
printf "%s\n" "$HEADER" > "$FAIL"

# Filter and write rows
awk -F',' 'NR>1 && $4=="\"alive\""   && $5=="\"PASS\"" {print}' "$INPUT_PATH" >> "$ACTIVE_PASS"
awk -F',' 'NR>1 && $4=="\"inactive\""                      {print}' "$INPUT_PATH" >> "$INACTIVE"
awk -F',' 'NR>1 &&                     $5=="\"FAIL\""      {print}' "$INPUT_PATH" >> "$FAIL"

# Counts (exclude header by subtracting 1; clamp at 0)
lines_minus_header() {
  local f="$1"
  local n
  n=$(wc -l < "$f")
  if [[ "$n" -le 1 ]]; then echo 0; else echo $((n - 1)); fi
}

count_pass=$(lines_minus_header "$ACTIVE_PASS")
count_inactive=$(lines_minus_header "$INACTIVE")
count_fail=$(lines_minus_header "$FAIL")

total=$((count_pass + count_fail + count_inactive))

# Percentages with divide-by-zero guard
pct() {
  local part="$1" total="$2"
  if [[ "$total" -eq 0 ]]; then
    printf "0.00"
  else
    awk -v p="$part" -v t="$total" 'BEGIN { printf "%.2f", (p/t)*100 }'
  fi
}

percent_pass=$(pct "$count_pass" "$total")
percent_fail=$(pct "$count_fail" "$total")
percent_inactive=$(pct "$count_inactive" "$total")

# Report where files are
echo
echo "Output directory: $OUTDIR"
echo "Created files:"
echo " - $ACTIVE_PASS"
echo " - $INACTIVE"
echo " - $FAIL"

# Summary to STDOUT
echo
echo "Summary:"
echo "$count_pass Host - Passed (${percent_pass}%)"
echo "$count_fail Host - Failed (${percent_fail}%)"
echo "$count_inactive Host - Inactive (${percent_inactive}%)"
echo "Total Hosts: $total"
