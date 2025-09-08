#!/bin/bash

# Parse arguments
while getopts "i:" opt; do
  case $opt in
    i) inputfile="$OPTARG" ;;
    *) echo "Usage: $0 -i inputfile.txt" >&2; exit 1 ;;
  esac
done

# Validate input
if [[ -z "$inputfile" ]]; then
  echo "Usage: $0 -i inputfile.txt" >&2
  exit 1
fi

# Derive output name by removing .txt and appending _sorted.txt
basename="${inputfile%.txt}"
outputfile="${basename}_sorted.txt"

# Clean and sort
sed -E 's/[-*] ?//g' "$inputfile" | sort -V > "$outputfile"

echo "✅ Cleaned and sorted file saved to: $outputfile"
