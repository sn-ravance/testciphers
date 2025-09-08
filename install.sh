#!/usr/bin/env bash
# install.sh
# Cross-platform wrapper to install tools required by tls_sweeper.sh
# - macOS: uses Homebrew via install_macos_tools.sh
# - Linux: uses distro package manager via install_linux_tools.sh

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

is_macos() {
  [ "${OSTYPE:-}" = "darwin" ] || [[ "${OSTYPE:-}" == darwin* ]]
}

is_linux() {
  [ "${OSTYPE:-}" = "linux-gnu" ] || [[ "${OSTYPE:-}" == linux* ]]
}

main() {
  echo "========================================"
  echo "TLS Sweeper Installer"
  echo "========================================"

  if is_macos; then
    echo "Detected macOS"
    if [ ! -f "$here/install_macos_tools.sh" ]; then
      echo "ERROR: Missing install_macos_tools.sh next to this script." >&2
      exit 2
    fi
    chmod +x "$here/install_macos_tools.sh"
    exec "$here/install_macos_tools.sh" "$@"
  elif is_linux; then
    echo "Detected Linux"
    if [ ! -f "$here/install_linux_tools.sh" ]; then
      echo "ERROR: Missing install_linux_tools.sh next to this script." >&2
      exit 2
    fi
    chmod +x "$here/install_linux_tools.sh"
    exec "$here/install_linux_tools.sh" "$@"
  else
    echo "ERROR: Unsupported OS type: ${OSTYPE:-unknown}." >&2
    echo "Please install: nmap, testssl.sh, openssl (CLI), netcat (nc/ncat) manually." >&2
    exit 3
  fi
}

main "$@"
