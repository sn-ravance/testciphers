#!/usr/bin/env bash
# install_macos_tools.sh
# Installs required tools for tls_sweeper.sh on macOS using Homebrew.
# Tools: nmap, testssl.sh, openssl (brew), nc (system-provided), git (optional)

set -euo pipefail

have_cmd() { command -v "$1" >/dev/null 2>&1; }

print_header() {
  echo "========================================"
  echo "$1"
  echo "========================================"
}

ensure_xcode_cli() {
  if ! xcode-select -p >/dev/null 2>&1; then
    print_header "Installing Xcode Command Line Tools"
    xcode-select --install || true
    echo "If a dialog popped up, complete that installation and re-run this script."
  fi
}

ensure_homebrew() {
  if ! have_cmd brew; then
    print_header "Installing Homebrew"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Initialize brew for current shell session
    if [[ -d "/opt/homebrew/bin" ]]; then
      eval "$('/opt/homebrew/bin/brew' shellenv)"
    elif [[ -d "/usr/local/bin" ]]; then
      eval "$('/usr/local/bin/brew' shellenv)"
    fi
  fi
}

brew_install() {
  local formula="$1"
  if brew list --formula "$formula" >/dev/null 2>&1; then
    echo "✅ $formula already installed"
  else
    echo "➡️  Installing $formula"
    brew install "$formula"
  fi
}

main() {
  print_header "macOS environment setup for TLS Sweeper"

  ensure_xcode_cli
  ensure_homebrew

  # Core tools
  brew_install nmap
  brew_install testssl

  # Optional but recommended: latest OpenSSL (system provides LibreSSL by default)
  brew_install openssl@3 || true

  # Verify tools
  echo
  print_header "Verifying tools"
  for t in nmap testssl.sh openssl nc; do
    if have_cmd "$t"; then
      printf "%-12s %s\n" "$t" "OK ($(command -v "$t"))"
    else
      printf "%-12s %s\n" "$t" "MISSING"
    fi
  done

  # Guidance for OpenSSL from Homebrew
  if brew --prefix openssl@3 >/dev/null 2>&1; then
    OPENSSL_PREFIX="$(brew --prefix openssl@3)"
    echo
    echo "OpenSSL from Homebrew is at: $OPENSSL_PREFIX"
    echo "If needed, add to your environment:" 
    echo "  export PATH=\"$OPENSSL_PREFIX/bin:$PATH\""
    echo "  export LDFLAGS=\"-L$OPENSSL_PREFIX/lib\""
    echo "  export CPPFLAGS=\"-I$OPENSSL_PREFIX/include\""
  fi

  echo
  print_header "Done"
  echo "You can now run ./tls_sweeper.sh. For HTML details, use -E (requires testssl.sh)."
}

main "$@"
