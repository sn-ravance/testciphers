#!/usr/bin/env bash
# install_linux_tools.sh
# Installs required tools for tls_sweeper.sh on common Linux distributions.
# Tools: nmap, testssl.sh, openssl/openssl-cli, netcat (nc/ncat), git (for testssl clone)

set -euo pipefail

need_sudo() {
  if [ "$EUID" -ne 0 ]; then
    echo "This script uses sudo for package installation and file operations."
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo not found; please run as root." >&2
      exit 1
    fi
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

print_header() {
  echo "========================================"
  echo "$1"
  echo "========================================"
}

# Detect package manager
pkg_mgr=""
if command -v apt-get >/dev/null 2>&1; then
  pkg_mgr="apt"
elif command -v dnf >/dev/null 2>&1; then
  pkg_mgr="dnf"
elif command -v yum >/dev/null 2>&1; then
  pkg_mgr="yum"
elif command -v zypper >/dev/null 2>&1; then
  pkg_mgr="zypper"
else
  pkg_mgr=""
fi

install_pkgs() {
  case "$pkg_mgr" in
    apt)
      sudo apt-get update
      sudo apt-get install -y nmap git openssl netcat-openbsd
      ;;
    dnf)
      sudo dnf install -y nmap git openssl nmap-ncat
      ;;
    yum)
      sudo yum install -y nmap git openssl nmap-ncat
      ;;
    zypper)
      sudo zypper refresh
      sudo zypper install -y nmap git openssl netcat-openbsd
      ;;
    *)
      echo "Unsupported or unknown package manager. Please install: nmap, git, openssl, and netcat manually." >&2
      ;;
  esac
}

install_testssl() {
  # Prefer system package if available; otherwise clone
  if have_cmd testssl.sh; then
    echo "✅ testssl.sh already installed: $(command -v testssl.sh)"
    return 0
  fi

  # Some distros provide a package (e.g., Debian/Ubuntu: testssl.sh)
  case "$pkg_mgr" in
    apt)
      if apt-cache show testssl.sh >/dev/null 2>&1; then
        sudo apt-get install -y testssl.sh && return 0 || true
      fi
      ;;
    dnf)
      if dnf info testssl >/dev/null 2>&1; then
        sudo dnf install -y testssl && return 0 || true
      fi
      ;;
    yum)
      if yum info testssl >/dev/null 2>&1; then
        sudo yum install -y testssl && return 0 || true
      fi
      ;;
    zypper)
      if zypper info testssl.sh >/dev/null 2>&1; then
        sudo zypper install -y testssl.sh && return 0 || true
      fi
      ;;
  esac

  # Fallback: clone from GitHub to /opt/testssl.sh and symlink
  local dir="/opt/testssl.sh"
  if [ ! -d "$dir/.git" ]; then
    print_header "Installing testssl.sh from GitHub"
    sudo mkdir -p "$dir"
    sudo chown "$USER":"$USER" "$dir" || true
    git clone --depth 1 https://github.com/drwetter/testssl.sh "$dir"
  else
    echo "Updating existing testssl.sh clone at $dir"
    git -C "$dir" pull --ff-only || true
  fi

  # Symlink into /usr/local/bin
  if [ ! -e "/usr/local/bin/testssl.sh" ]; then
    sudo ln -s "$dir/testssl.sh" /usr/local/bin/testssl.sh
  fi
  sudo chmod +x "$dir/testssl.sh"

  if have_cmd testssl.sh; then
    echo "✅ testssl.sh installed: $(command -v testssl.sh)"
  else
    echo "⚠️  testssl.sh installation attempted but not found on PATH. Ensure /usr/local/bin is in PATH." >&2
  fi
}

verify_tools() {
  print_header "Verifying tools"
  for t in nmap testssl.sh openssl nc ncat; do
    if have_cmd "$t"; then
      printf "%-12s %s\n" "$t" "OK ($(command -v "$t"))"
    else
      printf "%-12s %s\n" "$t" "MISSING"
    fi
  done
}

main() {
  print_header "Linux environment setup for TLS Sweeper"
  need_sudo

  if [ -z "$pkg_mgr" ]; then
    echo "No supported package manager detected (apt, dnf, yum, zypper)." >&2
    echo "Please install: nmap, git, openssl, and netcat (nc/ncat) manually, then run this script again to install testssl.sh." >&2
  else
    install_pkgs
  fi

  install_testssl
  verify_tools

  echo
  print_header "Done"
  echo "You can now run ./tls_sweeper.sh. Use -E/--details to create per-FAIL testssl reports."
}

main "$@"
