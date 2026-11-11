#!/usr/bin/env bash
# MATT easy installer.
#
#   git clone https://github.com/manatthetop/MATT.git && cd MATT && ./install.sh
#
# Puts the `matt` command on your PATH and AUTO-INSTALLS the tools MATT uses
# (tcpdump, ettercap, hashcat) if they are missing, using your system package
# manager. Re-runnable and safe: anything already present is left alone.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
c_say() { printf '\033[1;36m[matt]\033[0m %s\n' "$*"; }
c_ok()  { printf '\033[1;32m[matt]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[matt]\033[0m %s\n' "$*"; }

# -- sudo only if we are not already root --
SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

# -- detect the package manager --
PM="" ; INSTALL="" ; UPDATE=""
if   command -v apt-get >/dev/null 2>&1; then PM=apt;    INSTALL="apt-get install -y"; UPDATE="apt-get update -qq"
elif command -v dnf     >/dev/null 2>&1; then PM=dnf;    INSTALL="dnf install -y"
elif command -v pacman  >/dev/null 2>&1; then PM=pacman; INSTALL="pacman -S --noconfirm --needed"
elif command -v zypper  >/dev/null 2>&1; then PM=zypper; INSTALL="zypper --non-interactive install"
elif command -v brew    >/dev/null 2>&1; then PM=brew;   INSTALL="brew install"
fi

# -- map a generic tool name to the package name for this manager --
pkg_for() {
  case "$1" in
    tcpdump)  echo tcpdump ;;
    hashcat)  echo hashcat ;;
    python3)  echo python3 ;;
    ettercap) [ "$PM" = apt ] && echo ettercap-text-only || echo ettercap ;;
  esac
}

install_tool() {
  local tool="$1" pkg
  if command -v "$tool" >/dev/null 2>&1; then c_ok "$tool already installed"; return 0; fi
  if [ -z "$PM" ]; then c_warn "no supported package manager found; please install '$tool' yourself"; return 0; fi
  pkg="$(pkg_for "$tool")"
  c_say "installing missing tool: $tool ($pkg) ..."
  if $SUDO $INSTALL "$pkg" >/dev/null 2>&1; then c_ok "$tool installed"; else
    c_warn "could not auto-install $tool -- install it manually ($INSTALL $pkg)"; fi
}

c_say "MATT easy installer ($PM${PM:+ detected})"

# 1. Python 3 is required for MATT itself.
if ! command -v python3 >/dev/null 2>&1; then
  [ -n "$PM" ] && { [ -n "${UPDATE:-}" ] && $SUDO $UPDATE || true; install_tool python3; }
fi
if ! command -v python3 >/dev/null 2>&1; then
  c_warn "Python 3.11+ is required and could not be installed automatically. Install it and re-run."; exit 1
fi

# 2. Put `matt` on PATH (and on sudo's PATH).
if [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; then
  $SUDO ln -sf "$REPO_DIR/bin/matt" /usr/local/bin/matt
  [ -d /usr/sbin ] && $SUDO ln -sf "$REPO_DIR/bin/matt" /usr/sbin/matt || true
  [ -f "$REPO_DIR/man/matt.1" ] && $SUDO install -Dm0644 "$REPO_DIR/man/matt.1" /usr/share/man/man1/matt.1 2>/dev/null || true
else
  mkdir -p "$HOME/.local/bin" && ln -sf "$REPO_DIR/bin/matt" "$HOME/.local/bin/matt"
  c_warn "installed to ~/.local/bin/matt -- make sure that is on your PATH"
fi
hash -r 2>/dev/null || true
c_ok "the 'matt' command is installed"

# 3. Auto-install the tools MATT uses for live capture + cracking.
[ "$PM" = apt ] && [ -n "${UPDATE:-}" ] && { c_say "refreshing package lists ..."; $SUDO $UPDATE || true; }
for t in tcpdump ettercap hashcat; do install_tool "$t"; done

echo
c_ok "done.  Try it:   matt --help"
c_ok "offline demo:   matt --analyze-only examples/enterprise_capture.json --table"
