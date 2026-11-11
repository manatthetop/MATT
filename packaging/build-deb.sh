#!/bin/bash
# Build a .deb for MATT. Pure-Python, arch-independent. Run from the repo root:
#   ./packaging/build-deb.sh
# Produces matt_<version>_all.deb in the current directory.
set -euo pipefail

cd "$(dirname "$0")/.."
VER="$(python3 -c "import sys;sys.path.insert(0,'.');from matt import __version__;print(__version__)")"
WORK="$(mktemp -d)"
PKG="$WORK/matt_${VER}_all"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$PKG/DEBIAN" "$PKG/usr/share/matt/matt" \
         "$PKG/usr/bin" "$PKG/usr/share/man/man1" "$PKG/usr/share/doc/matt"

# the package, minus caches
cp -r matt/* "$PKG/usr/share/matt/matt/"
find "$PKG/usr/share/matt" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

# launcher on PATH (works under sudo -- no PYTHONPATH reliance)
cat > "$PKG/usr/bin/matt" <<'LAUNCH'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/share/matt")
from matt.cli import main
sys.exit(main())
LAUNCH
chmod 0755 "$PKG/usr/bin/matt"

gzip -9 -c man/matt.1 > "$PKG/usr/share/man/man1/matt.1.gz"
cp README.md USAGE.md INSTALL.md CHANGELOG.md "$PKG/usr/share/doc/matt/" 2>/dev/null || true

cat > "$PKG/DEBIAN/control" <<CONTROL
Package: matt
Version: ${VER}
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.11)
Recommends: tcpdump, ettercap-text-only, hashcat
Suggests: tshark, aircrack-ng, hcxtools
Maintainer: manatthetop <security@manatthetop>
Homepage: https://github.com/manatthetop/MATT
Description: MATT - MAN AT THE TOP, authorized MITM credential toolkit
 Two-stage credential-recovery toolkit for authorized wireless MITM
 engagements: ARP-poison MITM capture and deterministic decode of SMB/HTTP/
 FTP/POP3/IMAP/SMTP/LDAP/SNMP/telnet/Kerberos/WPA into hashcat-ready candidates
 and plain-English findings. No runtime dependencies; AI is never required.
CONTROL

dpkg-deb --build --root-owner-group "$PKG" >/dev/null
mv "$PKG.deb" "./matt_${VER}_all.deb"
echo "built matt_${VER}_all.deb"
