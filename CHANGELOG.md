# Changelog

All notable changes to MATT are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow semver.

## [1.8.0] — 2026-11-12

### Added
- **Monitor-mode auto channel select** (`--monitor-setup`) — hops a
  monitor-capable adapter across the common 2.4/5 GHz channels, counts
  distinct transmitting devices on each, and locks onto the busiest one so
  it's ready for passive capture in Wireshark; `--monitor-restore` undoes it.
  Shows a live progress bar while scanning. `wifi.best_channel_by_activity()`
  / `wifi.dwell_scan()` are the building blocks (tshark-based device
  counting, with a tcpdump frame-count fallback).
- **Menu redesign** — the interactive menu is now a short list of categories
  (Capture & analyze / Poison & intercept / Monitor mode / Crack & identify /
  Live dashboard / About); picking one opens a submenu of the actual actions.
  A blank Enter in any submenu runs the item marked "(recommended)", so the
  common case is one keystroke. The menu now also exposes LLMNR/NBT-NS
  poisoning, monitor-mode setup, the live dashboard, and `--identify` — all
  previously CLI-flag-only, not reachable from the menu.
- **Progress bar** (`ui.progress_bar()`) — plain-ASCII `[####----] NN%`,
  used by the channel scan and reusable anywhere else a known-fraction wait
  needs to show it's alive.

### Fixed
- **ARP-poison MITM now enables `net.ipv4.ip_forward`** before starting
  ettercap, and restores its prior value when poisoning stops. Without this,
  a poisoned victim's traffic is dropped at this host instead of passing
  through where it can be captured — the kernel does not forward it by
  default, so the "MITM" silently became a denial of service with nothing
  captured. `capture.start_ettercap()` now also refuses to start (with a
  clear reason) if it cannot enable forwarding.
- **Menu actions other than analyze/live capture were silently broken** —
  `_parse_and_run()` (what the menu's dispatch calls) only ever checked
  `--analyze-only` vs a live capture, never `--wpa`/`--llmnr`/`--dashboard`/
  `--identify`/`--monitor-setup`. Picking "Wi-Fi handshake capture" from the
  menu, for example, built the right `--wpa ...` argv but it then fell
  through to a plain live ARP capture that ignored those flags. Both the menu
  dispatch and `main()` now share one `_route()`.

## [1.7.0] — 2026-11-11

### Added
- **GUIDE.md** — a complete, keyword-rich reference guide (what MATT is, who
  it is for, install, the two-stage model, every protocol, hash identify/crack,
  encrypted-traffic intel, active techniques, enterprise testing, command
  reference, safety, FAQ).
- **Discoverability** — README badges + keyword/topics footer; GitHub repo
  description and 20 topics set for search.
- **Large-packet / enterprise test** — a ~50 KB jumbo/GRO packet reassembles
  into one payload and a credential buried deep inside it is still decoded
  (no packet-size or row-count truncation).

## [1.6.0] — 2026-11-11

### Added
- **Colour-coded output** — findings are now colour coded by category:
  green = a secret in hand (cleartext login or cracked), yellow = a crackable
  hash, cyan = recon (TLS/SNMPv3/QUIC), dim = nothing yet. Applies to the table,
  the per-finding view, the terminal dashboard, and `--identify`.

### Changed
- **Live capture is no longer truncated** — the hard `-c 200` packet cap is
  gone; a capture is bounded only by `--duration`, so a busy link is captured in
  full instead of just its first sub-second of frames. `--max-packets N` sets a
  cap when you want one.

## [1.5.0] — 2026-11-11

### Added
- **Terminal dashboard** — `matt --dashboard DIR` now shows a live,
  auto-refreshing findings table in the TERMINAL (no browser). The web page is
  opt-in behind `--web`.
- **TLS certificate names** — subject CN, issuer CN, and SAN DNS names pulled
  from an X.509 cert in a TLS 1.2 ServerHello (cleartext metadata, no
  decryption).
- **LLMNR / NBT-NS poisoning** (`matt --llmnr --our-ip <ip>`) — answers LLMNR
  (UDP 5355) and NBT-NS (UDP 137) name queries with the tester's address so a
  victim's auth is funnelled here, where the NetNTLMv2 decoder catches it. Same
  gate as the ARP poison: root + written authorization, local segment only;
  `--dry-run` prints the plan.
- **Packaging** — `packaging/build-deb.sh` builds a `.deb`, and
  `packaging/PKGBUILD` is an AUR recipe.

## [1.4.0] — 2026-11-11

### Added
- **WPA/WPA2 handshake capture** (`matt --wpa --iface <mon> --bssid <AP> --channel <n>`):
  monitor mode, channel-locked capture, a deauth trigger to force a reconnect,
  and conversion to hashcat 22000. Needs a monitor-mode adapter + aircrack-ng /
  hcxtools; `--dry-run` (or missing tools) prints the exact plan.
- **HTTP/2 & QUIC awareness**: ALPN is read from the TLS ClientHello (so a
  session is flagged HTTP/2), and QUIC/HTTP3 long-header Initial packets are
  detected (their SNI is AEAD-encrypted and not recoverable with the stdlib).
- **Live web dashboard** (`matt --dashboard DIR`): a zero-dependency local web
  page (stdlib http.server) that shows every finding as an auto-refreshing table
  — point it at the directory `--watch` writes to for a live view.

## [1.3.0] — 2026-11-11

### Added
- **Full hash catalog in `--identify`** — recognizes the broad families
  (cryptographic SHA/MD/BLAKE/RIPEMD/Whirlpool/Streebog/SM3/..., password KDFs
  Argon2/bcrypt/scrypt/PBKDF2/yescrypt/phpass/Django/Drupal/NTLM/LM, MACs,
  non-crypto CRC/xxHash/Murmur/FNV, checksums, perceptual/fuzzy) by prefix and
  length, each with its hashcat mode where one exists. `core.HASH_CATALOG` lists
  them by category.
- **TLS/HTTPS metadata from encrypted traffic** — `core.tls_sni` reads the
  server name from the ClientHello SNI (sent in the clear), so MATT reports which
  server an *encrypted* session is going to without any decryption.

## [1.2.0] — 2026-11-11

### Added
- **Hash identification** — `matt --identify HASH` names a hash's likely type(s)
  and hashcat mode (hashid-style: bcrypt, md5crypt, sha256/512crypt, Kerberos,
  SHA-1/256/384/512, NTLM, LM, MySQL, and more).
- **Instant reversal of common hashes** — a built-in rainbow table reverses weak
  MD5/SHA-1/SHA-256/NTLM hashes (common passwords) offline with no brute force;
  captured unsalted hashes are reversed automatically, so the table/JSON show
  them recovered for free.
- **Active response** — `matt --watch DIR` watches a directory for new
  `capture_report.json` files and analyzes each as it appears (works with
  `--crack`/`--table`/`--json`).
- **Release automation** — a GitHub Action builds and attaches the `matt.pyz`
  binary to every version tag.
- **Man page** — `man/matt.1`.

## [1.1.0] — 2026-11-11

### Added
- **Kerberos AS-REQ pre-auth** roasting (`$krb5pa$` → hashcat `-m 7500`), with
  the account and realm extracted.
- **SNMPv3** reconnaissance: the `msgUserName` is pulled from the USM security
  parameters and surfaced as an informational finding (the password is not on
  the wire, but the auth params crack with hashcat `-m 25100/25200`).
- `matt --version` prints the version and exits.
- The banner loads via `importlib.resources`, so it renders correctly from a
  zipapp (`matt.pyz`) as well as an installed checkout.

## [1.0.0] — 2026-11-11

First stable release.

### Added
- **Two-stage pipeline:** ARP-poison MITM capture (`ettercap` + `tcpdump`/
  `tshark`, per-packet reassembly) → deterministic decode + plain-English prose.
- **Hash recovery:** NetNTLMv2 (`5600`, with the target server name read from the
  blob), NetNTLMv1 (`5500`), WPA PMKID (`16800`), WPA handshake (`22000`),
  Kerberos AS-REP (`18200`) and TGS-REP / kerberoast (`13100`, with SPN),
  MD5/SHA-1/SHA-256.
- **Cleartext secrets:** FTP, POP3, IMAP, SMTP AUTH, LDAP simple bind, SNMP
  v1/v2c community strings, telnet, HTTP Basic / form logins.
- **Each credential names its destination** (server name, SPN, URL) so a report
  of many is never ambiguous.
- **`--crack`:** runs hashcat on the findings and maps recovered plaintext back
  to each user and destination.
- **Interface:** colour ASCII banner + interactive menu with a colour key,
  `matt -h`, `--table`, `--json`, and the optional `--use-model` LLM prose (the
  only path that opens a socket).
- **Launcher:** `matt` / `sudo matt` via `/usr/local/bin` and `/usr/sbin`.
- **Zero runtime dependencies** (pure standard library); a default run opens no
  socket and costs zero tokens. **AI is never required.**
- **Safety gates:** a live run refuses unless root + an existing `--iface` +
  `--i-have-written-authorization`.
- CI on Python 3.11–3.14.
