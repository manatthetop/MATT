# MATT — The Complete Guide

**MATT (MAN AT THE TOP)** is an open-source, zero-dependency **network credential
capture and analysis toolkit** for **authorized penetration testing**, **red team
engagements**, and **security research**. It performs **man-in-the-middle (MITM)**
capture on a local network, decodes the authentication material it sees into
**hashcat-ready hashes** and plain-English findings, and cracks or relays them.

> Keywords: penetration testing, pentest, red team, credential capture, NTLM hash
> capture, NetNTLMv2, Kerberoasting, AS-REP roasting, LLMNR poisoning, NBT-NS
> spoofing, Responder alternative, ARP spoofing, MITM, WPA handshake capture,
> deauth, hashcat, packet sniffer, network security, Kali Linux, Wi-Fi security,
> hash identifier, hash cracking, SNMP, telnet, FTP, SMB, Active Directory.

This guide is the single reference for installing, running, and getting the most
out of MATT. For a quick overview see [README.md](README.md); for a fast how-to
see [USAGE.md](USAGE.md); for install specifics see [INSTALL.md](INSTALL.md).

---

## Table of contents

1. [What MATT is (and is not)](#1-what-matt-is-and-is-not)
2. [Who it is for](#2-who-it-is-for)
3. [Design principles](#3-design-principles)
4. [Installation](#4-installation)
5. [The two-stage model](#5-the-two-stage-model)
6. [Quick start](#6-quick-start)
7. [Protocols and credentials MATT understands](#7-protocols-and-credentials-matt-understands)
8. [Hash identification, reversal, and cracking](#8-hash-identification-reversal-and-cracking)
9. [Intel from encrypted traffic](#9-intel-from-encrypted-traffic)
10. [Active techniques: ARP, LLMNR/NBT-NS, WPA](#10-active-techniques-arp-llmnrnbt-ns-wpa)
11. [Enterprise-grade testing](#11-enterprise-grade-testing)
12. [Output: report, table, JSON, dashboard](#12-output-report-table-json-dashboard)
13. [Command reference](#13-command-reference)
14. [Safety, legality, and scope](#14-safety-legality-and-scope)
15. [FAQ](#15-faq)

---

## 1. What MATT is (and is not)

MATT is a **credential-recovery toolkit**. On a flat Layer-2 network, whoever
answers everyone's ARP requests sits at the top of the traffic path — the *man at
the top* — and sees authentication as it flows. MATT takes that seat, captures the
bytes, and turns them into something you can act on: a NetNTLMv2 hash ready for
`hashcat -m 5600`, a cleartext FTP password, a Kerberos ticket to roast, or a list
of the HTTPS servers a host is talking to.

MATT **is**: a packet-capture + protocol-decode + hash-identify + crack pipeline
for authorized engagements.

MATT **is not**: a magic decryptor. It does not break TLS, it does not invent
plaintext, and it never claims to have cracked a password until a wordlist
actually does. When a secret is on the wire in the clear, MATT reports it as
recovered; when it is a hash, MATT says exactly which hashcat mode cracks it.

## 2. Who it is for

- **Penetration testers** running internal network assessments.
- **Red teams** needing fast NTLM/Kerberos credential capture.
- **Blue teams** validating that their network leaks nothing in the clear.
- **Security researchers and students** learning how LAN credential theft works.
- **CTF players** decoding captured authentication material.

All usage assumes **written authorization** for the target network.

## 3. Design principles

- **Zero runtime dependencies.** The whole tool is the Python standard library.
  Nothing to `pip install`; it runs on a target-facing laptop with no network.
- **Zero tokens, no AI required.** A default run is deterministic and opens no
  socket. The optional `--use-model` LLM prose is the only network path, and it
  is off by default.
- **Honest output.** Decode (byte-exact) is separated from interpretation.
- **Safe by default.** Live capture refuses to start without root, a real
  interface, and `--i-have-written-authorization`.

## 4. Installation

```bash
# from source
git clone https://github.com/manatthetop/MATT.git
cd MATT
sudo ln -sf "$PWD/bin/matt" /usr/local/bin/matt
sudo ln -sf "$PWD/bin/matt" /usr/sbin/matt

# or a .deb (Debian / Kali / Ubuntu)
./packaging/build-deb.sh && sudo dpkg -i matt_*_all.deb

# or the single-file binary from the Releases page
chmod +x matt.pyz && ./matt.pyz --help
```

Requirements: Python 3.11+. For live capture: `tcpdump` (or `tshark`),
`ettercap`. For cracking: `hashcat`. For WPA: `aircrack-ng` + `hcxtools`.

## 5. The two-stage model

1. **Capture (stage 1).** ARP-poison the segment with ettercap, sniff with
   tcpdump/tshark, reassemble each packet from its hex dump, and write a
   deterministic `capture_report.json`.
2. **Analyze (stage 2).** Decode the payloads into hashcat-ready candidates and
   plain-English findings; optionally crack them with hashcat.

The split matters: stage 1 is byte-exact and reproducible (the hash you hand to
hashcat); stage 2 is the human-readable narrative, which can be regenerated
without touching the evidence.

## 6. Quick start

```bash
matt                                              # interactive menu
matt --analyze-only examples/enterprise_capture.json --table   # try it risk-free
matt --identify 5f4dcc3b5aa765d61d8327deb882cf99  # identify + reverse a hash
sudo matt --iface wlan0 --no-poison --i-have-written-authorization  # passive
sudo matt --iface wlan0 --i-have-written-authorization --crack      # MITM + crack
```

## 7. Protocols and credentials MATT understands

MATT decodes credentials and authentication material from a broad set of
protocols — the kind you meet on a real enterprise LAN:

- **SMB / NTLM** — NetNTLMv2 (`hashcat -m 5600`) and NetNTLMv1 (`-m 5500`); the
  target **server name** is read from the NTLMv2 blob (AV_PAIRs).
- **Kerberos** — AS-REP roasting (`-m 18200`), TGS-REP / **kerberoasting**
  (`-m 13100`, with the SPN), and AS-REQ **pre-auth** (`-m 7500`).
- **HTTP** — form logins, HTTP Basic, and the destination URL.
- **Cleartext logins** — **FTP**, **POP3**, **IMAP**, **SMTP** (AUTH PLAIN),
  **LDAP** simple bind, **SNMP** v1/v2c community strings, **telnet**. FTP and
  POP3 share the same `USER`/`PASS` verbs, so MATT uses the **service port** from
  the capture (21 vs 110/995) to label each flow correctly, falling back to the
  server greeting when no port was recorded.
- **SNMPv3** — the username (recon; the auth params crack with `-m 25100/25200`).
- **Wi-Fi** — **WPA/WPA2** PMKID (`-m 16800`) and 4-way handshake (`-m 22000`).

## 8. Hash identification, reversal, and cracking

- **Identify any hash:** `matt --identify <hash>` names the likely types and
  hashcat modes — bcrypt, md5crypt, sha256/512crypt, Argon2, PBKDF2, NTLM, LM,
  MD5, SHA-1/256/384/512, SHA-3, RIPEMD, Whirlpool, Streebog, SM3, MySQL,
  Kerberos, and more, plus non-cryptographic (CRC, xxHash, MurmurHash, FNV).
- **Reverse common hashes instantly:** a built-in rainbow table reverses weak
  unsalted MD5/SHA-1/SHA-256/NTLM hashes offline — no brute force. Captured weak
  hashes auto-reverse in the output.
- **Crack with hashcat:** `--crack` runs hashcat on the findings and maps the
  recovered plaintext back to each user and destination. For NTLM you can also
  **relay** (`ntlmrelayx`) to authenticate without cracking at all.

## 9. Intel from encrypted traffic

Even when traffic is TLS/HTTPS, MATT reads the **metadata** that is sent in the
clear — no decryption, no key material:

- **TLS SNI** — the server name from the ClientHello.
- **ALPN** — flags HTTP/2 vs HTTP/1.1.
- **TLS certificate** — subject CN, issuer CN, and SAN DNS names (TLS 1.2).
- **QUIC / HTTP3** — detected by version (its SNI is AEAD-encrypted).

## 10. Active techniques: ARP, LLMNR/NBT-NS, WPA

All are gated on root + `--i-have-written-authorization`, local segment only:

- **ARP poisoning** (default live mode) — insert MATT into the traffic path.
- **LLMNR / NBT-NS poisoning** (`--llmnr`) — answer Windows name-resolution
  fallbacks so a victim's auth is funnelled to you (a **Responder**-style
  primitive) for the NetNTLMv2 decoder.
- **WPA handshake capture** (`--wpa`) — monitor mode, channel-locked capture, a
  **deauth** to force a reconnect, converted to hashcat 22000. **Auto-configuring:**
  give it `--ssid NAME` (or `--bssid`) and MATT scans, finds the AP's **channel**
  and BSSID itself, sets the adapter to monitor mode in place with `iw` (works on
  the in-kernel USB drivers like rtw89 where airmon-ng's `*mon` interface is never
  created), captures, then restores managed mode. It is also menu option **5** —
  pick a network from a live scan and MATT does the rest. The captured
  `matt-wpa.22000` can be fed straight back in: `matt --analyze-only matt-wpa.22000
  --crack` (a plain hash file is accepted, not just a JSON report).

## 11. Enterprise-grade testing

MATT is built for real corporate networks:

- **Large packets.** Jumbo frames and GRO/TSO-coalesced segments (tens of KB)
  are reassembled whole, and credentials buried deep inside them are still
  decoded — there is no 200-packet or row-count cap truncating the capture
  (`--duration` bounds it; `--max-packets` caps it when you want).
- **Multi-packet logins.** Real FTP, POP3, IMAP, SMTP and telnet send the
  username and password in *separate* packets, split by the server's replies, so
  no single packet holds the pair. MATT rejoins each TCP flow and decodes the
  credential from the whole conversation — the common case a per-packet decoder
  would miss entirely.
- **Every host named.** Each finding carries its **source host** and **where the
  credential goes** (server name, SPN, URL), so a report with dozens of
  credentials is never ambiguous.
- **Active Directory flows.** SMB NTLMv2, Kerberos AS-REP/TGS/pre-auth, and LDAP
  binds are all first-class.
- **Scales to a full engagement.** `--watch` processes new captures as they land;
  the dashboard gives a live view; `--json` pipes into your own tooling or a SIEM.

## 12. Output: report, table, JSON, dashboard

- `--pretty` — one color-coded block per credential.
- `--table` — one compact row per credential (host · target · user · type ·
  secret), color-coded by category.
- `--json` — machine-readable, for `jq` / pipelines / SIEM ingestion.
- `--dashboard DIR` — a live, auto-refreshing findings table **in the terminal**
  (no browser; `--web` is opt-in).

Color code: **green** = a secret in hand (cleartext or cracked), **yellow** = a
crackable hash, **cyan** = recon (TLS/SNMPv3/QUIC).

## 13. Command reference

Run `matt -h` for the authoritative list. Highlights:

| Flag | What it does |
|------|--------------|
| `--analyze-only REPORT` | decode an existing capture (no root, no network) |
| `--iface NAME` | interface to capture on |
| `--no-poison` | passive sniff only (no ARP poison) |
| `--i-have-written-authorization` | required gate for any live run |
| `--crack` / `--wordlist` | run hashcat on the findings |
| `--identify HASH` | identify + reverse a hash |
| `--table` / `--json` / `--pretty` | output formats |
| `--dashboard DIR` | live terminal dashboard |
| `--watch DIR` | analyze new captures as they land |
| `--wpa --bssid --channel` | WPA handshake capture (deauth) |
| `--llmnr --our-ip` | LLMNR/NBT-NS poisoning |
| `--max-packets N` | cap the capture (default 0 = duration-bounded) |
| `--use-model` | optional LLM prose (the only network path) |
| `--version` | print version |

## 14. Safety, legality, and scope

ARP, LLMNR/NBT-NS, and WPA deauth are **active interventions**: they rewrite other
people's traffic or knock clients off the air. Run them **only** on a network you
own or are **explicitly authorized** to test. MATT enforces this with a gate
(root + `--i-have-written-authorization`) and records a poison log in the report
as your evidentiary scope trail. Unauthorized interception is illegal in most
jurisdictions. You are responsible for staying in scope.

## 15. FAQ

**Does MATT need AI?** No. A default run is deterministic standard-library code.

**Will it get passwords from my normal Wi-Fi?** Only where traffic is cleartext
(HTTP/FTP/telnet/SNMP) or where it can capture an auth hash (SMB/NTLM via MITM).
Most browsing is HTTPS, so there you get metadata (SNI, certs), not plaintext.

**Can it decrypt HTTPS / TLS?** No. Nothing can without the keys. MATT reads the
cleartext handshake metadata only.

**Is it a Responder clone?** It includes a Responder-style LLMNR/NBT-NS poisoning
primitive, plus ARP and WPA capture, and a full decode/identify/crack pipeline on
top — all in one zero-dependency tool.

**What makes it "enterprise grade"?** Large-packet reassembly, Active Directory
credential coverage (NTLM/Kerberos/LDAP), per-finding destination tracking,
live dashboard, JSON for pipelines, and a tested, released, packaged codebase.
