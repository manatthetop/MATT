# MATT — MAN AT THE TOP

> **Network credential capture & analysis toolkit for authorized penetration
> testing and red teams.** MITM capture → decode SMB/NTLM, Kerberos
> (kerberoasting / AS-REP), HTTP, FTP/POP3/IMAP/SMTP/LDAP/SNMP/telnet, and WPA →
> identify, reverse, and crack hashes with hashcat. Zero dependencies, no AI.

![CI](https://github.com/manatthetop/MATT/actions/workflows/ci.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/manatthetop/MATT)
![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)
![Tests](https://img.shields.io/badge/tests-221%20passing-brightgreen)
![Dependencies](https://img.shields.io/badge/dependencies-zero-success)

**MATT** is a two-stage **credential-recovery toolkit** for *authorized* wireless
and LAN **MITM** (man-in-the-middle) engagements. It sits in the middle of an
ARP-poisoned segment, harvests **authentication material** (NTLM hashes, Kerberos
tickets, cleartext logins) as it flows past, and turns that opaque wire data into
a human-readable report: **hashcat**-ready candidates plus plain-English findings
you can paste into a **pentest** write-up.

> 📖 **New here? Read the [complete guide](GUIDE.md).** Quick how-to: [USAGE.md](USAGE.md). Install: [INSTALL.md](INSTALL.md).

The name is literal. On a flat Layer 2 network, whoever answers everyone's ARP
requests *is* the man at the top of the traffic path. MATT takes that seat,
reads what comes through, and hands you the paperwork.

Running `matt` greets you with a colour ASCII banner (`matt/banner.txt`) and a
red/green interactive menu; findings are printed in colour too, each tagged with
its **source host → destination**, so a report full of credentials never gets
mixed up.

## The problem it solves

Traditional capture tooling gives you a pcap and a shrug. Responder,
`mitmdump`, `hcxdumptool` and friends are great at grabbing bytes and terrible
at telling you what those bytes mean. You end up with an NTLMv2 blob you still
have to identify, type, feed to hashcat, and interpret by hand, usually across
four terminals and a notes file.

MATT collapses that pipeline. Capture, decode, classify and translate happen in
one run, and the output is written both as machine-readable JSON and as prose a
human can act on.

## Design: zero dependencies, zero tokens by default

This is the part that makes MATT safe to drop on a target-facing laptop:

- **Standard library only.** The whole program is `json`, `hashlib`, `re`,
  `base64`, `subprocess`, `argparse`, and (only in the optional model path)
  `urllib`. There is nothing to `pip install`. The test suite *asserts* this, so
  an accidental `import requests` breaks the build instead of the engagement.
- **A default run opens no socket and costs zero usage tokens.** Stage 2 prose
  comes from a built-in, deterministic writer. Exactly one function in the whole
  package can reach the network — the optional model client — and it runs only
  when you pass `--use-model`.
- **No root, no interface needed to analyze.** `matt --analyze-only report.json`
  works offline on a quiet machine with no privileges at all.

## How it works

1. **Position (the "man at the top" step).** MATT runs `ettercap` to ARP-poison
   the gateway and the segment, so frames traverse the MATT host before being
   forwarded on — the victim never notices.
2. **Capture.** It sniffs with `tcpdump` (or `tshark`), reassembles each packet
   from its hex dump, and writes a deterministic `capture_report.json`: the raw
   payloads, the clients seen, the gateway, the poison status, and tool
   versions.
3. **Decode (stage 1 — byte-exact).** Wire bytes are decoded to text: NTLMSSP
   string fields are UTF-16LE, with a hex fallback for anything that is not text
   at all. Candidates are pulled out of each payload — HTTP POST logins, HTTP
   Basic pairs, NetNTLM triplets, WPA PMKID / EAPOL lines, **Kerberos roasts
   (AS-REP / TGS-REP)**, and **cleartext protocol secrets (FTP/POP3, IMAP, SMTP
   AUTH, LDAP simple bind, SNMP v1/v2c community strings, telnet)** — and each
   hash is classified into a hashcat mode (`5600`
   NetNTLMv2, `5500` NetNTLMv1, `16800` PMKID, `22000` WPA handshake, `18200`
   Kerberos AS-REP, `13100` Kerberos TGS, `7500` Kerberos pre-auth, `0/100/1400`
   for MD5/SHA-1/SHA-256). SNMPv3 usernames are surfaced for recon too, and even
   **encrypted HTTPS traffic gives up its destination** — MATT reads the server
   name from the TLS ClientHello SNI (cleartext metadata, no decryption). The
   `--identify` command knows the whole hash catalog (cryptographic, password/
   KDF, MAC, non-crypto, checksum, perceptual).
   NTLMv2 gives up the **target server name** (from the AV_PAIRs in the blob) and
   a TGS roast gives up its **SPN**, so a finding reads `→ FILESERVER01` or
   `→ MSSQLSvc/db01.corp.local:1433`. Unknown blobs are kept verbatim, never
   guessed.
4. **Translate (stage 2 — prose).** Each finding becomes a sentence: who was
   seen, over what, what it is, and what to do next (`hashcat -m 5600 ...`). By
   default this is the built-in writer; with `--use-model` it is an LLM spoken to
   over the Anthropic Messages API — the only thing in MATT that opens a socket.

### The decode / crack split is honest

Stage 1 is deterministic and verifiable: it produces the exact hash you hand to
hashcat or John. Stage 2 is language-shaped and can be regenerated or swapped
without touching the evidence. **MATT never claims to have recovered a
plaintext.** It says *"candidate recovered, hashcat mode 5600, awaiting offline
crack"* — which is what actually happened.

## Install

Nothing to install but the launcher — there are no runtime dependencies.

```bash
git clone https://github.com/manatthetop/MATT.git
sudo ln -s "$PWD/MATT/bin/matt" /usr/local/bin/matt   # `matt` for your user
sudo ln -s "$PWD/MATT/bin/matt" /usr/sbin/matt        # `sudo matt` for root
```

External tools used as subprocesses (not imported): `tcpdump` or `tshark` for
capture, `ettercap` for the ARP poison, and `hashcat` for the offline crack.

See **[INSTALL.md](INSTALL.md)** for the full guide (including the Kali
one-liner and troubleshooting).

### Try it immediately

The repo ships an example corporate capture — an SMB NTLMv2 hash, a web-app
login, and a Wi-Fi PMKID — so you can watch MATT translate hashes into plain
English right after cloning, with no root and no network:

```bash
matt --analyze-only examples/enterprise_capture.json --pretty
```

The NTLMv2 line it prints is a genuine `hashcat -m 5600` hash whose demo
password is in rockyou, so it cracks end to end to `jdoe : Password1`.

## Usage

Just run `matt`. With no arguments in a terminal it opens an interactive menu:

```
  [1]  Analyze a capture file        offline, no root, zero network, zero tokens
  [2]  Live passive capture          sniff an interface only -- needs root
  [3]  Live MITM capture             ARP-poison + sniff -- needs root + authorization
  [4]  Crack a capture with hashcat  recover plaintext from the findings
  [5]  About / how it works
  [q]  Quit
```

See **[USAGE.md](USAGE.md)** for the full how-to (every mode, the crack step,
`--table`/`--json`, reading the output). Or drive it directly with flags:

```bash
# analyze an existing capture report (no root, no network, no tokens)
matt --analyze-only capture_report.json --pretty

# live ARP-poison MITM capture for 60s on wlan0 (needs root + the gate flag)
sudo matt --iface wlan0 --duration 60 --i-have-written-authorization

# passive capture only -- sniff, do not poison
sudo matt --iface wlan0 --no-poison --i-have-written-authorization

# opt in to LLM-written prose (the only path that makes a network call)
export ANTHROPIC_API_KEY=sk-ant-...
sudo matt --iface wlan0 --use-model --allow-default-endpoint --i-have-written-authorization
```

Or let MATT crack them for you — add `--crack` to any analyze or live run (or
pick `[4]` in the menu). It runs hashcat and maps each recovered password back
to the user and destination it belongs to:

```bash
matt --analyze-only capture_report.json --crack --wordlist rockyou.txt
```

```
=== crack this now (hashcat) ===
  [CRACKED] jdoe @ 10.0.4.25 (WKS-FINANCE-07)  (ntlmv2 -m 5600)  =  Password1
  cracked 1/3.
```

### The safety gates

A live run refuses to start unless **all three** are true, checked before
anything is opened, so a typo cannot start an ARP storm:

- the process is **root**,
- `--iface` names an interface that **exists**, and
- **`--i-have-written-authorization`** was passed (the menu asks you to type
  `YES` for the MITM option).

## Output

- `capture_report.json` — stage 1: raw payloads, clients, gateway, poison
  status, tool versions.
- `matt_analysis.json` — stage 2: per-finding `kind`, `hashcat_mode`,
  `candidate`, `host`, `target`, `username`, and `prose`, plus counts (hosts,
  candidates, credential-bearing, network calls).
- `--json` prints that analysis straight to stdout for piping into `jq` or other
  tools (banner and human summary suppressed); with `--crack` it also folds in
  any recovered `plaintext`:

  ```bash
  matt --analyze-only capture_report.json --json | jq '.findings[] | {host, target, username, kind}'
  ```

## Scope, legality and ethics

MATT assumes **written authorization** from the network owner before the poison
pass begins. ARP poisoning is disruptive by nature — it inserts a hop into other
people's traffic and can inspect data that was never meant for you. On any
network you do not own, running it without permission is unauthorized
interception, not a gray area. The report's poison log (window, targets,
gateway) is the evidentiary trail that an engagement stayed in scope.

## Development

```bash
python3 -m unittest discover -s tests -v   # no install, standard library only
```

CI runs the suite on Python 3.11–3.14 on every push and PR.

---

## Keywords / topics

`penetration-testing` · `pentest` · `red-team` · `credential-harvesting` ·
`man-in-the-middle` · `mitm` · `arp-spoofing` · `ntlm` · `netntlmv2` ·
`kerberos` · `kerberoasting` · `asrep-roasting` · `llmnr-poisoning` ·
`nbt-ns` · `responder` · `wpa` · `wpa2-handshake` · `deauth` · `hashcat` ·
`hash-cracking` · `hash-identifier` · `packet-capture` · `packet-sniffer` ·
`network-security` · `wifi-security` · `active-directory` · `smb` · `snmp` ·
`tls-sni` · `kali-linux` · `infosec` · `security-tools` · `python` ·
`zero-dependency`

If MATT is useful to you, a ⭐ on GitHub helps others find it.
