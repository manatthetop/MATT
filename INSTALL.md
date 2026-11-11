# Installing MATT

## Easiest: one command (auto-installs missing tools)

```bash
git clone https://github.com/manatthetop/MATT.git && cd MATT && ./install.sh
```

`install.sh` puts the `matt` command on your PATH and **auto-installs any missing
tools it needs** (tcpdump, ettercap, hashcat) with your system package manager
(apt / dnf / pacman / zypper / brew). Re-runnable and safe.

MATT has **no runtime dependencies** — it is pure Python standard library — so
"installing" is really just putting the `matt` command on your PATH. Takes about
thirty seconds.

## Requirements

- **Python 3.11+** (3.11, 3.12, 3.13 and 3.14 are all tested in CI).
- For a **live** capture only: `tcpdump` (or `tshark`), `ettercap`, and root.
  On Kali these are already installed. Offline analysis needs none of them.
- For cracking the candidates MATT writes: `hashcat`.

Nothing is pip-installed. There is no virtualenv to create.

## Install from a .deb (Kali / Debian / Ubuntu)

```bash
./packaging/build-deb.sh
sudo dpkg -i matt_*_all.deb
```

## Quick install (from the repo)

```bash
git clone https://github.com/manatthetop/MATT.git
cd MATT

# put `matt` on your PATH (for your user) and on sudo's PATH (for root)
sudo ln -sf "$PWD/bin/matt" /usr/local/bin/matt
sudo ln -sf "$PWD/bin/matt" /usr/sbin/matt

# check it
matt --help
```

`bin/matt` resolves its own location, so the symlinks work from anywhere and
under `sudo` (which strips `PYTHONPATH`). If your shell was already open, run
`hash -r` (bash) or `rehash` (zsh) once so it notices the new command.

Optional — install the man page:

```bash
sudo install -m 0644 man/matt.1 /usr/share/man/man1/matt.1 && sudo mandb -q
man matt
```

Prefer a single file? Download `matt.pyz` from the
[latest release](https://github.com/manatthetop/MATT/releases) and run it
directly: `chmod +x matt.pyz && ./matt.pyz --help`.

### One-liner

```bash
git clone https://github.com/manatthetop/MATT.git && \
  sudo ln -sf "$PWD/MATT/bin/matt" /usr/local/bin/matt && \
  sudo ln -sf "$PWD/MATT/bin/matt" /usr/sbin/matt && \
  matt --help
```

## Try it immediately (no root, no network, no tokens)

The repo ships an example enterprise capture — an SMB NTLMv2 hash, a web-app
login, and a corporate Wi-Fi PMKID — so you can see MATT translate hashes into
plain English right after cloning:

```bash
matt --analyze-only examples/enterprise_capture.json --pretty
```

The NTLMv2 line it prints is a real, crackable `hashcat -m 5600` hash (the demo
user's password is in rockyou):

```bash
# pull the ntlmv2 candidate out and crack it to plaintext
matt --analyze-only examples/enterprise_capture.json --analysis out.json >/dev/null
python3 -c "import json;print([f['candidate'] for f in json.load(open('out.json'))['analysis']['findings'] if f['kind']=='ntlmv2'][0])" > ntlmv2.txt
hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt   # -> jdoe : Password1
```

## Run it

```bash
matt                      # interactive menu (no arguments, in a terminal)
sudo matt --iface wlan0 --i-have-written-authorization          # live MITM
sudo matt --iface wlan0 --no-poison --i-have-written-authorization   # passive
```

## Uninstall

```bash
sudo rm -f /usr/local/bin/matt /usr/sbin/matt
rm -rf MATT          # the clone itself
```

## Run the tests (optional)

```bash
python3 -m unittest discover -s tests -v    # no install needed
```

## Troubleshooting

- **`matt: command not found` after install** — your shell cached its PATH.
  Run `hash -r` (bash) / `rehash` (zsh), or open a new terminal.
- **`sudo matt: command not found`** — sudo's `secure_path` may exclude
  `/usr/local/bin`; that is why we also symlink into `/usr/sbin`. Confirm it
  exists: `ls -l /usr/sbin/matt`.
- **A live run says "refusing to run"** — that is the safety gate. A live
  capture needs all three of: root, an `--iface` that exists, and
  `--i-have-written-authorization`. Use `--analyze-only` to work offline.
