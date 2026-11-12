"""matt.crack -- the optional "crack this now" step.

Takes the credential-bearing findings MATT already decoded and runs ``hashcat``
over them against a wordlist, then maps any recovered plaintext back to the
finding it belongs to (host, user, destination). This is the one place MATT
turns a candidate into an actual password, and it only runs when the operator
asks for it (``--crack`` / the menu).

Standard library only, and it opens no socket. ``hashcat`` is invoked as a
subprocess; nothing is imported from it. Importing this module spawns nothing,
so ``matt.cli`` can import it lazily the moment a crack is requested.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile

__all__ = ["have_hashcat", "have_aircrack", "crackable", "group_by_mode",
           "parse_outfile", "crack", "crack_wpa_cap", "seeds_from_findings",
           "build_contextual_wordlist"]

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

_AIRCRACK_KEY_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")


def have_hashcat(which=shutil.which) -> bool:
    """True if a hashcat binary is on PATH."""
    return bool(which("hashcat"))


def have_aircrack(which=shutil.which) -> bool:
    """True if an aircrack-ng binary is on PATH."""
    return bool(which("aircrack-ng"))


def crackable(findings) -> list:
    """The findings worth handing to hashcat: those with a real hashcat mode and
    a candidate string. http-basic (mode None) and unknown blobs are skipped --
    there is nothing for hashcat to do with them."""
    out = []
    for f in findings or []:
        if f.get("hashcat_mode") and str(f.get("candidate") or "").strip():
            out.append(f)
    return out


def group_by_mode(findings) -> dict:
    """Map hashcat mode -> list of findings, so one hashcat run covers each mode.
    De-duplicates identical candidates within a mode."""
    groups: dict = {}
    for f in crackable(findings):
        mode = str(f["hashcat_mode"])
        groups.setdefault(mode, [])
        if f["candidate"] not in [g["candidate"] for g in groups[mode]]:
            groups[mode].append(f)
    return groups


def parse_outfile(text: str) -> dict:
    """Parse a hashcat outfile (``hash:plaintext`` per line) into a map keyed by
    the lower-cased hash. hashcat may echo the hash with a different case (it
    upper-cases the NTLM account name), so the key is lower-cased for matching;
    the plaintext is the last ':'-separated field and is kept verbatim."""
    recovered: dict = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        hash_part, plain = line.rsplit(":", 1)
        recovered[hash_part.strip().lower()] = plain
    return recovered


def _match_outfile(text, mode, group) -> dict:
    """Map a hashcat outfile's lines back to the candidate(s) they cracked,
    keyed by ``candidate.lower()`` like the rest of this module expects.

    Every mode but WPA echoes the exact hash it was given, so parse_outfile()
    already does this correctly. Mode 22000 does not: hashcat reformats a
    cracked WPA hash as ``hash:AP-MAC:client-MAC:ESSID:plaintext``, discarding
    the original ``WPA*02*hash*ap_mac*sta_mac*essid*...`` candidate string
    entirely -- so a literal ``cand.lower()`` lookup against that line can
    never match, and a real WPA crack was being reported as "not in
    wordlist" even when hashcat found the password. Match by the (hash,
    AP MAC, client MAC) triple embedded in both instead.
    """
    if mode != "22000":
        return parse_outfile(text)
    index = {}
    for g in group:
        fields = g["candidate"].split("*")
        if len(fields) >= 5:
            index[(fields[2].lower(), fields[3].lower(), fields[4].lower())] = \
                g["candidate"].lower()
    recovered: dict = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        key = (parts[0].strip().lower(), parts[1].strip().lower(),
               parts[2].strip().lower())
        cand = index.get(key)
        if cand:
            recovered[cand] = ":".join(parts[4:])
    return recovered


def seeds_from_findings(findings, extra=None) -> list:
    """Pull plausible target-specific password seeds out of MATT's own
    findings: usernames, hosts, destinations, and (for an email username) its
    local-part and domain. A real password is far more often built from
    something about its own target than from a generic top-1000 list, so
    these feed credcap's contextual generator ahead of anything generic.
    ``extra`` lets a caller add something MATT itself doesn't decode from the
    wire, like the WPA SSID being targeted.
    """
    seeds: list = []

    def add(s):
        s = str(s or "").strip()
        if s and s.lower() not in ("none", "unknown") and s not in seeds:
            seeds.append(s)

    for f in findings or []:
        add(f.get("username"))
        add(f.get("host"))
        add(f.get("target"))
        user = f.get("username") or ""
        if "@" in user:
            local, _, domain = user.partition("@")
            add(local)
            add(domain.split(".")[0])
    for s in extra or []:
        add(s)
    return seeds


def build_contextual_wordlist(seeds, out_path, span=12) -> bool:
    """Write a small credcap-style wordlist built from ``seeds`` to
    ``out_path``. Returns False (writing nothing) if there are no usable
    seeds or tools/credcap.py cannot be imported, so a caller can just skip
    straight to its normal wordlist."""
    if not seeds:
        return False
    try:
        tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
        import credcap
    except Exception:
        return False
    n = 0
    seen = set()
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            for cand in credcap.generate_contextual(seeds, span=span):
                if cand not in seen:
                    seen.add(cand)
                    fh.write(cand + "\n")
                    n += 1
    except OSError:
        return False
    return n > 0


def _default_runner(cmd, timeout):
    """Run hashcat. Returns the CompletedProcess; the outfile it wrote (``-o``)
    is read by crack(). Never raises for a non-zero exit (an exhausted wordlist
    is exit 1, which is normal)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          check=False)


def crack_wpa_cap(cap_file, wordlist, aircrack="aircrack-ng", runner=None,
                  timeout=300) -> dict:
    """Run aircrack-ng directly against a raw WPA handshake capture (.cap).

    aircrack-ng's dictionary attack needs a small fraction of the memory
    hashcat's -m 22000 kernel wants -- useful as a fallback on a low-RAM box
    (hashcat allocates ~1.4 GB for that mode regardless of wordlist size).
    aircrack-ng reads the .cap directly, not the 22000 hash line, so this
    takes the capture file, not a candidate string. Returns
    ``{"plaintext": str|None, "note": str|None}``.
    """
    runner = runner or _default_runner
    if not cap_file or not os.path.exists(cap_file):
        return {"plaintext": None, "note": "cap file not found: %s" % cap_file}
    cmd = [aircrack, "-w", wordlist, "-q", cap_file]
    try:
        proc = runner(cmd, timeout)
    except subprocess.TimeoutExpired:
        return {"plaintext": None, "note": "timed out"}
    except OSError as exc:
        return {"plaintext": None, "note": "aircrack-ng error: %s" % exc}
    text = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
    match = _AIRCRACK_KEY_RE.search(text)
    if match:
        return {"plaintext": match.group(1), "note": None}
    if "Passphrase not in dictionary" in text:
        return {"plaintext": None, "note": "not in wordlist"}
    return {"plaintext": None, "note": "aircrack-ng found nothing (no handshake "
                                        "in capture, or wrong network?)"}


def crack(findings, wordlist=DEFAULT_WORDLIST, hashcat="hashcat", runner=None,
          timeout=300, tmpdir=None, extra_args=(), optimized=True,
          wpa_cap=None, aircrack="aircrack-ng", aircrack_runner=None,
          context_seeds=None) -> list:
    """Run hashcat over every crackable finding and return a result per finding.

    Each result is a dict: host, username, target, kind, mode, candidate, and
    ``plaintext`` (the recovered password, or None if the wordlist was
    exhausted or the run timed out). ``runner(cmd, timeout)`` is injectable so
    tests never need a real hashcat; the default runs it for real.

    One hashcat invocation per mode (not per hash), writing to a per-mode
    outfile, so a report with ten NTLMv2 hashes is one run, not ten.

    ``wpa_cap``, if given, is the raw .cap a WPA (mode 22000) finding was
    captured into. If hashcat reports an out-of-memory failure for that mode,
    MATT retries with aircrack-ng against this .cap before giving up -- it
    needs far less memory, so a low-RAM box still gets a real answer instead
    of "crack on a bigger machine".

    ``context_seeds``, if given (see ``seeds_from_findings``), builds a small
    credcap wordlist from them and tries it against each mode BEFORE the real
    ``wordlist`` -- a password built from the target's own SSID/username/
    hostname/email cracks in this pass almost instantly, well ahead of where
    it would sit in a generic list.
    """
    runner = runner or _default_runner
    items = crackable(findings)
    owns_tmp = tmpdir is None
    tmp = tmpdir or tempfile.mkdtemp(prefix="matt-crack-")
    recovered: dict = {}
    notes: dict = {}

    if optimized and "-O" not in extra_args:
        extra_args = tuple(extra_args) + ("-O",)
    context_wordlist = None
    if context_seeds:
        candidate_path = os.path.join(tmp, "context.txt")
        if build_contextual_wordlist(context_seeds, candidate_path):
            context_wordlist = candidate_path
    try:
        _crack_into(items, tmp, hashcat, wordlist, runner, timeout, extra_args,
                    recovered, notes, wpa_cap=wpa_cap, aircrack=aircrack,
                    aircrack_runner=aircrack_runner,
                    context_wordlist=context_wordlist)
    finally:
        # Only remove a directory we made ourselves: a caller-supplied tmpdir
        # (tests inject one to inspect the hash/outfiles afterward) is theirs
        # to clean up, not ours. Without this, a long session running --crack
        # repeatedly (the menu's "crack a capture" option, or --watch --crack
        # on a directory of incoming reports) leaves one abandoned
        # "matt-crack-*" directory under /tmp per run, forever.
        if owns_tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    results = []
    for f in items:
        cand = f["candidate"]
        results.append({
            "host": f.get("host"),
            "username": f.get("username"),
            "target": f.get("target"),
            "kind": f.get("kind"),
            "mode": str(f.get("hashcat_mode")),
            "candidate": cand,
            "plaintext": recovered.get(cand.lower()),
            "note": notes.get(cand.lower()),
        })
    return results


def _try_contextual_pass(group, mode, tmp, hashcat, context_wordlist, runner,
                         timeout, extra_args, recovered) -> None:
    """Best-effort pre-pass against the small MATT-generated contextual
    wordlist (SSID/username/hostname/email-derived). Silent on any failure --
    whatever happens, the caller just falls through to the real wordlist pass
    for anything this didn't recover."""
    hashfile = os.path.join(tmp, "hashes_%s_ctx.txt" % mode)
    outfile = os.path.join(tmp, "cracked_%s_ctx.txt" % mode)
    try:
        with open(hashfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(g["candidate"] for g in group) + "\n")
        cmd = [hashcat, "-m", mode, "-a", "0", "--potfile-disable", "--quiet",
               "-o", outfile, hashfile, context_wordlist, *extra_args]
        runner(cmd, timeout)
        with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
            recovered.update(_match_outfile(fh.read(), mode, group))
    except Exception:
        pass


def _crack_into(items, tmp, hashcat, wordlist, runner, timeout, extra_args,
                recovered, notes, wpa_cap=None, aircrack="aircrack-ng",
                aircrack_runner=None, context_wordlist=None) -> None:
    """The actual hashcat-running loop, factored out of crack() so the
    tmpdir-cleanup in its caller is a single try/finally around one call,
    not duplicated around every early return this loop used to have."""
    for mode, group in group_by_mode(items).items():
        if context_wordlist:
            unresolved = [g for g in group if g["candidate"].lower() not in recovered]
            if unresolved:
                _try_contextual_pass(unresolved, mode, tmp, hashcat,
                                     context_wordlist, runner, timeout,
                                     extra_args, recovered)
            group = [g for g in group if g["candidate"].lower() not in recovered]
            if not group:
                continue
        hashfile = os.path.join(tmp, "hashes_%s.txt" % mode)
        outfile = os.path.join(tmp, "cracked_%s.txt" % mode)
        try:
            os.path.exists(outfile) and os.remove(outfile)
        except OSError:
            pass
        with open(hashfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(g["candidate"] for g in group) + "\n")

        base = [hashcat, "-m", mode, "-a", "0", "--potfile-disable", "--quiet",
                "-o", outfile, hashfile, wordlist, *extra_args]

        def _run(cmd):
            try:
                return runner(cmd, timeout), None
            except subprocess.TimeoutExpired:
                return None, "timed out"
            except OSError as exc:
                return None, "hashcat error: %s" % exc

        proc, err = _run(base)
        if err:
            for g in group:
                notes[g["candidate"].lower()] = err
            if err.startswith("hashcat error"):
                continue

        # A weak / low-RAM box (e.g. a 4 GB laptop with only a CPU backend) can
        # fail to allocate the default backend's memory and exit 0 having cracked
        # NOTHING -- which looks exactly like an exhausted wordlist. Detect that
        # from hashcat's own message and retry once pinned to the CPU backend
        # with a small allocation, so cracking actually works on modest hardware.
        out_text = ""
        if proc is not None:
            out_text = (getattr(proc, "stdout", "") or "") + \
                       (getattr(proc, "stderr", "") or "")
        def _is_oom(text):
            return any(s in text for s in (
                "Not enough allocatable device memory",
                "No devices found/left", "Not enough allocatable"))

        def _no_runtime(text):
            return "No OpenCL, HIP or CUDA compatible platform found" in text

        # Retry once pinned to the CPU backend, which allocates more modestly.
        if _is_oom(out_text) and "-D" not in base and not _outfile_has_data(outfile):
            proc, err = _run(base + ["-D", "1"])
            if proc is not None:
                out_text = (getattr(proc, "stdout", "") or "") + \
                           (getattr(proc, "stderr", "") or "")

        rc = getattr(proc, "returncode", None)
        if not _outfile_has_data(outfile):
            if _is_oom(out_text) and mode == "22000" and wpa_cap:
                # hashcat's -m 22000 kernel wants ~1.4 GB regardless of
                # wordlist size, which a 4 GB box under memory pressure can't
                # always give it. aircrack-ng attacks the same WPA handshake
                # with a tiny fraction of that footprint, so fall back to it
                # against the raw .cap before reporting a resource failure.
                air = crack_wpa_cap(wpa_cap, wordlist, aircrack=aircrack,
                                    runner=aircrack_runner, timeout=timeout)
                if air["plaintext"] is not None:
                    for g in group:
                        recovered[g["candidate"].lower()] = air["plaintext"]
                else:
                    for g in group:
                        notes[g["candidate"].lower()] = (
                            "hashcat OOM'd; aircrack-ng fallback: %s"
                            % (air["note"] or "no result"))
            elif _is_oom(out_text):
                # Do NOT let this look like an exhausted wordlist: it is a
                # resource failure, and the honest fix is a bigger box.
                for g in group:
                    notes[g["candidate"].lower()] = (
                        "hashcat ran out of memory on this machine -- crack on a "
                        "host with more RAM or a GPU")
            elif _no_runtime(out_text):
                # hashcat found no OpenCL/CUDA/HIP platform at all -- there is
                # no GPU driver or CPU OpenCL runtime installed on this
                # machine, so hashcat never even started a kernel. Distinct
                # from an exhausted wordlist (and from the generic "hashcat
                # exited N" below), so the operator knows a driver install is
                # what's missing, not a bigger wordlist.
                for g in group:
                    notes[g["candidate"].lower()] = (
                        "no OpenCL/CUDA/HIP runtime found on this machine -- "
                        "install a GPU driver (or the Intel/AMD CPU OpenCL "
                        "runtime) to crack here")
            elif rc not in (None, 0, 1):
                for g in group:
                    notes.setdefault(g["candidate"].lower(),
                                     "hashcat exited %s" % rc)
        try:
            with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
                recovered.update(_match_outfile(fh.read(), mode, group))
        except OSError:
            pass


def _outfile_has_data(path) -> bool:
    try:
        return os.path.getsize(path) > 0
    except OSError:
        return False
