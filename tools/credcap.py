#!/usr/bin/env python3
"""credcap -- a smarter password wordlist generator for authorized testing.

rockyou.txt is a raw 2009 breach dump: huge, but unordered, full of junk, and
blind to everything after 2009 (modern years, "Season+Year!" corporate resets,
current keyboard walks). credcap builds a list that is *better* in the ways that
matter for a real crack:

  1. Front-loaded.  The most statistically likely passwords come FIRST, so a
     hashcat/MATT run in list order lands its hits in the first seconds, not
     after grinding megabytes of noise.
  2. Modern.  Current years (through next year), seasons+year+symbol, months,
     and up-to-date keyboard walks that a 2009 dump never had.
  3. Rule-mutated.  A curated set of high-yield base words is expanded with the
     leet / case / affix rules real people use (P@ssw0rd!, Summer2026!, …).
  4. Deduplicated and ordered.  No entry appears twice; strength grows as you go
     deeper, so you can stop early for a quick pass or run long for coverage.
  5. Optionally a strict superset of rockyou (`--merge rockyou.txt`): credcap's
     smart candidates first, then every rockyou entry not already emitted -- so
     you never lose coverage, you just reach the likely answers sooner.

Standard library only; deterministic (same inputs -> same list).

    python3 credcap.py -o credcap.txt
    python3 credcap.py -o credcap.txt --merge /usr/share/wordlists/rockyou.txt
    sudo matt --analyze-only hs.22000 --crack --wordlist credcap.txt
"""
from __future__ import annotations

import argparse
import datetime
import itertools
import sys

# --------------------------------------------------------------------------
# 1. the head of the list: the passwords that crack the most accounts, first.
#    Curated from the recurring top of public breach-frequency lists, with the
#    dead-2009 noise dropped and modern staples added.
# --------------------------------------------------------------------------
TOP = """
123456 password 123456789 12345678 12345 1234567 1234567890 qwerty abc123
password1 111111 123123 1234 000000 iloveyou qwerty123 1q2w3e 1q2w3e4r
admin welcome monkey dragon letmein login princess solo passw0rd starwars
football baseball master hello freedom whatever qazwsx trustno1 654321
superman batman access shadow michael jordan harley hunter buster soccer
tigger charlie andrew michelle jessica pepper zxcvbnm asdfgh asdfghjkl
qwertyuiop 121212 112233 123321 666666 696969 7777777 888888 aa123456
Password1 Password123 Welcome1 Welcome123 Admin123 P@ssw0rd P@ssw0rd1
Qwerty123 Changeme123 Summer2024 Summer2025 Winter2024 Spring2025
google facebook amazon netflix spotify instagram minecraft pokemon
samsung iphone android computer internet cookie chocolate maverick
"""

# --------------------------------------------------------------------------
# 2. base words that mutate well. Kept broad but curated -- the kinds of tokens
#    people actually build passwords from.
# --------------------------------------------------------------------------
BASES = """
password passw0rd pass admin root user guest login welcome secret letmein
qwerty azerty dragon monkey master shadow superman batman spiderman ironman
football baseball basketball soccer hockey cowboys lakers yankees liverpool
summer winter spring autumn january february march april may june july august
september october november december monday friday
love money freedom happy sunshine rainbow flower princess angel baby cookie
chocolate coffee whiskey vodka beer pizza ninja hunter gamer player killer
google facebook amazon apple netflix spotify twitter youtube tiktok discord
microsoft windows linux android iphone samsung tesla paypal
michael jennifer jessica ashley amanda david john james robert william mary
charlie max bella luna buddy daisy rocky lucky oliver
company corp office work team project server network system data cloud
"""

SUFFIX_DIGITS = ["", "1", "2", "12", "123", "1234", "12345", "123456",
                 "007", "69", "11", "22", "99", "00", "01", "321"]
SUFFIX_SYMBOLS = ["", "!", "@", "#", "$", ".", "*", "!!", "123!", "1!", "@123"]
PREFIXES = ["", "!", "1", "@"]
SEASONS = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
KEYBOARD = ["qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
            "1q2w3e", "1q2w3e4r", "1q2w3e4r5t", "1qaz2wsx", "1qaz2wsx3edc",
            "qazwsx", "qweasdzxc", "q1w2e3r4", "zaq12wsx", "!qaz2wsx",
            "poiuyt", "mnbvcxz", "0987654321", "qwer1234", "qweqwe"]

# Two leet styles: "light" swaps only the vowel-ish letters (so password ->
# p@ssw0rd, the classic corporate form), "full" also hits s -> $.
_LEET_LIGHT = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0"})
_LEET_FULL = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})


def _years(span: int) -> list:
    """Likely year tokens, newest first: current year back `span` years, plus
    two-digit forms. Newer years crack more now, so they lead."""
    now = datetime.date.today().year
    out = []
    for y in range(now + 1, now - span, -1):
        out.append(str(y))
        out.append("%02d" % (y % 100))
    return out


def _case_variants(w: str):
    yield w
    yield w.capitalize()
    yield w.upper()


def _emit(base, years, heavy):
    """Yield mutated forms of one base word, likeliest first. `heavy` applies the
    full rule set; otherwise a light set, to keep the long tail lean."""
    seen_local = set()

    def push(v):
        if v and v not in seen_local:
            seen_local.add(v)
            return v
        return None

    # plain + case
    for c in _case_variants(base):
        r = push(c)
        if r:
            yield r
    # case x short digit/symbol affixes
    cases = list(_case_variants(base)) if heavy else [base, base.capitalize()]
    digits = SUFFIX_DIGITS if heavy else ["1", "123", "12"]
    syms = SUFFIX_SYMBOLS if heavy else ["", "!", "123!"]
    for c in cases:
        for d in digits:
            for s in syms:
                r = push(c + d + s)
                if r:
                    yield r
    # case x year (+ optional symbol)
    for c in (cases if heavy else [base.capitalize()]):
        for y in years:
            for s in (["", "!", "@", "#"] if heavy else ["", "!"]):
                r = push(c + y + s)
                if r:
                    yield r
    # leet of the base (light vowel-leet, then full), +/- affixes
    for leet in (base.translate(_LEET_LIGHT), base.translate(_LEET_FULL)):
        if leet == base:
            continue
        for c in (leet, leet.capitalize()):
            for s in (SUFFIX_SYMBOLS + ["1", "123", "1!", "123!"] if heavy
                      else ["", "!", "1", "123!"]):
                r = push(c + s)
                if r:
                    yield r
    # prefixed forms (heavy only)
    if heavy:
        for p in PREFIXES[1:]:
            for d in ["", "1", "123", "!"]:
                r = push(p + base.capitalize() + d)
                if r:
                    yield r


def generate(span: int = 12, heavy_top: int = 60):
    """Yield credcap candidates, most-likely first. `heavy_top` base words get
    the full rule set; the rest get a lighter one."""
    years = _years(span)
    tokens = TOP.split()
    bases = []
    for w in BASES.split():
        if w not in bases:
            bases.append(w)

    # 1. the curated top list, verbatim, first.
    for t in tokens:
        yield t

    # 2. season/month + year (+ symbol) -- the modern corporate-reset pattern.
    for fam in (SEASONS, MONTHS):
        for word in fam:
            for y in years:
                for s in ("", "!", "@", "123", "1", "#", "2!"):
                    yield word + y + s

    # 3. keyboard walks + light year/symbol variants.
    for k in KEYBOARD:
        yield k
        yield k.capitalize()
        for y in years[:6]:
            yield k + y
        for s in ("!", "123", "1", "@"):
            yield k + s

    # 4. the mutated base words.
    for i, base in enumerate(bases):
        for cand in _emit(base, years, heavy=(i < heavy_top)):
            yield cand


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="credcap", description="Generate the credcap wordlist.")
    ap.add_argument("-o", "--out", default="credcap.txt",
                    help="output file (default: credcap.txt)")
    ap.add_argument("--years", type=int, default=12,
                    help="how many years back to include (default: 12)")
    ap.add_argument("--heavy", type=int, default=60,
                    help="how many top base words get the full rule set")
    ap.add_argument("--merge", metavar="WORDLIST",
                    help="append every line of this list (e.g. rockyou.txt) that "
                         "credcap did not already emit -- a strict superset")
    ap.add_argument("--max", type=int, default=0,
                    help="stop after N entries (0 = no cap)")
    args = ap.parse_args(argv)

    seen = set()
    n = 0
    with open(args.out, "w", encoding="utf-8", errors="ignore") as fh:
        def write(w):
            nonlocal n
            if not w or w in seen:
                return False
            seen.add(w)
            fh.write(w + "\n")
            n += 1
            return True

        for cand in generate(span=args.years, heavy_top=args.heavy):
            write(cand)
            if args.max and n >= args.max:
                break
        smart = n
        if args.merge and not (args.max and n >= args.max):
            try:
                with open(args.merge, encoding="utf-8", errors="ignore") as src:
                    for line in src:
                        write(line.rstrip("\n"))
                        if args.max and n >= args.max:
                            break
            except OSError as exc:
                sys.stderr.write("credcap: could not read %s: %s\n"
                                 % (args.merge, exc))
    merged = n - smart
    print("credcap: wrote %d entries to %s" % (n, args.out))
    print("  smart/generated : %d (these come first, likeliest -> deepest)" % smart)
    if args.merge:
        print("  merged-in extras: %d unique lines from %s" % (merged, args.merge))
    print("  use:  sudo matt --analyze-only HASHFILE --crack --wordlist %s"
          % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
