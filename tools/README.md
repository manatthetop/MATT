# credcap — a smarter wordlist than rockyou

`credcap.py` generates a password wordlist built for how a real crack actually
runs, for **authorized** testing only.

The ready-to-use smart core — [`credcap.txt`](credcap.txt) (~58k entries,
~630 KB) — is **shipped in this repo**, so you can crack with it straight away:

```bash
sudo matt --analyze-only hs.22000 --crack --wordlist tools/credcap.txt   # use the shipped list

python3 tools/credcap.py -o credcap.txt                       # regenerate the smart core (~58k)
python3 tools/credcap.py -o credcap-full.txt \
        --merge /usr/share/wordlists/rockyou.txt              # build the strict superset of rockyou
```

The 14.4 M-entry `credcap-full` superset is **not** committed (it is far too
large for git and is a rockyou derivative) — build it locally with `--merge`,
as shown above.

## Why it beats rockyou

rockyou.txt is a raw 2009 breach dump — huge, unordered, and blind to anything
after 2009. credcap fixes the parts that matter:

| | rockyou.txt | credcap.txt (core) | credcap-full.txt |
|---|---|---|---|
| Entries | 14.34 M | ~58 k | **14.40 M** (⊇ rockyou) |
| Ordering | breach order | **likeliest first** | smart first, then rockyou |
| Modern years / `Season+Year!` | ✗ (stops at 2009) | ✓ | ✓ |
| Corporate `P@ssw0rd!` leet forms | partial | ✓ | ✓ |
| First-hit speed on weak creds | slow | **fast** | fast |

- **Front-loaded.** The most statistically likely passwords come first, so a
  run in list order lands its hits in the first seconds.
- **Modern.** Current/next years, `Summer2026!`, `October2026`, up-to-date
  keyboard walks (`1qaz2wsx3edc`) — things a 2009 dump never had. (Verified:
  credcap cracks `Summer2026!`, which rockyou cannot.)
- **Rule-mutated.** Curated base words expanded with the leet / case / affix
  rules people actually use.
- **A strict superset on demand.** `--merge rockyou.txt` keeps every rockyou
  entry (so you lose no coverage) but reaches the likely answers sooner.

Deterministic and standard-library only. `--years N`, `--heavy N`, `--max N`
tune span, rule depth, and size.

> Cracking is CPU/GPU- and RAM-heavy. On a low-RAM machine MATT auto-retries on
> the CPU backend and, if it still can't allocate, says so plainly rather than
> pretending the wordlist was exhausted — run the crack on a box with a GPU or
> more memory.
