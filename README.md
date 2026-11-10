# ReconSage

**Turns raw nmap scan results into a prioritized, correlated recon report** —
the kind of checklist an experienced operator builds in their head, generated
automatically so you can spend your time on the interesting part: actually
investigating and exploiting.

![demo](docs/demo.gif)
*(see [`RECONSAGE_REPORT`](RECONSAGE_REPORT.pdf) for the full report this run produced)*

---

## Why

Recon produces a lot of raw data fast. Turning "port 445 is open, running
Samba 3.0.20" into "try a null session, check for CVE-2007-2447, this might
be part of a Domain Controller" is exactly the kind of pattern-matching
experienced testers do automatically and juniors have to look up every time.
ReconSage automates the lookup, not the judgment — so you can focus your time
on verification and exploitation, not re-researching the same ports every
engagement.

ReconSage is a **recon-to-recommendation** tool. It parses scan output,
matches services against a knowledge base of manual checks / known CVEs /
MITRE ATT&CK techniques, and correlates combinations of services into
higher-level findings (e.g. "this is a Domain Controller"). It does **not**
exploit anything, brute-force anything, or touch the target beyond the scan
you explicitly run. Every line in its output is a lead for a human to
investigate — nothing is auto-fired.

> **Use only against systems you own or are explicitly authorized to test** —
> your own lab, CTF platforms, or an engagement with signed authorization.

## Install

```bash
git clone https://github.com/<your-username>/reconsage.git
cd reconsage
pip install -e .                       # or: pipx install -e .
```

Requires Python 3.10+ and PyYAML. `nmap` must be installed and on your PATH
if you want ReconSage to run scans for you — the `analyze` command works
without nmap installed, using a scan file you already have.

## Usage

Run a scan and get an analyzed report in one step:

```bash
reconsage scan 192.168.56.102 -o report.md
```

Or analyze an nmap scan you already ran:

```bash
nmap -sV -sC -oX scan.xml 192.168.56.102
reconsage analyze scan.xml -o report.md
```

Try it immediately with zero setup, no nmap or network required:

```bash
reconsage analyze sample_data/sample_scan.xml
```

## Sample output — a real scan

[`RECONSAGE_REPORT.md`](RECONSAGE_REPORT.md) is the actual, unedited report
ReconSage produced against a Metasploitable2 instance in my own VirtualBox
lab (host-only network, no internet-facing target involved). A short excerpt:

```
- [!!!] CVE-2011-2523  21/tcp version match: CVE-2011-2523
    Known backdoored vsftpd build -- check for the smiley-face backdoor on port 6200
- [!!!] T1210  139/tcp smb — recommended checks
    Check for a null/anonymous session: smbclient -L //<target> -N
    Run enum4linux or enum4linux-ng for share/user enumeration
    Check SMB signing status -- unsigned SMB enables relay attacks
```

## How it works

```
nmap scan (-oX)
      │
      ▼
 parser.py        → structured Host/Service objects
      │
      ▼
 rules_engine.py  → per-service findings (checks, CVE hints, ATT&CK IDs)
      │                 driven by data/services.yaml
      ▼
 correlate.py     → cross-service pattern findings (e.g. DC detection)
      │                 driven by data/patterns.yaml
      ▼
 report.py        → prioritized Markdown report
```

The "intelligence" lives entirely in two YAML files, not hardcoded logic —
extend it as you learn more without touching any Python:

- **`reconsage/data/services.yaml`** — one entry per service: manual checks
  to try, version-specific CVE hints, and a MITRE ATT&CK technique ID.
- **`reconsage/data/patterns.yaml`** — rules that look at *combinations* of
  open services on a host and flag what they mean together (Domain
  Controller fingerprint, legacy-protocol clusters, directly exposed
  databases, etc.).

## Project layout

```
reconsage/
├── reconsage/
│   ├── cli.py             # scan / analyze subcommands
│   ├── parser.py          # nmap XML → Host/Service models
│   ├── models.py          # Host, Service, Finding dataclasses
│   ├── rules_engine.py    # per-service matching
│   ├── correlate.py       # cross-service pattern matching
│   ├── report.py          # Markdown report rendering
│   └── data/
│       ├── services.yaml
│       └── patterns.yaml
├── sample_data/
│   └── sample_scan.xml    # demo scan — try it with no setup
├── tests/
│   └── test_reconsage.py  # 5/5 passing
├── RECONSAGE_REPORT.md    # real sample output from a live lab scan
└── README.md
```

## What I learned building and testing this

Running ReconSage against a real Metasploitable2 box (not just the bundled
sample XML) surfaced a gap the sample data never would have: port 1524 —
nmap's own banner literally reads *"Metasploitable root shell"* — produced
**no finding at all**, because `services.yaml` had no entry for it. Same for
port 6667 (UnrealIRCd), which runs the exact backdoored build behind
CVE-2010-2075.

That's not a bug so much as the expected, useful result of testing a
recommendation engine against something real: it proved the rule set was
incomplete, and incomplete rule sets are fixable with a YAML edit, not a
rewrite. See [`RECONSAGE_REPORT.md`](RECONSAGE_REPORT.md) for the full
breakdown of what was missed and why, and `reconsage/data/services.yaml` for
the fix.

## Roadmap ideas

- NVD API lookup for version-specific CVEs not in the static YAML
- HTML report output alongside Markdown
- SQLite-backed scan history so you can diff two scans of the same host
- A `--min-severity` flag to filter report noise on large scans

## Scope, on purpose

ReconSage stops at *recommendation*. It deliberately does not chain into
automated exploitation — that line matters both for safety (a public
auto-exploit tool invites scrutiny you don't want early in your career) and
for learning (the goal is to sharpen your judgment, not replace it).

## License

MIT — see [LICENSE](LICENSE).
