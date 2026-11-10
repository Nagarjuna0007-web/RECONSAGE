"""
ReconSage CLI.

Two subcommands:
  scan     - run nmap against a target and analyze the result
  analyze  - analyze an nmap XML file you already have (e.g. from -oX)

ReconSage only ever reads nmap output and produces recommendations.
It never runs an exploit, brute-forces anything, or touches the target
beyond the scan you explicitly ask it to run.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile

from .correlate import correlate_host, load_patterns
from .parser import parse_nmap_xml
from .report import render_markdown, write_markdown
from .rules_engine import analyze_host, load_service_rules


def _run_nmap(target: str, out_xml: str, extra_args: list[str]) -> None:
    if shutil.which("nmap") is None:
        sys.exit("nmap was not found on PATH. Install it, or use 'reconsage analyze' "
                 "with an existing -oX scan file instead.")

    cmd = ["nmap", "-sV", "-sC", "-oX", out_xml, *extra_args, target]
    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        sys.exit(f"nmap exited with code {result.returncode}")


def _analyze_and_report(xml_path: str, out_path: str | None) -> None:
    hosts = parse_nmap_xml(xml_path)
    if not hosts:
        print("[!] No live hosts with open ports found in this scan.")
        return

    service_rules = load_service_rules()
    pattern_rules = load_patterns()

    for host in hosts:
        analyze_host(host, service_rules)
        correlate_host(host, pattern_rules)

    report = render_markdown(hosts)
    print(report)

    if out_path:
        write_markdown(hosts, out_path)
        print(f"[*] Report written to {out_path}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="reconsage",
        description="Turn nmap scan results into a prioritized, correlated recon report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Run nmap against a target and analyze it")
    scan_p.add_argument("target", help="IP, hostname, or CIDR range to scan")
    scan_p.add_argument("-o", "--output", help="Path to write the Markdown report to")
    scan_p.add_argument(
        "--nmap-args", nargs=argparse.REMAINDER,
        help="Extra arguments passed straight through to nmap",
    )

    analyze_p = sub.add_parser("analyze", help="Analyze an existing nmap XML file")
    analyze_p.add_argument("xml_file", help="Path to an nmap -oX output file")
    analyze_p.add_argument("-o", "--output", help="Path to write the Markdown report to")

    args = parser.parse_args(argv)

    if args.command == "scan":
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        _run_nmap(args.target, xml_path, args.nmap_args or [])
        _analyze_and_report(xml_path, args.output)

    elif args.command == "analyze":
        _analyze_and_report(args.xml_file, args.output)


if __name__ == "__main__":
    main()
