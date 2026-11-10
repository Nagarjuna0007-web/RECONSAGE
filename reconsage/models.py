"""
Core data models used across ReconSage.

These are intentionally plain dataclasses -- no behavior baked in --
so parsing, rule-matching, and reporting all stay decoupled and easy
to test independently.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    protocol: str          # tcp/udp
    name: str              # nmap's guessed service name, e.g. "ssh"
    product: str = ""      # e.g. "OpenSSH"
    version: str = ""      # e.g. "7.2p2"
    extra_info: str = ""   # raw nmap "extrainfo" field, sometimes has useful hints

    @property
    def banner(self) -> str:
        """Human-readable one-line banner, e.g. 'OpenSSH 7.2p2'."""
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else self.name


@dataclass
class Finding:
    """One actionable recommendation attached to a service."""
    title: str
    detail: str
    attack_technique: str = ""   # MITRE ATT&CK technique ID, e.g. "T1110"
    cve: str = ""
    severity: str = "info"       # info | low | medium | high


@dataclass
class Host:
    ip: str
    hostname: str = ""
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)       # per-service findings
    pattern_findings: list[Finding] = field(default_factory=list)  # cross-service correlation findings

    def all_findings(self) -> list[Finding]:
        return self.findings + self.pattern_findings
