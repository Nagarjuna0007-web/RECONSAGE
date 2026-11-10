"""
Matches parsed Services against the services.yaml knowledge base to
produce per-service Findings (manual checks, CVE hints, ATT&CK IDs).

This is deliberately a *recommendation* engine, not an exploitation
engine: every Finding is something a human still has to go try.
"""
from __future__ import annotations

import os

import yaml

from .models import Finding, Host, Service

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_SERVICES_FILE = os.path.join(_DATA_DIR, "services.yaml")


def load_service_rules(path: str = _SERVICES_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _service_matches_rule(service: Service, rule: dict) -> bool:
    match = rule.get("match", {})

    # service_name may be a single string or a list of acceptable names
    by_name = match.get("service_name")
    names = [by_name] if isinstance(by_name, str) else (by_name or [])
    if names and service.name in names:
        return True

    by_ports = match.get("ports", [])
    if by_ports and service.port in by_ports:
        return True
    return False


def apply_service_rules(service: Service, rules: list[dict]) -> list[Finding]:
    """Return every Finding generated for a single service."""
    findings: list[Finding] = []

    for rule in rules:
        if not _service_matches_rule(service, rule):
            continue

        base_detail = "; ".join(rule.get("checks", []))
        findings.append(
            Finding(
                title=f"{service.port}/{service.protocol} {rule['id']} — recommended checks",
                detail=base_detail,
                attack_technique=rule.get("attack_technique", ""),
                severity=rule.get("severity", "info"),
            )
        )

        banner = service.banner.lower()
        for hint in rule.get("cve_hints", []):
            needle = hint.get("contains", "").lower()
            if needle and needle in banner:
                findings.append(
                    Finding(
                        title=f"{service.port}/{service.protocol} version match: {hint.get('cve', '')}",
                        detail=hint.get("note", ""),
                        cve=hint.get("cve", ""),
                        severity="high",
                    )
                )

    return findings


def analyze_host(host: Host, rules: list[dict] | None = None) -> None:
    """Populate host.findings in place from the service rule set."""
    rules = rules if rules is not None else load_service_rules()
    host.findings = []
    for service in host.services:
        host.findings.extend(apply_service_rules(service, rules))
