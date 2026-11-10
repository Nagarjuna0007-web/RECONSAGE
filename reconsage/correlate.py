"""
Cross-service pattern correlation -- the "read the whole host like an
operator" layer. Individual open ports are interesting; combinations of
open ports are often MORE interesting (e.g. Kerberos+LDAP+SMB together
means "this is a Domain Controller", not three unrelated findings).
"""
from __future__ import annotations

import os

import yaml

from .models import Finding, Host

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_PATTERNS_FILE = os.path.join(_DATA_DIR, "patterns.yaml")


def load_patterns(path: str = _PATTERNS_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _pattern_matches(service_names: set[str], match: dict) -> bool:
    if "all_of" in match:
        return set(match["all_of"]).issubset(service_names)

    if "any_of" in match:
        return any(name in service_names for name in match["any_of"])

    if "any_of_groups" in match:
        # True if ALL services in ANY ONE of the listed groups are present
        for group in match["any_of_groups"]:
            if set(group).issubset(service_names):
                return True
        return False

    if "any_n_of" in match:
        n = match["any_n_of"].get("n", 1)
        candidates = match["any_n_of"].get("services", [])
        hits = sum(1 for name in candidates if name in service_names)
        return hits >= n

    return False


def correlate_host(host: Host, patterns: list[dict] | None = None) -> None:
    """Populate host.pattern_findings in place from the pattern rule set."""
    patterns = patterns if patterns is not None else load_patterns()
    service_names = {s.name for s in host.services if s.name}

    host.pattern_findings = []
    for pattern in patterns:
        if _pattern_matches(service_names, pattern.get("match", {})):
            host.pattern_findings.append(
                Finding(
                    title=pattern["title"],
                    detail=pattern.get("detail", "").strip(),
                    attack_technique=pattern.get("attack_technique", ""),
                    severity=pattern.get("severity", "info"),
                )
            )
