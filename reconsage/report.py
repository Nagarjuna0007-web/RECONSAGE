"""
Renders analyzed Hosts into a readable Markdown report -- a prioritized
checklist a tester can work through, not an auto-exploitation log.
"""
from __future__ import annotations

from .models import Host

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEVERITY_ICON = {"high": "[!!!]", "medium": "[!!]", "low": "[!]", "info": "[i]"}


def _sorted_findings(host: Host):
    return sorted(host.all_findings(), key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))


def render_markdown(hosts: list[Host]) -> str:
    lines: list[str] = []
    lines.append("# ReconSage Report\n")
    lines.append(
        "> Recon-to-recommendation only. Every item below is a lead to "
        "investigate manually -- nothing here was auto-exploited.\n"
    )

    for host in hosts:
        title = host.ip + (f" ({host.hostname})" if host.hostname else "")
        lines.append(f"\n## {title}\n")

        if not host.services:
            lines.append("_No open ports found._\n")
            continue

        lines.append("### Open services\n")
        lines.append("| Port | Proto | Service | Banner |")
        lines.append("|---|---|---|---|")
        for s in sorted(host.services, key=lambda s: s.port):
            lines.append(f"| {s.port} | {s.protocol} | {s.name} | {s.banner or '-'} |")

        findings = _sorted_findings(host)
        if findings:
            lines.append("\n### Prioritized findings\n")
            for f in findings:
                icon = _SEVERITY_ICON.get(f.severity, "[i]")
                tag = f" `{f.attack_technique}`" if f.attack_technique else ""
                cve = f" **{f.cve}**" if f.cve else ""
                lines.append(f"- {icon}{cve}{tag} **{f.title}**")
                if f.detail:
                    lines.append(f"  - {f.detail}")
        else:
            lines.append("\n_No automated findings -- time for manual review._\n")

    return "\n".join(lines) + "\n"


def write_markdown(hosts: list[Host], out_path: str) -> None:
    content = render_markdown(hosts)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
