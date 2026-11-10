import os

from reconsage.correlate import correlate_host, load_patterns
from reconsage.parser import parse_nmap_xml
from reconsage.rules_engine import analyze_host, load_service_rules

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_data", "sample_scan.xml")


def _analyzed_hosts():
    hosts = parse_nmap_xml(SAMPLE)
    rules = load_service_rules()
    patterns = load_patterns()
    for h in hosts:
        analyze_host(h, rules)
        correlate_host(h, patterns)
    return hosts


def test_parses_both_hosts():
    hosts = parse_nmap_xml(SAMPLE)
    assert len(hosts) == 2
    ips = {h.ip for h in hosts}
    assert "192.168.56.105" in ips
    assert "192.168.56.110" in ips


def test_vsftpd_backdoor_cve_detected():
    hosts = _analyzed_hosts()
    target = next(h for h in hosts if h.ip == "192.168.56.105")
    cves = {f.cve for f in target.findings if f.cve}
    assert "CVE-2011-2523" in cves


def test_smb_finding_not_duplicated():
    hosts = _analyzed_hosts()
    target = next(h for h in hosts if h.ip == "192.168.56.105")
    smb_445_checks = [
        f for f in target.findings
        if f.title.startswith("445/tcp smb — recommended checks")
    ]
    assert len(smb_445_checks) == 1


def test_domain_controller_pattern_fires():
    hosts = _analyzed_hosts()
    dc = next(h for h in hosts if h.ip == "192.168.56.110")
    titles = {f.title for f in dc.pattern_findings}
    assert "Likely Active Directory Domain Controller" in titles


def test_non_dc_host_has_no_dc_finding():
    hosts = _analyzed_hosts()
    msf = next(h for h in hosts if h.ip == "192.168.56.105")
    titles = {f.title for f in msf.pattern_findings}
    assert "Likely Active Directory Domain Controller" not in titles
