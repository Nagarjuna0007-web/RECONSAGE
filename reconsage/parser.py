"""
Parses nmap's XML output (-oX) into ReconSage's Host/Service models.

Why XML and not text output: nmap's XML is structured and stable across
versions, so we don't end up regex-scraping human-readable text that
changes between nmap releases.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .models import Host, Service


def parse_nmap_xml(path: str) -> list[Host]:
    tree = ET.parse(path)
    root = tree.getroot()

    hosts: list[Host] = []

    for host_el in root.findall("host"):
        # Skip hosts nmap marked down/filtered entirely
        status = host_el.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
                break

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        host = Host(ip=ip, hostname=hostname)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is not None and state_el.get("state") != "open":
                    continue  # only care about open ports for recon

                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                service_name = ""
                product = ""
                version = ""
                extra_info = ""

                service_el = port_el.find("service")
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    extra_info = service_el.get("extrainfo", "")

                host.services.append(
                    Service(
                        port=port_num,
                        protocol=protocol,
                        name=service_name,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                    )
                )

        hosts.append(host)

    return hosts
