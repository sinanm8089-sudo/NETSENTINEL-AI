"""Nmap XML Parser & Observation Normalizer (PRD Module 1)."""
import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ParsedPortObservation:
    port_number: int
    protocol: str  # TCP | UDP
    state: str  # open | closed | filtered | open|filtered
    reason: str
    service_name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ParsedHostObservation:
    ip_address: str
    subnet: str
    status: str  # up | down | unreachable
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    operating_system: str = "Unknown OS"
    os_accuracy: float = 0.0
    ports: List[ParsedPortObservation] = field(default_factory=list)


@dataclass
class ParsedScanResult:
    scanner: str
    args: str
    start_str: str
    hosts: List[ParsedHostObservation] = field(default_factory=list)
    scan_stats: Dict[str, str] = field(default_factory=dict)


def infer_subnet_24(ip_str: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            if ip_obj.is_loopback:
                return "127.0.0.0/8"
            return str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
    except ValueError:
        return "0.0.0.0/0"


def parse_nmap_xml(xml_content: str) -> ParsedScanResult:
    """
    Safely parses Nmap XML output into normalized host and port observations.
    Raises ValueError if XML is malformed.
    """
    if not xml_content or not xml_content.strip():
        raise ValueError("Empty Nmap XML output provided.")

    try:
        root = ET.fromstring(xml_content.strip())
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse Nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError(f"Unexpected root XML element '{root.tag}'; expected 'nmaprun'.")

    result = ParsedScanResult(
        scanner=root.attrib.get("scanner", "nmap"),
        args=root.attrib.get("args", ""),
        start_str=root.attrib.get("startstr", ""),
    )

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        host_state = status_el.attrib.get("state", "up") if status_el is not None else "up"

        ip_addr: Optional[str] = None
        mac_addr: Optional[str] = None
        vendor: Optional[str] = None

        for addr_el in host_el.findall("address"):
            addr_type = addr_el.attrib.get("addrtype", "ipv4")
            if addr_type in ("ipv4", "ipv6"):
                ip_addr = addr_el.attrib.get("addr")
            elif addr_type == "mac":
                mac_addr = addr_el.attrib.get("addr")
                vendor = addr_el.attrib.get("vendor")

        if not ip_addr:
            continue

        hostname: Optional[str] = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.attrib.get("name")

        os_name = "Unknown OS"
        os_acc = 0.0
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch_el = os_el.find("osmatch")
            if osmatch_el is not None:
                os_name = osmatch_el.attrib.get("name", "Unknown OS")
                try:
                    os_acc = float(osmatch_el.attrib.get("accuracy", "0"))
                except ValueError:
                    os_acc = 0.0

        parsed_ports: List[ParsedPortObservation] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                try:
                    port_id = int(port_el.attrib.get("portid", "0"))
                except ValueError:
                    continue
                protocol = port_el.attrib.get("protocol", "tcp").upper()

                state_el = port_el.find("state")
                p_state = state_el.attrib.get("state", "open") if state_el is not None else "open"
                p_reason = state_el.attrib.get("reason", "syn-ack") if state_el is not None else "syn-ack"

                service_el = port_el.find("service")
                svc_name = "unknown"
                product = None
                version = None
                extrainfo = None
                if service_el is not None:
                    svc_name = service_el.attrib.get("name", "unknown")
                    product = service_el.attrib.get("product")
                    version = service_el.attrib.get("version")
                    extrainfo = service_el.attrib.get("extrainfo")

                script_banners = []
                for script_el in port_el.findall("script"):
                    s_id = script_el.attrib.get("id", "")
                    s_out = script_el.attrib.get("output", "")
                    if s_out:
                        script_banners.append(f"[{s_id}] {s_out}")

                banner_parts = [p for p in [product, version, extrainfo] if p]
                if script_banners:
                    banner_parts.extend(script_banners)
                banner = " | ".join(banner_parts) if banner_parts else None

                parsed_ports.append(
                    ParsedPortObservation(
                        port_number=port_id,
                        protocol=protocol,
                        state=p_state,
                        reason=p_reason,
                        service_name=svc_name,
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                        banner=banner,
                    )
                )

        result.hosts.append(
            ParsedHostObservation(
                ip_address=ip_addr,
                subnet=infer_subnet_24(ip_addr),
                status="ACTIVE" if host_state == "up" else "UNREACHABLE",
                hostname=hostname,
                mac_address=mac_addr,
                vendor=vendor,
                operating_system=os_name,
                os_accuracy=os_acc,
                ports=parsed_ports,
            )
        )

    runstats_el = root.find("runstats/finished")
    if runstats_el is not None:
        result.scan_stats["elapsed"] = runstats_el.attrib.get("elapsed", "0")
        result.scan_stats["summary"] = runstats_el.attrib.get("summary", "")

    return result

