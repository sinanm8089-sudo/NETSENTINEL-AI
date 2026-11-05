"""Port-to-Application Intelligence Engine (PRD Section 3.2 & Module 2)."""
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class PortKnowledgeEntry:
    conventional_service: str
    typical_purpose: str
    exposure_class: str
    base_exposure_weight: float
    default_recommendation: str


# Comprehensive Enterprise Port Knowledge Base
PORT_KNOWLEDGE_BASE: Dict[Tuple[int, str], PortKnowledgeEntry] = {
    (21, "TCP"): PortKnowledgeEntry(
        conventional_service="ftp",
        typical_purpose="Legacy cleartext file transfer protocol",
        exposure_class="UNENCRYPTED_LEGACY",
        base_exposure_weight=30.0,
        default_recommendation="Decommission cleartext FTP; migrate file transfers to SFTP (SSH) or HTTPS.",
    ),
    (22, "TCP"): PortKnowledgeEntry(
        conventional_service="ssh",
        typical_purpose="Remote system administration & secure file transfer",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=15.0,
        default_recommendation="Restrict SSH access to approved jump hosts/management subnets and enforce key-based authentication.",
    ),
    (23, "TCP"): PortKnowledgeEntry(
        conventional_service="telnet",
        typical_purpose="Unencrypted legacy remote terminal access",
        exposure_class="CRITICAL_UNENCRYPTED_ADMIN",
        base_exposure_weight=35.0,
        default_recommendation="Disable Telnet immediately and replace with SSH using strong key cryptography.",
    ),
    (25, "TCP"): PortKnowledgeEntry(
        conventional_service="smtp",
        typical_purpose="Mail transfer and relay service",
        exposure_class="MESSAGING_INFRASTRUCTURE",
        base_exposure_weight=14.0,
        default_recommendation="Verify open relay prevention, enforce STARTTLS, and restrict outbound/inbound relay scope.",
    ),
    (53, "UDP"): PortKnowledgeEntry(
        conventional_service="domain",
        typical_purpose="DNS name resolution",
        exposure_class="CORE_NETWORK_INFRASTRUCTURE",
        base_exposure_weight=10.0,
        default_recommendation="Disable open recursion for untrusted networks and enforce DNS response rate limiting (RRL).",
    ),
    (53, "TCP"): PortKnowledgeEntry(
        conventional_service="domain",
        typical_purpose="DNS zone transfers and large queries",
        exposure_class="CORE_NETWORK_INFRASTRUCTURE",
        base_exposure_weight=12.0,
        default_recommendation="Restrict AXFR/IXFR zone transfers to authorized secondary name servers using TSIG.",
    ),
    (80, "TCP"): PortKnowledgeEntry(
        conventional_service="http",
        typical_purpose="Unencrypted web application or HTTP redirect endpoint",
        exposure_class="WEB_APPLICATION",
        base_exposure_weight=12.0,
        default_recommendation="Enforce 301 redirect to HTTPS (443/TCP), configure HSTS headers, and verify WAF coverage.",
    ),
    (88, "TCP"): PortKnowledgeEntry(
        conventional_service="kerberos-sec",
        typical_purpose="Active Directory Kerberos authentication service",
        exposure_class="IDENTITY_INFRASTRUCTURE",
        base_exposure_weight=18.0,
        default_recommendation="Ensure only domain controllers expose Kerberos and monitor for AS-REP roasting/ brute-force anomalies.",
    ),
    (111, "TCP"): PortKnowledgeEntry(
        conventional_service="rpcbind",
        typical_purpose="ONC RPC portmapper service",
        exposure_class="INTERNAL_INFRASTRUCTURE",
        base_exposure_weight=22.0,
        default_recommendation="Block rpcbind at subnet boundaries unless required for authorized NFSv3 clusters.",
    ),
    (123, "UDP"): PortKnowledgeEntry(
        conventional_service="ntp",
        typical_purpose="Network Time Protocol synchronization",
        exposure_class="CORE_NETWORK_INFRASTRUCTURE",
        base_exposure_weight=8.0,
        default_recommendation="Disable ntpdc monlist commands and restrict time queries to internal network segments.",
    ),
    (135, "TCP"): PortKnowledgeEntry(
        conventional_service="msrpc",
        typical_purpose="Microsoft RPC Endpoint Mapper",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=22.0,
        default_recommendation="Restrict MSRPC across VLAN boundaries via host and perimeter firewall rules.",
    ),
    (139, "TCP"): PortKnowledgeEntry(
        conventional_service="netbios-ssn",
        typical_purpose="Legacy NetBIOS Session Service",
        exposure_class="FILE_SHARING_LEGACY",
        base_exposure_weight=25.0,
        default_recommendation="Disable NetBIOS over TCP/IP where modern SMBv3 is used and segment workstation traffic.",
    ),
    (161, "UDP"): PortKnowledgeEntry(
        conventional_service="snmp",
        typical_purpose="Simple Network Management Protocol monitoring",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=26.0,
        default_recommendation="Upgrade to SNMPv3 with authPriv encryption and rotate any default community strings.",
    ),
    (389, "TCP"): PortKnowledgeEntry(
        conventional_service="ldap",
        typical_purpose="Directory Services lookup and authentication",
        exposure_class="IDENTITY_INFRASTRUCTURE",
        base_exposure_weight=20.0,
        default_recommendation="Enforce LDAP Signing and Channel Binding; migrate clients to LDAPS (636/TCP).",
    ),
    (443, "TCP"): PortKnowledgeEntry(
        conventional_service="https",
        typical_purpose="TLS-encrypted web application or API gateway",
        exposure_class="WEB_APPLICATION",
        base_exposure_weight=6.0,
        default_recommendation="Verify TLS 1.2/1.3 cipher suites, certificate validity, and application authentication controls.",
    ),
    (445, "TCP"): PortKnowledgeEntry(
        conventional_service="microsoft-ds",
        typical_purpose="SMB file sharing and Windows remote IPC administration",
        exposure_class="HIGH_RISK_LATERAL_MOVEMENT",
        base_exposure_weight=28.0,
        default_recommendation="Enforce SMB signing, disable SMBv1, and block port 445 between non-file-server segments.",
    ),
    (1433, "TCP"): PortKnowledgeEntry(
        conventional_service="ms-sql-s",
        typical_purpose="Microsoft SQL Server database connectivity",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=28.0,
        default_recommendation="Restrict MSSQL access strictly to authorized application tier IPs and enforce TLS encryption.",
    ),
    (1521, "TCP"): PortKnowledgeEntry(
        conventional_service="oracle",
        typical_purpose="Oracle TNS database listener",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=28.0,
        default_recommendation="Isolate Oracle TNS listener inside the database VLAN and require strong mutual authentication.",
    ),
    (2375, "TCP"): PortKnowledgeEntry(
        conventional_service="docker",
        typical_purpose="Unencrypted Docker Engine remote management API",
        exposure_class="CRITICAL_UNENCRYPTED_ADMIN",
        base_exposure_weight=35.0,
        default_recommendation="Immediately bind Docker daemon to unix:///var/run/docker.sock or enforce mutual TLS on 2376/TCP.",
    ),
    (3306, "TCP"): PortKnowledgeEntry(
        conventional_service="mysql",
        typical_purpose="MySQL / MariaDB relational database connectivity",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=28.0,
        default_recommendation="Bind MySQL to private application interfaces only, disallow remote root login, and enforce TLS.",
    ),
    (3389, "TCP"): PortKnowledgeEntry(
        conventional_service="ms-wbt-server",
        typical_purpose="Windows Remote Desktop Protocol (RDP)",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=30.0,
        default_recommendation="Enforce Network Level Authentication (NLA), MFA via RD Gateway, and restrict access to jump hosts.",
    ),
    (5432, "TCP"): PortKnowledgeEntry(
        conventional_service="postgresql",
        typical_purpose="PostgreSQL relational database connectivity",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=28.0,
        default_recommendation="Harden pg_hba.conf to permit only known application tier IPs with scram-sha-256 over SSL.",
    ),
    (5900, "TCP"): PortKnowledgeEntry(
        conventional_service="vnc",
        typical_purpose="Virtual Network Computing graphical remote desktop",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=32.0,
        default_recommendation="Tunnel VNC exclusively over SSH or VPN and disable direct network exposure.",
    ),
    (5985, "TCP"): PortKnowledgeEntry(
        conventional_service="wsman",
        typical_purpose="Windows Remote Management (WinRM HTTP)",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=24.0,
        default_recommendation="Migrate WinRM to HTTPS (5986/TCP) and restrict TrustedHosts / firewall policies to bastion hosts.",
    ),
    (6379, "TCP"): PortKnowledgeEntry(
        conventional_service="redis",
        typical_purpose="Redis in-memory key-value datastore and cache",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=32.0,
        default_recommendation="Enable Redis ACLs/requirepass, bind to private interfaces, and disable dangerous commands (FLUSHALL, CONFIG).",
    ),
    (6443, "TCP"): PortKnowledgeEntry(
        conventional_service="kubernetes-api",
        typical_purpose="Kubernetes control plane API server",
        exposure_class="REMOTE_ADMINISTRATION",
        base_exposure_weight=22.0,
        default_recommendation="Disable anonymous API auth, enforce RBAC, and restrict control plane access to management CIDRs.",
    ),
    (8080, "TCP"): PortKnowledgeEntry(
        conventional_service="http-proxy",
        typical_purpose="Alternate HTTP application server, reverse proxy, or management console",
        exposure_class="WEB_APPLICATION",
        base_exposure_weight=16.0,
        default_recommendation="Place application behind a TLS reverse proxy and verify administrative endpoints are not exposed.",
    ),
    (8443, "TCP"): PortKnowledgeEntry(
        conventional_service="https-alt",
        typical_purpose="Alternate HTTPS web service or appliance management console",
        exposure_class="WEB_APPLICATION",
        base_exposure_weight=12.0,
        default_recommendation="Audit whether port 8443 hosts an administrative UI and enforce MFA and IP allowlisting.",
    ),
    (9090, "TCP"): PortKnowledgeEntry(
        conventional_service="prometheus",
        typical_purpose="Prometheus metrics endpoint or Cockpit Linux web console",
        exposure_class="TELEMETRY_OR_ADMIN",
        base_exposure_weight=20.0,
        default_recommendation="Require authentication in front of metrics/management consoles and restrict to monitoring VLAN.",
    ),
    (9200, "TCP"): PortKnowledgeEntry(
        conventional_service="elasticsearch",
        typical_purpose="Elasticsearch REST search and analytics API",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=30.0,
        default_recommendation="Enable Elasticsearch X-Pack security/TLS and block direct external subnet access to 9200/9300.",
    ),
    (27017, "TCP"): PortKnowledgeEntry(
        conventional_service="mongodb",
        typical_purpose="MongoDB NoSQL document database connectivity",
        exposure_class="DATABASE_EXPOSURE",
        base_exposure_weight=30.0,
        default_recommendation="Enforce SCRAM authentication, TLS transport, and strict network segmentation for MongoDB nodes.",
    ),
}

# Normalization aliases so equivalent Nmap service names don't trigger false mismatches
SERVICE_EQUIVALENTS = {
    "http": {"http", "http-alt", "http-proxy", "nginx", "apache", "werkzeug", "uvicorn"},
    "https": {"https", "ssl/http", "ssl/https", "https-alt", "tls"},
    "ssh": {"ssh", "openssh"},
    "domain": {"domain", "dns", "named", "bind", "dnsmasq"},
    "ms-wbt-server": {"ms-wbt-server", "rdp", "ssl/ms-wbt-server"},
    "microsoft-ds": {"microsoft-ds", "smb", "netbios-ssn", "samba"},
    "mysql": {"mysql", "mariadb"},
    "postgresql": {"postgresql", "postgres"},
    "redis": {"redis", "redis-server"},
    "mongodb": {"mongodb", "mongod"},
    "elasticsearch": {"elasticsearch", "wap-wsp"},
}


def are_services_equivalent(conventional: str, detected: str) -> bool:
    c = (conventional or "unknown").lower().strip()
    d = (detected or "unknown").lower().strip()
    if c == "unknown" or d == "unknown" or c == d:
        return True
    for _, group in SERVICE_EQUIVALENTS.items():
        if c in group and d in group:
            return True
    return False


@dataclass
class EnrichedPortIntelligence:
    conventional_service: str
    detected_service: str
    service_mismatch: bool
    typical_purpose: str
    exposure_class: str
    base_exposure_weight: float
    recommended_action: str


def enrich_port_observation(
    port_number: int,
    protocol: str,
    detected_service: str,
    product: Optional[str] = None,
    version: Optional[str] = None,
) -> EnrichedPortIntelligence:
    """
    Resolves port-to-application intelligence while strictly distinguishing
    conventional port expectation from Nmap's actual detected service probe.
    """
    proto = protocol.upper()
    kb_entry = PORT_KNOWLEDGE_BASE.get((port_number, proto))
    detected_clean = (detected_service or "unknown").lower().strip()

    if kb_entry is None:
        # Infer from detected service name when running on an ephemeral or custom port
        inferred_purpose = f"Custom or dynamic port running detected service '{detected_clean}'"
        exposure_class = "CUSTOM_SERVICE_PORT"
        weight = 14.0
        rec = f"Verify authorization for service '{detected_clean}' on non-standard port {port_number}/{proto}."
        if detected_clean in ("ssh", "rdp", "ms-wbt-server", "vnc", "telnet"):
            exposure_class = "NON_STANDARD_ADMIN_PORT"
            weight = 24.0
            rec = (
                f"Administrative service '{detected_clean}' detected on non-standard port {port_number}/{proto}. "
                "Security through port obscurity is insufficient; enforce strict ACLs and MFA."
            )
        elif detected_clean in ("mysql", "postgresql", "redis", "mongodb"):
            exposure_class = "DATABASE_EXPOSURE"
            weight = 28.0
            rec = f"Database service '{detected_clean}' detected on custom port {port_number}/{proto}; restrict to application tier."
        return EnrichedPortIntelligence(
            conventional_service="unassigned-or-custom",
            detected_service=detected_clean,
            service_mismatch=False,
            typical_purpose=inferred_purpose,
            exposure_class=exposure_class,
            base_exposure_weight=weight,
            recommended_action=rec,
        )

    mismatch = not are_services_equivalent(kb_entry.conventional_service, detected_clean)
    purpose = kb_entry.typical_purpose
    rec = kb_entry.default_recommendation
    exposure_class = kb_entry.exposure_class
    weight = kb_entry.base_exposure_weight

    if mismatch:
        purpose = (
            f"PORT-SERVICE MISMATCH: Port {port_number}/{proto} conventionally hosts '{kb_entry.conventional_service}' "
            f"({kb_entry.typical_purpose}), but Nmap probe detected '{detected_clean}'"
            + (f" ({product} {version})" if product else "")
            + "."
        )
        rec = (
            f"Investigate why '{detected_clean}' is bound to conventional '{kb_entry.conventional_service}' port "
            f"{port_number}/{proto}. Confirm whether this is an intentional port override or unauthorized tunneling."
        )
        exposure_class = "SERVICE_PORT_MISMATCH"
        weight = max(weight, 25.0)

    return EnrichedPortIntelligence(
        conventional_service=kb_entry.conventional_service,
        detected_service=detected_clean,
        service_mismatch=mismatch,
        typical_purpose=purpose,
        exposure_class=exposure_class,
        base_exposure_weight=weight,
        recommended_action=rec,
    )

