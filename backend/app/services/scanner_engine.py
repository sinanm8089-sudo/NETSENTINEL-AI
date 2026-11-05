"""Network Discovery & Autonomous Intelligence Loop Orchestrator (PRD Module 1 & Section 9)."""
from datetime import datetime, timezone
import ipaddress
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from app.config import settings
from app.core.cidr_validator import get_active_cidr_list, validate_target_authorization
from app.core.websocket_hub import ws_hub
from app.models.entities import (
    Asset,
    Finding,
    NetworkChange,
    Port,
    ScanJob,
)
from app.services.ai_adapter import generate_finding_explanation
from app.services.alert_service import trigger_deduplicated_alert
from app.services.change_detector import (
    compute_asset_volatility_predictions,
    detect_and_record_network_changes,
)
from app.services.exposure_investigator import create_autonomous_investigation
from app.services.nmap_parser import (
    ParsedHostObservation,
    infer_subnet_24,
    parse_nmap_xml,
)
from app.services.port_intelligence import enrich_port_observation
from app.services.risk_engine import classify_risk_score, compute_port_risk_score
from app.services.topology_builder import record_topology_snapshot


# Pre-configured Enterprise Metadata for Realistic Port-to-Business-Service Mapping (Innovation 3)
KNOWN_ENTERPRISE_ASSET_CONTEXT: Dict[str, Dict[str, Any]] = {
    "192.168.56.1": {
        "criticality": "CRITICAL",
        "business_service": "Core Subnet Perimeter Gateway",
        "owner_team": "Network Engineering",
        "is_gateway_verified": True,
        "gateway_evidence": "Verified via OS routing table default route (0.0.0.0/0 -> 192.168.56.1)",
    },
    "192.168.56.10": {
        "criticality": "HIGH",
        "business_service": "Customer Identity & Portal API",
        "owner_team": "Platform Engineering",
        "is_gateway_verified": False,
        "gateway_evidence": None,
    },
    "192.168.56.20": {
        "criticality": "CRITICAL",
        "business_service": "Primary Financial Ledger Database",
        "owner_team": "Database Reliability Engineering",
        "is_gateway_verified": False,
        "gateway_evidence": None,
    },
    "192.168.56.30": {
        "criticality": "HIGH",
        "business_service": "Enterprise Active Directory & DNS",
        "owner_team": "Identity & Access Management",
        "is_gateway_verified": False,
        "gateway_evidence": None,
    },
    "192.168.56.45": {
        "criticality": "MEDIUM",
        "business_service": "Shadow DevOps Build Runner",
        "owner_team": "Unassigned / Shadow IT",
        "is_gateway_verified": False,
        "gateway_evidence": None,
    },
    "10.20.30.15": {
        "criticality": "HIGH",
        "business_service": "Real-Time Telemetry & Cache Cluster",
        "owner_team": "Data Platform Team",
        "is_gateway_verified": False,
        "gateway_evidence": None,
    },
}


def build_nmap_command_preview(target: str, scan_profile: str) -> str:
    p = (scan_profile or "STANDARD_TCP_INTEL").upper()
    if p == "FULL_TCP":
        return f"nmap -sS -p 1-65535 -sV -O --max-rate {settings.SCAN_MAX_RATE_PPS} -oX - {target}"
    if p == "FULL_UDP":
        return f"nmap -sU -p 1-65535 -sV --max-rate {settings.SCAN_MAX_RATE_PPS} -oX - {target}"
    if p == "CONNECT_TCP":
        return f"nmap -sT -p 1-65535 -sV -oX - {target}"
    if p == "DISCOVERY_ONLY":
        return f"nmap -sn -PE -oX - {target}"
    return f"nmap -sT -sV -O --top-ports 1000 --max-rate {settings.SCAN_MAX_RATE_PPS} -oX - {target}"


def generate_simulated_nmap_xml(
    target: str,
    scan_profile: str,
    scenario: str = "ENTERPRISE_DRIFT",
) -> str:
    """
    Generates authentic Nmap XML output for controlled local/lab testing
    without requiring root raw sockets or external target hosts.
    """
    scen = (scenario or "ENTERPRISE_DRIFT").upper()
    if "BASELINE" in (scan_profile or "").upper():
        scen = "BASELINE"

    all_hosts_xml: List[str] = []

    def _should_include(ip_str: str) -> bool:
        try:
            if "/" in target:
                net = ipaddress.ip_network(target, strict=False)
                return ipaddress.ip_address(ip_str) in net
            return ip_str == target
        except ValueError:
            return False

    # Host 1: 192.168.56.1 — Verified Subnet Gateway
    if _should_include("192.168.56.1"):
        all_hosts_xml.append(
            """
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.56.1" addrtype="ipv4"/>
    <address addr="00:1A:2B:3C:4D:01" addrtype="mac" vendor="Cisco Systems"/>
    <hostnames><hostname name="gw-core-56.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.3p2" extrainfo="Cisco IOS-XE Mgmt"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" extrainfo="TLS 1.3 Gateway Admin"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain" product="ISC BIND" version="9.18.19"/>
      </port>
    </ports>
    <os><osmatch name="Cisco IOS XE 17.9" accuracy="98"/></os>
  </host>"""
        )

    # Host 2: 192.168.56.10 — Linux Application Server (Drift: MySQL 3306 & Mismatched SSH on 8080 appear in DRIFT!)
    if _should_include("192.168.56.10"):
        drift_ports = ""
        ssh_ver = "8.9p1 Ubuntu-3ubuntu0.6"
        if scen != "BASELINE":
            ssh_ver = "7.6p1 Ubuntu-4ubuntu0.7"  # Version drift!
            drift_ports = """
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="5.7.42-log" extrainfo="unauthorized remote bind 0.0.0.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Non-standard SSH bound to HTTP proxy port"/>
      </port>"""
        all_hosts_xml.append(
            f"""
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.10" addrtype="ipv4"/>
    <address addr="08:00:27:AA:10:01" addrtype="mac" vendor="PCS Systemtechnik / VirtualBox"/>
    <hostnames><hostname name="app-portal-01.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="{ssh_ver}"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0" extrainfo="TLSv1.3"/>
      </port>{drift_ports}
    </ports>
    <os><osmatch name="Linux 5.15 - 6.2 (Ubuntu 22.04 LTS)" accuracy="96"/></os>
  </host>"""
        )

    # Host 3: 192.168.56.20 — Database Server
    if _should_include("192.168.56.20"):
        extra_db_ports = ""
        if scen != "BASELINE":
            extra_db_ports = """
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack"/>
        <service name="redis" product="Redis key-value store" version="5.0.14" extrainfo="noauth cache interface"/>
      </port>"""
        all_hosts_xml.append(
            f"""
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.20" addrtype="ipv4"/>
    <address addr="08:00:27:BB:20:02" addrtype="mac" vendor="PCS Systemtechnik / VirtualBox"/>
    <hostnames><hostname name="db-ledger-primary.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.2p1 Debian"/>
      </port>
      <port protocol="tcp" portid="5432">
        <state state="open" reason="syn-ack"/>
        <service name="postgresql" product="PostgreSQL DB" version="15.4" extrainfo="SSL enabled"/>
      </port>{extra_db_ports}
    </ports>
    <os><osmatch name="Linux 6.1 (Debian 12 Bookworm)" accuracy="97"/></os>
  </host>"""
        )

    # Host 4: 192.168.56.30 — Windows Enterprise Directory Server
    if _should_include("192.168.56.30"):
        rdp_state = "filtered" if scen == "BASELINE" else "open"
        all_hosts_xml.append(
            f"""
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.30" addrtype="ipv4"/>
    <address addr="00:50:56:C0:00:30" addrtype="mac" vendor="VMware"/>
    <hostnames><hostname name="win-dc01.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="88">
        <state state="open" reason="syn-ack"/>
        <service name="kerberos-sec" product="Microsoft Windows Kerberos" version="2022"/>
      </port>
      <port protocol="tcp" portid="389">
        <state state="open" reason="syn-ack"/>
        <service name="ldap" product="Microsoft Windows Active Directory LDAP" version="2022"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Windows Server 2022 microsoft-ds" version="SMBv3"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="{rdp_state}" reason="syn-ack"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" version="10.0.20348"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain" product="Microsoft DNS" version="10.0.20348"/>
      </port>
    </ports>
    <os><osmatch name="Microsoft Windows Server 2022" accuracy="95"/></os>
  </host>"""
        )

    # Host 5: 192.168.56.45 — Newly Discovered Shadow DevOps Runner (Only appears in DRIFT!)
    if scen != "BASELINE" and _should_include("192.168.56.45"):
        all_hosts_xml.append(
            """
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.45" addrtype="ipv4"/>
    <address addr="02:42:AC:11:00:45" addrtype="mac" vendor="Docker Container Interface"/>
    <hostnames><hostname name="shadow-ci-runner.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.0p1"/>
      </port>
      <port protocol="tcp" portid="2375">
        <state state="open" reason="syn-ack"/>
        <service name="docker" product="Docker Engine API" version="24.0.7" extrainfo="Unencrypted TCP socket"/>
      </port>
      <port protocol="udp" portid="161">
        <state state="open|filtered" reason="no-response"/>
        <service name="snmp" product="Net-SNMP" version="v2c"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.15 (Alpine Container Host)" accuracy="92"/></os>
  </host>"""
        )

    # Host 6: 10.20.30.15 — Data Tier Analytics Node
    if _should_include("10.20.30.15"):
        all_hosts_xml.append(
            """
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.20.30.15" addrtype="ipv4"/>
    <address addr="00:16:3E:20:30:15" addrtype="mac" vendor="Xen Virtual"/>
    <hostnames><hostname name="elastic-telemetry-01.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="9200">
        <state state="open" reason="syn-ack"/>
        <service name="elasticsearch" product="Elasticsearch REST API" version="8.11.1"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.19 (Ubuntu)" accuracy="94"/></os>
  </host>"""
        )

    # Fallback if user scans a custom authorized IP inside the subnet (e.g., 192.168.56.99)
    if not all_hosts_xml and "/" not in target:
        all_hosts_xml.append(
            f"""
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="{target}" addrtype="ipv4"/>
    <hostnames><hostname name="host-{target.replace('.', '-')}.netsentinel.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.3p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25.3"/>
      </port>
    </ports>
    <os><osmatch name="Linux 6.1 Enterprise Node" accuracy="93"/></os>
  </host>"""
        )

    hosts_joined = "\n".join(all_hosts_xml)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="{build_nmap_command_preview(target, scan_profile)}" start="1730851200" startstr="Fri Nov 06 00:45:00 2026" version="7.94" xmloutputversion="1.05">
{hosts_joined}
  <runstats>
    <finished time="1730851204" timestr="Fri Nov 06 00:45:04 2026" elapsed="3.82" summary="Nmap done; {len(all_hosts_xml)} IP addresses scanned in 3.82 seconds" exit="success"/>
  </runstats>
</nmaprun>"""


def _execute_nmap_or_simulator(
    target: str,
    scan_profile: str,
    simulation_scenario: str = "ENTERPRISE_DRIFT",
) -> Tuple[str, str]:
    """
    Executes real Nmap binary when configured & available; otherwise runs the deterministic Safe Lab Simulator.
    Returns: (xml_output, execution_mode)
    """
    nmap_bin = shutil.which("nmap")
    use_real = settings.PREFER_REAL_NMAP and nmap_bin is not None and not scan_profile.startswith("LAB_SIMULATION")

    if use_real and nmap_bin:
        cmd = [nmap_bin, "-sT", "-sV", "--top-ports", "100", "--host-timeout", f"{settings.SCAN_HOST_TIMEOUT_SECONDS}s", "-oX", "-", target]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.SCAN_HOST_TIMEOUT_SECONDS + 15,
                check=False,
            )
            if proc.returncode == 0 and "<nmaprun" in proc.stdout:
                return proc.stdout, "REAL_NMAP"
        except Exception:
            pass

    return generate_simulated_nmap_xml(target, scan_profile, simulation_scenario), "SAFE_SIMULATION"


def execute_authorized_scan(
    db: Session,
    target: str,
    scan_profile: str = "STANDARD_TCP_INTEL",
    initiated_by: str = "sinan.mohammed",
    simulation_scenario: str = "ENTERPRISE_DRIFT",
) -> ScanJob:
    """
    Implements the complete 16-step Autonomous Monitoring & Intelligence Loop (PRD Section 9):
    Discover -> Identify -> Understand -> Analyze -> Prioritize -> Monitor -> Report
    """
    # Step 1 & 2: Load approved scan targets & validate CIDR authorization
    active_cidrs = get_active_cidr_list(db)
    is_auth, normalized_target, auth_reason = validate_target_authorization(target, active_cidrs)
    if not is_auth:
        raise PermissionError(auth_reason)

    # Check concurrency limits (PRD Section 11)
    running_count = db.query(ScanJob).filter(ScanJob.status == "RUNNING").count()
    if running_count >= settings.MAX_CONCURRENT_SCANS:
        raise RuntimeError(f"Maximum concurrent scan limit ({settings.MAX_CONCURRENT_SCANS}) reached.")

    # Step 4: Create scan job
    cmd_preview = build_nmap_command_preview(normalized_target, scan_profile)
    scan_job = ScanJob(
        target=normalized_target,
        scan_profile=scan_profile,
        nmap_command=cmd_preview,
        execution_mode="SAFE_SIMULATION",
        status="RUNNING",
        progress_pct=15,
        initiated_by=initiated_by,
        start_time=datetime.now(timezone.utc),
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    ws_hub.publish_event_sync(
        "scan.started",
        {
            "scan_id": scan_job.scan_id,
            "target": normalized_target,
            "scan_profile": scan_profile,
            "initiated_by": initiated_by,
        },
    )

    try:
        # Capture previous state of assets in scope for Step 10 Change Detection
        all_existing_assets = db.query(Asset).all()
        previous_assets_in_scope: Dict[str, Asset] = {}
        previous_ports_by_ip: Dict[str, Dict[Tuple[int, str], Dict[str, Any]]] = {}

        for a in all_existing_assets:
            in_scope, _, _ = validate_target_authorization(a.ip_address, [normalized_target])
            if in_scope:
                previous_assets_in_scope[a.ip_address] = a
                previous_ports_by_ip[a.ip_address] = {
                    (p.port_number, p.protocol.upper()): {
                        "state": p.state,
                        "detected_service": p.detected_service,
                        "product": p.product,
                        "version": p.version,
                    }
                    for p in a.ports
                }

        # Step 5, 6, 7: Run discovery & collect Nmap XML
        raw_xml, exec_mode = _execute_nmap_or_simulator(
            normalized_target, scan_profile, simulation_scenario
        )
        scan_job.raw_xml = raw_xml
        scan_job.execution_mode = exec_mode
        scan_job.progress_pct = 55
        db.commit()

        # Step 8: Parse and normalize observations
        parsed = parse_nmap_xml(raw_xml)

        # Step 10: Compare against previous observations (Autonomous Change Detection)
        changes, newly_opened_by_ip, version_changed_by_ip = detect_and_record_network_changes(
            db=db,
            scan_id=scan_job.scan_id,
            scan_profile=scan_profile,
            previous_assets=previous_assets_in_scope,
            previous_ports_by_ip=previous_ports_by_ip,
            observed_hosts=parsed.hosts,
        )

        # Step 9, 11, 12: Update Asset & Port Inventory, Run Statistical Risk Analysis, Generate Findings & Investigations
        new_findings_count = 0
        total_open_ports = 0

        for host_obs in parsed.hosts:
            asset = db.query(Asset).filter(Asset.ip_address == host_obs.ip_address).first()
            is_brand_new_asset = asset is None

            enterprise_ctx = KNOWN_ENTERPRISE_ASSET_CONTEXT.get(host_obs.ip_address, {})

            if asset is None:
                asset = Asset(
                    ip_address=host_obs.ip_address,
                    hostname=host_obs.hostname,
                    mac_address=host_obs.mac_address,
                    vendor=host_obs.vendor,
                    operating_system=host_obs.operating_system,
                    os_accuracy=host_obs.os_accuracy,
                    subnet=host_obs.subnet or infer_subnet_24(host_obs.ip_address),
                    asset_status=host_obs.status,
                    criticality=enterprise_ctx.get("criticality", "MEDIUM"),
                    business_service=enterprise_ctx.get("business_service", "Discovered Enterprise Host"),
                    owner_team=enterprise_ctx.get("owner_team", "IT Infrastructure"),
                    is_gateway_verified=enterprise_ctx.get("is_gateway_verified", False),
                    gateway_evidence=enterprise_ctx.get("gateway_evidence"),
                )
                db.add(asset)
                db.flush()

                # Record NEW_DEVICE change if baseline already existed
                if previous_assets_in_scope:
                    new_dev_chg = NetworkChange(
                        scan_id=scan_job.scan_id,
                        asset_id=asset.asset_id,
                        change_type="NEW_DEVICE",
                        severity="High",
                        summary=f"Newly discovered host {asset.ip_address} ({asset.hostname or 'unlabeled'}) joined subnet {asset.subnet}.",
                        previous_value={"status": "not_observed"},
                        current_value={
                            "ip_address": asset.ip_address,
                            "hostname": asset.hostname,
                            "operating_system": asset.operating_system,
                        },
                        significance_score=85.0,
                    )
                    db.add(new_dev_chg)
                    changes.append(new_dev_chg)

                    trigger_deduplicated_alert(
                        db=db,
                        category="NEW_ASSET_DISCOVERED",
                        severity="High",
                        title=f"New Asset Joined Subnet: {asset.ip_address}",
                        message=f"Host {asset.ip_address} ({asset.hostname}) discovered on {asset.subnet} running {asset.operating_system}.",
                        asset_ip=asset.ip_address,
                        dedup_key=f"new_asset:{asset.ip_address}",
                    )
            else:
                asset.last_seen = datetime.now(timezone.utc)
                asset.asset_status = host_obs.status
                if host_obs.hostname:
                    asset.hostname = host_obs.hostname
                if host_obs.mac_address:
                    asset.mac_address = host_obs.mac_address
                if host_obs.vendor:
                    asset.vendor = host_obs.vendor
                if host_obs.operating_system and host_obs.operating_system != "Unknown OS":
                    asset.operating_system = host_obs.operating_system
                    asset.os_accuracy = host_obs.os_accuracy

            existing_ports_map = {(p.port_number, p.protocol.upper()): p for p in asset.ports}
            max_port_risk = 0.0

            for p_obs in host_obs.ports:
                proto = p_obs.protocol.upper()
                if p_obs.state in ("open", "open|filtered"):
                    total_open_ports += 1

                intel = enrich_port_observation(
                    port_number=p_obs.port_number,
                    protocol=proto,
                    detected_service=p_obs.service_name,
                    product=p_obs.product,
                    version=p_obs.version,
                )

                is_newly_open = (p_obs.port_number, proto) in newly_opened_by_ip.get(host_obs.ip_address, set())
                ver_changed = (p_obs.port_number, proto) in version_changed_by_ip.get(host_obs.ip_address, set())

                risk_eval = compute_port_risk_score(
                    port_number=p_obs.port_number,
                    protocol=proto,
                    state=p_obs.state,
                    intel=intel,
                    asset_criticality=asset.criticality,
                    is_newly_exposed=is_newly_open or is_brand_new_asset,
                    version_changed=ver_changed,
                    product=p_obs.product,
                    version=p_obs.version,
                )

                max_port_risk = max(max_port_risk, risk_eval.total_score)

                port_entity = existing_ports_map.get((p_obs.port_number, proto))
                if port_entity is None:
                    port_entity = Port(
                        asset_id=asset.asset_id,
                        port_number=p_obs.port_number,
                        protocol=proto,
                        state=p_obs.state,
                        conventional_service=intel.conventional_service,
                        detected_service=intel.detected_service,
                        service_mismatch=intel.service_mismatch,
                        product=p_obs.product,
                        version=p_obs.version,
                        banner=p_obs.banner,
                        typical_purpose=intel.typical_purpose,
                        exposure_class=intel.exposure_class,
                        risk_score=risk_eval.total_score,
                        risk_classification=risk_eval.classification,
                        risk_factors_json=risk_eval.factors,
                        recommended_action=intel.recommended_action,
                    )
                    db.add(port_entity)
                    db.flush()
                else:
                    port_entity.state = p_obs.state
                    port_entity.conventional_service = intel.conventional_service
                    port_entity.detected_service = intel.detected_service
                    port_entity.service_mismatch = intel.service_mismatch
                    port_entity.product = p_obs.product
                    port_entity.version = p_obs.version
                    port_entity.banner = p_obs.banner
                    port_entity.typical_purpose = intel.typical_purpose
                    port_entity.exposure_class = intel.exposure_class
                    port_entity.risk_score = risk_eval.total_score
                    port_entity.risk_classification = risk_eval.classification
                    port_entity.risk_factors_json = risk_eval.factors
                    port_entity.recommended_action = intel.recommended_action
                    port_entity.last_observed = datetime.now(timezone.utc)
                    db.flush()

                # Generate Security Finding when risk score >= 40 (Medium, High, Critical) or service mismatch
                if p_obs.state in ("open", "open|filtered") and (
                    risk_eval.total_score >= 40.0 or intel.service_mismatch or is_newly_open
                ):
                    category = intel.exposure_class
                    if intel.service_mismatch:
                        category = "SERVICE_PORT_MISMATCH"
                    elif is_newly_open:
                        category = "NEW_SERVICE_EXPOSURE"

                    finding_title = (
                        f"{risk_eval.classification} Exposure: {intel.detected_service.upper()} on "
                        f"{asset.ip_address}:{p_obs.port_number}/{proto}"
                    )
                    if intel.service_mismatch:
                        finding_title = (
                            f"Port-to-Service Mismatch: '{intel.detected_service}' running on conventional "
                            f"'{intel.conventional_service}' port {p_obs.port_number}/{proto} ({asset.ip_address})"
                        )

                    ai_exp, ai_provider, uncertainty = generate_finding_explanation(
                        asset_ip=asset.ip_address,
                        hostname=asset.hostname,
                        business_service=asset.business_service,
                        criticality=asset.criticality,
                        port_number=p_obs.port_number,
                        protocol=proto,
                        state=p_obs.state,
                        conventional_service=intel.conventional_service,
                        detected_service=intel.detected_service,
                        service_mismatch=intel.service_mismatch,
                        product=p_obs.product,
                        version=p_obs.version,
                        banner=p_obs.banner,
                        risk_score=risk_eval.total_score,
                        severity=risk_eval.classification,
                        score_breakdown=risk_eval.factors,
                        recommendation=intel.recommended_action,
                    )

                    # Deduplicate or update existing OPEN finding for this asset + port
                    existing_finding = (
                        db.query(Finding)
                        .filter(
                            Finding.asset_id == asset.asset_id,
                            Finding.port_id == port_entity.port_id,
                            Finding.status == "OPEN",
                        )
                        .first()
                    )

                    evidence_payload = {
                        "ip_address": asset.ip_address,
                        "hostname": asset.hostname,
                        "port": p_obs.port_number,
                        "protocol": proto,
                        "state": p_obs.state,
                        "reason": p_obs.reason,
                        "conventional_service": intel.conventional_service,
                        "detected_service": intel.detected_service,
                        "service_mismatch": intel.service_mismatch,
                        "product": p_obs.product,
                        "version": p_obs.version,
                        "banner": p_obs.banner,
                        "scan_id": scan_job.scan_id,
                    }

                    if existing_finding is None:
                        finding_obj = Finding(
                            asset_id=asset.asset_id,
                            port_id=port_entity.port_id,
                            scan_id=scan_job.scan_id,
                            title=finding_title,
                            category=category,
                            severity=risk_eval.classification,
                            risk_score=risk_eval.total_score,
                            score_breakdown_json=risk_eval.factors,
                            evidence_json=evidence_payload,
                            recommendation=intel.recommended_action,
                            ai_explanation=ai_exp,
                            ai_provider_used=ai_provider,
                            uncertainty_note=uncertainty,
                            status="OPEN",
                        )
                        db.add(finding_obj)
                        db.flush()
                        new_findings_count += 1
                    else:
                        existing_finding.scan_id = scan_job.scan_id
                        existing_finding.title = finding_title
                        existing_finding.category = category
                        existing_finding.severity = risk_eval.classification
                        existing_finding.risk_score = risk_eval.total_score
                        existing_finding.score_breakdown_json = risk_eval.factors
                        existing_finding.evidence_json = evidence_payload
                        existing_finding.ai_explanation = ai_exp
                        existing_finding.ai_provider_used = ai_provider
                        db.flush()
                        finding_obj = existing_finding

                    # Innovation 2: Trigger Autonomous Exposure Investigator for new or high/critical findings
                    if is_newly_open or risk_eval.total_score >= 60.0 or intel.service_mismatch:
                        create_autonomous_investigation(
                            db=db,
                            finding=finding_obj,
                            asset=asset,
                            port=port_entity,
                            was_previously_present=not (is_newly_open or is_brand_new_asset),
                        )

                    # Module 8: Trigger deduplicated alerts for High/Critical exposures
                    if risk_eval.total_score >= 60.0:
                        trigger_deduplicated_alert(
                            db=db,
                            category=category,
                            severity=risk_eval.classification,
                            title=finding_title,
                            message=(
                                f"{finding_title} | Business Service: {asset.business_service} | "
                                f"Score: {risk_eval.total_score}/100. Action: {intel.recommended_action}"
                            ),
                            asset_ip=asset.ip_address,
                            dedup_key=f"finding:{asset.ip_address}:{p_obs.port_number}:{proto}:{category}",
                        )

            old_asset_class = asset.risk_classification
            asset.risk_score = round(max_port_risk, 1)
            asset.risk_classification = classify_risk_score(asset.risk_score)
            if (
                not is_brand_new_asset
                and old_asset_class
                and old_asset_class != asset.risk_classification
            ):
                risk_chg = NetworkChange(
                    scan_id=scan_job.scan_id,
                    asset_id=asset.asset_id,
                    change_type="RISK_CLASSIFICATION_CHANGED",
                    severity=asset.risk_classification,
                    summary=(
                        f"Asset {asset.ip_address} risk classification shifted from "
                        f"'{old_asset_class}' to '{asset.risk_classification}' ({asset.risk_score}/100)."
                    ),
                    previous_value={"risk_classification": old_asset_class},
                    current_value={"risk_classification": asset.risk_classification, "risk_score": asset.risk_score},
                    significance_score=asset.risk_score,
                )
                db.add(risk_chg)
                changes.append(risk_chg)

        # Update Volatility Predictions (Innovation 5)
        compute_asset_volatility_predictions(db)

        # Step 14 & 16: Record Digital Twin Topology Snapshot & finalize ScanJob
        snapshot_label = f"Scan {scan_job.scan_id[:8]} — {normalized_target} ({scan_profile})"
        snapshot = record_topology_snapshot(db, scan_id=scan_job.scan_id, label=snapshot_label)

        scan_job.status = "COMPLETED"
        scan_job.progress_pct = 100
        scan_job.end_time = datetime.now(timezone.utc)
        scan_job.summary_json = {
            "hosts_discovered": len(parsed.hosts),
            "open_ports_observed": total_open_ports,
            "changes_detected": len(changes),
            "new_findings_generated": new_findings_count,
            "topology_snapshot_id": snapshot.snapshot_id,
            "elapsed_seconds": parsed.scan_stats.get("elapsed", "1.0"),
        }
        db.commit()
        db.refresh(scan_job)

        # Step 13: Publish WebSocket completion event
        ws_hub.publish_event_sync(
            "scan.completed",
            {
                "scan_id": scan_job.scan_id,
                "target": scan_job.target,
                "status": scan_job.status,
                "summary": scan_job.summary_json,
            },
        )
        return scan_job

    except Exception as exc:
        scan_job.status = "FAILED"
        scan_job.error_message = str(exc)
        scan_job.end_time = datetime.now(timezone.utc)
        db.commit()
        trigger_deduplicated_alert(
            db=db,
            category="SCAN_FAILURE",
            severity="Medium",
            title=f"Scan Failed for {normalized_target}",
            message=f"Scan {scan_job.scan_id[:8]} failed with error: {exc}",
            asset_ip=normalized_target,
            dedup_key=f"scan_fail:{normalized_target}",
        )
        db.commit()
        raise

