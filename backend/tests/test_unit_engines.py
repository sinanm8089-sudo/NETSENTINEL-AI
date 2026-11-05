"""Unit Tests for Nmap XML Parser, Port Intelligence, Risk Scoring, CIDR Scope & Engineer Command Execution."""
from app.core.cidr_validator import validate_target_authorization
from app.core.command_validator import validate_terminal_command
from app.services.ai_adapter import (
    build_offline_explainable_analysis,
    sanitize_untrusted_scan_text,
)
from app.services.nmap_parser import parse_nmap_xml
from app.services.port_intelligence import enrich_port_observation
from app.services.risk_engine import classify_risk_score, compute_port_risk_score


def test_cidr_authorization_engineer_mode():
    allowlist = ["192.168.56.0/24", "10.20.30.0/24"]

    ok, norm, _ = validate_target_authorization("192.168.56.10", allowlist)
    assert ok is True
    assert norm == "192.168.56.10"

    ok_sub, norm_sub, _ = validate_target_authorization("192.168.56.0/25", allowlist)
    assert ok_sub is True
    assert norm_sub == "192.168.56.0/25"

    # In unrestricted engineer mode, on-demand external or lab targets are also authorized
    ok_ext, norm_ext, _ = validate_target_authorization("8.8.8.8", allowlist)
    assert ok_ext is True
    assert norm_ext == "8.8.8.8"


def test_port_to_application_mismatch_detection():
    ssh_intel = enrich_port_observation(22, "TCP", "ssh", "OpenSSH", "9.3p1")
    assert ssh_intel.conventional_service == "ssh"
    assert ssh_intel.detected_service == "ssh"
    assert ssh_intel.service_mismatch is False

    mismatch_intel = enrich_port_observation(80, "TCP", "ssh", "OpenSSH", "8.9p1")
    assert mismatch_intel.conventional_service == "http"
    assert mismatch_intel.detected_service == "ssh"
    assert mismatch_intel.service_mismatch is True
    assert mismatch_intel.exposure_class == "SERVICE_PORT_MISMATCH"


def test_statistical_risk_scoring_and_bands():
    assert classify_risk_score(10.0) == "Informational"
    assert classify_risk_score(25.0) == "Low"
    assert classify_risk_score(48.0) == "Medium"
    assert classify_risk_score(68.0) == "High"
    assert classify_risk_score(88.0) == "Critical"

    mysql_intel = enrich_port_observation(3306, "TCP", "mysql", "MySQL", "5.7.42")
    risk = compute_port_risk_score(
        port_number=3306,
        protocol="TCP",
        state="open",
        intel=mysql_intel,
        asset_criticality="CRITICAL",
        is_newly_exposed=True,
        version_changed=False,
        product="MySQL",
        version="5.7.42",
    )
    assert risk.total_score >= 80.0
    assert risk.classification == "Critical"
    assert risk.factors["service_exposure"] == 28.0
    assert risk.factors["asset_criticality"] == 25.0
    assert risk.factors["unexpected_change"] == 18.0
    assert risk.factors["version_intelligence"] == 10.0

    closed_risk = compute_port_risk_score(
        port_number=3306,
        protocol="TCP",
        state="closed",
        intel=mysql_intel,
        asset_criticality="CRITICAL",
    )
    assert closed_risk.total_score == 0.0
    assert closed_risk.classification == "Informational"


def test_command_validator_supports_all_engineer_and_shell_commands():
    assert validate_terminal_command("help").is_allowed is True
    assert validate_terminal_command("assets").is_allowed is True
    assert validate_terminal_command("scan --target 192.168.56.10").is_allowed is True
    assert validate_terminal_command("scan 192.168.56.10").is_allowed is True
    assert validate_terminal_command("ports 192.168.56.10").is_allowed is True
    assert validate_terminal_command("shell uname -a").is_allowed is True
    assert validate_terminal_command("whoami").is_allowed is True
    assert validate_terminal_command("whoami").command_type == "SYSTEM_SHELL"
    assert validate_terminal_command("ai Explain all open database ports").command_type == "AI_QUERY"


def test_nmap_xml_parser_extracts_hosts_and_ports():
    sample_xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap" args="nmap -sT -sV 192.168.56.10">
      <host>
        <status state="up" reason="syn-ack"/>
        <address addr="192.168.56.10" addrtype="ipv4"/>
        <hostnames><hostname name="srv01.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="9.0p1"/>
          </port>
        </ports>
        <os><osmatch name="Linux 6.1" accuracy="95"/></os>
      </host>
    </nmaprun>
    """
    parsed = parse_nmap_xml(sample_xml)
    assert len(parsed.hosts) == 1
    h = parsed.hosts[0]
    assert h.ip_address == "192.168.56.10"
    assert h.hostname == "srv01.local"
    assert h.operating_system == "Linux 6.1"
    assert len(h.ports) == 1
    assert h.ports[0].port_number == 22
    assert h.ports[0].service_name == "ssh"


def test_unrestricted_ai_banner_and_offline_explainer():
    raw_banner = "OpenSSH 8.9p1 Ubuntu-3ubuntu0.6 (Protocol 2.0)"
    cleaned = sanitize_untrusted_scan_text(raw_banner)
    assert cleaned == raw_banner

    exp, note = build_offline_explainable_analysis(
        asset_ip="192.168.56.10",
        hostname="app-01",
        business_service="Portal API",
        criticality="HIGH",
        port_number=3306,
        protocol="TCP",
        state="open",
        conventional_service="mysql",
        detected_service="mysql",
        service_mismatch=False,
        product="MySQL",
        version="5.7.42",
        banner=raw_banner,
        risk_score=75.0,
        severity="High",
        score_breakdown={"service_exposure": 28.0, "asset_criticality": 20.0},
        recommendation="Restrict MySQL access.",
    )
    assert "192.168.56.10" in exp
    assert "nmap -sV -sC -p 3306 192.168.56.10" in exp
    assert "Full technical telemetry active" in note
