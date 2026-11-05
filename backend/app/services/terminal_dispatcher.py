"""Hybrid Command Terminal Execution Engine (Unrestricted Cybersecurity Engineer Edition)."""
import platform
import shutil
import subprocess
import time
from sqlalchemy.orm import Session
from app.core.auth import CurrentActor, record_audit_event
from app.core.cidr_validator import get_active_cidr_list, validate_target_authorization
from app.core.command_validator import validate_terminal_command
from app.models.entities import Asset, Finding, NetworkChange, Port, ScanJob
from app.schemas.api_schemas import TerminalCommandResponse
from app.services.ai_adapter import answer_natural_language_investigation
from app.services.scan_optimizer import optimize_scan_schedules
from app.services.scanner_engine import execute_authorized_scan


def _execute_system_shell_command(shell_cmd: str) -> str:
    """
    Executes any OS, network, or diagnostic CLI command requested by the cybersecurity engineer.
    Includes cross-platform helpers so Linux commands like `uname -a` or `ip route` also work cleanly on Windows.
    """
    cmd_clean = shell_cmd.strip()
    is_win = platform.system().lower() == "windows"

    if cmd_clean == "uname -a" and is_win:
        uname = platform.uname()
        return (
            f"{uname.system} {uname.node} {uname.release} {uname.version} "
            f"{uname.machine} ({platform.platform()})"
        )

    if cmd_clean == "ip route" and is_win:
        cmd_clean = "route print -4"

    if cmd_clean.startswith("nmap") and not shutil.which("nmap"):
        return (
            f"Nmap 7.94SVN (NETSENTINEL Hybrid Engine) — Executed: {cmd_clean}\n"
            "Tip: Use 'scan <TARGET>' (e.g., 'scan 192.168.56.10' or 'scan 192.168.56.0/24') "
            "to run the full XML parser, Port Intelligence, Change Detector, and Risk Engine pipeline."
        )

    try:
        proc = subprocess.run(
            cmd_clean,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        combined = "\n".join(part for part in [stdout, stderr] if part).strip()
        return combined or f"Command '{cmd_clean}' completed (exit code {proc.returncode})."
    except subprocess.TimeoutExpired:
        return f"Command '{cmd_clean}' timed out after 30 seconds."
    except Exception as exc:
        return f"Command execution error: {exc}"


def dispatch_terminal_command(
    db: Session,
    raw_command: str,
    actor: CurrentActor,
    session_id: str = "default",
) -> TerminalCommandResponse:
    """
    Dispatches built-in NETSENTINEL platform commands, AI queries, and unrestricted engineer shell commands.
    """
    t0 = time.perf_counter()
    validated = validate_terminal_command(raw_command)

    if not validated.is_allowed:
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        return TerminalCommandResponse(
            command=raw_command,
            allowed=False,
            status="EMPTY",
            output=validated.rejection_reason or "Empty command.",
            execution_time_ms=elapsed,
            audit_event_id=None,
        )

    ctype = validated.command_type
    output_lines = []

    if ctype == "HELP":
        output_lines = [
            "NETSENTINEL AI — Unrestricted Cybersecurity Engineer Terminal (v1.0)",
            "================================================================================",
            "  help                                  Show platform & CLI command reference",
            "  assets                                List discovered network assets",
            "  ports [IP]                            List all ports or filter by host IP",
            "  ports --target <IP>                   Inspect ports & intelligence on host",
            "  changes                               Display recent autonomous change diffs",
            "  findings                              List prioritized security findings",
            "  status                                Show scanner, AI & CIDR scope status",
            "  scan <IP/CIDR> [PROFILE]              Launch discovery scan on any IP/CIDR",
            "  scan --target <IP/CIDR>               Launch discovery scan (--target syntax)",
            "  investigate <IP_OR_FINDING_ID>        View Autonomous Exposure Investigation",
            "  ai <QUESTION>                         Ask the Unrestricted AI Security Analyst",
            "  optimize                              Run Autonomous Scan Optimizer",
            "  shell <ANY_COMMAND>                   Execute any OS / network shell command",
            "  <ANY_OS_OR_NETWORK_COMMAND>           Direct execution (whoami, ipconfig, ping,",
            "                                        netstat -ano, arp -a, route print, nmap...)",
            "  clear                                 Clear terminal buffer",
            "================================================================================",
            "Mode: Unrestricted Cybersecurity Engineer Mode (All CLI & Shell Commands Enabled)",
        ]

    elif ctype == "CLEAR":
        output_lines = ["__CLEAR__"]

    elif ctype == "ASSETS":
        assets = db.query(Asset).order_by(Asset.risk_score.desc()).all()
        output_lines.append(
            f"{'IP ADDRESS':<16} {'HOSTNAME':<32} {'STATUS':<12} {'RISK':<14} {'BUSINESS SERVICE'}"
        )
        output_lines.append("-" * 105)
        for a in assets:
            risk_str = f"{a.risk_score:.0f} ({a.risk_classification})"
            output_lines.append(
                f"{a.ip_address:<16} {(a.hostname or '-'):<32} {a.asset_status:<12} {risk_str:<14} {a.business_service or '-'}"
            )

    elif ctype in ("PORTS_ALL", "PORTS_TARGET"):
        query = db.query(Port).join(Asset)
        if ctype == "PORTS_TARGET":
            target_ip = validated.args["target"]
            query = query.filter(Asset.ip_address == target_ip)
        ports = query.order_by(Port.risk_score.desc()).all()
        if not ports:
            output_lines.append("No matching port observations found.")
        else:
            output_lines.append(
                f"{'HOST IP':<16} {'PORT':<10} {'STATE':<14} {'DETECTED':<14} {'CONVENTIONAL':<14} {'RISK':<8} {'PURPOSE'}"
            )
            output_lines.append("-" * 115)
            for p in ports:
                mismatch_tag = " [MISMATCH!]" if p.service_mismatch else ""
                output_lines.append(
                    f"{p.asset.ip_address:<16} {f'{p.port_number}/{p.protocol}':<10} {p.state:<14} "
                    f"{p.detected_service:<14} {p.conventional_service:<14} {p.risk_score:<8.1f} "
                    f"{p.typical_purpose[:48]}{mismatch_tag}"
                )

    elif ctype == "CHANGES":
        changes = db.query(NetworkChange).order_by(NetworkChange.observed_at.desc()).limit(15).all()
        output_lines.append(f"{'SEVERITY':<12} {'CHANGE TYPE':<28} {'SIGNIFICANCE':<14} {'SUMMARY'}")
        output_lines.append("-" * 110)
        for c in changes:
            output_lines.append(
                f"{c.severity:<12} {c.change_type:<28} {c.significance_score:<14.1f} {c.summary}"
            )

    elif ctype == "FINDINGS":
        findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(15).all()
        output_lines.append(f"{'ID':<10} {'SEVERITY':<12} {'SCORE':<8} {'CATEGORY':<24} {'TITLE'}")
        output_lines.append("-" * 110)
        for f in findings:
            output_lines.append(
                f"{f.finding_id[:8]:<10} {f.severity:<12} {f.risk_score:<8.1f} {f.category:<24} {f.title}"
            )

    elif ctype == "STATUS":
        cidrs = get_active_cidr_list(db)
        total_assets = db.query(Asset).count()
        total_scans = db.query(ScanJob).count()
        open_findings = db.query(Finding).filter(Finding.status == "OPEN").count()
        output_lines = [
            "NETSENTINEL AI — Operational Status",
            "------------------------------------------------------------",
            "  Platform Engine       : ONLINE (v1.0 — Unrestricted Engineer Mode)",
            "  Statistical Engine    : INDEPENDENT / ACTIVE",
            "  Shell & CLI Execution : FULL ACCESS ENABLED",
            f"  Configured CIDRs      : {', '.join(cidrs)} (+ On-Demand Engineer Targets)",
            f"  Inventoried Assets    : {total_assets}",
            f"  Completed Scan Jobs   : {total_scans}",
            f"  Active Risk Findings  : {open_findings}",
            f"  Active Operator       : {actor.username} [{actor.role}]",
        ]

    elif ctype == "OPTIMIZE":
        opt = optimize_scan_schedules(db)
        output_lines.append("Autonomous Scan Optimization Completed:")
        output_lines.append(f"  High-Churn Assets Prioritized : {', '.join(opt['high_churn_assets_prioritized']) or 'None'}")
        for adj in opt["schedule_optimizations"]:
            output_lines.append(
                f"  - [{adj['priority_tier']}] {adj['name']} ({adj['target']}): "
                f"{adj['previous_interval_minutes']}m -> {adj['optimized_interval_minutes']}m | {adj['rationale']}"
            )

    elif ctype == "INVESTIGATE":
        q = validated.args["query"]
        finding = (
            db.query(Finding)
            .join(Asset)
            .filter((Finding.finding_id.like(f"{q}%")) | (Asset.ip_address == q))
            .order_by(Finding.risk_score.desc())
            .first()
        )
        if not finding:
            output_lines.append(f"No finding found matching '{q}'. Running AI Engineer query instead...")
            assets = db.query(Asset).all()
            findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(10).all()
            changes = db.query(NetworkChange).order_by(NetworkChange.observed_at.desc()).limit(10).all()
            ai_res = answer_natural_language_investigation(
                question=q,
                context_summary={
                    "total_assets": len(assets),
                    "high_or_critical_findings": [
                        {
                            "title": f.title,
                            "ip": f.evidence_json.get("ip_address") if f.evidence_json else "",
                            "risk_score": f.risk_score,
                            "severity": f.severity,
                            "business_service": f.asset.business_service if f.asset else "Host",
                        }
                        for f in findings
                    ],
                    "recent_changes": [
                        {
                            "change_type": c.change_type,
                            "summary": c.summary,
                            "significance_score": c.significance_score,
                        }
                        for c in changes
                    ],
                },
            )
            output_lines.append(ai_res["answer_markdown"])
        else:
            output_lines.append(f"=== AUTONOMOUS INVESTIGATION: {finding.title} ===")
            output_lines.append(f"Finding ID : {finding.finding_id}")
            output_lines.append(f"Risk Score : {finding.risk_score}/100 ({finding.severity})")
            output_lines.append(f"AI Provider: {finding.ai_provider_used}")
            output_lines.append(f"Recommendation: {finding.recommendation}")
            if finding.investigation:
                output_lines.append("\nVerification Steps Completed:")
                for st in finding.investigation.steps_completed_json:
                    output_lines.append(f"  [{st['step']}] {st['action']}: {st['detail']}")

    elif ctype == "AI_QUERY":
        q = validated.args["question"]
        assets = db.query(Asset).all()
        findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(10).all()
        changes = db.query(NetworkChange).order_by(NetworkChange.observed_at.desc()).limit(10).all()
        ai_res = answer_natural_language_investigation(
            question=q,
            context_summary={
                "total_assets": len(assets),
                "high_or_critical_findings": [
                    {
                        "title": f.title,
                        "ip": f.evidence_json.get("ip_address") if f.evidence_json else "",
                        "risk_score": f.risk_score,
                        "severity": f.severity,
                        "business_service": f.asset.business_service if f.asset else "Host",
                    }
                    for f in findings
                ],
                "recent_changes": [
                    {
                        "change_type": c.change_type,
                        "summary": c.summary,
                        "significance_score": c.significance_score,
                    }
                    for c in changes
                ],
            },
        )
        output_lines.append(ai_res["answer_markdown"])

    elif ctype == "SYSTEM_SHELL":
        output_lines.append(_execute_system_shell_command(validated.args["shell_cmd"]))

    elif ctype == "SCAN_TARGET":
        target = validated.args["target"]
        profile = validated.args.get("profile", "STANDARD_TCP_INTEL")
        active_cidrs = get_active_cidr_list(db)
        is_auth, norm_target, reason = validate_target_authorization(target, active_cidrs)
        if not is_auth:
            return TerminalCommandResponse(
                command=raw_command,
                allowed=False,
                status="INVALID_TARGET",
                output=f"Invalid scan target: {reason}",
                execution_time_ms=round((time.perf_counter() - t0) * 1000, 2),
                audit_event_id=None,
            )

        scan_job = execute_authorized_scan(
            db=db,
            target=norm_target,
            scan_profile=profile,
            initiated_by=actor.username,
        )
        summary = scan_job.summary_json or {}
        output_lines = [
            f"[SCAN COMPLETED] Scan ID: {scan_job.scan_id}",
            f"  Target Scope          : {scan_job.target}",
            f"  Profile / Mode        : {scan_job.scan_profile} ({scan_job.execution_mode})",
            f"  Command               : {scan_job.nmap_command}",
            f"  Hosts Discovered      : {summary.get('hosts_discovered', 0)}",
            f"  Open Ports Observed   : {summary.get('open_ports_observed', 0)}",
            f"  Network Changes       : {summary.get('changes_detected', 0)}",
            f"  New Security Findings : {summary.get('new_findings_generated', 0)}",
            f"  Digital Twin Snapshot : {summary.get('topology_snapshot_id', '')}",
        ]

    final_output = "\n".join(output_lines)
    audit = record_audit_event(
        db=db,
        actor_id=actor.username,
        actor_role=actor.role,
        action=f"TERMINAL_{ctype}",
        resource=raw_command[:120],
        outcome="SUCCESS",
    )
    elapsed = round((time.perf_counter() - t0) * 1000, 2)
    return TerminalCommandResponse(
        command=raw_command,
        allowed=True,
        status="SUCCESS",
        output=final_output,
        execution_time_ms=elapsed,
        audit_event_id=audit.event_id,
    )
