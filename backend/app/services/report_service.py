"""Reporting and Audit Export Engine (PRD Module 9)."""
import csv
from datetime import datetime, timezone
import io
from typing import Any, Dict
from sqlalchemy.orm import Session
from app.core.cidr_validator import get_active_cidr_list
from app.models.entities import Asset, AuditEvent, Finding, NetworkChange, Port, ScanJob


def generate_csv_asset_export(db: Session) -> str:
    """Exports the complete asset and open port inventory as a standard CSV document."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Asset ID",
            "IP Address",
            "Hostname",
            "Subnet",
            "Operating System",
            "Asset Status",
            "Criticality",
            "Business Service",
            "Owner Team",
            "Verified Gateway",
            "Asset Risk Score",
            "Risk Classification",
            "Volatility Score",
            "Open Ports Summary",
            "Last Seen (UTC)",
        ]
    )

    assets = db.query(Asset).order_by(Asset.risk_score.desc()).all()
    for a in assets:
        open_ports = [
            f"{p.port_number}/{p.protocol}({p.detected_service})"
            for p in a.ports
            if p.state in ("open", "open|filtered")
        ]
        writer.writerow(
            [
                a.asset_id,
                a.ip_address,
                a.hostname or "",
                a.subnet,
                a.operating_system or "",
                a.asset_status,
                a.criticality,
                a.business_service or "",
                a.owner_team or "",
                "YES" if a.is_gateway_verified else "NO",
                a.risk_score,
                a.risk_classification,
                a.volatility_score,
                "; ".join(open_ports),
                a.last_seen.isoformat() if a.last_seen else "",
            ]
        )

    return output.getvalue()


def generate_json_executive_audit_bundle(db: Session) -> Dict[str, Any]:
    """Generates a comprehensive JSON export including scan scope, limitations, findings, and audit trail."""
    assets = db.query(Asset).order_by(Asset.risk_score.desc()).all()
    findings = db.query(Finding).order_by(Finding.risk_score.desc()).all()
    changes = db.query(NetworkChange).order_by(NetworkChange.observed_at.desc()).limit(50).all()
    scans = db.query(ScanJob).order_by(ScanJob.start_time.desc()).limit(25).all()
    audits = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(50).all()
    cidrs = get_active_cidr_list(db)

    return {
        "report_metadata": {
            "platform": "NETSENTINEL AI — Autonomous Enterprise Network Intelligence",
            "creator": "Sinan Mohammed",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "authorized_cidr_scope": cidrs,
            "methodology_and_limitations": (
                "Observations reflect active Nmap TCP/UDP service probing within authorized CIDR boundaries. "
                "Ports not observed in a scan profile are distinguished from confirmed closed (RST) ports. "
                "Statistical risk scores (0-100) represent internal exposure prioritization bands, not CVSS scores. "
                "Open ports do not imply host compromise."
            ),
        },
        "executive_summary": {
            "total_assets": len(assets),
            "active_assets": sum(1 for a in assets if a.asset_status == "ACTIVE"),
            "critical_findings": sum(1 for f in findings if f.severity == "Critical"),
            "high_findings": sum(1 for f in findings if f.severity == "High"),
            "medium_findings": sum(1 for f in findings if f.severity == "Medium"),
            "total_network_changes": len(changes),
            "total_scans_recorded": len(scans),
        },
        "assets": [
            {
                "ip_address": a.ip_address,
                "hostname": a.hostname,
                "subnet": a.subnet,
                "operating_system": a.operating_system,
                "status": a.asset_status,
                "criticality": a.criticality,
                "business_service": a.business_service,
                "owner_team": a.owner_team,
                "risk_score": a.risk_score,
                "risk_classification": a.risk_classification,
            }
            for a in assets
        ],
        "prioritized_findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "score_breakdown": f.score_breakdown_json,
                "evidence": f.evidence_json,
                "recommendation": f.recommendation,
                "ai_provider_used": f.ai_provider_used,
                "uncertainty_note": f.uncertainty_note,
            }
            for f in findings
        ],
        "recent_changes": [
            {
                "change_type": c.change_type,
                "severity": c.severity,
                "summary": c.summary,
                "significance_score": c.significance_score,
                "observed_at": c.observed_at.isoformat() if c.observed_at else None,
            }
            for c in changes
        ],
        "administrator_audit_trail": [
            {
                "actor": e.actor_id,
                "role": e.actor_role,
                "action": e.action,
                "resource": e.resource,
                "outcome": e.outcome,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in audits
        ],
    }


def generate_printable_html_security_report(db: Session) -> str:
    """
    Generates a formatted, print-ready HTML/PDF Executive & Technical Security Report (PRD Module 9).
    Includes scan time, scan scope, configuration, limitations, executive summary, and evidence tables.
    """
    bundle = generate_json_executive_audit_bundle(db)
    meta = bundle["report_metadata"]
    exec_sum = bundle["executive_summary"]

    findings_rows = "".join(
        [
            f"""
            <tr>
              <td><strong>{f['severity']}</strong> ({f['risk_score']}/100)</td>
              <td>{f['title']}</td>
              <td><code>{f['category']}</code></td>
              <td><code>{f['evidence'].get('ip_address', '')}:{f['evidence'].get('port', '')}/{f['evidence'].get('protocol', '')}</code><br/>
                  <small>Detected: {f['evidence'].get('detected_service', '')} | Conventional: {f['evidence'].get('conventional_service', '')}</small>
              </td>
              <td>{f['recommendation']}</td>
            </tr>"""
            for f in bundle["prioritized_findings"]
        ]
    )

    assets_rows = "".join(
        [
            f"""
            <tr>
              <td><code>{a['ip_address']}</code></td>
              <td>{a['hostname'] or '-'}</td>
              <td>{a['operating_system'] or '-'}</td>
              <td>{a['business_service'] or '-'} ({a['criticality']})</td>
              <td><strong>{a['risk_score']}/100</strong> ({a['risk_classification']})</td>
            </tr>"""
            for a in bundle["assets"]
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>NETSENTINEL AI — Enterprise Network Security & Exposure Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 36px; line-height: 1.5; }}
    h1, h2, h3 {{ color: #020617; margin-bottom: 8px; }}
    .header {{ border-bottom: 3px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; }}
    .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
    .kpi-card {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13px; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; vertical-align: top; }}
    th {{ background: #f1f5f9; font-weight: 600; }}
    .limitations {{ background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px; margin-bottom: 24px; font-size: 13px; }}
    @media print {{ .no-print {{ display: none; }} }}
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 16px;">
    <button onclick="window.print()" style="background:#0284c7;color:white;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:600;">
      Print / Save as PDF
    </button>
  </div>
  <div class="header">
    <div>
      <h1>NETSENTINEL AI — Security Exposure & Audit Report</h1>
      <div>Autonomous Enterprise Network Discovery, Intelligence & Security Monitoring Platform</div>
      <div><strong>Product Creator & Architect:</strong> {meta['creator']}</div>
    </div>
    <div style="text-align:right;font-size:13px;">
      <div><strong>Generated (UTC):</strong> {meta['generated_at_utc']}</div>
      <div><strong>Authorized CIDR Scope:</strong> {', '.join(meta['authorized_cidr_scope'])}</div>
    </div>
  </div>

  <h2>1. Executive Summary</h2>
  <div class="kpi-grid">
    <div class="kpi-card"><strong>Inventoried Assets:</strong><br/><span style="font-size:22px;">{exec_sum['total_assets']}</span></div>
    <div class="kpi-card"><strong>Critical / High Findings:</strong><br/><span style="font-size:22px;color:#dc2626;">{exec_sum['critical_findings'] + exec_sum['high_findings']}</span></div>
    <div class="kpi-card"><strong>Detected Drift Events:</strong><br/><span style="font-size:22px;">{exec_sum['total_network_changes']}</span></div>
    <div class="kpi-card"><strong>Completed Scan Jobs:</strong><br/><span style="font-size:22px;">{exec_sum['total_scans_recorded']}</span></div>
  </div>

  <div class="limitations">
    <strong>Scope, Methodology & Analytical Limitations:</strong><br/>
    {meta['methodology_and_limitations']}
  </div>

  <h2>2. Prioritized Technical Security Findings & Evidence</h2>
  <table>
    <thead>
      <tr>
        <th>Priority Band</th>
        <th>Finding Title</th>
        <th>Category</th>
        <th>Observed Endpoint Evidence</th>
        <th>Recommended Defensive Action</th>
      </tr>
    </thead>
    <tbody>
      {findings_rows}
    </tbody>
  </table>

  <h2>3. Authorized Enterprise Asset Inventory</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Hostname</th>
        <th>Detected OS</th>
        <th>Business Service & Criticality</th>
        <th>Statistical Risk Score</th>
      </tr>
    </thead>
    <tbody>
      {assets_rows}
    </tbody>
  </table>
</body>
</html>"""

