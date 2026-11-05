"""Independent Statistical Multi-Factor Risk Scoring Engine (PRD Section 3.3 & Section 8)."""
from dataclasses import dataclass
from typing import Any, Dict, Optional
from app.services.port_intelligence import EnrichedPortIntelligence

CRITICALITY_WEIGHTS = {
    "LOW": 5.0,
    "MEDIUM": 12.0,
    "HIGH": 20.0,
    "CRITICAL": 25.0,
}

RISKY_VERSION_KEYWORDS = [
    ("openssh", "7.", 10.0, "Legacy OpenSSH 7.x series detected; verify patch status and disable legacy KEX algorithms."),
    ("apache", "2.4.49", 10.0, "Apache 2.4.49 has known path traversal exposure; upgrade immediately."),
    ("vsftpd", "2.3.4", 10.0, "vsftpd 2.3.4 version requires immediate security verification."),
    ("mysql", "5.7", 10.0, "MySQL 5.7 has reached End-of-Life; plan migration to MySQL 8.0 LTS."),
    ("redis", "5.", 9.0, "Older Redis 5.x lacks fine-grained ACL security controls introduced in Redis 6+."),
    ("microsoft-iis", "7.5", 9.0, "Legacy IIS 7.5 server version detected."),
    ("smb", "1.0", 10.0, "Legacy SMBv1 protocol indicator."),
]


def classify_risk_score(score: float) -> str:
    """
    PRD Section 8 Internal Prioritization Bands (0-100):
    0-19: Informational
    20-39: Low
    40-59: Medium
    60-79: High
    80-100: Critical
    """
    s = max(0.0, min(100.0, round(score, 1)))
    if s < 20:
        return "Informational"
    if s < 40:
        return "Low"
    if s < 60:
        return "Medium"
    if s < 80:
        return "High"
    return "Critical"


@dataclass
class PortRiskAssessment:
    total_score: float
    classification: str
    factors: Dict[str, Any]
    explanation_summary: str


def compute_port_risk_score(
    port_number: int,
    protocol: str,
    state: str,
    intel: EnrichedPortIntelligence,
    asset_criticality: str = "MEDIUM",
    is_newly_exposed: bool = False,
    version_changed: bool = False,
    product: Optional[str] = None,
    version: Optional[str] = None,
) -> PortRiskAssessment:
    """
    Computes an explainable 0-100 statistical risk score completely independent of AI.
    Every factor contribution is recorded so findings can cite exact mathematical evidence.
    """
    if state not in ("open", "open|filtered"):
        return PortRiskAssessment(
            total_score=0.0,
            classification="Informational",
            factors={
                "service_exposure": 0.0,
                "asset_criticality": 0.0,
                "unexpected_change": 0.0,
                "version_intelligence": 0.0,
                "service_mismatch": 0.0,
                "state_note": f"Port state is '{state}' (not actively open).",
            },
            explanation_summary=f"Port {port_number}/{protocol} is in '{state}' state and poses no active service exposure.",
        )

    # 1. Service Exposure Contribution (0 - 35)
    exposure_contrib = min(35.0, intel.base_exposure_weight)
    if state == "open|filtered":
        exposure_contrib = round(exposure_contrib * 0.65, 1)

    # 2. Asset Criticality Contribution (0 - 25)
    crit_key = (asset_criticality or "MEDIUM").upper()
    criticality_contrib = CRITICALITY_WEIGHTS.get(crit_key, 12.0)

    # 3. Unexpected Change Contribution (0 - 20)
    change_contrib = 0.0
    change_reasons = []
    if is_newly_exposed:
        change_contrib += 18.0
        change_reasons.append("Newly opened port compared to previous baseline (+18)")
    if version_changed:
        change_contrib += 5.0
        change_reasons.append("Service version fingerprint changed since previous scan (+5)")
    change_contrib = min(20.0, change_contrib)

    # 4. Version Intelligence Contribution (0 - 10)
    version_contrib = 0.0
    version_note = "Standard or current service banner."
    combined_ver = f"{product or ''} {version or ''} {intel.detected_service}".lower()
    for prod_kw, ver_kw, weight, note in RISKY_VERSION_KEYWORDS:
        if prod_kw in combined_ver and ver_kw in combined_ver:
            version_contrib = weight
            version_note = note
            break
    if version_contrib == 0.0 and not product and not version and intel.detected_service == "unknown":
        version_contrib = 4.0
        version_note = "Opaque service banner (service probe returned unknown version/product) (+4)."

    # 5. Service-to-Port Mismatch Contribution (0 - 10)
    mismatch_contrib = 10.0 if intel.service_mismatch else 0.0

    raw_total = (
        exposure_contrib
        + criticality_contrib
        + change_contrib
        + version_contrib
        + mismatch_contrib
    )
    normalized_score = min(100.0, max(0.0, round(raw_total, 1)))
    classification = classify_risk_score(normalized_score)

    factor_breakdown = {
        "service_exposure": exposure_contrib,
        "asset_criticality": criticality_contrib,
        "unexpected_change": change_contrib,
        "version_intelligence": version_contrib,
        "service_mismatch": mismatch_contrib,
        "exposure_class": intel.exposure_class,
        "asset_criticality_level": crit_key,
        "change_notes": change_reasons,
        "version_note": version_note,
    }

    explanation = (
        f"Score {normalized_score}/100 ({classification}): "
        f"Exposure({exposure_contrib}) + AssetCriticality[{crit_key}]({criticality_contrib}) "
        f"+ Change({change_contrib}) + VersionIntel({version_contrib}) + Mismatch({mismatch_contrib})."
    )

    return PortRiskAssessment(
        total_score=normalized_score,
        classification=classification,
        factors=factor_breakdown,
        explanation_summary=explanation,
    )
