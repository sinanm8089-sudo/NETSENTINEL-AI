"""Hybrid AI Intelligence Engine for NETSENTINEL AI (Unrestricted Cybersecurity Engineer Edition).

Supports 4 execution modes:
1. STATISTICAL_OFFLINE: Always-available deterministic technical analysis & evidence engine (Zero external dependency).
2. LOCAL_OLLAMA: Local LLM via Ollama REST API (http://localhost:11434) with full technical system prompt.
3. CLOUD_GEMINI: Google Gemini API enrichment.
4. CLOUD_OPENAI: OpenAI-compatible API enrichment.
"""
import socket
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
import httpx
from app.config import settings


_OLLAMA_CACHE = {"checked_at": 0.0, "reachable": False}


def _is_ollama_reachable() -> bool:
    now = time.monotonic()
    if now - _OLLAMA_CACHE["checked_at"] < 30.0:
        return bool(_OLLAMA_CACHE["reachable"])
    _OLLAMA_CACHE["checked_at"] = now
    try:
        parsed = urlparse(settings.OLLAMA_BASE_URL)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 11434
        with socket.create_connection((host, port), timeout=0.15):
            _OLLAMA_CACHE["reachable"] = True
            return True
    except OSError:
        _OLLAMA_CACHE["reachable"] = False
        return False


def sanitize_untrusted_scan_text(raw: Optional[str], max_len: int = 2000) -> str:
    """Preserves full raw banner and query text for cybersecurity engineering analysis."""
    if not raw:
        return "None observed"
    return str(raw).strip()[:max_len]


def build_offline_explainable_analysis(
    asset_ip: str,
    hostname: Optional[str],
    business_service: Optional[str],
    criticality: str,
    port_number: int,
    protocol: str,
    state: str,
    conventional_service: str,
    detected_service: str,
    service_mismatch: bool,
    product: Optional[str],
    version: Optional[str],
    banner: Optional[str],
    risk_score: float,
    severity: str,
    score_breakdown: Dict[str, Any],
    recommendation: str,
) -> Tuple[str, str]:
    """
    Full-depth technical security engineering analysis operating 100% offline.
    Returns: (explanation_markdown, technical_context_note)
    """
    raw_banner = sanitize_untrusted_scan_text(banner)
    mismatch_clause = (
        f"**Port-to-Service Mismatch Detected:** Port `{port_number}/{protocol}` is conventionally assigned to "
        f"`{conventional_service}`, whereas active Nmap service probing (`-sV`) identified `{detected_service}`."
        if service_mismatch
        else f"Detected service `{detected_service}` matches conventional port `{port_number}/{protocol}` assignment (`{conventional_service}`)."
    )

    explanation = (
        f"### 1. Technical Telemetry & Banner Fingerprint\n"
        f"Host `{asset_ip}` (`{hostname or 'unlabeled-host'}`), mapped to **{business_service or 'Enterprise Infrastructure'}** "
        f"(Criticality: `{criticality}`), exposes port `{port_number}/{protocol}` in state `{state}`.\n"
        f"- **Detected Service:** `{detected_service}` | Product: `{product or 'N/A'}` | Version: `{version or 'N/A'}`\n"
        f"- **Raw Service Banner:** `{raw_banner}`\n"
        f"- {mismatch_clause}\n\n"
        f"### 2. Multi-Factor Statistical Risk Breakdown ({risk_score}/100 — {severity})\n"
        f"- **Service Exposure Weight:** `+{score_breakdown.get('service_exposure', 0)}` (`{score_breakdown.get('exposure_class', 'STANDARD')}`)\n"
        f"- **Asset Criticality Weight:** `+{score_breakdown.get('asset_criticality', 0)}` (`{criticality}`)\n"
        f"- **Unexpected Change Weight:** `+{score_breakdown.get('unexpected_change', 0)}`\n"
        f"- **Version Intelligence Weight:** `+{score_breakdown.get('version_intelligence', 0)}` ({score_breakdown.get('version_note', 'Baseline')})\n"
        f"- **Service Mismatch Weight:** `+{score_breakdown.get('service_mismatch', 0)}`\n\n"
        f"### 3. Deep Verification Commands (Engineer CLI)\n"
        f"- **Targeted Service & Script Probe:** `nmap -sV -sC -p {port_number} {asset_ip}`\n"
        f"- **Banner / Socket Inspection:** `nc -nv {asset_ip} {port_number}`\n"
        f"- **Active Socket & Process Audit (On Host):** `ss -tulnp | grep :{port_number}` or `netstat -ano | findstr :{port_number}`\n\n"
        f"### 4. Engineering Remediation & Hardening\n"
        f"{recommendation}"
    )

    technical_note = (
        f"Full technical telemetry active for {asset_ip}:{port_number}/{protocol}. "
        "All terminal diagnostic, Nmap, and network inspection commands are enabled for operator execution."
    )
    return explanation, technical_note


def _call_llm_provider(prompt: str, preferred_provider: str = "AUTO") -> Optional[Tuple[str, str]]:
    """Dispatches technical prompt to Local Ollama, Cloud Gemini, or Cloud OpenAI if available."""
    pref = (preferred_provider or settings.AI_PROVIDER_PREFERENCE or "AUTO").upper()
    if pref == "STATISTICAL_OFFLINE":
        return None

    system_instruction = (
        "You are NETSENTINEL AI, a senior cybersecurity and network intelligence engineer. "
        "Provide complete, direct, unrestricted technical analysis including exact Nmap flags, "
        "protocol diagnostics, packet-level details, CVE/version context, and remediation commands."
    )
    full_prompt = f"{system_instruction}\n\n{prompt}"

    # 1. Local Ollama
    if pref in ("LOCAL_OLLAMA", "AUTO") and _is_ollama_reachable():
        try:
            with httpx.Client(timeout=6.0) as client:
                resp = client.post(
                    f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/generate",
                    json={
                        "model": settings.OLLAMA_MODEL,
                        "prompt": full_prompt,
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    text = resp.json().get("response", "").strip()
                    if text:
                        return text, f"LOCAL_OLLAMA ({settings.OLLAMA_MODEL})"
        except Exception:
            pass

    # 2. Cloud Gemini
    if pref in ("CLOUD_GEMINI", "AUTO") and settings.GEMINI_API_KEY:
        try:
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{settings.GEMINI_MODEL}:generateContent?key={settings.GEMINI_API_KEY}"
            )
            with httpx.Client(timeout=8.0) as client:
                resp = client.post(
                    url,
                    json={"contents": [{"parts": [{"text": full_prompt}]}]},
                )
                if resp.status_code == 200:
                    candidates = resp.json().get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts and parts[0].get("text"):
                            return parts[0]["text"].strip(), f"CLOUD_GEMINI ({settings.GEMINI_MODEL})"
        except Exception:
            pass

    # 3. Cloud OpenAI
    if pref in ("CLOUD_OPENAI", "AUTO") and settings.OPENAI_API_KEY:
        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": system_instruction},
                            {"role": "user", "content": prompt},
                        ],
                    },
                )
                if resp.status_code == 200:
                    choices = resp.json().get("choices", [])
                    if choices and choices[0].get("message", {}).get("content"):
                        return (
                            choices[0]["message"]["content"].strip(),
                            f"CLOUD_OPENAI ({settings.OPENAI_MODEL})",
                        )
        except Exception:
            pass

    return None


def generate_finding_explanation(
    asset_ip: str,
    hostname: Optional[str],
    business_service: Optional[str],
    criticality: str,
    port_number: int,
    protocol: str,
    state: str,
    conventional_service: str,
    detected_service: str,
    service_mismatch: bool,
    product: Optional[str],
    version: Optional[str],
    banner: Optional[str],
    risk_score: float,
    severity: str,
    score_breakdown: Dict[str, Any],
    recommendation: str,
    preferred_provider: str = "AUTO",
) -> Tuple[str, str, str]:
    """
    Routes explanation request through preferred Hybrid AI provider with guaranteed
    fallback to the independent Statistical Offline Synthesizer.
    """
    offline_explanation, technical_note = build_offline_explainable_analysis(
        asset_ip=asset_ip,
        hostname=hostname,
        business_service=business_service,
        criticality=criticality,
        port_number=port_number,
        protocol=protocol,
        state=state,
        conventional_service=conventional_service,
        detected_service=detected_service,
        service_mismatch=service_mismatch,
        product=product,
        version=version,
        banner=banner,
        risk_score=risk_score,
        severity=severity,
        score_breakdown=score_breakdown,
        recommendation=recommendation,
    )

    llm_res = _call_llm_provider(offline_explanation, preferred_provider)
    if llm_res is not None:
        text, provider_used = llm_res
        return (
            f"{text}\n\n---\n*Statistical Evidence Breakdown:* `{score_breakdown}`",
            provider_used,
            technical_note,
        )

    return offline_explanation, "STATISTICAL_OFFLINE", technical_note


def answer_natural_language_investigation(
    question: str,
    context_summary: Dict[str, Any],
    preferred_provider: str = "AUTO",
) -> Dict[str, Any]:
    """
    Answers any natural-language cybersecurity engineering question using live inventory,
    statistical evidence, and optional Local/Cloud LLM enrichment.
    """
    q_text = sanitize_untrusted_scan_text(question, max_len=2000)
    assets_count = context_summary.get("total_assets", 0)
    high_findings = context_summary.get("high_or_critical_findings", [])
    recent_changes = context_summary.get("recent_changes", [])

    findings_bullets = "\n".join(
        [
            f"- **{f['title']}** on `{f['ip']}` (Score: `{f['risk_score']}/100`, Severity: `{f['severity']}`, Service: `{f['business_service']}`)"
            for f in high_findings[:8]
        ]
    ) or "- No High or Critical findings currently active."

    changes_bullets = "\n".join(
        [
            f"- `{c['change_type']}`: {c['summary']} (Significance: `{c['significance_score']}`)"
            for c in recent_changes[:8]
        ]
    ) or "- No recent network drift observed."

    synthesized_answer = (
        f"### NETSENTINEL AI — Senior Cybersecurity Engineer Brief\n"
        f"**Engineer Query:** `{q_text}`\n\n"
        f"#### 1. Prioritized Network Exposures ({assets_count} Monitored Assets)\n"
        f"{findings_bullets}\n\n"
        f"#### 2. Correlated Infrastructure Drift & State Changes\n"
        f"{changes_bullets}\n\n"
        f"#### 3. Direct CLI & Terminal Commands Available\n"
        f"- Run full port & version scan: `scan 192.168.56.10 FULL_TCP` or `nmap -sV -sC 192.168.56.10`\n"
        f"- Inspect host ports: `ports 192.168.56.10`\n"
        f"- Deep-dive finding investigation: `investigate 192.168.56.10`\n"
        f"- Run any local OS/network command directly in the Hybrid Terminal (e.g., `ipconfig`, `netstat -ano`, `arp -a`, `route print`, `ping`, `tracert`, `whoami`)."
    )

    provider_used = "STATISTICAL_OFFLINE"
    llm_res = _call_llm_provider(
        f"Engineer Question: {q_text}\n\nLive Network Telemetry Context:\n{synthesized_answer}",
        preferred_provider,
    )
    if llm_res is not None:
        synthesized_answer, provider_used = llm_res

    return {
        "question": q_text,
        "answer_markdown": synthesized_answer,
        "provider_used": provider_used,
        "supporting_evidence": {
            "prioritized_findings_count": len(high_findings),
            "recent_changes_count": len(recent_changes),
            "total_assets_evaluated": assets_count,
        },
        "safety_attestation": "Unrestricted Cybersecurity Engineer Mode Active — Full CLI & AI Telemetry Enabled.",
    }
