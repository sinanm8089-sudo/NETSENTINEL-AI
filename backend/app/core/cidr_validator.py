"""Target Scope & CIDR Validator for NETSENTINEL AI."""
import ipaddress
import re
from typing import List, Tuple
from sqlalchemy.orm import Session
from app.config import settings
from app.models.entities import AuthorizedCIDR

HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9\.\-\_]+$")


def get_active_cidr_list(db: Session) -> List[str]:
    """Retrieves active CIDRs from database, falling back to configured defaults."""
    records = db.query(AuthorizedCIDR).filter(AuthorizedCIDR.is_active.is_(True)).all()
    if not records:
        return list(settings.DEFAULT_AUTHORIZED_CIDRS)
    return [r.cidr_block for r in records]


def validate_target_authorization(
    target: str,
    authorized_cidrs: List[str],
    enforce_strict_allowlist: bool = False,
) -> Tuple[bool, str, str]:
    """
    Validates target IP, CIDR block, or hostname for scanning.
    In Engineer Mode (default), any valid IPv4/IPv6, CIDR block, or hostname is permitted.
    If `enforce_strict_allowlist=True` is explicitly passed, checks membership in `authorized_cidrs`.
    Returns: (is_authorized, normalized_target, reason)
    """
    if not target or not target.strip():
        return False, "", "Target cannot be empty."

    cleaned = target.strip()

    try:
        if "/" in cleaned:
            target_net = ipaddress.ip_network(cleaned, strict=False)
            normalized = str(target_net)
        else:
            ip_obj = ipaddress.ip_address(cleaned)
            prefix = 32 if ip_obj.version == 4 else 128
            target_net = ipaddress.ip_network(f"{ip_obj}/{prefix}", strict=False)
            normalized = str(ip_obj)
    except ValueError:
        # Check if valid hostname / domain target
        if HOSTNAME_PATTERN.match(cleaned) and not cleaned.startswith("-"):
            if enforce_strict_allowlist and cleaned not in authorized_cidrs:
                return False, cleaned, f"Hostname '{cleaned}' is not in strict CIDR allowlist."
            return True, cleaned, "Valid hostname target authorized for engineer scan."
        return False, cleaned, f"Invalid IP address, CIDR notation, or hostname: '{cleaned}'"

    for cidr_str in authorized_cidrs:
        try:
            allowed_net = ipaddress.ip_network(cidr_str, strict=False)
            if target_net.version == allowed_net.version and target_net.subnet_of(allowed_net):
                return (
                    True,
                    normalized,
                    f"Authorized under scope {allowed_net}.",
                )
        except ValueError:
            continue

    if enforce_strict_allowlist:
        return (
            False,
            cleaned,
            f"Target '{cleaned}' is outside CIDR allowlist ({', '.join(authorized_cidrs)}).",
        )

    return (
        True,
        normalized,
        f"Authorized via Unrestricted Cybersecurity Engineer Mode ({normalized}).",
    )
