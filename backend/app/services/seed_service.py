"""Initial Enterprise Seed Service for NETSENTINEL AI."""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.config import settings
from app.models.entities import AuthorizedCIDR, ScanJob, ScanSchedule, User
from app.services.scanner_engine import execute_authorized_scan


def initialize_platform_seed_data(db: Session) -> None:
    """
    Seeds default RBAC users, authorized CIDR enclaves, autonomous scan schedules,
    and executes a two-stage baseline + drift scan sequence if the database is empty.
    """
    # 1. Seed RBAC Users matching the 5 mandatory PRD Section 4 roles
    if db.query(User).count() == 0:
        default_users = [
            User(
                username="sinan.mohammed",
                full_name="Sinan Mohammed (Creator & Super Admin)",
                email="sinan@netsentinel.ai",
                role="SUPER_ADMIN",
                api_token="ns-token-super-admin",
            ),
            User(
                username="secadmin.ops",
                full_name="Enterprise Security Admin",
                email="secadmin@netsentinel.ai",
                role="SECURITY_ADMIN",
                api_token="ns-token-sec-admin",
            ),
            User(
                username="soc.analyst",
                full_name="Tier-2 SOC Analyst",
                email="soc@netsentinel.ai",
                role="SOC_ANALYST",
                api_token="ns-token-soc-analyst",
            ),
            User(
                username="net.admin",
                full_name="Lead Network Administrator",
                email="netadmin@netsentinel.ai",
                role="NETWORK_ADMIN",
                api_token="ns-token-net-admin",
            ),
            User(
                username="compliance.auditor",
                full_name="External Security Auditor",
                email="auditor@netsentinel.ai",
                role="AUDITOR",
                api_token="ns-token-auditor",
            ),
        ]
        db.add_all(default_users)
        db.commit()

    # 2. Seed Authorized CIDRs
    if db.query(AuthorizedCIDR).count() == 0:
        cidrs = [
            AuthorizedCIDR(
                cidr_block="192.168.56.0/24",
                description="Core Enterprise Production & Identity Subnet",
                environment="Production Enclave",
                owner_team="SecOps & Core Infrastructure",
                is_active=True,
            ),
            AuthorizedCIDR(
                cidr_block="10.20.30.0/24",
                description="Analytics & Telemetry Data Tier Subnet",
                environment="Data Platform Enclave",
                owner_team="Data Platform Engineering",
                is_active=True,
            ),
            AuthorizedCIDR(
                cidr_block="127.0.0.1/32",
                description="Local Loopback Diagnostic Target",
                environment="Localhost",
                owner_team="Platform Diagnostics",
                is_active=True,
            ),
        ]
        db.add_all(cidrs)
        db.commit()

    # 3. Seed Autonomous Scan Schedules (Module 1 + Innovation 6)
    if db.query(ScanSchedule).count() == 0:
        now = datetime.now(timezone.utc)
        schedules = [
            ScanSchedule(
                name="Core Production TCP Intelligence Sweep",
                target="192.168.56.0/24",
                scan_profile="STANDARD_TCP_INTEL",
                interval_minutes=60,
                priority_tier="HIGH_CHURN_PRIORITY",
                optimization_reason="Prioritized due to active application & database tier services.",
                is_enabled=True,
                last_run_at=now - timedelta(minutes=15),
                next_run_at=now + timedelta(minutes=45),
            ),
            ScanSchedule(
                name="Data Tier Service Verification",
                target="10.20.30.0/24",
                scan_profile="STANDARD_TCP_INTEL",
                interval_minutes=120,
                priority_tier="NORMAL",
                optimization_reason="Standard bi-hourly verification for telemetry cluster.",
                is_enabled=True,
                last_run_at=now - timedelta(minutes=30),
                next_run_at=now + timedelta(minutes=90),
            ),
            ScanSchedule(
                name="Off-Peak UDP Infrastructure Discovery",
                target="192.168.56.0/24",
                scan_profile="FULL_UDP",
                interval_minutes=360,
                priority_tier="LOW_FREQUENCY_UDP",
                optimization_reason="Scheduled every 6 hours to prevent open|filtered UDP congestion.",
                is_enabled=True,
                last_run_at=now - timedelta(hours=2),
                next_run_at=now + timedelta(hours=4),
            ),
        ]
        db.add_all(schedules)
        db.commit()

    # 4. Run initial Baseline Scan followed by Drift Scan so Digital Twin, Change Detection, and Investigator are populated
    if db.query(ScanJob).count() == 0:
        # Stage A: Baseline scan on 192.168.56.0/24 and 10.20.30.0/24
        execute_authorized_scan(
            db=db,
            target="192.168.56.0/24",
            scan_profile="LAB_SIMULATION_BASELINE",
            initiated_by="autonomous-scheduler",
            simulation_scenario="BASELINE",
        )
        execute_authorized_scan(
            db=db,
            target="10.20.30.0/24",
            scan_profile="STANDARD_TCP_INTEL",
            initiated_by="autonomous-scheduler",
            simulation_scenario="BASELINE",
        )
        # Stage B: Subsequent Drift Scan on 192.168.56.0/24 (detects new MySQL 3306, SSH on 8080 mismatch, new Shadow Docker host .45, RDP opened on .30)
        execute_authorized_scan(
            db=db,
            target="192.168.56.0/24",
            scan_profile="STANDARD_TCP_INTEL",
            initiated_by="sinan.mohammed",
            simulation_scenario="ENTERPRISE_DRIFT",
        )

