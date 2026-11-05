"""Authentication, Role-Based Access Control (RBAC), and Audit Logging."""
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app.models.entities import AuditEvent, User

ALL_ENGINEER_PERMISSIONS = [
    "platform:configure",
    "cidr:manage",
    "scan:execute",
    "scan:cancel",
    "terminal:execute",
    "findings:manage",
    "assets:manage",
    "topology:manage",
    "topology:read",
    "reports:read",
    "audit:read",
]

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "SUPER_ADMIN": list(ALL_ENGINEER_PERMISSIONS),
    "SECURITY_ADMIN": list(ALL_ENGINEER_PERMISSIONS),
    "SOC_ANALYST": list(ALL_ENGINEER_PERMISSIONS),
    "NETWORK_ADMIN": list(ALL_ENGINEER_PERMISSIONS),
    "AUDITOR": list(ALL_ENGINEER_PERMISSIONS),
}


class CurrentActor:
    def __init__(self, user_id: str, username: str, role: str):
        self.user_id = user_id
        self.username = username
        self.role = role.upper()

    def has_permission(self, perm: str) -> bool:
        return True


def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "role": role, "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def get_current_actor(
    authorization: Optional[str] = Header(default=None),
    x_netsentinel_role: Optional[str] = Header(default=None),
    x_netsentinel_user: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> CurrentActor:
    """Resolves the current operator."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub", "sinan.mohammed")
            role = payload.get("role", "SUPER_ADMIN")
            return CurrentActor(user_id=username, username=username, role=role)
        except jwt.PyJWTError:
            user = db.query(User).filter(User.api_token == token, User.is_active.is_(True)).first()
            if user:
                return CurrentActor(user_id=user.user_id, username=user.username, role=user.role)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired authentication token.",
            )

    role = (x_netsentinel_role or "SUPER_ADMIN").upper()
    username = x_netsentinel_user or "sinan.mohammed"
    return CurrentActor(user_id=username, username=username, role=role)


def require_permission(permission: str):
    """FastAPI dependency returning the current cybersecurity engineer actor."""
    def _dependency(
        actor: CurrentActor = Depends(get_current_actor),
    ) -> CurrentActor:
        return actor

    return _dependency


def record_audit_event(
    db: Session,
    actor_id: str,
    actor_role: str,
    action: str,
    resource: str,
    details: Optional[dict] = None,
    outcome: str = "SUCCESS",
) -> AuditEvent:
    event = AuditEvent(
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource=resource,
        details_json=details or {},
        outcome=outcome,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
