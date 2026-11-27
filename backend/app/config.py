"""Configuration and security constants for the Zero Trust System."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "zerotrust.db"


@dataclass(frozen=True)
class SecurityConfig:
    """Centralized Zero Trust security policy thresholds and token lifetimes."""

    db_path: str = os.environ.get("ZT_DB_PATH", str(DEFAULT_DB_PATH))
    jwt_secret: str = os.environ.get(
        "ZT_JWT_SECRET", "zt-dev-ephemeral-signing-key-change-in-prod-9f4a2c"
    )
    access_token_ttl_seconds: int = int(os.environ.get("ZT_ACCESS_TTL", "900"))  # 15 min short-lived
    step_up_ttl_seconds: int = int(os.environ.get("ZT_STEPUP_TTL", "300"))  # 5 min elevated window
    totp_step_seconds: int = 30
    totp_digits: int = 6
    totp_window: int = 1
    # Risk score thresholds (0 = lowest risk, 100 = highest risk)
    allow_max_risk: int = 35
    step_up_max_risk: int = 65
    # Above step_up_max_risk (> 65) -> DENY
    max_failed_attempts: int = 4
    impossible_travel_speed_kmh: float = 900.0


CONFIG = SecurityConfig()
