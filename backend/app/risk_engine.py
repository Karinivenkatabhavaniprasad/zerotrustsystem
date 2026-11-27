"""Continuous Risk Scoring Engine & Device Posture Evaluator."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from .config import CONFIG
from .database import GEO_COORDS

UNTRUSTED_IP_PREFIXES = ("185.220.", "45.155.", "198.98.", "104.244.")
HIGH_RISK_GEOS = {"RU-MOW", "KP-FNJ", "IR-THR"}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle distance in kilometers between two coordinates."""
    r = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * r * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@dataclass
class RiskFactor:
    code: str
    category: str
    delta: int
    description: str


@dataclass
class RiskAssessment:
    risk_score: int
    device_trust_score: int
    risk_level: str
    anomalies: list[str] = field(default_factory=list)
    factors: list[dict[str, Any]] = field(default_factory=list)


def compute_device_trust_score(device: dict[str, Any]) -> tuple[int, list[RiskFactor]]:
    """Compute a 0-100 device posture score from security telemetry."""
    if device.get("quarantined"):
        return 0, [
            RiskFactor("DEV_QUARANTINED", "device", 100, "Device is actively quarantined by SecOps")
        ]

    trust = 100
    factors: list[RiskFactor] = []

    if not device.get("managed"):
        trust -= 28
        factors.append(RiskFactor("DEV_UNMANAGED", "device", 25, "Unmanaged BYOD device (no MDM enrollment)"))
    if not device.get("disk_encrypted"):
        trust -= 22
        factors.append(RiskFactor("DEV_NO_DISK_ENC", "device", 20, "Full-disk encryption is disabled"))
    if not device.get("edr_active"):
        trust -= 22
        factors.append(RiskFactor("DEV_NO_EDR", "device", 20, "Endpoint Detection & Response (EDR) agent inactive"))

    patch_age = int(device.get("patch_age_days", 0))
    if patch_age > 90:
        trust -= 20
        factors.append(RiskFactor("DEV_PATCH_CRITICAL", "device", 18, f"OS security patches {patch_age} days overdue"))
    elif patch_age > 30:
        trust -= 10
        factors.append(RiskFactor("DEV_PATCH_STALE", "device", 10, f"OS security patches {patch_age} days old"))

    if device.get("jailbroken"):
        trust -= 50
        factors.append(RiskFactor("DEV_JAILBROKEN", "device", 45, "Rooted/jailbroken OS integrity violation"))

    return max(0, trust), factors


def evaluate_continuous_risk(
    *,
    identity: dict[str, Any],
    device: dict[str, Any],
    resource: dict[str, Any],
    ip_address: str,
    geo_location: str,
    mfa_verified: bool,
    hour_utc: int | None = None,
    now: int | None = None,
) -> RiskAssessment:
    """Evaluate continuous risk (0-100) across identity, device, network, and geo telemetry."""
    current_ts = now if now is not None else int(time.time())
    utc_hour = hour_utc if hour_utc is not None else time.gmtime(current_ts).tm_hour

    device_trust, factors = compute_device_trust_score(device)
    anomalies: list[str] = []

    if device.get("quarantined"):
        anomalies.append("QUARANTINED_DEVICE")
    if device.get("jailbroken"):
        anomalies.append("COMPROMISED_ENDPOINT_INTEGRITY")

    # Identity signals
    if identity.get("status") != "active":
        factors.append(
            RiskFactor("ID_NOT_ACTIVE", "identity", 100, f"Identity status is '{identity.get('status')}'")
        )
        anomalies.append("INACTIVE_OR_LOCKED_IDENTITY")

    failed_attempts = int(identity.get("failed_attempts", 0))
    if failed_attempts > 0:
        penalty = min(30, failed_attempts * 10)
        factors.append(
            RiskFactor("ID_FAILED_LOGINS", "identity", penalty, f"{failed_attempts} recent failed login attempts")
        )
        if failed_attempts >= 3:
            anomalies.append("BRUTE_FORCE_SUSPECTED")

    if not mfa_verified:
        factors.append(
            RiskFactor("AUTH_NO_MFA", "identity", 20, "Session lacks fresh MFA verification")
        )

    if identity.get("role") == "contractor":
        factors.append(
            RiskFactor("ID_EXTERNAL_CONTRACTOR", "identity", 10, "External vendor identity carries elevated baseline risk")
        )

    # Network & Tor/Proxy heuristics
    if ip_address.startswith(UNTRUSTED_IP_PREFIXES):
        factors.append(
            RiskFactor("NET_ANONYMIZER_IP", "network", 32, f"Request originates from known anonymizer/Tor range ({ip_address})")
        )
        anomalies.append("TOR_OR_ANONYMIZER_EXIT")

    if geo_location in HIGH_RISK_GEOS:
        factors.append(
            RiskFactor("GEO_HIGH_RISK", "geo", 40, f"High-risk / sanctioned origin region ({geo_location})")
        )
        anomalies.append("HIGH_RISK_GEO_ORIGIN")

    # Impossible travel check against last known login location and timestamp
    prev_geo = identity.get("last_known_geo")
    prev_ts = int(identity.get("last_login_at") or 0)
    if prev_geo and prev_geo != geo_location and prev_ts > 0:
        coord_a = GEO_COORDS.get(prev_geo)
        coord_b = GEO_COORDS.get(geo_location)
        if coord_a and coord_b:
            dist_km = _haversine_km(coord_a[0], coord_a[1], coord_b[0], coord_b[1])
            elapsed_hours = max(0.05, (current_ts - prev_ts) / 3600.0)
            speed_kmh = dist_km / elapsed_hours
            if dist_km > 500 and speed_kmh > CONFIG.impossible_travel_speed_kmh:
                factors.append(
                    RiskFactor(
                        "GEO_IMPOSSIBLE_TRAVEL",
                        "geo",
                        45,
                        f"Impossible travel detected: {prev_geo} -> {geo_location} ({int(dist_km)} km in {elapsed_hours:.1f}h = {int(speed_kmh)} km/h)",
                    )
                )
                anomalies.append("IMPOSSIBLE_TRAVEL")

    # Off-hours behavioral signal for non-SecOps roles
    if 0 <= utc_hour < 5 and identity.get("role") != "secops_admin":
        factors.append(
            RiskFactor("TIME_OFF_HOURS", "behavior", 10, f"Access attempted during off-hours ({utc_hour:02d}:00 UTC)")
        )

    # Resource sensitivity baseline adjustment
    if resource.get("classification") == "restricted" and not mfa_verified:
        factors.append(
            RiskFactor("RES_RESTRICTED_NO_MFA", "resource", 10, "Restricted segment requested without active MFA")
        )

    raw_score = sum(f.delta for f in factors)
    risk_score = max(0, min(100, raw_score))

    if risk_score <= CONFIG.allow_max_risk:
        risk_level = "LOW"
    elif risk_score <= CONFIG.step_up_max_risk:
        risk_level = "MEDIUM"
    else:
        risk_level = "CRITICAL"

    return RiskAssessment(
        risk_score=risk_score,
        device_trust_score=device_trust,
        risk_level=risk_level,
        anomalies=anomalies,
        factors=[
            {
                "code": f.code,
                "category": f.category,
                "delta": f.delta,
                "description": f.description,
            }
            for f in factors
        ],
    )
