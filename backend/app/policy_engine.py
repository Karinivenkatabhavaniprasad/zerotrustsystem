"""NIST SP 800-207 Policy Decision Point (PDP): ABAC + RBAC + Micro-Segmentation + Risk Gate."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from .risk_engine import RiskAssessment, evaluate_continuous_risk


@dataclass
class PolicyDecision:
    decision: str  # ALLOW | STEP_UP | DENY
    risk_score: int
    device_trust_score: int
    risk_level: str
    matched_policy: str
    reason: str
    anomalies: list[str] = field(default_factory=list)
    risk_factors: list[dict[str, Any]] = field(default_factory=list)
    rule_trace: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_score": self.risk_score,
            "device_trust_score": self.device_trust_score,
            "risk_level": self.risk_level,
            "matched_policy": self.matched_policy,
            "reason": self.reason,
            "anomalies": self.anomalies,
            "risk_factors": self.risk_factors,
            "rule_trace": self.rule_trace,
        }


def _policy_matches(
    policy: dict[str, Any],
    *,
    identity: dict[str, Any],
    device: dict[str, Any],
    resource: dict[str, Any],
    geo_location: str,
    mfa_verified: bool,
    risk: RiskAssessment,
) -> tuple[bool, str]:
    """Evaluate a single ABAC policy's JSON conditions uniformly against context."""
    cond = json.loads(policy["conditions_json"])
    effect = policy["effect"]

    # Optional scope filters (if specified, request must match them for rule to apply)
    if "roles" in cond and identity["role"] not in cond["roles"]:
        return False, "Role outside policy scope"
    if "segments" in cond and resource["segment"] not in cond["segments"]:
        return False, "Segment outside policy scope"
    if "classifications" in cond and resource["classification"] not in cond["classifications"]:
        return False, "Classification outside policy scope"

    if effect == "DENY":
        if cond.get("block_quarantined") and device.get("quarantined"):
            return True, "Device is quarantined"
        if cond.get("block_jailbroken") and device.get("jailbroken"):
            return True, "Device integrity compromised (jailbroken/rooted)"
        if "blocked_geos" in cond and geo_location in cond["blocked_geos"]:
            return True, f"Geo origin {geo_location} is blocked by policy"
        if "min_risk_to_trigger" in cond and risk.risk_score >= int(cond["min_risk_to_trigger"]):
            return True, f"Continuous risk score {risk.risk_score} >= threshold {cond['min_risk_to_trigger']}"
        if cond.get("require_managed") and not device.get("managed"):
            return True, "Unmanaged device denied on sensitive micro-segment"
        if cond.get("require_edr") and not device.get("edr_active"):
            return True, "Endpoint without active EDR denied on sensitive micro-segment"
        if cond.get("require_disk_encrypted") and not device.get("disk_encrypted"):
            return True, "Unencrypted endpoint denied on sensitive micro-segment"
        # Purely scoped deny (e.g. role + segment match without extra predicates)
        predicate_keys = {
            "block_quarantined",
            "block_jailbroken",
            "blocked_geos",
            "min_risk_to_trigger",
            "require_managed",
            "require_edr",
            "require_disk_encrypted",
        }
        if not (predicate_keys & cond.keys()):
            return True, f"Explicit deny rule matched ({policy['name']})"
        return False, "Deny conditions not met"

    if effect == "STEP_UP":
        if cond.get("enforce_resource_mfa") and resource.get("require_mfa") and not mfa_verified:
            return True, f"Resource '{resource['name']}' requires active MFA verification"
        r_min = cond.get("risk_min")
        r_max = cond.get("risk_max")
        if r_min is not None and r_max is not None and int(r_min) <= risk.risk_score <= int(r_max):
            if not mfa_verified:
                return True, f"Elevated risk score ({risk.risk_score}) requires Step-Up MFA"
        return False, "Step-up not required"

    if effect == "ALLOW":
        max_risk = int(cond.get("max_risk", 35))
        if risk.risk_score <= max_risk:
            return True, f"Risk score ({risk.risk_score}) within allowed threshold (<= {max_risk})"
        return False, f"Risk score ({risk.risk_score}) exceeds allow threshold ({max_risk})"

    return False, f"Unsupported effect '{effect}'"


def evaluate_access_request(
    conn: sqlite3.Connection,
    *,
    identity: dict[str, Any],
    device: dict[str, Any],
    resource: dict[str, Any],
    ip_address: str,
    geo_location: str,
    mfa_verified: bool,
    hour_utc: int | None = None,
    now: int | None = None,
) -> PolicyDecision:
    """Evaluate a Zero Trust access request through PDP gates (Identity, RBAC, ABAC, Risk)."""
    risk = evaluate_continuous_risk(
        identity=identity,
        device=device,
        resource=resource,
        ip_address=ip_address,
        geo_location=geo_location,
        mfa_verified=mfa_verified,
        hour_utc=hour_utc,
        now=now,
    )

    trace: list[dict[str, Any]] = []

    # Gate 1: Identity status ("Never trust, always verify")
    if identity["status"] != "active":
        trace.append({"gate": "identity_status", "result": "FAIL", "detail": f"Status={identity['status']}"})
        return PolicyDecision(
            decision="DENY",
            risk_score=100,
            device_trust_score=risk.device_trust_score,
            risk_level="CRITICAL",
            matched_policy="gate-identity-status",
            reason=f"Identity '{identity['email']}' is {identity['status']}.",
            anomalies=risk.anomalies,
            risk_factors=risk.factors,
            rule_trace=trace,
        )
    trace.append({"gate": "identity_status", "result": "PASS", "detail": "Identity active"})

    # Gate 2: Device ownership / binding check
    if device["owner_id"] != identity["id"] and identity["role"] != "secops_admin":
        trace.append({
            "gate": "device_binding",
            "result": "FAIL",
            "detail": f"Device {device['id']} belongs to {device['owner_id']}, not {identity['id']}",
        })
        return PolicyDecision(
            decision="DENY",
            risk_score=max(risk.risk_score, 85),
            device_trust_score=risk.device_trust_score,
            risk_level="CRITICAL",
            matched_policy="gate-device-binding",
            reason="Device-to-identity cryptographic binding mismatch.",
            anomalies=[*risk.anomalies, "DEVICE_IDENTITY_MISMATCH"],
            risk_factors=risk.factors,
            rule_trace=trace,
        )
    trace.append({"gate": "device_binding", "result": "PASS", "detail": f"Device {device['id']} bound"})

    # Gate 3: Micro-segmentation RBAC & Clearance (Least Privilege)
    allowed_roles = json.loads(resource["allowed_roles_json"])
    if identity["role"] not in allowed_roles:
        trace.append({
            "gate": "microseg_rbac",
            "result": "FAIL",
            "detail": f"Role '{identity['role']}' not in {allowed_roles}",
        })
        return PolicyDecision(
            decision="DENY",
            risk_score=risk.risk_score,
            device_trust_score=risk.device_trust_score,
            risk_level=risk.risk_level,
            matched_policy="gate-least-privilege-rbac",
            reason=f"Role '{identity['role']}' is not authorized for micro-segment '{resource['segment']}'.",
            anomalies=risk.anomalies,
            risk_factors=risk.factors,
            rule_trace=trace,
        )

    if int(identity["clearance_level"]) < int(resource["min_clearance"]):
        trace.append({
            "gate": "clearance_level",
            "result": "FAIL",
            "detail": f"Clearance L{identity['clearance_level']} < required L{resource['min_clearance']}",
        })
        return PolicyDecision(
            decision="DENY",
            risk_score=risk.risk_score,
            device_trust_score=risk.device_trust_score,
            risk_level=risk.risk_level,
            matched_policy="gate-clearance-level",
            reason=f"Clearance level {identity['clearance_level']} is below required level {resource['min_clearance']}.",
            anomalies=risk.anomalies,
            risk_factors=risk.factors,
            rule_trace=trace,
        )
    trace.append({
        "gate": "microseg_rbac",
        "result": "PASS",
        "detail": f"Role '{identity['role']}' & clearance L{identity['clearance_level']} authorized",
    })

    if resource.get("require_managed_device") and not device.get("managed"):
        trace.append({
            "gate": "resource_managed_device",
            "result": "FAIL",
            "detail": "Resource requires corporate MDM-managed device",
        })
        return PolicyDecision(
            decision="DENY",
            risk_score=risk.risk_score,
            device_trust_score=risk.device_trust_score,
            risk_level=risk.risk_level,
            matched_policy="gate-managed-device",
            reason=f"Resource '{resource['name']}' requires a corporate managed device.",
            anomalies=risk.anomalies,
            risk_factors=risk.factors,
            rule_trace=trace,
        )
    trace.append({"gate": "resource_managed_device", "result": "PASS", "detail": "Device posture gate passed"})

    # Gate 4: Ordered ABAC policies from SQLite
    policies = [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM policies WHERE enabled = 1 ORDER BY priority ASC, id ASC"
        ).fetchall()
    ]

    for pol in policies:
        matched, detail = _policy_matches(
            pol,
            identity=identity,
            device=device,
            resource=resource,
            geo_location=geo_location,
            mfa_verified=mfa_verified,
            risk=risk,
        )
        trace.append({
            "gate": f"policy:{pol['id']}",
            "policy_name": pol["name"],
            "effect": pol["effect"],
            "result": "MATCH" if matched else "SKIP",
            "detail": detail,
        })
        if matched:
            return PolicyDecision(
                decision=pol["effect"],
                risk_score=risk.risk_score,
                device_trust_score=risk.device_trust_score,
                risk_level=risk.risk_level,
                matched_policy=pol["id"],
                reason=detail,
                anomalies=risk.anomalies,
                risk_factors=risk.factors,
                rule_trace=trace,
            )

    # Gate 5: Default-Deny Posture (never fail-open)
    trace.append({"gate": "default_deny", "result": "DENY", "detail": "No explicit ALLOW policy matched"})
    return PolicyDecision(
        decision="DENY",
        risk_score=risk.risk_score,
        device_trust_score=risk.device_trust_score,
        risk_level=risk.risk_level,
        matched_policy="default-deny",
        reason="Default-deny: request did not satisfy any active ALLOW policy.",
        anomalies=risk.anomalies,
        risk_factors=risk.factors,
        rule_trace=trace,
    )
