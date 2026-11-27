"""Policy Enforcement Point (PEP) Gateway & Zero Trust Session/Auth Services."""

from __future__ import annotations

import secrets
import sqlite3
import time
from typing import Any

from .audit import record_audit_event
from .config import CONFIG
from .crypto import sign_token, verify_password, verify_token, verify_totp
from .policy_engine import evaluate_access_request
from .risk_engine import compute_device_trust_score


def authenticate_user(
    conn: sqlite3.Connection,
    *,
    email: str,
    password: str,
    device_id: str,
    ip_address: str = "10.24.1.15",
    geo_location: str = "US-SFO",
    totp_code: str | None = None,
) -> dict[str, Any]:
    """Authenticate identity + verify password + optional TOTP MFA and issue short-lived JWT."""
    now = int(time.time())
    row = conn.execute("SELECT * FROM identities WHERE email = ?", (email.strip().lower(),)).fetchone()
    if not row:
        record_audit_event(
            conn,
            event_type="AUTH",
            actor_id="unknown",
            actor_email=email,
            device_id=device_id,
            resource_id="auth-gateway",
            action="LOGIN",
            decision="DENY",
            risk_score=75,
            reason="Unknown identity attempted login",
            details={"ip_address": ip_address, "geo_location": geo_location},
            timestamp=now,
        )
        return {"ok": False, "status_code": 401, "error": "Invalid credentials"}

    identity = dict(row)
    if identity["status"] != "active":
        record_audit_event(
            conn,
            event_type="AUTH",
            actor_id=identity["id"],
            actor_email=identity["email"],
            device_id=device_id,
            resource_id="auth-gateway",
            action="LOGIN",
            decision="DENY",
            risk_score=95,
            reason=f"Login blocked: identity status is '{identity['status']}'",
            details={"ip_address": ip_address, "geo_location": geo_location},
            timestamp=now,
        )
        return {"ok": False, "status_code": 403, "error": f"Account is {identity['status']}"}

    if not verify_password(password, identity["password_hash"]):
        new_attempts = int(identity["failed_attempts"]) + 1
        new_status = "locked" if new_attempts >= CONFIG.max_failed_attempts else identity["status"]
        conn.execute(
            "UPDATE identities SET failed_attempts = ?, status = ? WHERE id = ?",
            (new_attempts, new_status, identity["id"]),
        )
        record_audit_event(
            conn,
            event_type="ANOMALY" if new_attempts >= 3 else "AUTH",
            actor_id=identity["id"],
            actor_email=identity["email"],
            device_id=device_id,
            resource_id="auth-gateway",
            action="LOGIN",
            decision="DENY",
            risk_score=min(100, 40 + new_attempts * 15),
            reason=(
                f"Account auto-locked after {new_attempts} failed password attempts"
                if new_status == "locked"
                else f"Invalid password (attempt {new_attempts})"
            ),
            details={"ip_address": ip_address, "geo_location": geo_location, "failed_attempts": new_attempts},
            timestamp=now,
        )
        return {"ok": False, "status_code": 401, "error": "Invalid credentials"}

    dev_row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not dev_row:
        return {"ok": False, "status_code": 400, "error": f"Unknown device '{device_id}'"}
    device = dict(dev_row)
    if device["quarantined"]:
        record_audit_event(
            conn,
            event_type="AUTH",
            actor_id=identity["id"],
            actor_email=identity["email"],
            device_id=device_id,
            resource_id="auth-gateway",
            action="LOGIN",
            decision="DENY",
            risk_score=100,
            reason="Login denied: endpoint device is quarantined",
            details={"ip_address": ip_address, "geo_location": geo_location},
            timestamp=now,
        )
        return {"ok": False, "status_code": 403, "error": "Device is quarantined"}

    mfa_verified = False
    if totp_code:
        if not verify_totp(
            identity["totp_secret"],
            totp_code,
            for_time=now,
            step=CONFIG.totp_step_seconds,
            digits=CONFIG.totp_digits,
            window=CONFIG.totp_window,
        ):
            record_audit_event(
                conn,
                event_type="AUTH",
                actor_id=identity["id"],
                actor_email=identity["email"],
                device_id=device_id,
                resource_id="auth-gateway",
                action="MFA_VERIFY",
                decision="DENY",
                risk_score=70,
                reason="Invalid TOTP MFA code supplied",
                details={"ip_address": ip_address, "geo_location": geo_location},
                timestamp=now,
            )
            return {"ok": False, "status_code": 401, "error": "Invalid MFA TOTP code"}
        mfa_verified = True

    # Reset failed attempts and record session
    jti = secrets.token_hex(16)
    expires_at = now + CONFIG.access_token_ttl_seconds
    step_up_until = (now + CONFIG.step_up_ttl_seconds) if mfa_verified else 0

    conn.execute(
        "UPDATE identities SET failed_attempts = 0, last_known_geo = ?, last_login_at = ? WHERE id = ?",
        (geo_location, now, identity["id"]),
    )
    conn.execute(
        """
        INSERT INTO sessions (
            id, identity_id, device_id, ip_address, geo_location,
            mfa_verified, step_up_until, risk_score_at_issue, revoked, expires_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (jti, identity["id"], device_id, ip_address, geo_location, int(mfa_verified), step_up_until, 0, expires_at, now),
    )

    token = sign_token(
        {
            "sub": identity["id"],
            "email": identity["email"],
            "role": identity["role"],
            "device_id": device_id,
            "jti": jti,
        },
        CONFIG.jwt_secret,
        CONFIG.access_token_ttl_seconds,
    )

    record_audit_event(
        conn,
        event_type="AUTH",
        actor_id=identity["id"],
        actor_email=identity["email"],
        device_id=device_id,
        resource_id="auth-gateway",
        action="LOGIN",
        decision="ALLOW",
        risk_score=10 if mfa_verified else 30,
        reason="Short-lived Zero Trust session issued" + (" with TOTP MFA" if mfa_verified else " (MFA pending)"),
        details={"session_id": jti, "mfa_verified": mfa_verified, "geo_location": geo_location},
        timestamp=now,
    )

    return {
        "ok": True,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": CONFIG.access_token_ttl_seconds,
        "session": {
            "id": jti,
            "identity_id": identity["id"],
            "email": identity["email"],
            "role": identity["role"],
            "device_id": device_id,
            "mfa_verified": mfa_verified,
            "step_up_until": step_up_until,
            "expires_at": expires_at,
        },
    }


def verify_step_up_mfa(
    conn: sqlite3.Connection, *, token: str, totp_code: str
) -> dict[str, Any]:
    """Elevate an active Zero Trust session via TOTP MFA step-up verification."""
    now = int(time.time())
    claims = verify_token(token, CONFIG.jwt_secret)
    if not claims:
        return {"ok": False, "status_code": 401, "error": "Invalid or expired token"}

    sess_row = conn.execute("SELECT * FROM sessions WHERE id = ?", (claims["jti"],)).fetchone()
    if not sess_row or sess_row["revoked"] or int(sess_row["expires_at"]) <= now:
        return {"ok": False, "status_code": 401, "error": "Session revoked or expired"}

    id_row = conn.execute("SELECT * FROM identities WHERE id = ?", (claims["sub"],)).fetchone()
    if not id_row or id_row["status"] != "active":
        return {"ok": False, "status_code": 403, "error": "Identity unavailable"}

    if not verify_totp(
        id_row["totp_secret"],
        totp_code,
        for_time=now,
        step=CONFIG.totp_step_seconds,
        digits=CONFIG.totp_digits,
        window=CONFIG.totp_window,
    ):
        record_audit_event(
            conn,
            event_type="AUTH",
            actor_id=id_row["id"],
            actor_email=id_row["email"],
            device_id=sess_row["device_id"],
            resource_id="auth-gateway",
            action="STEP_UP_MFA",
            decision="DENY",
            risk_score=72,
            reason="Step-Up MFA challenge failed: invalid TOTP code",
            details={"session_id": sess_row["id"]},
            timestamp=now,
        )
        return {"ok": False, "status_code": 401, "error": "Invalid TOTP code"}

    step_up_until = now + CONFIG.step_up_ttl_seconds
    conn.execute(
        "UPDATE sessions SET mfa_verified = 1, step_up_until = ? WHERE id = ?",
        (step_up_until, sess_row["id"]),
    )
    record_audit_event(
        conn,
        event_type="AUTH",
        actor_id=id_row["id"],
        actor_email=id_row["email"],
        device_id=sess_row["device_id"],
        resource_id="auth-gateway",
        action="STEP_UP_MFA",
        decision="ALLOW",
        risk_score=8,
        reason="Session elevated via Step-Up TOTP MFA",
        details={"session_id": sess_row["id"], "step_up_until": step_up_until},
        timestamp=now,
    )
    return {"ok": True, "mfa_verified": True, "step_up_until": step_up_until}


def enforce_resource_access(
    conn: sqlite3.Connection,
    *,
    token: str,
    resource_id: str,
    ip_address: str | None = None,
    geo_location: str | None = None,
    hour_utc: int | None = None,
) -> dict[str, Any]:
    """Enforce Zero Trust policy on a live protected micro-segmented resource request."""
    now = int(time.time())
    claims = verify_token(token, CONFIG.jwt_secret)
    if not claims:
        record_audit_event(
            conn,
            event_type="ACCESS_DECISION",
            actor_id="anonymous",
            actor_email="anonymous",
            device_id="unknown",
            resource_id=resource_id,
            action="ACCESS_RESOURCE",
            decision="DENY",
            risk_score=90,
            reason="Missing, tampered, or expired Zero Trust bearer token",
            details={},
            timestamp=now,
        )
        return {"ok": False, "status_code": 401, "decision": "DENY", "error": "Invalid or expired token"}

    sess_row = conn.execute("SELECT * FROM sessions WHERE id = ?", (claims["jti"],)).fetchone()
    if not sess_row or sess_row["revoked"] or int(sess_row["expires_at"]) <= now:
        record_audit_event(
            conn,
            event_type="ACCESS_DECISION",
            actor_id=claims["sub"],
            actor_email=claims.get("email", "unknown"),
            device_id=claims.get("device_id", "unknown"),
            resource_id=resource_id,
            action="ACCESS_RESOURCE",
            decision="DENY",
            risk_score=92,
            reason="Zero Trust session has been revoked or expired",
            details={"session_id": claims["jti"]},
            timestamp=now,
        )
        return {"ok": False, "status_code": 401, "decision": "DENY", "error": "Session revoked or expired"}

    identity = dict(conn.execute("SELECT * FROM identities WHERE id = ?", (claims["sub"],)).fetchone())
    device = dict(conn.execute("SELECT * FROM devices WHERE id = ?", (sess_row["device_id"],)).fetchone())
    res_row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
    if not res_row:
        return {"ok": False, "status_code": 404, "decision": "DENY", "error": "Unknown micro-segmented resource"}
    resource = dict(res_row)

    eff_ip = ip_address or sess_row["ip_address"]
    eff_geo = geo_location or sess_row["geo_location"]
    fresh_mfa = bool(sess_row["mfa_verified"]) and int(sess_row["step_up_until"]) > now

    decision = evaluate_access_request(
        conn,
        identity=identity,
        device=device,
        resource=resource,
        ip_address=eff_ip,
        geo_location=eff_geo,
        mfa_verified=fresh_mfa,
        hour_utc=hour_utc,
        now=now,
    )

    # Refresh persisted device trust score
    trust_score, _ = compute_device_trust_score(device)
    conn.execute("UPDATE devices SET trust_score = ?, last_seen_at = ? WHERE id = ?", (trust_score, now, device["id"]))

    event_type = "ANOMALY" if decision.anomalies else "ACCESS_DECISION"
    record_audit_event(
        conn,
        event_type=event_type,
        actor_id=identity["id"],
        actor_email=identity["email"],
        device_id=device["id"],
        resource_id=resource["id"],
        action="ACCESS_RESOURCE",
        decision=decision.decision,
        risk_score=decision.risk_score,
        reason=decision.reason,
        details={
            "matched_policy": decision.matched_policy,
            "anomalies": decision.anomalies,
            "ip_address": eff_ip,
            "geo_location": eff_geo,
        },
        timestamp=now,
    )

    if decision.decision == "ALLOW":
        return {
            "ok": True,
            "status_code": 200,
            **decision.to_dict(),
            "resource": {
                "id": resource["id"],
                "name": resource["name"],
                "segment": resource["segment"],
                "classification": resource["classification"],
                "data": resource["sensitive_data_preview"],
            },
        }
    if decision.decision == "STEP_UP":
        return {
            "ok": False,
            "status_code": 403,
            **decision.to_dict(),
            "challenge": "STEP_UP_MFA_REQUIRED",
        }
    return {
        "ok": False,
        "status_code": 403,
        **decision.to_dict(),
    }
