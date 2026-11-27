"""Starlette ASGI Application for the Zero Trust Control Plane & PEP Gateway."""

from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from .audit import record_audit_event, verify_audit_chain
from .config import CONFIG
from .crypto import compute_totp, verify_token
from .database import GEO_COORDS, get_db, init_db
from .pep_gateway import authenticate_user, enforce_resource_access, verify_step_up_mfa
from .policy_engine import evaluate_access_request
from .risk_engine import compute_device_trust_score

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(_app: Starlette):
    init_db()
    yield


def _extract_bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


async def _read_json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "architecture": "NIST SP 800-207 Zero Trust"})


async def overview(_request: Request) -> JSONResponse:
    now = int(time.time())
    with get_db() as conn:
        audit_rows = conn.execute(
            "SELECT decision, event_type, risk_score FROM audit_logs"
        ).fetchall()
        devices = conn.execute("SELECT trust_score, quarantined FROM devices").fetchall()
        active_sessions = conn.execute(
            "SELECT COUNT(*) AS cnt FROM sessions WHERE revoked = 0 AND expires_at > ?",
            (now,),
        ).fetchone()["cnt"]
        locked_identities = conn.execute(
            "SELECT COUNT(*) AS cnt FROM identities WHERE status != 'active'"
        ).fetchone()["cnt"]
        enabled_policies = conn.execute(
            "SELECT COUNT(*) AS cnt FROM policies WHERE enabled = 1"
        ).fetchone()["cnt"]
        integrity = verify_audit_chain(conn)

    decisions = {"ALLOW": 0, "STEP_UP": 0, "DENY": 0}
    anomalies = 0
    risk_sum = 0
    decision_count = 0
    for row in audit_rows:
        dec = row["decision"]
        if dec in decisions:
            decisions[dec] += 1
            decision_count += 1
            risk_sum += int(row["risk_score"])
        if row["event_type"] == "ANOMALY":
            anomalies += 1

    avg_device_trust = (
        round(sum(int(d["trust_score"]) for d in devices) / len(devices), 1)
        if devices
        else 0.0
    )
    quarantined_devices = sum(1 for d in devices if d["quarantined"])

    return JSONResponse({
        "decisions": decisions,
        "anomalies_detected": anomalies,
        "avg_risk_score": round(risk_sum / decision_count, 1) if decision_count else 0.0,
        "avg_device_trust": avg_device_trust,
        "quarantined_devices": quarantined_devices,
        "active_sessions": active_sessions,
        "locked_identities": locked_identities,
        "enabled_policies": enabled_policies,
        "audit_integrity": integrity,
        "geo_locations": list(GEO_COORDS.keys()),
    })


async def auth_login(request: Request) -> JSONResponse:
    data = await _read_json(request)
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    device_id = str(data.get("device_id", "")).strip()
    ip_address = str(data.get("ip_address", "10.24.1.15")).strip()
    geo_location = str(data.get("geo_location", "US-SFO")).strip()
    totp_code = data.get("totp_code")

    if not email or not password or not device_id:
        return JSONResponse(
            {"error": "email, password, and device_id are required"}, status_code=400
        )

    with get_db() as conn:
        result = authenticate_user(
            conn,
            email=email,
            password=password,
            device_id=device_id,
            ip_address=ip_address,
            geo_location=geo_location,
            totp_code=str(totp_code) if totp_code else None,
        )
    status = 200 if result.get("ok") else int(result.get("status_code", 401))
    return JSONResponse(result, status_code=status)


async def auth_step_up(request: Request) -> JSONResponse:
    token = _extract_bearer(request)
    if not token:
        return JSONResponse({"error": "Missing Bearer token"}, status_code=401)
    data = await _read_json(request)
    totp_code = str(data.get("totp_code", "")).strip()
    if not totp_code:
        return JSONResponse({"error": "totp_code is required"}, status_code=400)

    with get_db() as conn:
        result = verify_step_up_mfa(conn, token=token, totp_code=totp_code)
    status = 200 if result.get("ok") else int(result.get("status_code", 401))
    return JSONResponse(result, status_code=status)


async def auth_logout(request: Request) -> JSONResponse:
    token = _extract_bearer(request)
    if not token:
        return JSONResponse({"error": "Missing Bearer token"}, status_code=401)
    claims = verify_token(token, CONFIG.jwt_secret)
    if not claims:
        return JSONResponse({"error": "Invalid or expired token"}, status_code=401)

    with get_db() as conn:
        conn.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (claims["jti"],))
        record_audit_event(
            conn,
            event_type="AUTH",
            actor_id=claims["sub"],
            actor_email=claims.get("email", "unknown"),
            device_id=claims.get("device_id", "unknown"),
            resource_id="auth-gateway",
            action="LOGOUT",
            decision="INFO",
            risk_score=0,
            reason="Session explicitly terminated by user",
            details={"session_id": claims["jti"]},
        )
    return JSONResponse({"ok": True, "revoked_session_id": claims["jti"]})


async def demo_totp(request: Request) -> JSONResponse:
    identity_id = request.path_params["identity_id"]
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, email, totp_secret FROM identities WHERE id = ?", (identity_id,)
        ).fetchone()
    if not row:
        return JSONResponse({"error": "Identity not found"}, status_code=404)
    now = int(time.time())
    code = compute_totp(
        row["totp_secret"],
        for_time=now,
        step=CONFIG.totp_step_seconds,
        digits=CONFIG.totp_digits,
    )
    seconds_remaining = CONFIG.totp_step_seconds - (now % CONFIG.totp_step_seconds)
    return JSONResponse({
        "identity_id": row["id"],
        "email": row["email"],
        "totp_code": code,
        "seconds_remaining": seconds_remaining,
    })


async def pep_simulate(request: Request) -> JSONResponse:
    data = await _read_json(request)
    identity_id = str(data.get("identity_id", "")).strip()
    device_id = str(data.get("device_id", "")).strip()
    resource_id = str(data.get("resource_id", "")).strip()
    ip_address = str(data.get("ip_address", "10.24.1.15")).strip()
    geo_location = str(data.get("geo_location", "US-SFO")).strip()
    mfa_verified = bool(data.get("mfa_verified", True))
    hour_utc = data.get("hour_utc")
    record_audit = bool(data.get("record_audit", True))

    if not identity_id or not device_id or not resource_id:
        return JSONResponse(
            {"error": "identity_id, device_id, and resource_id are required"},
            status_code=400,
        )

    with get_db() as conn:
        id_row = conn.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
        dev_row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        res_row = conn.execute("SELECT * FROM resources WHERE id = ?", (resource_id,)).fetchone()
        if not id_row or not dev_row or not res_row:
            return JSONResponse({"error": "Invalid identity_id, device_id, or resource_id"}, status_code=404)

        identity = dict(id_row)
        device = dict(dev_row)
        resource = dict(res_row)

        decision = evaluate_access_request(
            conn,
            identity=identity,
            device=device,
            resource=resource,
            ip_address=ip_address,
            geo_location=geo_location,
            mfa_verified=mfa_verified,
            hour_utc=int(hour_utc) if hour_utc is not None else None,
        )

        if record_audit:
            record_audit_event(
                conn,
                event_type="ANOMALY" if decision.anomalies else "ACCESS_DECISION",
                actor_id=identity["id"],
                actor_email=identity["email"],
                device_id=device["id"],
                resource_id=resource["id"],
                action="PEP_SIMULATE",
                decision=decision.decision,
                risk_score=decision.risk_score,
                reason=decision.reason,
                details={
                    "matched_policy": decision.matched_policy,
                    "anomalies": decision.anomalies,
                    "ip_address": ip_address,
                    "geo_location": geo_location,
                    "mfa_verified": mfa_verified,
                },
            )

    payload = decision.to_dict()
    payload["resource_preview"] = (
        resource["sensitive_data_preview"] if decision.decision == "ALLOW" else None
    )
    return JSONResponse(payload)


async def list_resources(_request: Request) -> JSONResponse:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM resources ORDER BY min_clearance ASC").fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "name": r["name"],
            "segment": r["segment"],
            "classification": r["classification"],
            "min_clearance": r["min_clearance"],
            "require_managed_device": bool(r["require_managed_device"]),
            "require_mfa": bool(r["require_mfa"]),
            "allowed_roles": json.loads(r["allowed_roles_json"]),
        })
    return JSONResponse({"resources": items})


async def access_protected_resource(request: Request) -> JSONResponse:
    resource_id = request.path_params["resource_id"]
    token = _extract_bearer(request) or ""
    ip_address = request.headers.get("x-forwarded-for")
    geo_location = request.headers.get("x-geo-location")
    hour_hdr = request.headers.get("x-sim-hour-utc")

    with get_db() as conn:
        result = enforce_resource_access(
            conn,
            token=token,
            resource_id=resource_id,
            ip_address=ip_address,
            geo_location=geo_location,
            hour_utc=int(hour_hdr) if hour_hdr is not None else None,
        )
    return JSONResponse(result, status_code=int(result.get("status_code", 200)))


async def list_identities(_request: Request) -> JSONResponse:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, email, name, role, department, clearance_level,
                   mfa_enabled, status, failed_attempts, last_known_geo, last_login_at
            FROM identities ORDER BY clearance_level DESC
            """
        ).fetchall()
    return JSONResponse({"identities": [dict(r) for r in rows]})


async def update_identity(request: Request) -> JSONResponse:
    identity_id = request.path_params["identity_id"]
    data = await _read_json(request)
    new_status = data.get("status")
    reset_attempts = bool(data.get("reset_failed_attempts", False))
    last_known_geo = data.get("last_known_geo")

    if new_status and new_status not in {"active", "locked", "suspended"}:
        return JSONResponse({"error": "Invalid identity status"}, status_code=400)

    with get_db() as conn:
        row = conn.execute("SELECT * FROM identities WHERE id = ?", (identity_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "Identity not found"}, status_code=404)

        status_val = new_status or row["status"]
        attempts_val = 0 if (reset_attempts or new_status == "active") else row["failed_attempts"]
        geo_val = last_known_geo or row["last_known_geo"]

        conn.execute(
            "UPDATE identities SET status = ?, failed_attempts = ?, last_known_geo = ? WHERE id = ?",
            (status_val, attempts_val, geo_val, identity_id),
        )
        if status_val != "active":
            conn.execute("UPDATE sessions SET revoked = 1 WHERE identity_id = ?", (identity_id,))

        record_audit_event(
            conn,
            event_type="ADMIN_ACTION",
            actor_id="secops-console",
            actor_email="admin@corp.local",
            device_id="control-plane",
            resource_id=identity_id,
            action="UPDATE_IDENTITY",
            decision="INFO",
            risk_score=10 if status_val == "active" else 60,
            reason=f"Identity {row['email']} updated (status={status_val}, failed_attempts={attempts_val})",
            details={"status": status_val, "failed_attempts": attempts_val, "last_known_geo": geo_val},
        )
        updated = conn.execute(
            """
            SELECT id, email, name, role, department, clearance_level,
                   mfa_enabled, status, failed_attempts, last_known_geo, last_login_at
            FROM identities WHERE id = ?
            """,
            (identity_id,),
        ).fetchone()
    return JSONResponse({"identity": dict(updated)})


async def list_devices(_request: Request) -> JSONResponse:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY trust_score DESC").fetchall()
    items = []
    for d in rows:
        item = dict(d)
        for key in ("managed", "disk_encrypted", "edr_active", "jailbroken", "quarantined"):
            item[key] = bool(item[key])
        items.append(item)
    return JSONResponse({"devices": items})


async def update_device(request: Request) -> JSONResponse:
    device_id = request.path_params["device_id"]
    data = await _read_json(request)

    with get_db() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "Device not found"}, status_code=404)

        updated = dict(row)
        for bool_field in ("managed", "disk_encrypted", "edr_active", "jailbroken", "quarantined"):
            if bool_field in data:
                updated[bool_field] = int(bool(data[bool_field]))
        if "patch_age_days" in data:
            updated["patch_age_days"] = max(0, int(data["patch_age_days"]))

        trust_score, _ = compute_device_trust_score(updated)
        updated["trust_score"] = trust_score

        conn.execute(
            """
            UPDATE devices
            SET managed = ?, disk_encrypted = ?, edr_active = ?, patch_age_days = ?,
                jailbroken = ?, quarantined = ?, trust_score = ?
            WHERE id = ?
            """,
            (
                updated["managed"],
                updated["disk_encrypted"],
                updated["edr_active"],
                updated["patch_age_days"],
                updated["jailbroken"],
                updated["quarantined"],
                trust_score,
                device_id,
            ),
        )
        if updated["quarantined"]:
            conn.execute("UPDATE sessions SET revoked = 1 WHERE device_id = ?", (device_id,))

        record_audit_event(
            conn,
            event_type="ADMIN_ACTION",
            actor_id="secops-console",
            actor_email="admin@corp.local",
            device_id=device_id,
            resource_id="device-posture",
            action="UPDATE_DEVICE_POSTURE",
            decision="DENY" if updated["quarantined"] else "INFO",
            risk_score=100 - trust_score,
            reason=f"Device {updated['device_name']} posture updated (trust_score={trust_score}, quarantined={bool(updated['quarantined'])})",
            details={"trust_score": trust_score, "quarantined": bool(updated["quarantined"])},
        )

    for key in ("managed", "disk_encrypted", "edr_active", "jailbroken", "quarantined"):
        updated[key] = bool(updated[key])
    return JSONResponse({"device": updated})


async def list_policies(_request: Request) -> JSONResponse:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM policies ORDER BY priority ASC, id ASC").fetchall()
    items = []
    for p in rows:
        items.append({
            "id": p["id"],
            "name": p["name"],
            "description": p["description"],
            "priority": p["priority"],
            "effect": p["effect"],
            "enabled": bool(p["enabled"]),
            "conditions": json.loads(p["conditions_json"]),
        })
    return JSONResponse({"policies": items})


async def create_policy(request: Request) -> JSONResponse:
    data = await _read_json(request)
    pol_id = str(data.get("id", "")).strip() or f"pol-custom-{int(time.time())}"
    name = str(data.get("name", "")).strip()
    description = str(data.get("description", "")).strip()
    priority = int(data.get("priority", 55))
    effect = str(data.get("effect", "DENY")).upper()
    conditions = data.get("conditions", {})

    if not name or effect not in {"ALLOW", "STEP_UP", "DENY"} or not isinstance(conditions, dict):
        return JSONResponse(
            {"error": "Valid name, effect (ALLOW|STEP_UP|DENY), and conditions object required"},
            status_code=400,
        )

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO policies (id, name, description, priority, effect, enabled, conditions_json)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (pol_id, name, description or name, priority, effect, json.dumps(conditions)),
        )
        record_audit_event(
            conn,
            event_type="ADMIN_ACTION",
            actor_id="secops-console",
            actor_email="admin@corp.local",
            device_id="control-plane",
            resource_id=pol_id,
            action="CREATE_POLICY",
            decision="INFO",
            risk_score=0,
            reason=f"Created Zero Trust policy '{name}' ({effect}, priority={priority})",
            details={"conditions": conditions},
        )
    return JSONResponse(
        {
            "policy": {
                "id": pol_id,
                "name": name,
                "description": description or name,
                "priority": priority,
                "effect": effect,
                "enabled": True,
                "conditions": conditions,
            }
        },
        status_code=201,
    )


async def update_policy(request: Request) -> JSONResponse:
    policy_id = request.path_params["policy_id"]
    data = await _read_json(request)
    with get_db() as conn:
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "Policy not found"}, status_code=404)
        enabled = int(bool(data["enabled"])) if "enabled" in data else row["enabled"]
        priority = int(data["priority"]) if "priority" in data else row["priority"]
        conn.execute(
            "UPDATE policies SET enabled = ?, priority = ? WHERE id = ?",
            (enabled, priority, policy_id),
        )
        record_audit_event(
            conn,
            event_type="ADMIN_ACTION",
            actor_id="secops-console",
            actor_email="admin@corp.local",
            device_id="control-plane",
            resource_id=policy_id,
            action="UPDATE_POLICY",
            decision="INFO",
            risk_score=15 if not enabled else 0,
            reason=f"Policy '{row['name']}' updated (enabled={bool(enabled)}, priority={priority})",
            details={"enabled": bool(enabled), "priority": priority},
        )
        updated = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    return JSONResponse({
        "policy": {
            "id": updated["id"],
            "name": updated["name"],
            "description": updated["description"],
            "priority": updated["priority"],
            "effect": updated["effect"],
            "enabled": bool(updated["enabled"]),
            "conditions": json.loads(updated["conditions_json"]),
        }
    })


async def list_sessions(_request: Request) -> JSONResponse:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT s.*, i.email, i.name AS identity_name, i.role, d.device_name
            FROM sessions s
            JOIN identities i ON s.identity_id = i.id
            JOIN devices d ON s.device_id = d.id
            ORDER BY s.created_at DESC
            LIMIT 50
            """
        ).fetchall()
    now = int(time.time())
    items = []
    for r in rows:
        item = dict(r)
        item["mfa_verified"] = bool(item["mfa_verified"])
        item["revoked"] = bool(item["revoked"])
        item["active"] = (not item["revoked"]) and int(item["expires_at"]) > now
        items.append(item)
    return JSONResponse({"sessions": items})


async def revoke_session(request: Request) -> JSONResponse:
    session_id = request.path_params["session_id"]
    with get_db() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "Session not found"}, status_code=404)
        conn.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (session_id,))
        record_audit_event(
            conn,
            event_type="ADMIN_ACTION",
            actor_id="secops-console",
            actor_email="admin@corp.local",
            device_id=row["device_id"],
            resource_id=session_id,
            action="REVOKE_SESSION",
            decision="DENY",
            risk_score=50,
            reason=f"SecOps forcefully revoked session {session_id[:10]}...",
            details={"identity_id": row["identity_id"]},
        )
    return JSONResponse({"ok": True, "session_id": session_id, "revoked": True})


async def list_audit_logs(request: Request) -> JSONResponse:
    limit = min(200, max(1, int(request.query_params.get("limit", "60"))))
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        integrity = verify_audit_chain(conn)
    logs = []
    for r in rows:
        item = dict(r)
        item["details"] = json.loads(item.pop("details_json"))
        logs.append(item)
    return JSONResponse({"logs": logs, "integrity": integrity})


async def verify_audit(_request: Request) -> JSONResponse:
    with get_db() as conn:
        result = verify_audit_chain(conn)
    return JSONResponse(result)


async def spa_fallback(_request: Request):
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return JSONResponse({"message": "Zero Trust API running. Frontend not built yet."})


routes = [
    Route("/api/health", health, methods=["GET"]),
    Route("/api/overview", overview, methods=["GET"]),
    Route("/api/auth/login", auth_login, methods=["POST"]),
    Route("/api/auth/step-up", auth_step_up, methods=["POST"]),
    Route("/api/auth/logout", auth_logout, methods=["POST"]),
    Route("/api/auth/demo-totp/{identity_id}", demo_totp, methods=["GET"]),
    Route("/api/pep/simulate", pep_simulate, methods=["POST"]),
    Route("/api/resources", list_resources, methods=["GET"]),
    Route("/api/resources/{resource_id}", access_protected_resource, methods=["GET"]),
    Route("/api/identities", list_identities, methods=["GET"]),
    Route("/api/identities/{identity_id}", update_identity, methods=["PATCH"]),
    Route("/api/devices", list_devices, methods=["GET"]),
    Route("/api/devices/{device_id}", update_device, methods=["PATCH"]),
    Route("/api/policies", list_policies, methods=["GET"]),
    Route("/api/policies", create_policy, methods=["POST"]),
    Route("/api/policies/{policy_id}", update_policy, methods=["PATCH"]),
    Route("/api/sessions", list_sessions, methods=["GET"]),
    Route("/api/sessions/{session_id}/revoke", revoke_session, methods=["POST"]),
    Route("/api/audit", list_audit_logs, methods=["GET"]),
    Route("/api/audit/verify", verify_audit, methods=["GET"]),
]

if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        routes.append(Mount("/assets", app=StaticFiles(directory=str(assets_dir)), name="assets"))
    routes.append(Route("/", spa_fallback, methods=["GET"]))

app = Starlette(
    routes=routes,
    lifespan=lifespan,
    middleware=[
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )
    ],
)
