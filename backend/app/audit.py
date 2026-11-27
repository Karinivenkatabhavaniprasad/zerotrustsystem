"""Tamper-evident hash-chained audit logging and cryptographic chain verification."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import Any

from .crypto import compute_audit_hash


def record_audit_event(
    conn: sqlite3.Connection,
    *,
    event_type: str,
    actor_id: str,
    actor_email: str,
    device_id: str,
    resource_id: str,
    action: str,
    decision: str,
    risk_score: int,
    reason: str,
    details: dict[str, Any] | None = None,
    timestamp: int | None = None,
) -> dict[str, Any]:
    """Append an immutable hash-chained audit event inside the given SQLite transaction."""
    ts = timestamp if timestamp is not None else int(time.time())
    details_obj = details or {}

    last_row = conn.execute(
        "SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = last_row["record_hash"] if last_row else "0" * 64

    payload = {
        "timestamp": ts,
        "event_type": event_type,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "device_id": device_id,
        "resource_id": resource_id,
        "action": action,
        "decision": decision,
        "risk_score": int(risk_score),
        "reason": reason,
        "details": details_obj,
    }
    record_hash = compute_audit_hash(prev_hash, payload)

    cursor = conn.execute(
        """
        INSERT INTO audit_logs (
            timestamp, event_type, actor_id, actor_email, device_id, resource_id,
            action, decision, risk_score, reason, details_json, prev_hash, record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ts,
            event_type,
            actor_id,
            actor_email,
            device_id,
            resource_id,
            action,
            decision,
            int(risk_score),
            reason,
            json.dumps(details_obj, sort_keys=True),
            prev_hash,
            record_hash,
        ),
    )

    return {
        "id": cursor.lastrowid,
        **payload,
        "prev_hash": prev_hash,
        "record_hash": record_hash,
    }


def verify_audit_chain(conn: sqlite3.Connection) -> dict[str, Any]:
    """Verify SHA-256 hash chain integrity across every audit log record."""
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
    expected_prev = "0" * 64

    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_records": len(rows),
                "broken_at_id": row["id"],
                "error": "Previous hash pointer mismatch (possible deletion or reordering)",
            }

        payload = {
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "actor_id": row["actor_id"],
            "actor_email": row["actor_email"],
            "device_id": row["device_id"],
            "resource_id": row["resource_id"],
            "action": row["action"],
            "decision": row["decision"],
            "risk_score": row["risk_score"],
            "reason": row["reason"],
            "details": json.loads(row["details_json"]),
        }
        recomputed = compute_audit_hash(row["prev_hash"], payload)
        if recomputed != row["record_hash"]:
            return {
                "valid": False,
                "total_records": len(rows),
                "broken_at_id": row["id"],
                "error": "Record hash mismatch (log entry tampered)",
            }
        expected_prev = row["record_hash"]

    return {
        "valid": True,
        "total_records": len(rows),
        "broken_at_id": None,
        "head_hash": expected_prev,
    }
