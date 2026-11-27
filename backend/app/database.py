"""SQLite persistence layer and realistic Zero Trust seed data."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from .config import CONFIG
from .crypto import compute_audit_hash, hash_password

GEO_COORDS: dict[str, tuple[float, float]] = {
    "US-NYC": (40.7128, -74.0060),
    "US-SFO": (37.7749, -122.4194),
    "UK-LON": (51.5072, -0.1276),
    "DE-FRA": (50.1109, 8.6821),
    "IN-BLR": (12.9716, 77.5946),
    "SG-SIN": (1.3521, 103.8198),
    "RU-MOW": (55.7558, 37.6173),
    "KP-FNJ": (39.0392, 125.7625),
    "IR-THR": (35.6892, 51.3890),
}

# Fixed Base32 secrets for deterministic demo & automated verification.
# In production these are randomly generated per user via crypto.generate_totp_secret().
DEMO_TOTP_SECRETS = {
    "id-alice": "JBSWY3DPEHPK3PXP",
    "id-bob": "KRSXG5CTMVRXEZLU",
    "id-admin": "MFRGGZDFMZTWQ2LK",
    "id-contractor": "NBSWY3DPFQQHO33S",
}


@contextmanager
def get_db(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield a SQLite connection with row dict access and foreign keys enabled."""
    conn = sqlite3.connect(db_path or CONFIG.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | None = None) -> None:
    """Create schema tables if missing and seed initial Zero Trust entities."""
    with get_db(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                department TEXT NOT NULL,
                clearance_level INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                mfa_enabled INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                last_known_geo TEXT NOT NULL DEFAULT 'US-NYC',
                last_login_at INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                os_type TEXT NOT NULL,
                os_version TEXT NOT NULL,
                managed INTEGER NOT NULL DEFAULT 1,
                disk_encrypted INTEGER NOT NULL DEFAULT 1,
                edr_active INTEGER NOT NULL DEFAULT 1,
                patch_age_days INTEGER NOT NULL DEFAULT 5,
                jailbroken INTEGER NOT NULL DEFAULT 0,
                trust_score INTEGER NOT NULL DEFAULT 100,
                quarantined INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES identities(id)
            );

            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                segment TEXT NOT NULL,
                classification TEXT NOT NULL,
                min_clearance INTEGER NOT NULL,
                require_managed_device INTEGER NOT NULL DEFAULT 1,
                require_mfa INTEGER NOT NULL DEFAULT 1,
                allowed_roles_json TEXT NOT NULL,
                sensitive_data_preview TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                priority INTEGER NOT NULL,
                effect TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                conditions_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                geo_location TEXT NOT NULL,
                mfa_verified INTEGER NOT NULL DEFAULT 0,
                step_up_until INTEGER NOT NULL DEFAULT 0,
                risk_score_at_issue INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (identity_id) REFERENCES identities(id),
                FOREIGN KEY (device_id) REFERENCES devices(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_email TEXT NOT NULL,
                device_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            );
            """
        )

        existing = conn.execute("SELECT COUNT(*) AS cnt FROM identities").fetchone()["cnt"]
        if existing == 0:
            _seed_data(conn)


def _seed_data(conn: sqlite3.Connection) -> None:
    now = int(time.time())
    demo_pw_hash = hash_password("ZeroTrust!2026")

    identities = [
        (
            "id-alice",
            "alice@corp.local",
            "Alice Chen",
            "engineer",
            "Platform Engineering",
            3,
            demo_pw_hash,
            DEMO_TOTP_SECRETS["id-alice"],
            1,
            "active",
            0,
            "US-SFO",
            now - 1800,
            now - 86400 * 30,
        ),
        (
            "id-bob",
            "bob@corp.local",
            "Bob Martinez",
            "finance_analyst",
            "Corporate Finance",
            2,
            demo_pw_hash,
            DEMO_TOTP_SECRETS["id-bob"],
            1,
            "active",
            0,
            "US-NYC",
            now - 3600,
            now - 86400 * 30,
        ),
        (
            "id-admin",
            "admin@corp.local",
            "Elena Vance",
            "secops_admin",
            "Security Operations",
            4,
            demo_pw_hash,
            DEMO_TOTP_SECRETS["id-admin"],
            1,
            "active",
            0,
            "UK-LON",
            now - 900,
            now - 86400 * 60,
        ),
        (
            "id-contractor",
            "contractor@vendor.ext",
            "Marcus Reed",
            "contractor",
            "External Vendor",
            1,
            demo_pw_hash,
            DEMO_TOTP_SECRETS["id-contractor"],
            1,
            "active",
            0,
            "DE-FRA",
            now - 7200,
            now - 86400 * 10,
        ),
    ]
    conn.executemany(
        """
        INSERT INTO identities (
            id, email, name, role, department, clearance_level, password_hash,
            totp_secret, mfa_enabled, status, failed_attempts, last_known_geo,
            last_login_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        identities,
    )

    devices = [
        ("dev-mac-alice", "MacBook Pro M4 (Corp)", "id-alice", "macOS", "15.2", 1, 1, 1, 4, 0, 96, 0, now - 600),
        ("dev-win-bob", "ThinkPad X1 Carbon (Corp)", "id-bob", "Windows", "11 24H2", 1, 1, 1, 12, 0, 92, 0, now - 1200),
        ("dev-linux-admin", "SecOps Hardened Workstation", "id-admin", "Ubuntu", "24.04 LTS", 1, 1, 1, 2, 0, 99, 0, now - 300),
        ("dev-byod-untrusted", "Unmanaged Personal Laptop", "id-contractor", "Windows", "10 21H2", 0, 0, 0, 120, 0, 22, 0, now - 3600),
    ]
    conn.executemany(
        """
        INSERT INTO devices (
            id, device_name, owner_id, os_type, os_version, managed, disk_encrypted,
            edr_active, patch_age_days, jailbroken, trust_score, quarantined, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        devices,
    )

    resources = [
        (
            "eng-repo",
            "Engineering Source Repository",
            "engineering",
            "internal",
            2,
            1,
            0,
            json.dumps(["engineer", "secops_admin"]),
            "git://internal.corp/core-gateway (branch: main, 14 active PRs)",
        ),
        (
            "finance-ledger",
            "Corporate Finance Ledger",
            "finance",
            "confidential",
            2,
            1,
            1,
            json.dumps(["finance_analyst", "secops_admin"]),
            "Q4 Operating Ledger: $42.8M ARR | Payroll Batch #2026-11 [Protected]",
        ),
        (
            "prod-k8s",
            "Production Kubernetes Control Plane",
            "engineering",
            "restricted",
            3,
            1,
            1,
            json.dumps(["engineer", "secops_admin"]),
            "k8s-prod-us-east: 28 nodes healthy | Vault CSI Driver active",
        ),
        (
            "iam-vault",
            "Zero Trust IAM & Root Secrets Vault",
            "restricted_admin",
            "restricted",
            4,
            1,
            1,
            json.dumps(["secops_admin"]),
            "HSM Keyring: 12 active root policies | Break-glass sealed",
        ),
    ]
    conn.executemany(
        """
        INSERT INTO resources (
            id, name, segment, classification, min_clearance, require_managed_device,
            require_mfa, allowed_roles_json, sensitive_data_preview
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        resources,
    )

    policies = [
        (
            "pol-deny-compromised",
            "Block Compromised & Quarantined Endpoints",
            "Immediately deny access from quarantined or jailbroken devices or locked identities.",
            10,
            "DENY",
            1,
            json.dumps({"block_jailbroken": True, "block_quarantined": True}),
        ),
        (
            "pol-deny-sanctioned-geo",
            "Block High-Risk Geo Origins",
            "Deny requests originating from sanctioned or high-risk geographic regions.",
            20,
            "DENY",
            1,
            json.dumps({"blocked_geos": ["RU-MOW", "KP-FNJ", "IR-THR"]}),
        ),
        (
            "pol-deny-critical-risk",
            "Deny Critical Continuous Risk Score",
            "Deny requests when real-time continuous risk exceeds 65.",
            30,
            "DENY",
            1,
            json.dumps({"min_risk_to_trigger": 66}),
        ),
        (
            "pol-deny-unmanaged-sensitive",
            "Require Managed & EDR-Protected Devices for Sensitive Segments",
            "Confidential and restricted micro-segments require corporate MDM + active EDR.",
            40,
            "DENY",
            1,
            json.dumps({
                "classifications": ["confidential", "restricted"],
                "require_managed": True,
                "require_edr": True,
            }),
        ),
        (
            "pol-stepup-elevated-risk",
            "Require Step-Up MFA for Elevated Risk or Restricted Segments",
            "Challenge with Step-Up MFA when risk is 36-65 or accessing MFA-gated resources without fresh MFA.",
            50,
            "STEP_UP",
            1,
            json.dumps({"risk_min": 36, "risk_max": 65, "enforce_resource_mfa": True}),
        ),
        (
            "pol-allow-least-privilege",
            "Allow Verified Least-Privilege Access",
            "Permit access only when identity, device posture, role, clearance, and risk thresholds pass.",
            100,
            "ALLOW",
            1,
            json.dumps({"max_risk": 35}),
        ),
    ]
    conn.executemany(
        """
        INSERT INTO policies (id, name, description, priority, effect, enabled, conditions_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        policies,
    )

    genesis_record = {
        "timestamp": now,
        "event_type": "SYSTEM",
        "actor_id": "system",
        "actor_email": "system@zerotrust.local",
        "device_id": "control-plane",
        "resource_id": "control-plane",
        "action": "BOOTSTRAP",
        "decision": "INFO",
        "risk_score": 0,
        "reason": "Zero Trust Control Plane initialized with NIST SP 800-207 baseline policies.",
        "details": {"policies_loaded": len(policies), "resources_segmented": len(resources)},
    }
    genesis_prev = "0" * 64
    genesis_hash = compute_audit_hash(genesis_prev, genesis_record)
    conn.execute(
        """
        INSERT INTO audit_logs (
            timestamp, event_type, actor_id, actor_email, device_id, resource_id,
            action, decision, risk_score, reason, details_json, prev_hash, record_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            genesis_record["timestamp"],
            genesis_record["event_type"],
            genesis_record["actor_id"],
            genesis_record["actor_email"],
            genesis_record["device_id"],
            genesis_record["resource_id"],
            genesis_record["action"],
            genesis_record["decision"],
            genesis_record["risk_score"],
            genesis_record["reason"],
            json.dumps(genesis_record["details"], sort_keys=True),
            genesis_prev,
            genesis_hash,
        ),
    )
