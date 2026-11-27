"""Comprehensive test suite for the Zero Trust Architecture system."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from app.audit import verify_audit_chain
from app.config import CONFIG
from app.crypto import compute_totp, hash_password, verify_password, verify_totp
from app.database import DEMO_TOTP_SECRETS, get_db, init_db
from app.main import app


class ZeroTrustSystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp_dir.name) / "test_zt.db")
        # Override CONFIG.db_path dynamically via object.__setattr__ on frozen dataclass
        object.__setattr__(CONFIG, "db_path", self.db_path)
        init_db(self.db_path)
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_password_hashing_and_totp(self) -> None:
        pw_hash = hash_password("S3cur3-ZT-Pass!")
        self.assertTrue(verify_password("S3cur3-ZT-Pass!", pw_hash))
        self.assertFalse(verify_password("WrongPass!", pw_hash))

        secret = DEMO_TOTP_SECRETS["id-alice"]
        code = compute_totp(secret)
        self.assertEqual(len(code), 6)
        self.assertTrue(verify_totp(secret, code))
        self.assertFalse(verify_totp(secret, "000000" if code != "000000" else "111111"))

    def test_least_privilege_and_step_up_mfa_flow(self) -> None:
        # 1. Login as Alice without TOTP code
        login_res = self.client.post(
            "/api/auth/login",
            json={
                "email": "alice@corp.local",
                "password": "ZeroTrust!2026",
                "device_id": "dev-mac-alice",
                "ip_address": "10.24.1.15",
                "geo_location": "US-SFO",
            },
        )
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Accessing internal eng-repo passes (risk ~20 <= 35, require_mfa=False)
        eng_res = self.client.get("/api/resources/eng-repo", headers=headers)
        self.assertEqual(eng_res.status_code, 200)
        self.assertEqual(eng_res.json()["decision"], "ALLOW")

        # 3. Accessing restricted prod-k8s triggers STEP_UP because MFA isn't verified yet
        k8s_res = self.client.get("/api/resources/prod-k8s", headers=headers)
        self.assertEqual(k8s_res.status_code, 403)
        self.assertEqual(k8s_res.json()["decision"], "STEP_UP")
        self.assertEqual(k8s_res.json()["challenge"], "STEP_UP_MFA_REQUIRED")

        # 4. Complete Step-Up MFA with valid TOTP
        totp = self.client.get("/api/auth/demo-totp/id-alice").json()["totp_code"]
        step_res = self.client.post(
            "/api/auth/step-up",
            headers=headers,
            json={"totp_code": totp},
        )
        self.assertEqual(step_res.status_code, 200)
        self.assertTrue(step_res.json()["mfa_verified"])

        # 5. Now prod-k8s succeeds!
        k8s_res2 = self.client.get("/api/resources/prod-k8s", headers=headers)
        self.assertEqual(k8s_res2.status_code, 200)
        self.assertEqual(k8s_res2.json()["decision"], "ALLOW")

        # 6. Least privilege: Engineer Alice is DENIED access to finance-ledger & iam-vault
        fin_res = self.client.get("/api/resources/finance-ledger", headers=headers)
        self.assertEqual(fin_res.status_code, 403)
        self.assertEqual(fin_res.json()["decision"], "DENY")

        vault_res = self.client.get("/api/resources/iam-vault", headers=headers)
        self.assertEqual(vault_res.status_code, 403)
        self.assertEqual(vault_res.json()["decision"], "DENY")

    def test_impossible_travel_and_tor_anomaly_blocks_access(self) -> None:
        totp = self.client.get("/api/auth/demo-totp/id-admin").json()["totp_code"]
        login_res = self.client.post(
            "/api/auth/login",
            json={
                "email": "admin@corp.local",
                "password": "ZeroTrust!2026",
                "device_id": "dev-linux-admin",
                "ip_address": "10.10.0.5",
                "geo_location": "UK-LON",
                "totp_code": totp,
            },
        )
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]

        # Simulate instant jump UK-LON -> SG-SIN + Tor exit IP
        res = self.client.get(
            "/api/resources/iam-vault",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "185.220.101.42",
                "X-Geo-Location": "SG-SIN",
            },
        )
        self.assertEqual(res.status_code, 403)
        body = res.json()
        self.assertEqual(body["decision"], "DENY")
        self.assertGreater(body["risk_score"], 65)
        self.assertIn("IMPOSSIBLE_TRAVEL", body["anomalies"])
        self.assertIn("TOR_OR_ANONYMIZER_EXIT", body["anomalies"])

    def test_device_quarantine_revokes_session_immediately(self) -> None:
        totp = self.client.get("/api/auth/demo-totp/id-bob").json()["totp_code"]
        login_res = self.client.post(
            "/api/auth/login",
            json={
                "email": "bob@corp.local",
                "password": "ZeroTrust!2026",
                "device_id": "dev-win-bob",
                "ip_address": "10.30.2.10",
                "geo_location": "US-NYC",
                "totp_code": totp,
            },
        )
        token = login_res.json()["access_token"]
        self.assertEqual(
            self.client.get("/api/resources/finance-ledger", headers={"Authorization": f"Bearer {token}"}).status_code,
            200,
        )

        # SecOps quarantines Bob's device ("Assume Breach")
        q_res = self.client.patch("/api/devices/dev-win-bob", json={"quarantined": True})
        self.assertEqual(q_res.status_code, 200)
        self.assertEqual(q_res.json()["device"]["trust_score"], 0)

        # Subsequent request with same previously valid token is immediately rejected
        blocked = self.client.get("/api/resources/finance-ledger", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(blocked.status_code, 401)
        self.assertEqual(blocked.json()["decision"], "DENY")

    def test_brute_force_auto_lock_and_audit_chain_tamper_detection(self) -> None:
        # 4 bad password attempts lock contractor account
        for _ in range(4):
            r = self.client.post(
                "/api/auth/login",
                json={
                    "email": "contractor@vendor.ext",
                    "password": "wrong-password",
                    "device_id": "dev-byod-untrusted",
                },
            )
            self.assertEqual(r.status_code, 401)

        locked_attempt = self.client.post(
            "/api/auth/login",
            json={
                "email": "contractor@vendor.ext",
                "password": "ZeroTrust!2026",
                "device_id": "dev-byod-untrusted",
            },
        )
        self.assertEqual(locked_attempt.status_code, 403)

        # Audit hash chain must be cryptographically valid
        verify_res = self.client.get("/api/audit/verify").json()
        self.assertTrue(verify_res["valid"])
        self.assertGreaterEqual(verify_res["total_records"], 6)

        # Simulate database tampering and confirm verify_audit_chain catches it
        with get_db(self.db_path) as conn:
            conn.execute("UPDATE audit_logs SET decision = 'ALLOW' WHERE id = 2")
            tamper_check = verify_audit_chain(conn)
        self.assertFalse(tamper_check["valid"])
        self.assertEqual(tamper_check["broken_at_id"], 2)


if __name__ == "__main__":
    unittest.main()
