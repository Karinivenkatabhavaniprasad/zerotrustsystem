# Zero Trust Security System (NIST SP 800-207)

A full-stack **Zero Trust Architecture (ZTA)** reference platform featuring a **Policy Decision Point (PDP)**, **Policy Enforcement Point (PEP)** gateway, **Continuous Risk Scoring Engine**, **Device Posture Verification**, **Micro-Segmented Resources**, **RFC 6238 TOTP Step-Up MFA**, and a **Tamper-Evident SHA-256 Hash-Chained Audit Trail**.

## Architecture

- **Backend (`backend/app/`)**: Python 3.12 + Starlette + Uvicorn + SQLite
  - `crypto.py`: PBKDF2-HMAC-SHA256 password hashing, RFC 6238 TOTP MFA, HMAC-SHA256 JWT tokens, SHA-256 audit hash chaining.
  - `risk_engine.py`: Continuous risk (0–100) and endpoint trust (0–100) evaluation across MDM/EDR/encryption/patch posture, impossible geo-travel (Haversine velocity), anonymizer/Tor IP prefixes, failed login bursts, and off-hours access.
  - `policy_engine.py`: Ordered ABAC + RBAC + Clearance + Default-Deny PDP evaluation with full rule-by-rule trace.
  - `pep_gateway.py`: Per-request PEP enforcement, session revocation, and step-up MFA elevation.
  - `audit.py`: Immutable hash-chained audit ledger and cryptographic integrity verifier.
- **Frontend (`frontend/`)**: React + TypeScript + Vite Zero Trust Security Command Center.

## Running Locally

### 1. Run Backend Tests
```powershell
$env:PYTHONPATH = "backend"
python -m unittest discover -s backend/tests -v
```

### 2. Start Backend API Server (Port 8000)
```powershell
$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Build or Run Frontend Dashboard
```powershell
cd frontend
npm install
npm run build   # Builds into frontend/dist (served automatically by backend on port 8000)
# OR for dev mode with HMR on port 5173:
npm run dev
```

## Demo Identities (Default Password: `ZeroTrust!2026`)
| Email | Role | Clearance | Device |
| :--- | :--- | :--- | :--- |
| `alice@corp.local` | `engineer` | Level 3 | `dev-mac-alice` (Managed, EDR) |
| `bob@corp.local` | `finance_analyst` | Level 2 | `dev-win-bob` (Managed, EDR) |
| `admin@corp.local` | `secops_admin` | Level 4 | `dev-linux-admin` (Hardened) |
| `contractor@vendor.ext` | `contractor` | Level 1 | `dev-byod-untrusted` (Unmanaged BYOD) |
