# QR Guard

A cybersecurity-first QR code safety platform that scans QR payloads before opening them and warns users when a destination looks malicious. The system combines URL reputation checks, threat intelligence lookups, typo-squatting detection, and blockchain-backed reputation records to help prevent phishing and scam redirections.

## Mission

The project protects users from malicious QR codes by:
- extracting the destination URL from a QR payload
- normalizing and validating it
- scoring risk based on phishing, suspicious patterns, and domain reputation
- warning the user before they open it
- logging and sharing trust metadata using a blockchain-backed reputation ledger

## Core features

- QR payload extraction and URL validation
- Safe / suspicious / malicious classification engine
- Domain reputation checks and threat intelligence feeds
- Typo-squatting and brand impersonation detection
- Risk UI with clear warnings and user actions
- Blockchain-backed threat reputation registry for transparency and auditability
- Reporting pipeline for false positives and missed threats

## Architecture overview

- Mobile/Web client: scans QR codes and displays warnings
- Backend API: analyzes URLs and returns a risk score + reasons
- Threat intelligence layer: checks against known malicious databases
- Blockchain layer: stores hashed URL reputation records and report attestations
- Reporting service: collects user feedback and updates trust signals

## Suggested stack

- Backend: Python + FastAPI
- URL classification: custom risk logic + threat feed adapters
- Blockchain: Solidity smart contracts on Polygon/Base-compatible EVM chains
- Data storage: PostgreSQL + Redis cache
- Mobile app: React Native or Flutter

## Repository structure

```text
.
├── README.md
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── __init__.py
│       ├── main.py
│       ├── config.py
│       └── services/
│           ├── __init__.py
│           └── url_risk.py
├── blockchain/
│   └── contracts/
│       └── QRReputation.sol
├── docs/
│   └── ROADMAP.md
└── .gitignore
```

## Quick start

### 1. Create environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Start backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 3. Query the risk engine

```bash
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"url":"https://paypal-security-login.com/reset"}'
```

## Security principles

- Never store full user URLs or PII on-chain
- Hash sensitive identifiers before blockchain storage
- Always show explicit risk warnings before opening destination URLs
- Use threat feeds and human reports together; do not trust a single signal
- Keep a false-positive review path so legitimate domains are not blocked unfairly
- Prefer allowlist/denylist checks combined with heuristic analysis, not just a single blacklist result

## MVP scope

The initial version will:
- scan QR payloads from a camera or file
- extract and normalize destination URLs
- classify risk using local heuristics and known malicious feeds
- block or warn based on risk level
- provide a backend API for scoring and reporting
- store only hashed records on the blockchain ledger

## Roadmap

See `docs/ROADMAP.md` for the detailed implementation plan.

## License

MIT
