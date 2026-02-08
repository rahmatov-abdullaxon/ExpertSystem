Expert System for E-commerce Fraud Detection

Compact, rule-based engine for explainable transaction decisions. Forward chaining with confidence propagation yields deterministic, auditable recommendations: APPROVE, STEP_UP_VERIFY, MANUAL_REVIEW, DECLINE.
Features

    Forward chaining rules with confidence math c=c1+c2−c1⋅c2

    Human‑readable trace of fired rules and derived facts

    Risk indicators and prioritized action recommendations

    Questioning/step‑up logic for additional verification (OTP, identity checks)

    Unit tests for circular rules, immutability, and confidence merging

    Pre‑commit hooks: Black + Ruff

Quickstart
bash

git clone https://github.com/<user>/ExpertSystem.git
cd ExpertSystem
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
pip install -r dev-requirements.txt
pre-commit install
pre-commit run --all-files

Usage
python

from expert_system import InferenceEngine, ALL_RULES

e = InferenceEngine(ALL_RULES)
e.load_data({"amount":2000,"ip_risk_score":60,"account_age_days":2})
e.forward_chain()
print(e.get_recommendations())   # prioritized actions with confidences
print(e.trace)                   # audit trail of rule firings

Files

    expert_system.py — core engine, rules, API

    test_inference_engine.py — unit tests

    .pre-commit-config.yaml — Black + Ruff hooks

    .gitignore and LICENSE (add if missing)
Tests & CI

Run pytest -q. Tests cover immutability, forward chaining, circular rules, confidence math, and decision logic.

CI: run pre-commit run --all-files and pytest -q on PRs. Use GitHub Actions to enforce.

Security Contributing License

    Secrets: never commit real data or .env files; add .env.example.

    If exposed: git rm --cached path/to/file then rotate credentials.

    Contributing: open issues; PRs must include tests and pass pre‑commit + CI.

    License: MIT.
