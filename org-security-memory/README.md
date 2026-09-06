# Organizational Security Memory — Streamlit MVP

A hackathon-grade B2B cybersecurity prototype that turns SOC history into longitudinal security intelligence.

## Current phase

Phase 3 adds a **Streamlit Community Cloud-ready UI** over the deterministic security-memory engine.

### Product questions

1. **Why does this keep happening?** — recurrence intelligence
2. **What aren't we detecting?** — detection blind-spot intelligence
3. **What should we do about it?** — remediation memory

## Run locally

Use Python 3.12 for the closest match to Streamlit Community Cloud.

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

Run from the repository root so relative paths behave the same way as Community Cloud.

## Deploy to Streamlit Community Cloud

1. Push this repository to GitHub.
2. In Streamlit Community Cloud choose **Create app**.
3. Select your repository and branch.
4. Set the entrypoint to `streamlit_app.py`.
5. Deploy.

The app uses only the bundled synthetic dataset in this phase. No API key or secret is required.

## Important

`backend/data/generated/ground_truth.json` is **evaluation-only**. The Streamlit UI does not load it. It must not be used as application input because it would make the evaluation circular.

## Repository structure

```text
org-security-memory/
├── streamlit_app.py
├── requirements.txt
├── .streamlit/config.toml
├── backend/
│   ├── app/
│   │   ├── analytics/
│   │   └── models/
│   ├── data/
│   │   └── generated/
│   ├── security_memory.db
│   └── tests/
├── docs/
└── README.md
```

## Next phases

- Semantic incident retrieval
- Detection coverage engine hardening
- Claude evidence-bundle synthesis
- Evidence traceability validation
- Formal evaluation dashboard
- Counterfactual analysis
