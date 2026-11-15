# BugHunter AI

BugHunter AI is a Streamlit-based defensive static-analysis dashboard. Upload a ZIP archive of source code you own or are authorized to assess. The app checks source text for common insecure patterns and can run Bandit against Python files.

## Features

- ZIP source upload with archive path and size protections
- Built-in checks for hardcoded credentials, private keys, SQL string interpolation, disabled TLS verification, unsafe deserialization, dynamic evaluation, shell execution, weak hashes, debug mode, and wildcard CORS
- Optional Bandit scan for Python code
- Critical / High / Medium / Low severity classification
- Filterable findings table
- CSV and PDF report downloads
- Scan history for the current browser session

## Safety design

- Uploaded project files are read as text; project code is **never executed**.
- ZIP path traversal, encrypted entries, oversized files, and oversized archives are rejected or skipped.
- Use only on systems and source code you own or have explicit permission to assess.
- Findings are heuristic indicators and must be manually validated. A clean scan is not proof that software is secure.

## Run locally

Use Python 3.11 or 3.12 for broad package compatibility.

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

python -m pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud

1. Push this repository to GitHub.
2. Sign in at https://share.streamlit.io/ with the GitHub account that owns the repository.
3. Choose **Create app** and select `ap566/BugHunter-AI`.
4. Set the branch to `main` and main file path to `app.py`.
5. Deploy. Streamlit Cloud installs packages from `requirements.txt`.

No API key is required for the built-in scanner. Do not commit credentials, private keys, or real sensitive source code to this public repository.

## Project structure

- `app.py` — Streamlit interface, safe ZIP reader, static rules, optional Bandit runner, and report export
- `requirements.txt` — runtime dependencies

## Limitations

This is a starter static-analysis tool, not a full SAST platform. It does not perform dynamic testing, exploit verification, complete dependency vulnerability analysis, or AI-powered reasoning. Pattern matches may be false positives or miss issues; review results before making security decisions.
