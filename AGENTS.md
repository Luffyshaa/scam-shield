# Repository instructions

Scam Shield is a senior-friendly Streamlit app. Keep language plain, preserve the
warning that low risk does not prove legitimacy, and never encourage using contact
details from suspicious messages.

Read CODEX_HANDOFF.md before implementing release work. Use the existing checkout;
cloud tasks are isolated. Do not create a worktree unless explicitly requested.
Work on codex/v0.2-integration for this release, with pull requests targeting main.
Do not merge or deploy production without user authorization.

Use Python 3.10+, install requirements.txt in a virtual environment, and install
Tesseract with English data for OCR. In the prepared cloud environment use
/workspace/.venvs/scam-shield/bin/python. Run python -m pytest -q and python -m
pip check. Start with python -m streamlit run app.py --server.headless=true.
Validate actual message submission and OCR, not only server health. Tests must
cover behavior changes; do not weaken expectations merely to make tests pass.

Do not commit credentials, uploaded messages, screenshots, virtualenvs, or caches.
Keep detector scoring deterministic. AI integration requires explicit provider,
privacy, structured output, fallback, and credential decisions.
