# Scam Shield — Codex Instructions

Scam Shield is a senior-friendly scam detection product. The public prototype is a Streamlit app deployed from the `main` branch.

## Product principles

- Optimize for senior safety, clarity, large readable UI, and low cognitive load.
- Never tell a user that a message is definitely legitimate. A low-risk result means only that no obvious warning signs were found.
- Prefer explainable detection. The deterministic rule engine remains the first layer even after AI is introduced.
- Do not expose internal numeric risk scores to end users; use High / Medium / Low risk levels.
- Do not silently remove working features while refactoring.
- Preserve screenshot/photo OCR support already present on `main` (`image_processor.py`, Pillow, pytesseract, `packages.txt`).
- User-provided messages and screenshots should not be persisted by the app unless a future feature explicitly adds storage with consent and privacy controls.

## Current architecture

Input (pasted message OR screenshot/photo)
→ OCR when needed
→ normalization
→ deterministic rules
→ link analysis
→ combination bonuses / hard signals
→ risk verdict + reasons
→ safe next actions
→ family-share summary
→ recovery/reporting guidance

## v0.2 integration goal

Integrate the improved detector/rules/test dataset on this branch with the existing OCR-enabled Streamlit app from `main`.

Required outcomes:

1. Keep text input and screenshot/photo upload.
2. Use `rules.py` as the source of deterministic detection rules.
3. Use the improved `scam_detector.py` with normalization, negation handling, link analysis, hard signals, and combination bonuses.
4. Keep channel context (Text message, Email, Phone call, Pop-up, Social media/other) and phone-call-specific advice.
5. Add the recovery/help UI from the user's proposed `app.py` without removing OCR.
6. Keep `evaluate.py` and the labeled regression dataset under `tests/data/`.
7. Run `pytest` and `python evaluate.py` before proposing merge.
8. Update README so v0.2 = improved rule engine + OCR; v0.3 = AI-assisted second opinion.
9. Add CI if practical so pytest runs on pull requests.

## AI layer (v0.3, not required for the first integration)

The future AI layer should run after deterministic rules and return structured fields such as risk level, confidence, red flags, explanation, and recommended actions. It must not override strong deterministic scam signals with false reassurance.

## Safety testing priorities

Track at least:
- scam recall
- false-clear rate
- high-risk precision
- false-warning rate

The existing labeled data is synthetic/regression data, not proof of real-world accuracy. Keep a future validation set separate from data used to tune rules.

## Cloud development

Use the existing checkout; cloud tasks are isolated. Do not create a worktree
unless explicitly requested. The prepared interpreter is
/workspace/.venvs/scam-shield/bin/python. Read docs/CODEX_HANDOFF.md for the full
release specification and CODEX_HANDOFF.md for current integration status.
Run python -m pytest -q and python -m pip check. Do not commit credentials,
virtual environments, uploaded messages, or screenshots.
