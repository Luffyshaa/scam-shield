# 🛡️ Scam Shield

Scam Shield is a senior-friendly scam detection web app. Paste a suspicious message and it returns a plain-English risk verdict, explains the warning signs it found, gives safe next steps, and creates a summary that can be forwarded to family.

## Current version

**v0.2 — improved rule engine and screenshot OCR**

The current engine looks for common scam patterns such as:

- Government threats
- Urgent pressure
- Gift card requests
- Cryptocurrency payments
- Wire-transfer and instant-payment requests
- Unexpected prizes and lotteries
- Advance fees
- Grandparent/family emergency scams
- Requests for secrecy
- Account lock/security claims
- Suspicious links
- Remote-access requests
- Password or verification-code requests
- Requests for sensitive personal information
- Fake virus/tech-support warnings

The app deliberately avoids saying a low-risk message is definitely legitimate. A clean result only means that no obvious warning signs matched the current rules.

## Run locally

1. Install Python 3.10 or newer and Tesseract OCR with English language data.
   On Debian/Ubuntu: `sudo apt-get install tesseract-ocr tesseract-ocr-eng`.
2. Clone this repository.
3. Create and activate a virtual environment.
4. Install the dependencies:

```bash
pip install -r requirements.txt
```

5. Start the app:

```bash
streamlit run app.py
```

## Run tests

```bash
python -m pytest -q
python evaluate.py
```

## v0.2 workflow

Paste a message or upload a PNG, JPEG, or WebP screenshot/photo. Review and correct
OCR text before checking it. Select how it reached you: text, email, phone call,
pop-up, or social media. Phone calls include advice to hang up and independently
call back.

The app shows High / Medium / Low risk, plain-language warning signs, safe next
steps, and a family-share summary. Numeric scores stay internal. Recovery and
reporting guidance is available even before analysis. Specific reporting phone
numbers and direct links are not displayed because current official information
could not be verified from the development environment.

The deterministic detector uses `rules.py`, text normalization, safety-warning
negation, hard scam signals, combination bonuses, and URL inspection for
shorteners, IP addresses, look-alike domains, and hidden destinations. These are
heuristics; links are not visited and no reputation service is queried. OCR runs
locally through Tesseract. This release does not use an AI provider or add app-level
storage of messages/screenshots.

## Regression evaluation

`tests/data/labeled_messages.json` contains 74 supplied synthetic examples: 38
scams and 36 legitimate messages. `tests/data/build_dataset.py` rebuilds that file.
`evaluate.py` reports scam recall (High or Medium), false-clear rate (scams rated
Low), high-risk precision, and false-warning rate (legitimate examples rated High
or Medium). It fails if scam recall falls below 90% or any legitimate example is
rated High, matching the supplied regression test contract.

Local v0.2 validation: 38 tests passed, all 38 synthetic scams were flagged,
and all 36 legitimate examples were rated Low. These examples were developed
alongside the rules; the results do not establish real-world accuracy. Keep a
separate validation set for future accuracy claims. GitHub Actions is configured
to run tests, OCR checks, dependency checks, and evaluation on pull requests.

## Project structure

```text
scam-shield/
├── app.py
├── image_processor.py
├── scam_detector.py
├── rules.py
├── evaluate.py
├── requirements.txt
├── packages.txt
└── tests/
    ├── test_scam_detector.py
    ├── test_v02_workflow.py
    ├── test_evaluate.py
    └── data/
        ├── build_dataset.py
        └── labeled_messages.json
```

## Planned v0.3 — AI-assisted second opinion

An optional AI layer remains future work. Select a provider, define structured
outputs and fallback behavior, and agree on privacy and credential handling before
implementation. Deterministic rules remain first; AI must not override strong
scam signals with false reassurance.

## Release workflow

Read `AGENTS.md` and `CODEX_HANDOFF.md`. Develop on
`codex/v0.2-integration`, run tests, and open a pull request targeting `main`.
Merge after review. In Streamlit Community Cloud, configure `main` and `app.py`;
`requirements.txt` supplies Python dependencies and `packages.txt` installs
Tesseract. Verify text analysis and screenshot OCR after deployment.

## Safety note

Scam Shield is an educational safety aid and cannot guarantee that a message is genuine or fraudulent. When money, passwords, verification codes, account access, or sensitive personal information are involved, verify the request independently using contact information you trust.

## License

MIT
