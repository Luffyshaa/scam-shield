# 🛡️ Scam Shield

Scam Shield is a senior-friendly scam detection web app. Paste a suspicious message and it returns a plain-English risk verdict, explains the warning signs it found, gives safe next steps, and creates a summary that can be forwarded to family.

## Current version

**v0.2 integration in progress — screenshot OCR and rule-based detection**

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
pytest
```

## Project structure

```text
scam-shield/
├── app.py
├── scam_detector.py
├── requirements.txt
├── README.md
└── tests/
    └── test_scam_detector.py
```

## v0.2 workflow

Paste a message or upload a PNG, JPEG, or WebP screenshot/photo. Review and correct
OCR text before checking it. The app shows a risk verdict, warning signs, safe next
steps, and a summary to share with family. OCR runs locally through Tesseract;
this release does not send messages to an AI provider.

Urgent cryptocurrency requests retain the existing combination bonus and return
LIKELY SCAM. Government threats now recognize “arrested,” and gift card rules
recognize both singular and plural wording.

The complete v0.2 integration requirements and outstanding supplied-file inputs
are recorded in `docs/CODEX_HANDOFF.md` and `CODEX_HANDOFF.md`.

## Future AI analysis

An optional AI layer remains future work. Select a provider, define structured
outputs and fallback behavior, and agree on privacy and credential handling before
implementation.

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
