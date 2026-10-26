# 🛡️ Scam Shield

Scam Shield is a senior-friendly scam detection web app. Paste a suspicious message and it returns a plain-English risk verdict, explains the warning signs it found, gives safe next steps, and creates a summary that can be forwarded to family.

## Current version

**v0.1 — rule-based detector**

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

1. Install Python 3.10 or newer.
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

## Planned v0.2

The next version will keep the rule engine and add an AI analysis layer for unfamiliar scam scripts, plus screenshot/image input with OCR. The AI output should be constrained to structured fields such as risk level, confidence, red flags, explanation, and recommended actions.

## Safety note

Scam Shield is an educational safety aid and cannot guarantee that a message is genuine or fraudulent. When money, passwords, verification codes, account access, or sensitive personal information are involved, verify the request independently using contact information you trust.

## License

MIT
