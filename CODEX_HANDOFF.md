# v0.2 integration status

The original release requirements are in docs/CODEX_HANDOFF.md and AGENTS.md.
The user supplied rules.py, scam_detector.py, detector tests, the dataset builder,
and the labeled JSON, and authorized integration. AI remains v0.3 work.

## Integrated

- Supplied detector, separate rules, normalization, negation, URL analysis,
  hard signals, and combination bonuses.
- Supplied 74-example synthetic dataset and builder, plus a new evaluate.py.
- Preserved screenshot upload, local OCR, editable extracted text, and family summary.
- Added channel selection and phone-call-specific advice.
- High / Medium / Low risk presentation; no numeric scores in UI or family summary.
- Recovery and reporting guidance available without submitting a message.
- CI for pytest, Tesseract OCR, dependency validation, and evaluation.

## Validation

38 local tests passed with no skips, including UI submission, OCR extraction and
correction before analysis, invalid images, channel advice, and evaluator metrics.
Evaluation: 38/38 synthetic scams flagged; 36/36 legitimate examples rated Low.
These regression results do not establish real-world accuracy. Dependency checks
passed. CI execution and Streamlit production are not validated by local checks.

## Delivery and limitations

Work remains on codex/v0.2-integration; target main with a pull request. Do not merge
or deploy automatically. The alternate proposed app.py and original evaluate.py
were not uploaded; their documented behaviors were implemented here.

Official reporting sites could not be verified because environment network policy
blocked access. The UI therefore uses general reporting guidance and omits the
unverified phone numbers/direct links in the supplied resource list. Verify any
specific contacts against official sources before adding them to the UI.
