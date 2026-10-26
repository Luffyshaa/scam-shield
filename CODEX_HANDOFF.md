# Scam Shield v0.2 handoff

## Scope and decisions

Release the existing screenshot/photo OCR flow alongside paste-text analysis.
Retain the deterministic rule engine, editable OCR text, plain-language risk
verdicts, safe next steps, and family-share summaries. AI analysis is deferred
pending a provider and privacy/credential decisions; the README previously listed
it as planned, but no provider integration exists.

Keep the existing urgent-payment combination bonus: Bitcoin plus urgency scores
55 and is LIKELY SCAM; Bitcoin alone scores 25 and is BE CAREFUL. Correct the stale
test expectation instead of lowering the risk score. Fix government threats using
“arrested” and singular/plural gift card detection. Use the actual low-risk verdict
constant when deciding whether to display the additional warning.

## Acceptance criteria

- Existing detector tests and new regression tests pass.
- Text submission renders the expected verdict and family-share summary.
- Low-risk input retains the safety caveat without the extra high-risk warning.
- Screenshot OCR extracts English text, allows review, and handles unreadable or
  invalid images with the existing friendly error.
- Python dependency checks and Streamlit startup succeed.

## Delivery

Branch: codex/v0.2-integration. Pull request target: main. Review before merging;
production deployment is a separate step requiring authorization. Streamlit uses
app.py, requirements.txt, and packages.txt. Verify production text and OCR flows
after deployment. Do not claim production validation from local tests.
