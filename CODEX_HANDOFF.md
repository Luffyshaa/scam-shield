# v0.2 integration status

The authoritative release requirements are in docs/CODEX_HANDOFF.md and AGENTS.md.
The user confirmed OCR and detection fixes; AI remains v0.3 work.

## Implemented and validated

- Preserved screenshot/photo upload, OCR correction, and family summaries.
- Fixed government-threat matching for “arrested” and plural gift card wording.
- Preserved the urgent cryptocurrency bonus (score 55, LIKELY SCAM); corrected
  the stale test expectation and tested crypto without urgency (25, BE CAREFUL).
- Corrected the low-risk verdict comparison controlling the additional warning.
- Added UI submission, empty-input, OCR, and invalid-image regression coverage.
- 17 tests passed locally, with no skips; dependency validation passed.

## Outstanding before the full v0.2 release

The remote handoff describes user-supplied rules.py, an improved detector,
evaluate.py, and a 74-example labeled dataset. Those files are not present in
this checkout or the fetched integration branch. Obtain the original files;
do not invent a replacement dataset or claim the documented evaluation passed.
Integrate normalization, negation, link inspection, channel context, risk levels,
and recovery/help UI against those files. Remove numeric scores from the UI and
family summary per AGENTS.md. Run pytest and python evaluate.py before proposing
merge. The current changes are a tested partial integration, not release signoff.

Do not merge main or deploy production automatically. Preserve existing remote
branch history and keep OCR working throughout the integration.
