# Codex Handoff — Scam Shield

## Project goal

Build **Scam Shield**, a senior-friendly scam detection product that helps a user check a suspicious text, email, phone-call script, social-media message, popup, or screenshot before taking action.

The long-term goal is a polished mobile product that can later be released on Google Play. For now, the working prototype is a Streamlit web app deployed from GitHub.

## Repository / deployment

- Repository: `Luffyshaa/scam-shield`
- Production branch: `main`
- Streamlit Community Cloud deploys the app from `main` using `app.py`.
- Do not break `main` while integrating changes. Work on `codex/v0.2-integration` and open a PR when ready.

## What is already live on main

The live prototype includes:

- Senior-friendly Streamlit UI
- Large readable text and buttons
- High / Medium / Low visual verdict treatment
- Pasted-message analysis
- Screenshot/photo upload
- OCR using `pytesseract` + Pillow
- `packages.txt` for the system Tesseract package on Streamlit Cloud
- Extracted OCR text is shown to the user for correction before analysis
- Family-share summary
- Clear safety warning that a low-risk result does not prove legitimacy

Important: preserve the OCR feature during integration.

## Improved detector supplied by the user

The user supplied a stronger v0.2 rule engine consisting of:

- `rules.py`
- improved `scam_detector.py`
- `evaluate.py`
- `tests/test_scam_detector.py`
- `tests/data/build_dataset.py`
- `tests/data/labeled_messages.json`
- an improved README
- an alternate proposed `app.py` with channel context and recovery/reporting guidance

### Detector improvements

The improved engine includes:

- rules separated from engine logic
- bounded regex patterns
- improved matching for terms such as `arrested`
- negation/safety-warning handling, e.g. legitimate wording like "we will never ask for your code"
- text normalization for zero-width characters, simple leetspeak, and spaced-out letters
- hard scam signals such as gift-card demands, remote access, and moving funds to a "safe account"
- combination bonuses
- URL extraction and inspection
- shortened-link detection
- IP-address URL detection
- punycode / look-alike character detection
- `@` URL destination tricks
- suspicious TLD detection
- look-alike brand-domain detection
- brand allowlists for common organizations
- High / Medium / Low risk levels
- phone-call-specific safety advice when channel context is supplied

### Expanded scam categories

Examples include:

- government threats
- urgent pressure
- gift-card payments
- crypto payments
- wire / Zelle / Cash App / Venmo requests
- money requests
- prizes / lotteries / advance fees
- family emergency and "new number" scams
- secrecy requests
- account lock / security claims
- suspicious links
- remote-access scams
- password / OTP requests
- sensitive personal-information requests
- fake virus / tech-support warnings
- callback-number traps
- fake subscription / unexpected-charge scams
- investment scams
- wrong-number / romance scams
- delivery and toll scams
- safe-account scams
- refund / overpayment scams
- recovery scams
- utility shut-off scams
- fake jobs
- Medicare / benefits scams

## Dataset and tests supplied by the user

The supplied regression dataset contains **74 synthetic labeled examples**:

- 38 scams
- 36 legitimate look-alike messages

It intentionally includes legitimate messages that contain words often found in scams (bank fraud alerts, OTPs, Medicare notices, delivery notices, Zelle confirmations, IRS/SSA messages, gift-card references, hospital/family language, etc.).

The test suite checks:

- common scam verdicts
- historical regex bugs
- safety-warning negation
- legitimate pharmacy behavior
- combination bonuses
- family summary output
- empty input
- simple evasion normalization
- suspicious-link flags
- official brand-domain allowlisting
- phone-call-specific action advice
- regression accuracy on the labeled dataset

### Previously observed local evaluation result

When these uploaded detector/test/data files were reviewed together, the reported result was:

- 27 tests passed
- 38/38 scams caught
- 36/36 legitimate examples left unflagged
- 100% precision on this synthetic dataset
- 100% recall on this synthetic dataset

Do **not** describe that as real-world 100% accuracy. The dataset is synthetic and partly developed alongside the rules. Treat it as a regression suite.

## User-interface ideas from the alternate app.py

Merge these ideas into the OCR-enabled live app rather than replacing OCR:

- Ask "How did this reach you?" with channel choices:
  - Text message
  - Email
  - Phone call
  - Pop-up on screen
  - Social media or other
- Use channel context in the detector; phone calls should tell the user to hang up and independently call back.
- Show risk level instead of numeric score to end users.
- Add "I already paid or shared information. What do I do now?"
- Add reporting/help resources.
- Keep the "ask someone you trust" family-share section.

Before publishing phone numbers or reporting resources, verify current official information.

## v0.2 target architecture

```
Text OR Screenshot/Photo
        ↓
OCR when needed
        ↓
User can correct extracted text
        ↓
Normalization
        ↓
Deterministic rules
        ↓
Link analysis
        ↓
Hard signals + combination logic
        ↓
High / Medium / Low verdict
        ↓
Plain-language warning signs
        ↓
What to do now
        ↓
Family-share summary
        ↓
Recovery/reporting help
```

## Immediate Codex task

On `codex/v0.2-integration`:

1. Integrate the user-supplied `rules.py` and improved `scam_detector.py`.
2. Add `evaluate.py` and the supplied test/data files.
3. Merge channel selection + recovery/help UI into the current OCR-enabled `app.py`.
4. Do not remove `image_processor.py`, Pillow/pytesseract, screenshot upload, or OCR correction.
5. Update README to accurately describe the integrated v0.2.
6. Run:
   - `pytest`
   - `python evaluate.py`
7. Fix regressions.
8. Add GitHub Actions CI for pytest if practical.
9. Open a PR from `codex/v0.2-integration` to `main`; do not merge automatically without review.

## Future v0.3

After v0.2 is stable, add an optional AI second-opinion layer **after** deterministic analysis. It should return constrained structured output such as:

- risk level
- confidence
- red flags
- explanation
- recommended actions

Rules must remain first for explainability and obvious high-risk signals. The AI layer must not turn a strong deterministic scam result into false reassurance.

## Product safety principles

- Never say "definitely legitimate."
- Do not encourage users to call numbers or visit links contained in suspicious messages.
- Encourage independent verification through an official website/app, trusted number, bank, family member, or known contact.
- Prioritize false-clear risk: missing a scam can be more harmful than asking a user to verify a questionable message.
- Avoid persisting pasted messages/screenshots by default.
- Make senior-facing language short, calm, clear, and action-oriented.
