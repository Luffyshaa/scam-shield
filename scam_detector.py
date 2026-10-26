from dataclasses import dataclass, asdict
import re
from typing import List, Dict


@dataclass
class RedFlag:
    code: str
    title: str
    explanation: str
    score: int


RULES = [
    ("government_threat", r"\b(irs|social security|medicare|police|sheriff|federal agent|government)\b.*\b(arrest(?:ed)?|warrant|suspend|lawsuit|legal action|jail)\b", "Government threat", "Scammers often pretend to be government agencies and threaten arrest, lawsuits, or benefit suspension.", 35),
    ("urgent_action", r"\b(act now|immediately|urgent|right away|within \d+ (minutes|hours)|final warning|last chance)\b", "Pressure to act fast", "Scammers create urgency so you do not have time to verify the story.", 15),
    ("gift_card", r"\b(gift cards?|itunes cards?|apple cards?|google play cards?|steam cards?)\b", "Gift card payment", "Legitimate organizations almost never demand payment with gift cards.", 30),
    ("crypto", r"\b(bitcoin|crypto|cryptocurrency|usdt|wallet address)\b", "Cryptocurrency request", "Scammers often request cryptocurrency because transfers are difficult to reverse.", 25),
    ("wire_payment", r"\b(wire transfer|western union|moneygram|zelle|cash app|venmo)\b", "Hard-to-reverse payment", "Requests for instant or hard-to-reverse payments are a common scam warning sign.", 20),
    ("prize", r"\b(winner|won|prize|lottery|sweepstakes|jackpot)\b", "Unexpected prize", "Unexpected prizes are commonly used to lure people into paying fees or sharing personal information.", 25),
    ("advance_fee", r"\b(processing fee|release fee|shipping fee|customs fee|activation fee|claim fee)\b", "Fee required first", "Scammers often ask for a small fee before releasing a fake prize, package, refund, or benefit.", 20),
    ("family_emergency", r"\b(grandson|granddaughter|grandchild|son|daughter|nephew|niece)\b.*\b(jail|arrested|hospital|accident|lawyer|bail|emergency)\b", "Family emergency story", "Scammers may impersonate relatives and invent emergencies to pressure families into sending money.", 35),
    ("secrecy", r"\b(don't tell|do not tell|keep this secret|between us|don't call anyone)\b", "Asked to keep it secret", "Scammers may tell you not to speak with family, friends, banks, or police because verification would expose the scam.", 20),
    ("account_problem", r"\b(account (is )?(locked|suspended|compromised)|verify your account|unusual activity|security alert)\b", "Account problem claim", "Fake account warnings are often used to steal passwords or payment details.", 15),
    ("click_link", r"\b(click|tap|visit|open)\b.{0,25}\b(link|website|url)\b|https?://|www\.", "Link included", "Scam messages often push you to a link that may lead to a fake login or payment page.", 10),
    ("remote_access", r"\b(anydesk|teamviewer|remote access|screen share|give me control|support app)\b", "Remote access request", "Legitimate companies generally do not unexpectedly ask to control your computer or phone.", 35),
    ("password_code", r"\b(password|passcode|verification code|one[- ]time code|otp|security code)\b", "Sensitive code requested", "Never share passwords or one-time security codes with someone who contacted you unexpectedly.", 30),
    ("personal_info", r"\b(social security number|ssn|bank account|routing number|credit card number|debit card number|date of birth)\b", "Sensitive personal information", "Unexpected requests for sensitive personal or financial information are a serious warning sign.", 25),
    ("malware_popup", r"\b(virus detected|computer infected|device infected|hackers detected|call microsoft|call apple support)\b", "Fake virus warning", "Pop-ups claiming your device is infected and telling you to call a number are a common tech-support scam.", 30),
]


def analyze_message(text: str) -> Dict:
    clean = (text or "").strip()
    lowered = clean.lower()
    flags: List[RedFlag] = []
    score = 0

    for code, pattern, title, explanation, points in RULES:
        if re.search(pattern, lowered, flags=re.IGNORECASE | re.DOTALL):
            flags.append(RedFlag(code, title, explanation, points))
            score += points

    # Bonus for combinations that are especially dangerous.
    codes = {f.code for f in flags}
    if "urgent_action" in codes and ("gift_card" in codes or "wire_payment" in codes or "crypto" in codes):
        score += 15
    if "family_emergency" in codes and "secrecy" in codes:
        score += 15
    if "account_problem" in codes and "click_link" in codes:
        score += 10

    if score >= 50:
        verdict = "LIKELY SCAM"
        emoji = "🛑"
        summary = "This message has several strong scam warning signs. Do not send money, share codes, or use links in the message."
    elif score >= 20:
        verdict = "BE CAREFUL"
        emoji = "⚠️"
        summary = "This message has warning signs. Verify it using a trusted phone number or website before doing anything."
    else:
        verdict = "NO OBVIOUS RED FLAGS"
        emoji = "✅"
        summary = "No obvious scam warning signs were found, but that does not prove the message is legitimate."

    actions = [
        "Do not reply, pay, or share passwords or verification codes until you verify the sender.",
        "Do not use phone numbers or links provided in a suspicious message.",
        "Contact the company, bank, agency, or family member using a trusted number you already know or find independently.",
        "If money or account access is involved, ask a trusted family member or your bank before taking action.",
    ]

    family_summary = (
        f"Scam Shield result: {emoji} {verdict}. Risk score: {score}. "
        + ("Warning signs: " + ", ".join(f.title for f in flags) + ". " if flags else "No obvious warning signs were detected. ")
        + summary
    )

    return {
        "score": score,
        "verdict": verdict,
        "emoji": emoji,
        "summary": summary,
        "red_flags": [asdict(flag) for flag in flags],
        "actions": actions,
        "family_summary": family_summary,
    }
