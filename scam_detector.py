"""Scam Shield detection engine (v0.2 rule-based).

Improvements over v0.1:
  * word-boundary bug fixed (e.g. "arrested" now matches the arrest rule)
  * bounded patterns, so unrelated parts of a long message are not joined
  * safety-warning sentences ("we will never ask for your code") are ignored
  * "hard" signals (gift cards, remote access, 'safe account') decide alone
  * link analysis: shorteners, IP links, lookalike brand domains, odd TLDs
  * text normalization against simple evasion (spaced letters, look-alikes)
  * rules live in rules.py so they can be edited without touching the engine
"""

from dataclasses import dataclass, asdict
import re
import unicodedata
from typing import Dict, List, Optional
from urllib.parse import urlparse

from rules import (
    BRANDS,
    COMBOS,
    NEGATION,
    RESOURCES,
    RULES,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

VERDICT_SCAM = "LIKELY SCAM"
VERDICT_CAREFUL = "BE CAREFUL"
VERDICT_CLEAR = "NO OBVIOUS RED FLAGS"

EMOJI = {VERDICT_SCAM: "🛑", VERDICT_CAREFUL: "⚠️", VERDICT_CLEAR: "✅"}
CARD_CLASS = {VERDICT_SCAM: "scam", VERDICT_CAREFUL: "caution", VERDICT_CLEAR: "safe"}
LEVEL = {VERDICT_SCAM: "High", VERDICT_CAREFUL: "Medium", VERDICT_CLEAR: "Low"}

SCAM_THRESHOLD = 50
CAREFUL_THRESHOLD = 20
MAX_SCORE = 100

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_COMMON_TLDS = {"com", "net", "org", "info", "biz", "us", "co", "io", "gov", "edu"} | SUSPICIOUS_TLDS
_URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"')]+"
    r"|\b(?:" + "|".join(re.escape(s) for s in URL_SHORTENERS) + r")/\S+"
    r"|\b(?:[a-z0-9-]+\.)+(?:" + "|".join(sorted(_COMMON_TLDS)) + r")\b(?:/[^\s<>\"')]*)?",
    re.IGNORECASE,
)
_NEGATION_RE = re.compile(NEGATION, re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_COMPOUND_SLD = {"co", "com", "org", "gov", "net", "ac"}


@dataclass
class RedFlag:
    code: str
    title: str
    explanation: str
    score: int


def normalize(text: str) -> str:
    """Lowercase and undo simple tricks scammers use to dodge keyword checks."""
    t = unicodedata.normalize("NFKC", text or "")
    t = t.translate(_ZERO_WIDTH).lower()
    # leetspeak inside words: "g1ft" -> "gift", "p@ssword" -> "password"
    t = re.sub(r"(?<=[a-z])[0@$](?=[a-z])", lambda m: {"0": "o", "@": "a", "$": "s"}[m.group()], t)
    t = re.sub(r"(?<=[a-z])1(?=[a-z])", "i", t)
    # spaced-out letters: "g i f t" -> "gift"
    t = re.sub(r"\b(?:[a-z][ .\-_]){3,}[a-z]\b", lambda m: re.sub(r"[ .\-_]", "", m.group()), t)
    return re.sub(r"[ \t]+", " ", t).strip()


def _registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _COMPOUND_SLD:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_tokens(host: str) -> List[str]:
    deleet = host.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"}))
    tokens = re.split(r"[.\-_]", host) + re.split(r"[.\-_]", deleet)
    return [t for t in tokens if t]


def analyze_links(text: str) -> List[RedFlag]:
    """Inspect every URL in the message for common scam tricks."""
    flags: List[RedFlag] = []
    seen = set()

    def add(code: str, title: str, explanation: str, score: int) -> None:
        if code not in seen:
            seen.add(code)
            flags.append(RedFlag(code, title, explanation, score))

    for raw in _URL_RE.findall(text or ""):
        url = raw.rstrip(".,;:!?")
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        reg = _registered_domain(host)
        tld = host.rsplit(".", 1)[-1]

        if reg in URL_SHORTENERS or host in URL_SHORTENERS:
            add("link_shortener", "Shortened link hides the real website",
                "Short links hide where they really go. Scammers use them to disguise fake sites.", 15)
        if _IPV4_RE.match(host):
            add("link_ip", "Link goes to a number address",
                "Real companies use their name in links, not a string of numbers.", 25)
        if host.startswith("xn--") or ".xn--" in host:
            add("link_punycode", "Link uses look-alike characters",
                "This web address uses special characters to imitate a real website.", 25)
        if parsed.username is not None or "@" in (parsed.netloc or ""):
            add("link_at_sign", "Link has a hidden destination",
                "A web address containing '@' can send you somewhere different from what it shows.", 20)
        if tld in SUSPICIOUS_TLDS:
            add("link_odd_tld", "Link ends in an unusual domain",
                f"Addresses ending in .{tld} are heavily used by scam sites.", 15)

        tokens = _host_tokens(host)
        for brand, official in BRANDS.items():
            matched = brand in tokens or (len(brand) >= 5 and any(t.startswith(brand) for t in tokens))
            if matched and reg not in official:
                add("link_lookalike", "Link pretends to be a trusted brand",
                    f"This web address mentions '{brand}' but is not the real {brand} website. "
                    "Scammers copy brand names in fake addresses.", 30)
                break
    return flags


def _sentences(text: str) -> List[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


def _rule_matches(rule: Dict, text: str, unsafe_sentences: List[str]) -> bool:
    pattern = re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
    if not rule.get("negatable"):
        return bool(pattern.search(text))
    return any(pattern.search(s) for s in unsafe_sentences)


def analyze_message(text: str, channel: Optional[str] = None) -> Dict:
    clean = (text or "").strip()
    normalized = normalize(clean)

    sentences = _sentences(normalized)
    # For negatable rules, ignore sentences that are safety warnings.
    unsafe_sentences = [s for s in sentences if not _NEGATION_RE.search(s)]

    flags: List[RedFlag] = []
    hard_hit = False
    for rule in RULES:
        if _rule_matches(rule, normalized, unsafe_sentences):
            flags.append(RedFlag(rule["code"], rule["title"], rule["explanation"], rule["score"]))
            hard_hit = hard_hit or bool(rule.get("hard"))

    flags.extend(analyze_links(clean))

    codes = {f.code for f in flags}
    if any(c.startswith("link_") for c in codes):
        codes.add("click_link")

    score = sum(f.score for f in flags)
    for required_all, required_any, bonus in COMBOS:
        if required_all <= codes and (not required_any or codes & required_any):
            score += bonus
    if "package_problem" in codes and any(c.startswith("link_") for c in codes):
        score += 10
    score = min(score, MAX_SCORE)

    if hard_hit or score >= SCAM_THRESHOLD:
        verdict = VERDICT_SCAM
        summary = ("This message has strong scam warning signs. Do not send money, share codes, "
                   "or use links or phone numbers in the message.")
    elif score >= CAREFUL_THRESHOLD:
        verdict = VERDICT_CAREFUL
        summary = ("This message has warning signs. Verify it using a trusted phone number or "
                   "website before doing anything.")
    else:
        verdict = VERDICT_CLEAR
        summary = ("No obvious scam warning signs were found, but that does not prove the "
                   "message is legitimate.")

    actions = [
        "Do not reply, pay, or share passwords or verification codes until you verify the sender.",
        "Do not use phone numbers or links provided in a suspicious message.",
        "Contact the company, bank, agency, or family member using a trusted number you already know or find independently.",
        "If money or account access is involved, ask a trusted family member or your bank before taking action.",
    ]
    if channel == "Phone call":
        actions.insert(0, "Hang up now. Then call the organization back using the number on your card, bill, or official website.")

    emoji = EMOJI[verdict]
    family_summary = (
        f"Scam Shield result: {emoji} {verdict}. "
        + ("Warning signs: " + ", ".join(f.title for f in flags) + ". " if flags else "No obvious warning signs were detected. ")
        + summary
    )

    return {
        "score": score,
        "level": LEVEL[verdict],
        "verdict": verdict,
        "emoji": emoji,
        "card_class": CARD_CLASS[verdict],
        "summary": summary,
        "red_flags": [asdict(f) for f in flags],
        "actions": actions,
        "family_summary": family_summary,
        "resources": RESOURCES,
    }
