"""Scam Shield detection rules.

Each rule is a dict:
  code        short id used in combination bonuses
  title       plain-English name shown to the user
  explanation why this is a warning sign (shown to the user)
  score       points added when the rule matches
  pattern     regex, matched against lowercased, normalized text
  hard        True = this signal alone makes the verdict LIKELY SCAM
  negatable   True = ignore matches inside sentences like
              "we will never ask for your password" (legit bank warnings)

Keep patterns bounded (use .{0,N}, never .*) so words from unrelated parts
of a long message are not joined into a false match.
"""


def near(a: str, b: str, gap: int = 100) -> str:
    """Match a and b within `gap` characters of each other, in either order."""
    return rf"(?:{a}).{{0,{gap}}}(?:{b})|(?:{b}).{{0,{gap}}}(?:{a})"


GOVERNMENT = r"\b(irs|social security|ssa|medicare|police|sheriff|federal agents?|government|fbi|dea|u\.?s\.? marshals?)\b"
THREAT = r"\b(arrest\w*|warrants?|suspend\w*|lawsuits?|legal action|jail|deport\w*|prosecut\w*|frozen|freeze)\b"
FAMILY = r"\b(grandson|granddaughter|grandchild|grandma|grandpa|nana|nephew|niece|son|daughter)\b"
EMERGENCY = r"\b(jail|arrested|hospital|accident|lawyer|bail|emergency|car crash|in trouble)\b"

RULES = [
    {
        "code": "government_threat",
        "title": "Government threat",
        "explanation": "Scammers pretend to be the IRS, Social Security, Medicare, or the police and threaten arrest, lawsuits, or loss of benefits. Real agencies do not threaten you by text, email, or phone call.",
        "score": 35,
        "pattern": near(GOVERNMENT, THREAT, 100),
    },
    {
        "code": "urgent_action",
        "title": "Pressure to act fast",
        "explanation": "Scammers create urgency so you do not have time to check the story or talk to someone.",
        "score": 15,
        "pattern": r"\b(act now|immediately|urgent(ly)?|right away|asap|within \d+ (minutes?|hours?)|final (warning|notice)|last chance|expires? (today|soon|tonight)|today only|respond (now|today))\b",
    },
    {
        "code": "gift_card",
        "title": "Gift card payment",
        "explanation": "Only scammers demand payment in gift cards. No real government agency, bank, or company will ever ask for this.",
        "score": 40,
        "hard": True,
        "pattern": (
            r"\b(buy|purchase|pay( with| using| in)?|paying|send|get me|load|need|deposit)\b.{0,40}"
            r"\b(gift ?cards?|(itunes|apple|google play|steam|vanilla|target|amazon) cards?)\b"
            r"|\b(gift ?cards?|(itunes|apple|google play|steam|vanilla|target|amazon) cards?)\b.{0,40}"
            r"\b(codes?|numbers?|pins?|photos?|pictures?|scratch|read (me )?the|back of the card)\b"
        ),
    },
    {
        "code": "crypto",
        "title": "Cryptocurrency request",
        "explanation": "Scammers ask for cryptocurrency or Bitcoin ATM deposits because the money is nearly impossible to get back.",
        "score": 25,
        "pattern": r"\b(bitcoin|btc|crypto(currency)?|usdt|ethereum|wallet address|bitcoin atm|crypto atm)\b",
    },
    {
        "code": "wire_payment",
        "title": "Hard-to-reverse payment",
        "explanation": "Requests for wire transfers, Zelle, Cash App, Venmo, or Western Union are a common scam warning sign because the money is very hard to recover.",
        "score": 20,
        "negatable": True,
        "pattern": r"\b(send|pay|wire|transfer|deposit|use)\b.{0,50}\b(wire transfer|western union|moneygram|zelle|cash ?app|venmo)\b",
    },
    {
        "code": "money_request",
        "title": "Asked to send money",
        "explanation": "Be very careful with any unexpected request to send money, especially from someone you cannot verify.",
        "score": 15,
        "pattern": r"\b(send|wire|transfer|pay|give|lend|loan|deposit|need)\b.{0,40}(\bmoney\b|\bcash\b|\bfunds\b|\bbail\b|\bbills?\b|\$\s?\d[\d,]*)",
    },
    {
        "code": "prize",
        "title": "Unexpected prize",
        "explanation": "Unexpected prizes are used to lure people into paying fees or sharing personal information. You cannot win a contest you did not enter.",
        "score": 25,
        "pattern": r"\b(you (have |just )?won|you are a winner|you('?ve| have) been selected|prize|lottery|sweepstakes|jackpot)\b",
    },
    {
        "code": "advance_fee",
        "title": "Fee required first",
        "explanation": "Scammers ask for a small fee before releasing a fake prize, package, refund, loan, or benefit.",
        "score": 20,
        "pattern": r"\b(processing|release|shipping|customs|activation|claim|handling|admin(istration)?|insurance) fees?\b",
    },
    {
        "code": "family_emergency",
        "title": "Family emergency story",
        "explanation": "Scammers pretend to be a grandchild or relative in trouble (jail, hospital, accident). Voice cloning can make the call sound real. Hang up and call the family member directly on a number you already have.",
        "score": 15,
        "pattern": near(FAMILY, EMERGENCY, 100),
    },
    {
        "code": "family_new_number",
        "title": "'New number' message from a relative",
        "explanation": "Texts like 'Hi Mom, I lost my phone, this is my new number' are a common scam. Call your child or grandchild on the old number before replying.",
        "score": 30,
        "pattern": r"\b(hi|hello|hey)[, ]+(mom|mum|dad|grandma|grandpa|nana)\b.{0,100}\b(new (phone|number)|lost my phone|phone (broke|is broken|fell|died)|dropped my phone)\b",
    },
    {
        "code": "new_number",
        "title": "'New phone' story",
        "explanation": "Messages saying 'new phone, new number' from someone claiming to be family are a common scam. Call your relative on the number you already have.",
        "score": 15,
        "pattern": r"\b(this is my new (phone|number)|got a new (phone|number)|new phone,? who|lost my phone|dropped my phone|phone (broke|is broken|fell in))\b",
    },
    {
        "code": "secrecy",
        "title": "Asked to keep it secret",
        "explanation": "Scammers tell you not to talk to family, your bank, or the police, because checking would expose the scam.",
        "score": 20,
        "pattern": r"\b(do not|don'?t|dont) (tell|call|talk to|speak (to|with)|inform)\b.{0,30}\b(anyone|anybody|family|bank|police|your (son|daughter|grandson|granddaughter|children|wife|husband|kids))\b|\bkeep (this|it) (a )?(secret|confidential|private|between us)\b|\bbetween us\b",
    },
    {
        "code": "account_problem",
        "title": "Account problem claim",
        "explanation": "Fake account warnings are often used to steal passwords or payment details. Log in by typing the company's website yourself, never through a message link.",
        "score": 15,
        "pattern": r"\b(account (is |has been |was )?(locked|suspended|compromised|limited|restricted|disabled)|verify your (account|identity)|unusual (activity|sign[- ]?in)|suspicious (activity|login|log[- ]in|transaction)|security alert)\b",
    },
    {
        "code": "click_link",
        "title": "Link included",
        "explanation": "Scam messages often push you to a link that leads to a fake login or payment page. Do not open links in unexpected messages.",
        "score": 10,
        "pattern": r"\b(click|tap|follow|open)\b.{0,25}\b(link|url|button)\b|https?://|www\.",
    },
    {
        "code": "remote_access",
        "title": "Remote access request",
        "explanation": "Real companies do not unexpectedly ask to control your computer or phone. Giving remote access lets a scammer see your bank accounts and passwords.",
        "score": 35,
        "hard": True,
        "pattern": r"\b(anydesk|teamviewer|ultraviewer|quick ?support|remote (access|desktop|control)|screen ?shar\w*|give me control|let me (connect|access) (to )?your|support app)\b",
    },
    {
        "code": "password_code",
        "title": "Asked for a password or security code",
        "explanation": "Never share passwords, PINs, or one-time codes with someone who contacted you. Anyone who asks for a code is trying to break into your account.",
        "score": 30,
        "negatable": True,
        "pattern": r"\b(send|tell|read|give|share|provide|forward|reply( with)?|text|confirm|verify|enter)\b.{0,50}\b(password|passcode|pin|verification code|one[- ]time (code|password)|otp|security code|login code|6[- ]digit code)\b",
    },
    {
        "code": "personal_info",
        "title": "Asked for sensitive personal information",
        "explanation": "Unexpected requests for your Social Security number, bank details, or card numbers are a serious warning sign.",
        "score": 25,
        "negatable": True,
        "pattern": r"\b(send|provide|confirm|verify|give|share|enter|reply|tell|need|update)\b.{0,60}\b(social security( number)?|ssn|bank account( number)?|routing number|(credit|debit) card( number)?|card number|date of birth|dob|medicare number|mother'?s maiden name)\b",
    },
    {
        "code": "malware_popup",
        "title": "Fake virus or tech-support warning",
        "explanation": "Pop-ups or calls claiming your device is infected, and telling you to call a number, are a classic tech-support scam. Close the window; real warnings never include a phone number.",
        "score": 30,
        "pattern": r"\b(virus detected|(computer|device|pc|phone|mac) (is |has been )?(infected|hacked|compromised|blocked)|hackers? detected|call (microsoft|apple|windows|geek squad) (support|now)|do not (restart|shut ?down|turn off))\b",
    },
    {
        "code": "callback_number",
        "title": "Asks you to call a number in the message",
        "explanation": "Scammers include a phone number so you call them. Look up the company's real number yourself instead.",
        "score": 15,
        "pattern": r"\b(call|phone|dial|contact|reach)\b.{0,40}(\+?1?[-.\s(]*\d{3}[-.\s)]*\d{3}[-.\s]?\d{4})",
    },
    {
        "code": "unexpected_charge",
        "title": "Unexpected charge or subscription",
        "explanation": "Fake invoices and 'you were charged' messages try to make you call a number to dispute the charge. That call is the scam.",
        "score": 15,
        "pattern": r"\b(you (have been|were|are being) charged|charge of \$|auto[- ]?renew\w*|subscription (has been )?(renewed|activated)|unauthorized (charge|transaction|purchase|payment)|purchase of \$\s?\d|invoice (for|of) \$)\b",
    },
    {
        "code": "investment_returns",
        "title": "Too-good-to-be-true investment",
        "explanation": "Investment fraud is the costliest scam type for older adults. Guaranteed returns, 'risk-free' profits, and crypto trading groups are red flags. Real investments always carry risk.",
        "score": 30,
        "pattern": r"\b(guaranteed (returns?|profits?|income)|risk[- ]free|double your (money|investment)|\d{2,}% (return|profit|daily|weekly|monthly)|insider (tip|trading)|trading (platform|signals?|group)|crypto (investment|mining)|can'?t lose)\b",
    },
    {
        "code": "wrong_number",
        "title": "'Wrong number' opening",
        "explanation": "A friendly text from a stranger ('sorry, wrong number') is often the first step of a romance or investment scam. Do not reply.",
        "score": 20,
        "pattern": r"\b(wrong number|texted the wrong|sent (this )?to the wrong|do we know each other|have we met)\b",
    },
    {
        "code": "romance",
        "title": "Romance-scam language",
        "explanation": "Someone you met online who quickly says they love you, can never video call, and then needs money is a classic romance scam.",
        "score": 10,
        "pattern": r"\b(i love you|my love|sweetheart|darling|soulmate|deployed|oil rig|stationed overseas|can'?t (video call|video chat|meet))\b",
    },
    {
        "code": "package_problem",
        "title": "Delivery problem notice",
        "explanation": "Fake USPS, FedEx, UPS, and Amazon notices ask for a fee or address confirmation. Check the tracking number on the carrier's real website.",
        "score": 15,
        "pattern": near(
            r"\b(usps|fedex|ups|dhl|amazon|package|parcel|delivery|shipment)\b",
            r"\b(unpaid|customs|address (is )?(incomplete|invalid|issue|problem)|redelivery fee|on hold|confirm (your )?address|held at)\b",
            100,
        ),
    },
    {
        "code": "toll_notice",
        "title": "Unpaid toll notice",
        "explanation": "Fake toll-violation texts (E-ZPass, SunPass and others) are widespread. Check your toll account on the agency's real website.",
        "score": 25,
        "pattern": near(
            r"\b(toll|e-?zpass|ez pass|sunpass|fastrak)\b",
            r"\b(unpaid|outstanding|overdue|balance|late fee|penalt\w+)\b",
            100,
        ),
    },
    {
        "code": "safe_account",
        "title": "Told to move money to a 'safe' account",
        "explanation": "No real bank or agency will ever tell you to move your money to a 'safe' or 'protected' account. This is a major scam that drains savings.",
        "score": 40,
        "hard": True,
        "pattern": r"\b(safe|secure|protected|holding) account\b|\bmove (all )?(of )?your (money|funds|savings)\b|\btransfer (all )?(of )?your (money|funds|savings)\b",
    },
    {
        "code": "refund_overpayment",
        "title": "Unexpected refund or overpayment",
        "explanation": "Scammers say you are owed a refund, or 'accidentally' sent you too much and ask for the difference back. The original payment is usually fake.",
        "score": 20,
        "pattern": r"\b(you (are|were) (owed|due|eligible)|eligible for (a )?refund|overpa(id|yment)|accidentally (sent|deposited|paid)|send (back )?the (difference|extra|excess)|refund (is )?(pending|ready|waiting))\b",
    },
    {
        "code": "recovery_scam",
        "title": "Offer to recover lost money",
        "explanation": "People who were scammed are targeted again by 'recovery' services that charge a fee and do nothing. Report to the FTC and your bank instead.",
        "score": 30,
        "pattern": r"\b(recover|get back|retrieve|reclaim)\b.{0,40}\b(lost|stolen|your) (money|funds|bitcoin|crypto|investment)\b|\b(fund recovery|asset recovery|recovery (agent|service|specialist|fee))\b",
    },
    {
        "code": "utility_shutoff",
        "title": "Utility shut-off threat",
        "explanation": "Scammers threaten to cut off power, gas, or water within hours unless you pay immediately. Real utilities send written notices first.",
        "score": 30,
        "pattern": r"\b(electric|power|gas|water|utility|internet|cable)\b.{0,80}\b(disconnect\w*|shut ?off|terminat\w+|cut off)\b.{0,80}\b(today|within|unless|immediately|\d+ (hours?|minutes?))\b",
    },
    {
        "code": "job_offer",
        "title": "Suspicious job offer",
        "explanation": "Fake jobs ask you to buy equipment, deposit a check and send money back, or pay a training fee. A real employer never makes you pay first.",
        "score": 25,
        "pattern": r"\b(work from home|remote (job|position)|job offer|we are hiring)\b.{0,100}\b(equipment|starter kit|training fee|deposit (a|the|this) check|cash (the|this) check|send back|purchase (supplies|software)|buy (supplies|equipment)|crypto)\b|\bmystery shopper\b|\bearn \$\d+ (per|a) (day|hour)\b",
    },
    {
        "code": "medicare_scam",
        "title": "Medicare or benefits scam",
        "explanation": "Medicare will not call or text to 'verify' your number, send a new card for a fee, or offer free tests and braces. These are used to steal your Medicare number.",
        "score": 25,
        "pattern": r"\bmedicare\b.{0,80}\b(new card|expire\w*|suspend\w*|verify|confirm|update|free (back|knee|brace|genetic|test|equipment))\b|\bfree (genetic|dna|back brace|knee brace) (test|kit|brace)\b",
    },
]

# Combination bonuses: (set of codes that must ALL be present, or any-of groups, bonus, label)
# Each combo is (required_all, required_any, bonus). required_any may be empty.
COMBOS = [
    ({"urgent_action"}, {"gift_card", "wire_payment", "crypto", "money_request"}, 15),
    ({"government_threat"}, {"gift_card", "wire_payment", "crypto", "money_request"}, 20),
    ({"family_emergency"}, {"secrecy", "money_request"}, 20),
    ({"account_problem", "click_link"}, set(), 10),
    ({"unexpected_charge", "callback_number"}, set(), 15),
    ({"malware_popup", "callback_number"}, set(), 10),
    ({"romance", "money_request"}, set(), 25),
    ({"new_number", "money_request"}, set(), 20),
    ({"investment_returns"}, {"crypto", "click_link"}, 15),
]

# Brand -> official registered domains (used for lookalike-link detection).
BRANDS = {
    "usps": {"usps.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "dhl": {"dhl.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citi.com", "citibank.com"},
    "capitalone": {"capitalone.com"},
    "irs": {"irs.gov"},
    "medicare": {"medicare.gov", "cms.gov"},
    "ssa": {"ssa.gov"},
    "socialsecurity": {"ssa.gov"},
    "netflix": {"netflix.com"},
    "ezpass": {"e-zpassny.com", "ezpassnj.com", "ezpassmd.com"},
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "t.ly", "buff.ly",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "icu", "vip", "buzz", "rest", "cyou", "cfd",
    "sbs", "tk", "ml", "ga", "cf", "gq", "monster", "lol",
}

# Phrases that mean "this is a safety warning, not a request".
NEGATION = r"\b(never|do not|don'?t|will not|won'?t|wouldn'?t|should not|shouldn'?t)\b.{0,40}\b(ask|request|call|text|email|share|give|send|tell|provide|reveal|disclose)\b"

# Where to report / get help (verify before publishing; these can change).
RESOURCES = [
    ("Report fraud to the FTC", "reportfraud.ftc.gov"),
    ("Report internet crime to the FBI (IC3)", "ic3.gov"),
    ("National Elder Fraud Hotline", "1-833-FRAUD-11 (1-833-372-8311)"),
    ("AARP Fraud Watch Helpline", "1-877-908-3360"),
    ("Forward scam texts to your carrier", "Text the message to 7726 (SPAM)"),
]
