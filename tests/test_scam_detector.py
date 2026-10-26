import json
import pathlib

import pytest

from scam_detector import (
    VERDICT_CAREFUL,
    VERDICT_CLEAR,
    VERDICT_SCAM,
    analyze_links,
    analyze_message,
    normalize,
)

DATA = pathlib.Path(__file__).parent / "data" / "labeled_messages.json"


@pytest.mark.parametrize(
    "message, expected",
    [
        ("This is the IRS. Pay immediately or you will be arrested.", VERDICT_SCAM),
        ("Your grandson is in jail. Do not tell anyone. Send money now.", VERDICT_SCAM),
        ("Pay the fine with gift cards and read me the numbers.", VERDICT_SCAM),
        ("Please install AnyDesk so I can fix your computer.", VERDICT_SCAM),
        ("Move your savings to a safe account to protect your money.", VERDICT_SCAM),
        ("Congratulations! You won a prize. Pay the processing fee to claim it.", VERDICT_CAREFUL),
        ("Your package is waiting. Pay a shipping fee at https://example.com", VERDICT_CAREFUL),
        ("Virus detected. Call Microsoft support now.", VERDICT_CAREFUL),
    ],
)
def test_common_scams(message, expected):
    result = analyze_message(message)
    assert result["verdict"] == expected
    assert result["score"] > 0


def test_arrested_matches_arrest_rule():
    # v0.1 bug: \barrest\b did not match "arrested"
    codes = {f["code"] for f in analyze_message("The IRS says you will be arrested.")["red_flags"]}
    assert "government_threat" in codes


def test_wont_is_not_a_prize():
    # v0.1 bug: \bwon\b matched the "won" in "won't"
    codes = {f["code"] for f in analyze_message("I won't be able to come Thursday.")["red_flags"]}
    assert "prize" not in codes


def test_bank_safety_warning_is_not_flagged():
    msg = "Wells Fargo: we will never ask for your PIN or one-time code. If someone does, hang up."
    assert analyze_message(msg)["verdict"] == VERDICT_CLEAR


def test_scam_asking_for_code_is_flagged():
    assert analyze_message("Please read me the verification code we texted you.")["verdict"] != VERDICT_CLEAR


def test_legitimate_pharmacy_message_has_no_obvious_flags():
    result = analyze_message("CVS Pharmacy: Your prescription is ready for pickup at your usual store.")
    assert result["score"] == 0
    assert result["verdict"] == VERDICT_CLEAR


def test_account_problem_plus_link_gets_combination_bonus():
    message = "Security alert: your account is locked. Click this link to verify your account: https://example.com"
    result = analyze_message(message)
    assert result["score"] >= 35
    assert len(result["red_flags"]) >= 2


def test_family_summary_is_created():
    result = analyze_message("You won a lottery prize. Pay a claim fee.")
    assert "Scam Shield result" in result["family_summary"]
    assert result["verdict"] in result["family_summary"]


def test_empty_message_is_clear():
    assert analyze_message("")["verdict"] == VERDICT_CLEAR


def test_normalize_defeats_simple_evasion():
    assert "gift card" in normalize("buy g1ft c4rd".replace("c4rd", "card"))
    assert "gift" in normalize("g i f t")
    assert "password" in normalize("p@ssword")


@pytest.mark.parametrize(
    "text, code",
    [
        ("Pay at bit.ly/3abc", "link_shortener"),
        ("Go to http://192.168.1.5/login", "link_ip"),
        ("Visit https://paypal-secure-login.xyz/verify", "link_lookalike"),
        ("Visit https://usps-redelivery.top/pay", "link_lookalike"),
        ("Open http://www.paypal.com@evil.example/login", "link_at_sign"),
    ],
)
def test_link_flags(text, code):
    assert code in {f.code for f in analyze_links(text)}


@pytest.mark.parametrize("text", ["https://www.paypal.com/signin", "https://www.irs.gov/refunds", "https://www.medicare.gov"])
def test_real_brand_links_not_flagged_as_lookalike(text):
    assert "link_lookalike" not in {f.code for f in analyze_links(text)}


def test_phone_call_channel_adds_hang_up_step():
    result = analyze_message("This is the IRS, pay with gift cards.", channel="Phone call")
    assert "Hang up" in result["actions"][0]


def test_accuracy_on_labeled_set():
    """Guards against regressions: no legit message may be called LIKELY SCAM,
    and the detector must catch nearly all scams in the labeled set."""
    rows = json.loads(DATA.read_text())
    scams = [r for r in rows if r["label"] == "scam"]
    legit = [r for r in rows if r["label"] == "legit"]
    caught = sum(analyze_message(r["text"])["verdict"] != VERDICT_CLEAR for r in scams)
    false_scam = [r["id"] for r in legit if analyze_message(r["text"])["verdict"] == VERDICT_SCAM]
    assert false_scam == []
    assert caught / len(scams) >= 0.9
