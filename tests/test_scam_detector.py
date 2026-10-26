import pytest
from scam_detector import analyze_message


@pytest.mark.parametrize(
    "message, expected",
    [
        ("This is the IRS. Pay immediately or you will be arrested.", "LIKELY SCAM"),
        ("Your grandson is in jail. Do not tell anyone. Send money now.", "LIKELY SCAM"),
        ("Congratulations! You won a prize. Pay the processing fee to claim it.", "BE CAREFUL"),
        ("Your package is waiting. Pay a shipping fee at https://example.com", "BE CAREFUL"),
        ("Send bitcoin to this wallet immediately.", "LIKELY SCAM"),
        ("Virus detected. Call Microsoft support now.", "BE CAREFUL"),
    ],
)
def test_common_scams(message, expected):
    result = analyze_message(message)
    assert result["verdict"] == expected
    assert result["score"] > 0


def test_legitimate_pharmacy_message_has_no_obvious_flags():
    message = "CVS Pharmacy: Your prescription is ready for pickup at your usual store."
    result = analyze_message(message)
    assert result["score"] == 0
    assert result["verdict"] == "NO OBVIOUS RED FLAGS"


def test_account_problem_plus_link_gets_combination_bonus():
    message = "Security alert: your account is locked. Click this link to verify your account: https://example.com"
    result = analyze_message(message)
    assert result["score"] >= 35
    assert len(result["red_flags"]) >= 2


def test_family_summary_is_created():
    result = analyze_message("You won a lottery prize. Pay a claim fee.")
    assert "Scam Shield result" in result["family_summary"]
    assert result["verdict"] in result["family_summary"]


@pytest.mark.parametrize("message", [
    "Pay immediately with gift cards.",
    "Pay immediately with a gift card.",
    "This is the police. Pay immediately or face arrest.",
])
def test_urgent_payment_and_government_threats(message):
    assert analyze_message(message)["verdict"] == "LIKELY SCAM"


def test_crypto_without_urgency_is_caution():
    result = analyze_message("Send bitcoin to this wallet.")
    assert result["verdict"] == "BE CAREFUL"
    assert result["score"] == 25
