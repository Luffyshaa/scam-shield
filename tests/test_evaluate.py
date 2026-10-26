import pytest

from evaluate import evaluate


def test_metrics_distinguish_false_clears_and_false_warnings():
    metrics = evaluate([
        {'id': 'caught', 'label': 'scam', 'text': 'Pay with gift cards now.'},
        {'id': 'missed', 'label': 'scam', 'text': 'Hello friend.'},
        {'id': 'warned', 'label': 'legit', 'text': 'Pay with gift cards now.'},
        {'id': 'clear', 'label': 'legit', 'text': 'Lunch tomorrow?'},
    ])
    assert metrics['scam_recall'] == 0.5
    assert metrics['false_clear_rate'] == 0.5
    assert metrics['high_risk_precision'] == 0.5
    assert metrics['false_warning_rate'] == 0.5
    assert metrics['false_high_risk_count'] == 1
    assert metrics['missed_scam_ids'] == ['missed']
    assert metrics['warned_legitimate_ids'] == ['warned']


@pytest.mark.parametrize('rows', [[], [{'label': 'scam', 'text': 'Hello'}], [{'label': 'unknown', 'text': 'Hi'}]])
def test_invalid_dataset_cannot_produce_passing_metrics(rows):
    with pytest.raises(ValueError):
        evaluate(rows)
