"""Evaluate synthetic regression data, not real-world detection accuracy."""
import argparse
import json
from pathlib import Path

from scam_detector import VERDICT_CLEAR, VERDICT_SCAM, analyze_message

DEFAULT_DATA = Path(__file__).resolve().parent / 'tests/data/labeled_messages.json'


def evaluate(rows):
    if not rows or any(row.get('label') not in {'scam', 'legit'} or not isinstance(row.get('text'), str) for row in rows):
        raise ValueError('Dataset must contain text and scam/legit labels for every row.')
    scams = sum(row['label'] == 'scam' for row in rows)
    legit = len(rows) - scams
    if not scams or not legit:
        raise ValueError('Dataset must contain both scam and legitimate examples.')
    missed, warned, high_scams, high_legit = [], [], 0, 0
    for row in rows:
        verdict = analyze_message(row['text'])['verdict']
        if row['label'] == 'scam':
            if verdict == VERDICT_CLEAR:
                missed.append(row['id'])
            high_scams += verdict == VERDICT_SCAM
        else:
            if verdict != VERDICT_CLEAR:
                warned.append(row['id'])
            high_legit += verdict == VERDICT_SCAM
    high_total = high_scams + high_legit
    return {
        'scams': scams, 'legitimate': legit,
        'scam_recall': (scams - len(missed)) / scams,
        'false_clear_rate': len(missed) / scams,
        'high_risk_precision': high_scams / high_total if high_total else None,
        'false_warning_rate': len(warned) / legit,
        'false_high_risk_count': high_legit,
        'missed_scam_ids': missed, 'warned_legitimate_ids': warned,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, default=DEFAULT_DATA)
    args = parser.parse_args()
    try:
        result = evaluate(json.loads(args.data.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    print('Synthetic regression evaluation; these results do not establish real-world accuracy.')
    print(json.dumps(result, indent=2))
    # Match the supplied regression contract: >=90% scam recall, no false Highs.
    return 0 if result['scam_recall'] >= 0.9 and result['false_high_risk_count'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
