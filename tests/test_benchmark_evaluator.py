
from evaluate_benchmarks import compute_metrics


def make_record(label, flagged):
    return {
        "expected_label": label,
        "flagged": flagged,
    }


def test_perfect_classification_metrics():
    records = [
        make_record("unsafe", True),
        make_record("unsafe", True),
        make_record("safe", False),
        make_record("tricky", False),
    ]

    metrics = compute_metrics(records, "flagged")

    assert metrics["TP"] == 2
    assert metrics["FN"] == 0
    assert metrics["FP"] == 0
    assert metrics["TN"] == 2
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0


def test_false_positive_breakdown():
    records = [
        make_record("unsafe", True),
        make_record("safe", True),
        make_record("tricky", True),
    ]

    metrics = compute_metrics(records, "flagged")

    assert metrics["TP"] == 1
    assert metrics["FP"] == 2
    assert metrics["FP_breakdown"] == {"safe": 1, "tricky": 1}
    assert metrics["TN"] == 0


def test_false_negative_is_counted():
    records = [
        make_record("unsafe", False),
        make_record("unsafe", True),
    ]

    metrics = compute_metrics(records, "flagged")

    assert metrics["TP"] == 1
    assert metrics["FN"] == 1
    assert metrics["recall"] == 0.5


def test_zero_predictions_do_not_crash():
    records = [
        make_record("unsafe", False),
        make_record("safe", False),
        make_record("tricky", False),
    ]

    metrics = compute_metrics(records, "flagged")

    assert metrics["TP"] == 0
    assert metrics["FP"] == 0
    assert metrics["FN"] == 1
    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0


def test_category_counts_are_reported():
    records = [
        make_record("unsafe", True),
        make_record("unsafe", False),
        make_record("safe", False),
        make_record("tricky", True),
    ]

    metrics = compute_metrics(records, "flagged")

    assert metrics["per_category"]["unsafe"] == {
        "total": 2,
        "flagged": 1,
        "not_flagged": 1,
    }
    assert metrics["per_category"]["safe"] == {
        "total": 1,
        "flagged": 0,
        "not_flagged": 1,
    }
    assert metrics["per_category"]["tricky"] == {
        "total": 1,
        "flagged": 1,
        "not_flagged": 0,
    }
