import pandas as pd

from src.metrics import summarize


def test_class_metrics_preserve_false_positive_and_false_negative_counts():
    frame = pd.DataFrame({"label": ["BENIGN", "BENIGN", "SCAN", "SCAN"]})
    predictions = pd.DataFrame({"decision": ["benign", "alert", "benign", "alert"],
                                "attack_type": ["BENIGN", "SCAN", "BENIGN", "SCAN"]})
    result = summarize(frame, predictions)
    assert result["binary_confusion_matrix"] == [[1, 1], [1, 1]]
    assert result["class_metrics"]["SCAN"] == {"precision": .5, "recall": .5, "f1": .5, "support": 2}


def test_empty_evaluation_has_explicit_absent_rates():
    result = summarize(pd.DataFrame({"label": pd.Series(dtype=str)}),
                       pd.DataFrame({"decision": pd.Series(dtype=str), "attack_type": pd.Series(dtype=str)}))
    assert result["flows"] == 0
    assert result["false_positive_rate"] is None
    assert result["category_macro_f1"] is None
    assert result["category_confusion_matrix"] == []
