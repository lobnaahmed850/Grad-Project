"""Binary detection and category metrics with counts and session-level evidence."""
import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support


def summarize(frame, predictions):
    if len(frame) != len(predictions):
        raise ValueError("Truth and prediction row counts differ")
    truth = frame["label"].to_numpy()
    detected = predictions["decision"].eq("alert").to_numpy()
    attack = truth != "BENIGN"
    if len(truth):
        tn, fp, fn, tp = confusion_matrix(attack, detected, labels=[False, True]).ravel()
        precision, recall, f1, _ = precision_recall_fscore_support(attack, detected, average="binary", zero_division=0)
    else:
        tn, fp, fn, tp = 0, 0, 0, 0
        precision, recall, f1 = 0.0, 0.0, 0.0
    categories = {}
    for label in sorted(set(truth)):
        where = truth == label
        categories[label] = {"flows": int(where.sum()), "detection_rate": float(detected[where].mean()),
                             "correct_type_rate": float((predictions["attack_type"].to_numpy()[where] == label).mean())}
    classes = sorted(set(truth) | set(predictions["attack_type"]))
    if len(truth):
        _, _, macro_f1, _ = precision_recall_fscore_support(truth, predictions["attack_type"], average="macro", zero_division=0)
        class_precision, class_recall, class_f1, support = precision_recall_fscore_support(
            truth, predictions["attack_type"], labels=classes, zero_division=0)
        class_metrics = {name: {"precision": float(class_precision[index]), "recall": float(class_recall[index]),
                               "f1": float(class_f1[index]), "support": int(support[index])}
                         for index, name in enumerate(classes)}
    else:
        macro_f1, class_metrics = None, {}
    per_attack = [value["detection_rate"] for label, value in categories.items() if label != "BENIGN"]
    result = {
        "flows": len(frame), "binary_confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "macro_detection_rate": float(np.mean(per_attack)) if per_attack else None,
        "category_macro_f1": float(macro_f1) if macro_f1 is not None else None,
        "categories": categories, "class_metrics": class_metrics,
        "category_confusion_labels": classes,
        "category_confusion_matrix": (
            [] if not classes else [[len(truth)]] if len(classes) == 1
            else confusion_matrix(truth, predictions["attack_type"], labels=classes).tolist()
        ),
    }
    if fp + tn:
        total = fp + tn
        proportion = fp / total
        center = (proportion + 1.96 ** 2 / (2 * total)) / (1 + 1.96 ** 2 / total)
        spread = 1.96 * np.sqrt(proportion * (1 - proportion) / total + 1.96 ** 2 / (4 * total ** 2)) / (1 + 1.96 ** 2 / total)
        result["false_positive_rate_95pct_wilson"] = [float(center - spread), float(center + spread)]
    return result


def evaluate(model, frame):
    predictions = model.predict(frame)
    result = summarize(frame, predictions)
    result["sessions"] = {
        name: summarize(frame.loc[positions], predictions.loc[positions])
        for name, positions in frame.groupby("session_id").groups.items()
    }
    return result
