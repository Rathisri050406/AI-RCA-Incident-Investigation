"""Training + evaluation. All metrics come from the held-out TEST split."""
import json
import joblib
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from backend.config import settings
from backend.ml.feature_engineering import FEATURES, build_features
from backend.ml.preprocessor import clean

try:
    from xgboost import XGBClassifier
except Exception:
    XGBClassifier = None


def _models(pos_weight):
    m = {}
    if XGBClassifier is not None:
        m["xgboost"] = XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                                     eval_metric="logloss", scale_pos_weight=pos_weight, n_jobs=-1)
    else:
        m["gradient_boosting (xgboost not installed)"] = GradientBoostingClassifier(random_state=42)
    m["random_forest"] = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42,
                                                class_weight="balanced")
    m["logistic_regression"] = make_pipeline(StandardScaler(),
                                             LogisticRegression(max_iter=500, class_weight="balanced"))
    return m


def _metrics(model, X, y):
    pred = model.predict(X)
    proba = model.predict_proba(X)[:, 1]
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
            "roc_auc": roc_auc_score(y, proba) if len(set(y)) > 1 else None,
            "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]}


def train_and_evaluate(df, data_source, out_dir=None, test_size=0.2, seed=42):
    out_dir = out_dir or settings.model_dir
    (out_dir / "plots").mkdir(parents=True, exist_ok=True)

    X_raw, y = clean(df)
    X = build_features(X_raw)
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size, stratify=y, random_state=seed)

    pos_weight = float((y_tr == 0).sum() / max(1, (y_tr == 1).sum()))
    results, fitted = {}, {}
    for name, model in _models(pos_weight).items():
        model.fit(X_tr, y_tr)                       # fit on TRAIN only
        fitted[name] = model
        results[name] = _metrics(model, X_te, y_te)  # evaluate on TEST only

    primary = next(iter(fitted))
    joblib.dump({"model": fitted[primary], "features": FEATURES, "name": primary,
                 "data_source": data_source}, out_dir / "detector.pkl")

    info = {"data_source": data_source, "primary_model": primary, "n_train": int(len(X_tr)),
            "n_test": int(len(X_te)),
            "class_counts_total": {"benign": int((y == 0).sum()), "attack": int((y == 1).sum())},
            "results": results}
    if data_source.startswith("synthetic"):
        info["warning"] = "Trained on SYNTHETIC data. Metrics do not reflect real-world performance."
    (out_dir / "metrics.json").write_text(json.dumps(info, indent=2, default=float))
    _plots(out_dir / "plots", fitted[primary], results[primary], y, results)
    return info


def _plots(d, model, res, y, all_res):
    plt.figure(figsize=(4, 3.5))
    cm = np.array(res["confusion_matrix"])
    plt.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            plt.text(j, i, cm[i, j], ha="center", va="center")
    plt.xticks([0, 1], ["Benign", "Attack"]); plt.yticks([0, 1], ["Benign", "Attack"])
    plt.xlabel("Predicted"); plt.ylabel("Actual"); plt.title("Confusion matrix (test)")
    plt.tight_layout(); plt.savefig(d / "confusion_matrix.png", dpi=120); plt.close()

    plt.figure(figsize=(4, 3.5))
    plt.bar(["Benign", "Attack"], [(y == 0).sum(), (y == 1).sum()], color=["#4c8bf5", "#e5534b"])
    plt.title("Class distribution"); plt.tight_layout(); plt.savefig(d / "class_distribution.png", dpi=120); plt.close()

    imp = getattr(model, "feature_importances_", None)
    if imp is not None:
        order = np.argsort(imp)
        plt.figure(figsize=(5, 4))
        plt.barh(np.array(FEATURES)[order], imp[order], color="#4c8bf5")
        plt.title("Feature importance"); plt.tight_layout(); plt.savefig(d / "feature_importance.png", dpi=120); plt.close()

    keys = ["accuracy", "precision", "recall", "f1"]
    plt.figure(figsize=(6, 3.5))
    w = 0.8 / len(all_res)
    for i, (n, r) in enumerate(all_res.items()):
        plt.bar(np.arange(4) + i * w, [r[k] for k in keys], w, label=n[:22])
    plt.xticks(np.arange(4) + 0.4 - w / 2, keys); plt.ylim(0, 1.05); plt.legend(fontsize=6)
    plt.title("Evaluation metrics (test)"); plt.tight_layout(); plt.savefig(d / "metrics.png", dpi=120); plt.close()
