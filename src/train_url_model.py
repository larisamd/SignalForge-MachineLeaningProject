"""
train_url_model.py
-------------------
Trains Module B (URL sub-component): malicious / phishing URL classifier.

Dataset: ~420K labelled URLs (good/bad). For a reasonable training time on
a laptop we take a stratified sample (default 100,000 rows, preserving the
original class ratio) — override with --sample-size or --full.

Features are hand-engineered lexical/structural signals (see
src/url_features.py), NOT the raw URL string, so the model reasons over
things like URL length, symbol counts, suspicious TLDs, IP-literal hosts,
and shortener usage rather than memorising exact domains.

Run from the project root:
    python src/train_url_model.py
    python src/train_url_model.py --sample-size 50000
    python src/train_url_model.py --full
"""

import os
import sys
import json
import argparse
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report, f1_score, confusion_matrix, roc_auc_score
)

sys.path.insert(0, os.path.dirname(__file__))
from url_features import features_to_vector, FEATURE_NAMES  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "raw", "malicious_urls.csv")
MODEL_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "url_metrics.json")


def load_data(sample_size):
    df = pd.read_csv(DATA_PATH)
    dataset_records = len(df)
    df.columns = [c.strip().lower() for c in df.columns]
    df["label_bin"] = (df["label"].str.strip().str.lower() == "bad").astype(int)

    if sample_size is not None and sample_size < len(df):
        frac = sample_size / len(df)
        parts = []
        for label_val, group in df.groupby("label_bin"):
            n = max(1, int(round(len(group) * frac)))
            parts.append(group.sample(n=min(n, len(group)), random_state=42))
        df = pd.concat(parts, axis=0)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.attrs["dataset_records"] = dataset_records
    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-size", type=int, default=100_000,
                         help="Stratified sample size to train on (default: 100000)")
    parser.add_argument("--full", action="store_true", help="Use the full dataset (slower)")
    args = parser.parse_args()
    sample_size = None if args.full else args.sample_size

    print("[Module B] Loading data from", DATA_PATH)
    df = load_data(sample_size)
    dataset_records = df.attrs["dataset_records"]
    print(f"[Module B] Training on {len(df)} URLs | "
          f"malicious={df['label_bin'].sum()} legitimate={(df['label_bin']==0).sum()}")

    print("[Module B] Extracting lexical/structural features (this may take a moment)...")
    feature_rows = [features_to_vector(u) for u in df["url"].astype(str)]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = df["label_bin"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    print("[Module B] Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=120, max_depth=14, min_samples_leaf=4,
        class_weight="balanced", n_jobs=-1, random_state=42
    )
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    probs = clf.predict_proba(X_test)[:, 1]
    f1 = f1_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    cm = confusion_matrix(y_test, preds).tolist()
    report = classification_report(y_test, preds, target_names=["legitimate", "malicious"], output_dict=True)

    print("\n[Module B] === RandomForestClassifier ===")
    print(classification_report(y_test, preds, target_names=["legitimate", "malicious"]))
    print("Confusion matrix [[TN, FP], [FN, TP]]:", cm)
    print(f"ROC-AUC: {auc:.4f}")

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1]
    )
    print("\n[Module B] Top 8 most important features:")
    for name, imp in importances[:8]:
        print(f"   {name:28s} {imp:.4f}")

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump({
            "f1_malicious": f1, "roc_auc": auc, "confusion_matrix": cm,
            "report": report, "n_train": len(X_train), "n_test": len(X_test),
            "dataset_records": dataset_records,
            "top_features": [{"feature": n, "importance": float(i)} for n, i in importances[:10]],
        }, f, indent=2)

    print(f"\n[Module B] Saved model   -> {MODEL_PATH}")
    print(f"[Module B] Saved metrics -> {METRICS_PATH}")


if __name__ == "__main__":
    main()
