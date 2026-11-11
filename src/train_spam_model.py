"""
train_spam_model.py
--------------------
Trains Module A: Spam vs. Ham text classifier.

Dataset: SMS Spam Collection (5,574 labelled messages).
Compares Multinomial Naive Bayes vs. Logistic Regression over TF-IDF
features, picks the better performer on a held-out validation split,
and saves the winning pipeline to models/spam_model.joblib.

Run from the project root:
    python src/train_spam_model.py
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    classification_report, f1_score, confusion_matrix, roc_auc_score
)

sys.path.insert(0, os.path.dirname(__file__))
from text_clean import clean_text  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(ROOT, "data", "raw", "sms_spam.tsv")
MODEL_DIR = os.path.join(ROOT, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "spam_model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "spam_metrics.json")


def load_data():
    df = pd.read_csv(DATA_PATH, sep="\t", header=None, names=["label", "text"])
    df["label_bin"] = (df["label"].str.strip().str.lower() == "spam").astype(int)
    df["clean_text"] = df["text"].apply(clean_text)
    return df


def main():
    print("[Module A] Loading data from", DATA_PATH)
    df = load_data()
    print(f"[Module A] {len(df)} messages | spam={df['label_bin'].sum()} ham={(df['label_bin']==0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["clean_text"], df["label_bin"], test_size=0.2,
        stratify=df["label_bin"], random_state=42
    )

    candidates = {
        "MultinomialNB": Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=6000, min_df=2)),
            ("clf", MultinomialNB()),
        ]),
        "LogisticRegression": Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=6000, min_df=2)),
            ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=5.0)),
        ]),
    }

    best_name, best_pipeline, best_f1 = None, None, -1
    results = {}

    for name, pipeline in candidates.items():
        pipeline.fit(X_train, y_train)
        preds = pipeline.predict(X_test)
        probs = pipeline.predict_proba(X_test)[:, 1]
        f1 = f1_score(y_test, preds)
        auc = roc_auc_score(y_test, probs)
        cm = confusion_matrix(y_test, preds).tolist()
        report = classification_report(y_test, preds, target_names=["ham", "spam"], output_dict=True)

        print(f"\n[Module A] === {name} ===")
        print(classification_report(y_test, preds, target_names=["ham", "spam"]))
        print("Confusion matrix [[TN, FP], [FN, TP]]:", cm)
        print(f"ROC-AUC: {auc:.4f}")

        results[name] = {"f1_spam": f1, "roc_auc": auc, "confusion_matrix": cm, "report": report}

        if f1 > best_f1:
            best_name, best_pipeline, best_f1 = name, pipeline, f1

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(best_pipeline, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump({
            "best_model": best_name,
            "results": results,
            "dataset_records": len(df),
            "n_train": len(X_train),
            "n_test": len(X_test),
        }, f, indent=2)

    print(f"\n[Module A] Best model: {best_name} (F1={best_f1:.4f})")
    print(f"[Module A] Saved pipeline -> {MODEL_PATH}")
    print(f"[Module A] Saved metrics  -> {METRICS_PATH}")


if __name__ == "__main__":
    main()
