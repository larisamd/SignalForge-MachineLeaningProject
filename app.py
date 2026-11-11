"""Flask backend for the local Email Threat Detector."""

import json
import os
import re
import sys
from urllib.parse import urlsplit

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from text_clean import clean_text  # noqa: E402
from url_features import extract_url_features, features_to_vector  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(ROOT, "models")
SPAM_MODEL_PATH = os.path.join(MODEL_DIR, "spam_model.joblib")
URL_MODEL_PATH = os.path.join(MODEL_DIR, "url_model.joblib")
SPAM_METRICS_PATH = os.path.join(MODEL_DIR, "spam_metrics.json")
URL_METRICS_PATH = os.path.join(MODEL_DIR, "url_metrics.json")
MAX_EMAIL_LENGTH = 20_000
MAX_URL_LENGTH = 2_048
MAX_BATCH_URLS = 50

URL_FIND_RE = re.compile(r"(https?://[^\s\)>\]\"']+|www\.[^\s\)>\]\"']+)", re.IGNORECASE)
TRUSTED_DOMAINS = {
    "apple.com", "bbc.com", "github.com", "google.com", "microsoft.com",
    "wikipedia.org", "youtube.com",
}
URGENCY_TERMS = re.compile(r"\b(urgent|immediately|act now|expires today|limited time|suspended)\b", re.I)
CREDENTIAL_TERMS = re.compile(
    r"\b(password|passcode|login|log in|sign in|verify your account|"
    r"confirm your identity|bank details|credit card)\b",
    re.I,
)
MONEY_TERMS = re.compile(r"\b(won|winner|prize|gift card|claim your|cash reward|lottery)\b", re.I)

app = Flask(__name__)

spam_pipeline = None
url_bundle = None


def load_models():
    global spam_pipeline, url_bundle
    if not os.path.exists(SPAM_MODEL_PATH) or not os.path.exists(URL_MODEL_PATH):
        raise FileNotFoundError(
            "Trained models not found. Run `python train_all.py` before starting the app."
        )
    spam_pipeline = joblib.load(SPAM_MODEL_PATH)
    url_bundle = joblib.load(URL_MODEL_PATH)
    print("[app] Models loaded successfully.")


def predict_spam(text: str):
    cleaned = clean_text(text)
    prob_spam = float(spam_pipeline.predict_proba([cleaned])[0][1])
    label = "spam" if prob_spam >= 0.5 else "ham"
    return {"label": label, "probability_spam": round(prob_spam, 4)}


def normalize_url(raw_url: str) -> tuple[str, str]:
    url = raw_url.strip().rstrip(".,;:!?)]}>\"'")
    if not url:
        raise ValueError("Please provide a URL.")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URLs must be {MAX_URL_LENGTH} characters or fewer.")
    if any(character.isspace() for character in url):
        raise ValueError("URLs cannot contain unescaped whitespace.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        parsed.port
    except ValueError as exc:
        raise ValueError("Please provide a valid URL with a valid host and port.") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise ValueError("Please provide a valid HTTP or HTTPS URL.")
    return url, hostname


def trusted_domain_match(hostname: str) -> str | None:
    for domain in TRUSTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return domain
    return None


def predict_url(raw_url: str):
    url, hostname = normalize_url(raw_url)
    parsed = urlsplit(url)
    model = url_bundle["model"]
    feature_names = url_bundle["feature_names"]
    vec = features_to_vector(url)
    X = pd.DataFrame([vec], columns=feature_names)
    model_probability = float(model.predict_proba(X)[0][1])
    trusted_domain = (
        None if parsed.username or parsed.password else trusted_domain_match(hostname)
    )

    if trusted_domain:
        label = "legitimate"
        probability = min(model_probability, 0.02)
        explanation = (
            f"The hostname belongs to the recognized {trusted_domain} domain. "
            "This is a domain-level signal, not a guarantee about a page or redirect."
        )
    else:
        probability = model_probability
        label = "malicious" if probability >= 0.5 else "legitimate"
        explanation = (
            "The URL model found multiple suspicious indicators."
            if label == "malicious"
            else "No strong malicious indicators were found by the URL model."
        )

    features = extract_url_features(url)
    signals = []
    if trusted_domain:
        signals.append("Recognized domain: " + trusted_domain)
    if features["has_ip"]:
        signals.append("Uses an IP address instead of a domain name")
    if features["suspicious_tld"]:
        signals.append("Uses a higher-risk top-level domain")
    if features["suspicious_word_count"]:
        signals.append("Contains account, payment, or urgency-related words")
    if features["num_subdomains"] >= 3:
        signals.append("Contains several nested subdomains")
    if features["has_https_token_in_path"]:
        signals.append("Contains misleading HTTPS text outside the hostname")
    if not signals:
        signals.append("No notable lexical risk indicators")

    return {
        "url": url,
        "hostname": hostname,
        "label": label,
        "probability_malicious": round(probability, 4),
        "model_probability_malicious": round(model_probability, 4),
        "trusted_domain": bool(trusted_domain),
        "explanation": explanation,
        "signals": signals,
    }


def extract_urls(text: str):
    return [match.rstrip(".,;:!?") for match in URL_FIND_RE.findall(text or "")]


def email_signals(text: str):
    signals = []
    if URGENCY_TERMS.search(text):
        signals.append({
            "severity": "medium",
            "title": "Urgency or pressure language",
            "detail": "The message pushes the reader to act quickly or threatens an account suspension.",
        })
    if CREDENTIAL_TERMS.search(text):
        signals.append({
            "severity": "high",
            "title": "Credential or sensitive-data request",
            "detail": "The message mentions passwords, identity verification, or financial details.",
        })
    if MONEY_TERMS.search(text):
        signals.append({
            "severity": "medium",
            "title": "Prize or unexpected-reward language",
            "detail": "Unexpected prizes and rewards are common social-engineering lures.",
        })
    return signals


def render_page(page: str):
    return render_template("index.html", active_page=page)


@app.route("/")
def index():
    return render_page("dashboard")


@app.route("/email-analyzer")
def email_analyzer():
    return render_page("email")


@app.route("/url-scanner")
def url_scanner():
    return render_page("urls")


@app.route("/security-center")
def security_center():
    return render_page("security")


@app.route("/model-lab")
def model_lab():
    return render_page("models")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True)
    text = data.get("text", "") if isinstance(data, dict) else ""
    if not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Please provide some email/message text."}), 400
    if len(text) > MAX_EMAIL_LENGTH:
        return jsonify({"error": f"Messages must be {MAX_EMAIL_LENGTH} characters or fewer."}), 400

    spam_result = predict_spam(text)
    urls = extract_urls(text)
    url_results = []
    for url in urls[:MAX_BATCH_URLS]:
        try:
            url_results.append(predict_url(url))
        except ValueError as exc:
            url_results.append({"url": url, "label": "invalid", "error": str(exc)})
    dangerous_urls = [result for result in url_results if result["label"] == "malicious"]
    cues = email_signals(text)

    if dangerous_urls:
        verdict, severity = "Phishing / malicious link risk", "high"
    elif spam_result["label"] == "spam" or any(cue["severity"] == "high" for cue in cues):
        verdict, severity = "Suspicious message", "medium"
    else:
        verdict, severity = "No strong threat indicators found", "low"

    return jsonify({
        "verdict": verdict,
        "severity": severity,
        "spam_module": spam_result,
        "url_module": url_results,
        "urls_found": len(urls),
        "urls_analyzed": len(url_results),
        "email_signals": cues,
        "analysis_note": (
            "This is an educational screening tool. A low-risk result is not proof that a message is safe."
        ),
    })


@app.route("/api/check-url", methods=["POST"])
def check_url_route():
    data = request.get_json(silent=True)
    url = data.get("url", "") if isinstance(data, dict) else ""
    try:
        return jsonify(predict_url(url if isinstance(url, str) else ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/check-urls", methods=["POST"])
def check_urls_route():
    data = request.get_json(silent=True)
    urls = data.get("urls", []) if isinstance(data, dict) else []
    if isinstance(urls, str):
        urls = urls.splitlines()
    if not isinstance(urls, list):
        return jsonify({"error": "Provide URLs as a list or newline-separated text."}), 400
    candidates = [url.strip() for url in urls if isinstance(url, str) and url.strip()]
    if not candidates:
        return jsonify({"error": "Paste at least one URL to scan."}), 400
    if len(candidates) > MAX_BATCH_URLS:
        return jsonify({"error": f"You can scan up to {MAX_BATCH_URLS} URLs at a time."}), 400

    results = []
    for url in candidates:
        try:
            results.append(predict_url(url))
        except ValueError as exc:
            results.append({"url": url, "label": "invalid", "error": str(exc)})
    return jsonify({
        "results": results,
        "scanned": len(results),
        "malicious": sum(result["label"] == "malicious" for result in results),
        "invalid": sum(result["label"] == "invalid" for result in results),
    })


@app.route("/api/model-stats")
def model_stats():
    with open(SPAM_METRICS_PATH, encoding="utf-8") as metrics_file:
        spam_metrics = json.load(metrics_file)
    with open(URL_METRICS_PATH, encoding="utf-8") as metrics_file:
        url_metrics = json.load(metrics_file)
    spam_result = spam_metrics["results"][spam_metrics["best_model"]]
    return jsonify({
        "datasets": [
            {
                "name": "SMS Spam Collection",
                "records": spam_metrics["dataset_records"],
                "classes": "Spam / legitimate",
            },
            {
                "name": "Malicious URLs",
                "records": url_metrics["dataset_records"],
                "classes": "Malicious / legitimate",
            },
        ],
        "models": [
            {
                "name": spam_metrics["best_model"],
                "task": "Message spam classification (SMS-trained)",
                "f1": spam_result["f1_spam"],
                "roc_auc": spam_result["roc_auc"],
                "training_records": spam_metrics["n_train"],
                "test_records": spam_metrics["n_test"],
            },
            {
                "name": "Random Forest",
                "task": "URL lexical risk classification",
                "f1": url_metrics["f1_malicious"],
                "roc_auc": url_metrics["roc_auc"],
                "training_records": url_metrics["n_train"],
                "test_records": url_metrics["n_test"],
                "top_features": url_metrics["top_features"][:6],
            },
        ],
        "evaluation_note": "Metrics come from held-out dataset splits; real-world performance may differ.",
    })


if __name__ == "__main__":
    load_models()
    app.run(debug=False, host="127.0.0.1", port=int(os.environ.get("PORT", "5000")))
