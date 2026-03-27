from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
import re
from typing import Optional
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

model = pickle.load(open("best_model.pkl", "rb"))

WHITELISTED_HOSTS = {
    "google.com",
    "github.com",
    "wikipedia.org",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "buff.ly",
    "tiny.cc",
    "is.gd",
    "rb.gy",
}

SUSPICIOUS_KEYWORDS = ["login", "verify", "bank", "secure", "account"]

INVALID_RESULT = {
    "result": "Invalid",
    "confidence": 0.0,
    "reason": "Invalid URL format. Please enter a URL starting with http:// or https://",
}

def normalize_url(url: str) -> str:
    return url.strip().lower()

def is_valid_url(url: str) -> bool:
    if not url:
        return False
    if not (url.startswith("http://") or url.startswith("https://")):
        return False

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    if "." not in hostname and not hostname.isdigit():
        return False
    return parsed.scheme in {"http", "https"}

def count_subdomains(hostname: str) -> int:
    parts = hostname.split(".")
    if len(parts) <= 2:
        return 0
    return max(0, len(parts) - 2)

def uses_ip_address(hostname: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", hostname or ""))

def is_shortener(hostname: str) -> bool:
    return hostname in SHORTENER_DOMAINS

def is_whitelisted_host(hostname: str) -> bool:
    if not hostname:
        return False
    return any(
        hostname == allowed or hostname.endswith(f".{allowed}")
        for allowed in WHITELISTED_HOSTS
    )

def extract_features(url: str) -> list:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    url_length = len(url)
    dot_count = url.count(".")
    has_at = 1 if "@" in url else 0
    has_dash = 1 if "-" in url else 0
    slash_count = url.count("/")
    https_flag = 1 if parsed.scheme == "https" else 0
    digit_count = sum(c.isdigit() for c in url)
    keyword_count = sum(word in url for word in SUSPICIOUS_KEYWORDS)
    ip_flag = 1 if uses_ip_address(hostname) else 0

    return [
        url_length,
        dot_count,
        has_at,
        has_dash,
        slash_count,
        https_flag,
        digit_count,
        keyword_count,
        ip_flag,
    ]

def rule_based_decision(url: str, features: list) -> Optional[dict]:
    hostname = urlparse(url).hostname or ""
    keyword_count = features[7]
    ip_flag = features[8]
    shortener_flag = is_shortener(hostname)
    subdomain_count = count_subdomains(hostname)
    special_char_count = (1 if "@" in url else 0) + (1 if "-" in url else 0) + url.count("_")

    if is_whitelisted_host(hostname):
        return {
            "result": "Safe",
            "confidence": 0.99,
            "reason": "Known legitimate domain",
        }

    if ip_flag:
        return {
            "result": "Phishing",
            "confidence": 0.95,
            "reason": "URL uses a raw IP address instead of a domain",
        }

    if shortener_flag:
        return {
            "result": "Phishing",
            "confidence": 0.90,
            "reason": "URL uses a URL shortening service",
        }

    if keyword_count >= 2:
        return {
            "result": "Phishing",
            "confidence": 0.88,
            "reason": "Contains multiple suspicious keywords",
        }

    if subdomain_count >= 4 and special_char_count >= 3:
        return {
            "result": "Phishing",
            "confidence": 0.85,
            "reason": "Many subdomains and suspicious special characters",
        }

    return None

def predict_with_model(features: list) -> tuple[str, float]:
    features_array = np.array(features).reshape(1, -1)
    prediction = model.predict(features_array)[0]
    confidence = 0.0

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(features_array)[0]
        confidence = float(max(proba))
    elif hasattr(model, "decision_function"):
        score = model.decision_function(features_array)[0]
        confidence = float(1 / (1 + np.exp(-score)))

    return ("Phishing" if prediction == 1 else "Safe", confidence)

@app.route("/predict", methods=["GET", "POST", "OPTIONS"])
def predict():
    if request.method == "GET":
        return jsonify({
            "result": "Info",
            "confidence": 0.0,
            "reason": "Use POST /predict with JSON {\"url\": \"https://example.com\"} to classify a URL.",
        })

    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.json or {}
    raw_url = data.get("url", "")
    normalized_url = normalize_url(raw_url)

    if not is_valid_url(normalized_url):
        return jsonify(INVALID_RESULT), 400

    features = extract_features(normalized_url)
    rule_result = rule_based_decision(normalized_url, features)
    if rule_result is not None:
        return jsonify(rule_result)

    model_result, confidence = predict_with_model(features)
    reason = (
        "Suspicious URL characteristics detected by the ML model"
        if model_result == "Phishing"
        else "URL appears safe based on the ML model"
    )

    return jsonify({
        "result": model_result,
        "confidence": round(confidence, 2),
        "reason": reason,
    })

@app.route("/", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "message": "QR Phishing Detector backend is running.",
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
