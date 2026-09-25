from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import joblib
import pandas as pd

from feature_extractor import extract_features
from test_live_features import get_live_features


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    static_folder="website",
    static_url_path=""
)

CORS(app)


# ============================================================
# LOAD MODEL
# ============================================================

MODEL_FILE = "phishing_model_c.pkl"

model = joblib.load(MODEL_FILE)

print("=" * 60)
print("PHISHGUARD BACKEND")
print("=" * 60)
print("Model loaded:", MODEL_FILE)
print("Model type:", type(model).__name__)
print("=" * 60)


# ============================================================
# 73 MODEL FEATURES
# ============================================================

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "hostname_length",
    "path_length",
    "first_dir_length",
    "tld_length",
    "tld_length_domain",
    "url_depth",
    "query_length",
    "path_segments_count",
    "num_digits",
    "num_letters",
    "num_special_chars",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_percent",
    "num_equals",
    "num_question",
    "num_ampersand",
    "num_hash",
    "num_underscore",
    "num_special",
    "num_slash",
    "num_params",
    "entropy_path",
    "query_entropy",
    "ratio_digits",
    "ratio_letters",
    "ratio_special_chars",
    "uppercase_ratio",
    "lowercase_ratio",
    "is_ip_address",
    "starts_with_ip",
    "is_suspicious_tld",
    "uses_https",
    "has_www",
    "unusual_double_slash",
    "multiple_http",
    "contains_port_number",
    "path_has_encoded_chars",
    "query_has_base64",
    "contains_login",
    "contains_secure",
    "contains_verify",
    "contains_account",
    "contains_update",
    "contains_bank",
    "contains_cloud",
    "contains_brand",
    "query_key_count",
    "query_value_length_avg",
    "subdomain_length",
    "subdomain_count",
    "hostname_labels",
    "hostname_length_calc",
    "success",
    "dns_resolves",
    "has_mx_record",
    "has_txt_record",
    "has_ns_record",
    "ttl_value",
    "ip_count",
    "cname_count",
    "resolves_to_private_ip",
    "whois_success",
    "domain_age_days",
    "domain_is_recent",
    "domain_registered_before_2020",
    "registrar_valid",
    "name_servers_count",
    "is_privacy_protected",
    "whois_missing"
]


# ============================================================
# SAFE VALUE HELPERS
# ============================================================

def safe_int(value, default=0):
    try:
        if value is None:
            return default

        return int(value)

    except Exception:
        return default


def safe_value(value, default=None):
    if value is None:
        return default

    return value


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def get_security_analysis(url, url_features, live_features):

    uses_https = safe_int(
        url_features.get("uses_https", 0)
    )

    suspicious_keywords = any(
        safe_int(url_features.get(keyword, 0)) == 1
        for keyword in [
            "contains_login",
            "contains_secure",
            "contains_verify",
            "contains_account",
            "contains_update",
            "contains_bank",
            "contains_cloud",
            "contains_brand"
        ]
    )

    dns_resolves = safe_int(
        live_features.get("dns_resolves", 0)
    )

    whois_success = safe_int(
        live_features.get("whois_success", 0)
    )

    analysis = {
        "url_structure": True,
        "domain_structure": True,

        "https_usage": bool(uses_https),

        "suspicious_keywords": bool(
            suspicious_keywords
        ),

        "dns_intelligence": bool(
            dns_resolves
        ),

        "whois_information": bool(
            whois_success
        ),

        "dns": bool(dns_resolves),
        "whois": bool(whois_success),

        "dns_resolves": dns_resolves,

        "domain_age_days": safe_value(
            live_features.get("domain_age_days")
        ),

        "cname_count": safe_int(
            live_features.get("cname_count", 0)
        ),

        "ip_count": safe_int(
            live_features.get("ip_count", 0)
        )
    }

    return analysis


# ============================================================
# DOMAIN INTELLIGENCE
# ============================================================

def get_domain_intelligence(
    url,
    url_features,
    live_features
):

    hostname = (
        url_features.get("hostname")
        or live_features.get("hostname")
        or ""
    )

    url_length = safe_int(
        url_features.get(
            "url_length",
            len(url)
        )
    )

    path_length = safe_int(
        url_features.get(
            "path_length",
            0
        )
    )

    query_length = safe_int(
        url_features.get(
            "query_length",
            0
        )
    )

    subdomain_count = safe_int(
        url_features.get(
            "subdomain_count",
            0
        )
    )

    dns_resolves = safe_int(
        live_features.get(
            "dns_resolves",
            0
        )
    )

    has_mx_record = safe_int(
        live_features.get(
            "has_mx_record",
            0
        )
    )

    has_txt_record = safe_int(
        live_features.get(
            "has_txt_record",
            0
        )
    )

    has_ns_record = safe_int(
        live_features.get(
            "has_ns_record",
            0
        )
    )

    ip_count = safe_int(
        live_features.get(
            "ip_count",
            0
        )
    )

    cname_count = safe_int(
        live_features.get(
            "cname_count",
            0
        )
    )

    domain_age_days = live_features.get(
        "domain_age_days"
    )

    domain_is_recent = safe_int(
        live_features.get(
            "domain_is_recent",
            0
        )
    )

    registrar_valid = safe_int(
        live_features.get(
            "registrar_valid",
            0
        )
    )

    name_servers_count = safe_int(
        live_features.get(
            "name_servers_count",
            0
        )
    )

    is_privacy_protected = safe_int(
        live_features.get(
            "is_privacy_protected",
            0
        )
    )

    return {

        "hostname": hostname,

        "url_length": url_length,

        "path_length": path_length,

        "query_length": query_length,

        "subdomain_count": subdomain_count,

        "dns_resolves": dns_resolves,

        "has_mx_record": has_mx_record,

        "has_txt_record": has_txt_record,

        "has_ns_record": has_ns_record,

        "ip_count": ip_count,

        "cname_count": cname_count,

        "domain_age_days": domain_age_days,

        "domain_is_recent": domain_is_recent,

        "registrar_valid": registrar_valid,

        "name_servers_count": name_servers_count,

        "is_privacy_protected": is_privacy_protected
    }


# ============================================================
# WEBSITE HOME ROUTE
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return send_from_directory(
        app.static_folder,
        "index.html"
    )


# ============================================================
# API STATUS
# ============================================================

@app.route("/api", methods=["GET"])
def api_status():

    return jsonify({
        "service": "PhishGuard API",
        "status": "online",
        "model": "Random Forest",
        "features": 73,
        "version": "2.0-live-intelligence"
    })


# ============================================================
# SCAN ROUTE
# ============================================================

@app.route("/scan", methods=["POST"])
def scan():

    try:

        # ----------------------------------------------------
        # READ REQUEST
        # ----------------------------------------------------

        data = request.get_json(
            silent=True
        )

        if not data:

            return jsonify({
                "success": False,
                "error": "No JSON data received."
            }), 400

        url = str(
            data.get("url", "")
        ).strip()

        if not url:

            return jsonify({
                "success": False,
                "error": "Please provide a URL."
            }), 400


        # ----------------------------------------------------
        # ADD HTTPS IF MISSING
        # ----------------------------------------------------

        if not url.startswith(
            ("http://", "https://")
        ):

            url = "https://" + url


        # ----------------------------------------------------
        # EXTRACT URL FEATURES
        # ----------------------------------------------------

        url_features = extract_features(url)


        # ----------------------------------------------------
        # GET LIVE DNS + WHOIS FEATURES
        # ----------------------------------------------------

        live_features = get_live_features(url)


        # ----------------------------------------------------
        # DEBUG OUTPUT
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print("PHISHGUARD LIVE ANALYSIS")
        print("=" * 60)

        print("URL:", url)

        print(
            "DNS resolves:",
            live_features.get("dns_resolves")
        )

        print(
            "MX record:",
            live_features.get("has_mx_record")
        )

        print(
            "TXT record:",
            live_features.get("has_txt_record")
        )

        print(
            "NS record:",
            live_features.get("has_ns_record")
        )

        print(
            "IP count:",
            live_features.get("ip_count")
        )

        print(
            "CNAME count:",
            live_features.get("cname_count")
        )

        print(
            "WHOIS success:",
            live_features.get("whois_success")
        )

        print(
            "Domain age:",
            live_features.get("domain_age_days")
        )

        print(
            "Recent domain:",
            live_features.get("domain_is_recent")
        )

        print(
            "Registrar valid:",
            live_features.get("registrar_valid")
        )

        print(
            "Name servers:",
            live_features.get("name_servers_count")
        )

        print(
            "Privacy protected:",
            live_features.get("is_privacy_protected")
        )

        print("=" * 60)


        # ----------------------------------------------------
        # COMBINE ALL 73 FEATURES
        # ----------------------------------------------------

        combined_features = {}

        combined_features.update(
            url_features
        )

        combined_features.update(
            live_features
        )


        # ----------------------------------------------------
        # CREATE MODEL INPUT
        # ----------------------------------------------------

        feature_values = {}

        for feature in FEATURE_COLUMNS:

            feature_values[feature] = (
                combined_features.get(
                    feature,
                    0
                )
            )


        X = pd.DataFrame(
            [feature_values],
            columns=FEATURE_COLUMNS
        )


        # ----------------------------------------------------
        # MODEL PREDICTION
        # ----------------------------------------------------

        prediction = int(
            model.predict(X)[0]
        )


        # ----------------------------------------------------
        # MODEL PROBABILITY
        # ----------------------------------------------------

        probabilities = model.predict_proba(X)[0]

        legitimate_probability = round(
            float(probabilities[0]) * 100,
            2
        )

        phishing_probability = round(
            float(probabilities[1]) * 100,
            2
        )


        # ----------------------------------------------------
        # RESULT
        # ----------------------------------------------------

        if prediction == 1:

            result = "Potential Phishing"

            message = (
                "This URL shows characteristics associated "
                "with potentially phishing websites."
            )

        else:

            result = "Likely Legitimate"

            message = (
                "This URL appears legitimate based on "
                "the analyzed characteristics."
            )


        # ----------------------------------------------------
        # SECURITY ANALYSIS
        # ----------------------------------------------------

        security_analysis = get_security_analysis(
            url,
            url_features,
            live_features
        )


        # ----------------------------------------------------
        # DOMAIN INTELLIGENCE
        # ----------------------------------------------------

        domain_intelligence = get_domain_intelligence(
            url,
            url_features,
            live_features
        )


        # ----------------------------------------------------
        # COMPLETE RESPONSE
        # ----------------------------------------------------

        response = {

            "success": True,

            "url": url,

            "prediction": prediction,

            "result": result,

            "legitimate_probability":
                legitimate_probability,

            "phishing_probability":
                phishing_probability,

            "message": message,

            "security_analysis":
                security_analysis,

            "domain_intelligence":
                domain_intelligence,

            "features_analyzed": 73
        }


        print()
        print("RESPONSE CHECK")
        print(
            "Result:",
            result
        )
        print(
            "Legitimate:",
            legitimate_probability
        )
        print(
            "Phishing:",
            phishing_probability
        )
        print("=" * 60)
        print()


        return jsonify(response), 200


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as error:

        print()
        print("=" * 60)
        print("PHISHGUARD ERROR")
        print("=" * 60)
        print(type(error).__name__)
        print(str(error))
        print("=" * 60)
        print()

        return jsonify({
            "success": False,
            "error": "Unable to analyze this URL.",
            "details": str(error)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("Starting PhishGuard Backend")
    print("=" * 60)
    print("Host: 0.0.0.0")
    print("Port: 5000")
    print("Live DNS + WHOIS enabled")
    print("73-feature Random Forest model")
    print("Website serving enabled")
    print("=" * 60)
    print()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )