import re
import math
import base64
import tldextract
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------
# ENTROPY FUNCTION
# ---------------------------------------------------------

def calculate_entropy(text):
    if not text:
        return 0.0

    probabilities = [
        text.count(char) / len(text)
        for char in set(text)
    ]

    return -sum(
        p * math.log2(p)
        for p in probabilities
        if p > 0
    )


# ---------------------------------------------------------
# SUSPICIOUS TLDs
# ---------------------------------------------------------

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "top",
    "xyz",
    "click",
    "link",
    "work",
    "zip",
    "review",
    "country"
}


# ---------------------------------------------------------
# COMMON BRANDS
# ---------------------------------------------------------

BRANDS = {
    "google",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "youtube",
    "paypal",
    "netflix",
    "linkedin",
    "twitter",
    "whatsapp",
    "telegram",
    "bank",
    "visa",
    "mastercard",
    "coinbase",
    "binance",
    "airbnb",
    "adobe",
    "chase",
    "citi",
    "americanexpress"
}


# ---------------------------------------------------------
# MAIN FEATURE EXTRACTION FUNCTION
# ---------------------------------------------------------

def extract_features(url):

    # -----------------------------------------------------
    # Basic URL parsing
    # -----------------------------------------------------

    parsed = urlparse(url)

    # Remove port number from hostname
    hostname = parsed.netloc.split(":")[0]

    path = parsed.path
    query = parsed.query

    # -----------------------------------------------------
    # TLDExtract
    # -----------------------------------------------------

    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # -----------------------------------------------------
    # NEW HOSTNAME / SUBDOMAIN FEATURES
    # -----------------------------------------------------

    subdomain_length = len(subdomain)

    subdomain_count = (
        len(subdomain.split("."))
        if subdomain
        else 0
    )

    hostname_labels = len(
        [
            part
            for part in [
                subdomain,
                domain,
                suffix
            ]
            if part
        ]
    )

    hostname_length_calc = len(hostname)

    # -----------------------------------------------------
    # Basic lengths
    # -----------------------------------------------------

    url_length = len(url)

    domain_length = len(domain)

    hostname_length = len(hostname)

    path_length = len(path)

    # -----------------------------------------------------
    # Path features
    # -----------------------------------------------------

    path_parts = [
        part
        for part in path.split("/")
        if part
    ]

    url_depth = len(path_parts)

    first_dir_length = (
        len(path_parts[0])
        if path_parts
        else 0
    )

    tld_length = len(suffix)

    tld_length_domain = (
        len(suffix) + len(domain)
    )

    path_segments_count = len(path_parts)

    # -----------------------------------------------------
    # Query features
    # -----------------------------------------------------

    query_length = len(query)

    query_params = parse_qs(query)

    query_key_count = len(query_params)

    if query_params:
        query_value_lengths = [
            len(value)
            for values in query_params.values()
            for value in values
        ]

        query_value_length_avg = (
            sum(query_value_lengths)
            / len(query_value_lengths)
        )
    else:
        query_value_length_avg = 0.0

    # -----------------------------------------------------
    # Character counts
    # -----------------------------------------------------

    num_digits = sum(
        char.isdigit()
        for char in url
    )

    num_letters = sum(
        char.isalpha()
        for char in url
    )

    num_special_chars = (
        url_length
        - num_digits
        - num_letters
    )

    num_dots = url.count(".")

    num_hyphens = url.count("-")

    num_at = url.count("@")

    num_percent = url.count("%")

    num_equals = url.count("=")

    num_question = url.count("?")

    num_ampersand = url.count("&")

    num_hash = url.count("#")

    num_underscore = url.count("_")

    num_slash = url.count("/")

    num_special = sum(
        not char.isalnum()
        for char in url
    )

    num_params = (
        len(query.split("&"))
        if query
        else 0
    )

    # -----------------------------------------------------
    # Entropy
    # -----------------------------------------------------

    entropy_url = calculate_entropy(url)

    entropy_hostname = calculate_entropy(
        hostname
    )

    entropy_domain = calculate_entropy(
        domain
    )

    entropy_path = calculate_entropy(
        path
    )

    query_entropy = calculate_entropy(
        query
    )

    # -----------------------------------------------------
    # Ratios
    # -----------------------------------------------------

    ratio_digits = (
        num_digits / url_length
        if url_length
        else 0
    )

    ratio_letters = (
        num_letters / url_length
        if url_length
        else 0
    )

    ratio_special_chars = (
        num_special_chars / url_length
        if url_length
        else 0
    )

    uppercase_count = sum(
        char.isupper()
        for char in url
    )

    lowercase_count = sum(
        char.islower()
        for char in url
    )

    uppercase_ratio = (
        uppercase_count / url_length
        if url_length
        else 0
    )

    lowercase_ratio = (
        lowercase_count / url_length
        if url_length
        else 0
    )

    # -----------------------------------------------------
    # IP address features
    # -----------------------------------------------------

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    is_ip_address = int(
        bool(re.match(ip_pattern, hostname))
    )

    starts_with_ip = int(
        bool(
            re.match(
                r"^(?:https?://)?"
                r"(?:\d{1,3}\.){3}",
                url
            )
        )
    )

    # -----------------------------------------------------
    # Suspicious TLD
    # -----------------------------------------------------

    is_suspicious_tld = int(
        suffix.lower()
        in SUSPICIOUS_TLDS
    )

    # -----------------------------------------------------
    # HTTPS / WWW
    # -----------------------------------------------------

    uses_https = int(
        parsed.scheme.lower() == "https"
    )

    has_www = int(
        hostname.lower().startswith("www.")
    )

    # -----------------------------------------------------
    # URL structure
    # -----------------------------------------------------

    unusual_double_slash = int(
        "//" in path
    )

    multiple_http = int(
        url.lower().count("http") > 1
    )

    contains_port_number = int(
        bool(
            re.search(
                r":\d+",
                parsed.netloc
            )
        )
    )

    path_has_encoded_chars = int(
        bool(
            re.search(
                r"%[0-9A-Fa-f]{2}",
                path
            )
        )
    )

    # -----------------------------------------------------
    # Base64 query detection
    # -----------------------------------------------------

    query_has_base64 = 0

    if query:
        values = re.findall(
            r"[^=&]+",
            query
        )

        for value in values:

            if len(value) >= 12:

                try:
                    decoded = base64.b64decode(
                        value,
                        validate=True
                    )

                    if decoded:
                        query_has_base64 = 1
                        break

                except Exception:
                    pass

    # -----------------------------------------------------
    # Suspicious keyword features
    # -----------------------------------------------------

    url_lower = url.lower()

    contains_login = int(
        "login" in url_lower
    )

    contains_secure = int(
        "secure" in url_lower
    )

    contains_verify = int(
        "verify" in url_lower
    )

    contains_account = int(
        "account" in url_lower
    )

    contains_update = int(
        "update" in url_lower
    )

    contains_bank = int(
        "bank" in url_lower
    )

    contains_cloud = int(
        "cloud" in url_lower
    )

    # -----------------------------------------------------
    # Brand detection
    # -----------------------------------------------------

    contains_brand = int(
        any(
            brand in url_lower
            for brand in BRANDS
        )
    )

    # -----------------------------------------------------
    # Return all URL features
    # -----------------------------------------------------

    return {

        # Original URL features
        "url_length": url_length,
        "domain_length": domain_length,
        "hostname_length": hostname_length,
        "path_length": path_length,
        "first_dir_length": first_dir_length,
        "tld_length": tld_length,
        "tld_length_domain": tld_length_domain,
        "url_depth": url_depth,
        "query_length": query_length,
        "path_segments_count": path_segments_count,

        "num_digits": num_digits,
        "num_letters": num_letters,
        "num_special_chars": num_special_chars,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_percent": num_percent,
        "num_equals": num_equals,
        "num_question": num_question,
        "num_ampersand": num_ampersand,
        "num_hash": num_hash,
        "num_underscore": num_underscore,
        "num_special": num_special,
        "num_slash": num_slash,
        "num_params": num_params,

        "entropy_url": entropy_url,
        "entropy_hostname": entropy_hostname,
        "entropy_domain": entropy_domain,
        "entropy_path": entropy_path,
        "query_entropy": query_entropy,

        "ratio_digits": ratio_digits,
        "ratio_letters": ratio_letters,
        "ratio_special_chars": ratio_special_chars,
        "uppercase_ratio": uppercase_ratio,
        "lowercase_ratio": lowercase_ratio,

        "is_ip_address": is_ip_address,
        "starts_with_ip": starts_with_ip,
        "is_suspicious_tld": is_suspicious_tld,
        "uses_https": uses_https,
        "has_www": has_www,
        "unusual_double_slash": unusual_double_slash,
        "multiple_http": multiple_http,
        "contains_port_number": contains_port_number,
        "path_has_encoded_chars": path_has_encoded_chars,
        "query_has_base64": query_has_base64,

        "contains_login": contains_login,
        "contains_secure": contains_secure,
        "contains_verify": contains_verify,
        "contains_account": contains_account,
        "contains_update": contains_update,
        "contains_bank": contains_bank,
        "contains_cloud": contains_cloud,
        "contains_brand": contains_brand,

        "query_key_count": query_key_count,
        "query_value_length_avg": query_value_length_avg,

        # NEW HOSTNAME FEATURES
        "subdomain_length": subdomain_length,
        "subdomain_count": subdomain_count,
        "hostname_labels": hostname_labels,
        "hostname_length_calc": hostname_length_calc
    }