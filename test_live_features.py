import socket
from datetime import datetime, timezone

import dns.resolver
import tldextract
import whois


# ---------------------------------------------------------
# GET REGISTERED DOMAIN
# ---------------------------------------------------------

def get_domain(url):
    """
    Extract the registered/root domain.

    Example:
        https://www.google.com/login
        -> google.com
    """

    try:
        extracted = tldextract.extract(url)

        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"

        return extracted.domain

    except Exception:
        return ""


# ---------------------------------------------------------
# GET FIRST WHOIS DATE
# ---------------------------------------------------------

def get_first_date(value):
    """
    WHOIS dates can be:
        - datetime
        - list of datetime
        - None
    """

    if value is None:
        return None

    if isinstance(value, list):
        for item in value:
            if isinstance(item, datetime):
                return item
        return None

    if isinstance(value, datetime):
        return value

    return None


# ---------------------------------------------------------
# DNS RESOLUTION
# ---------------------------------------------------------

def get_dns_features(domain):
    """
    Collect DNS information.

    Returns:
        dns_resolves
        has_mx_record
        has_txt_record
        has_ns_record
        ttl_value
        ip_count
        cname_count
        resolves_to_private_ip
    """

    result = {
        "dns_resolves": 0,
        "has_mx_record": 0,
        "has_txt_record": 0,
        "has_ns_record": 0,
        "ttl_value": 0,
        "ip_count": 0,
        "cname_count": 0,
        "resolves_to_private_ip": 0,
    }

    if not domain:
        return result

    # -----------------------------------------------------
    # A RECORD
    # -----------------------------------------------------

    try:
        answers = dns.resolver.resolve(
            domain,
            "A",
            lifetime=5
        )

        ips = []

        for answer in answers:
            ip = str(answer)
            ips.append(ip)

        if ips:
            result["dns_resolves"] = 1
            result["ip_count"] = len(ips)

            for ip in ips:
                try:
                    if ip.startswith("10."):
                        result["resolves_to_private_ip"] = 1

                    elif ip.startswith("192.168."):
                        result["resolves_to_private_ip"] = 1

                    elif ip.startswith("172."):
                        second_octet = int(ip.split(".")[1])

                        if 16 <= second_octet <= 31:
                            result["resolves_to_private_ip"] = 1

                    elif ip.startswith("127."):
                        result["resolves_to_private_ip"] = 1

                except Exception:
                    pass

        try:
            result["ttl_value"] = int(
                answers.rrset.ttl
            )
        except Exception:
            result["ttl_value"] = 0

    except Exception:
        # NXDOMAIN / timeout / no A record
        pass

    # -----------------------------------------------------
    # MX RECORD
    # -----------------------------------------------------

    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=5
        )

        if len(answers) > 0:
            result["has_mx_record"] = 1

    except Exception:
        pass

    # -----------------------------------------------------
    # TXT RECORD
    # -----------------------------------------------------

    try:
        answers = dns.resolver.resolve(
            domain,
            "TXT",
            lifetime=5
        )

        if len(answers) > 0:
            result["has_txt_record"] = 1

    except Exception:
        pass

    # -----------------------------------------------------
    # NS RECORD
    # -----------------------------------------------------

    try:
        answers = dns.resolver.resolve(
            domain,
            "NS",
            lifetime=5
        )

        if len(answers) > 0:
            result["has_ns_record"] = 1

    except Exception:
        pass

    # -----------------------------------------------------
    # CNAME
    # -----------------------------------------------------

    try:
        answers = dns.resolver.resolve(
            domain,
            "CNAME",
            lifetime=5
        )

        if len(answers) > 0:
            result["cname_count"] = len(answers)

    except Exception:
        pass

    return result


# ---------------------------------------------------------
# WHOIS INFORMATION
# ---------------------------------------------------------

def get_whois_features(domain):
    """
    Collect WHOIS information.

    Important:
    If WHOIS says the domain does not exist, we DO NOT
    convert that into fake values such as:
        domain_age_days = 0
        registrar_valid = 0
        name_servers_count = 0

    Instead:
        whois_success = 0
        whois_missing = 1
    """

    result = {
        "whois_success": 0,
        "domain_age_days": 0,
        "domain_is_recent": 0,
        "domain_registered_before_2020": 0,
        "registrar_valid": 0,
        "name_servers_count": 0,
        "is_privacy_protected": 0,
        "whois_missing": 0,
    }

    if not domain:
        result["whois_missing"] = 1
        return result

    try:
        data = whois.whois(domain)

        # -------------------------------------------------
        # DOMAIN EXISTENCE
        # -------------------------------------------------

        # Some WHOIS responses can be empty.
        if not data:
            result["whois_missing"] = 1
            return result

        # -------------------------------------------------
        # CREATION DATE
        # -------------------------------------------------

        creation_date = get_first_date(
            getattr(data, "creation_date", None)
        )

        if creation_date is not None:

            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(
                    tzinfo=timezone.utc
                )

            now = datetime.now(timezone.utc)

            age_days = (
                now - creation_date
            ).days

            if age_days < 0:
                age_days = 0

            result["domain_age_days"] = age_days

            # Recent = registered within the last 365 days
            if age_days <= 365:
                result["domain_is_recent"] = 1
            else:
                result["domain_is_recent"] = 0

            # Registered before 2020
            if creation_date.year < 2020:
                result["domain_registered_before_2020"] = 1
            else:
                result["domain_registered_before_2020"] = 0

        # -------------------------------------------------
        # REGISTRAR
        # -------------------------------------------------

        registrar = getattr(
            data,
            "registrar",
            None
        )

        if registrar:
            result["registrar_valid"] = 1

        # -------------------------------------------------
        # NAME SERVERS
        # -------------------------------------------------

        name_servers = getattr(
            data,
            "name_servers",
            None
        )

        if name_servers:

            if isinstance(name_servers, str):
                name_servers = [name_servers]

            try:
                result["name_servers_count"] = len(
                    set(
                        str(ns).lower()
                        for ns in name_servers
                        if ns
                    )
                )
            except Exception:
                result["name_servers_count"] = 0

        # -------------------------------------------------
        # PRIVACY PROTECTION
        # -------------------------------------------------

        privacy_text = ""

        for field_name in [
            "registrant_name",
            "registrant_organization",
            "registrant_email",
            "name",
            "org",
            "emails",
        ]:
            value = getattr(
                data,
                field_name,
                None
            )

            if value:
                privacy_text += " " + str(value).lower()

        privacy_keywords = [
            "privacy",
            "private",
            "whoisguard",
            "domains by proxy",
            "contact privacy",
            "redacted",
            "withheld",
            "data protected",
        ]

        for keyword in privacy_keywords:
            if keyword in privacy_text:
                result["is_privacy_protected"] = 1
                break

        # -------------------------------------------------
        # WHOIS SUCCESS
        # -------------------------------------------------

        result["whois_success"] = 1
        result["whois_missing"] = 0

        return result

    except Exception as e:

        error_text = str(e).lower()

        # -------------------------------------------------
        # DOMAIN DOES NOT EXIST
        # -------------------------------------------------

        not_found_keywords = [
            "no match",
            "not found",
            "no data",
            "no entries found",
            "domain not found",
            "does not exist",
            "no object found",
            "whoisdomainnotfound",
        ]

        if any(
            keyword in error_text
            for keyword in not_found_keywords
        ):
            result["whois_success"] = 0
            result["whois_missing"] = 1

            return result

        # -------------------------------------------------
        # OTHER WHOIS FAILURE
        # -------------------------------------------------

        result["whois_success"] = 0
        result["whois_missing"] = 0

        return result


# ---------------------------------------------------------
# MAIN LIVE FEATURE FUNCTION
# ---------------------------------------------------------

def get_live_features(url):

    result = {
        "success": 0,

        "dns_resolves": 0,
        "has_mx_record": 0,
        "has_txt_record": 0,
        "has_ns_record": 0,
        "ttl_value": 0,
        "ip_count": 0,
        "cname_count": 0,
        "resolves_to_private_ip": 0,

        "whois_success": 0,
        "domain_age_days": 0,
        "domain_is_recent": 0,
        "domain_registered_before_2020": 0,
        "registrar_valid": 0,
        "name_servers_count": 0,
        "is_privacy_protected": 0,
        "whois_missing": 0,
    }

    # -----------------------------------------------------
    # GET DOMAIN
    # -----------------------------------------------------

    domain = get_domain(url)

    if not domain:
        result["whois_missing"] = 1
        return result

    # -----------------------------------------------------
    # DNS
    # -----------------------------------------------------

    dns_features = get_dns_features(domain)

    result.update(dns_features)

    # -----------------------------------------------------
    # WHOIS
    # -----------------------------------------------------

    whois_features = get_whois_features(domain)

    result.update(whois_features)

    # -----------------------------------------------------
    # SUCCESS
    #
    # "success" means at least one live intelligence
    # source returned useful information.
    #
    # It does NOT mean the URL is legitimate.
    # -----------------------------------------------------

    if (
        result["dns_resolves"] == 1
        or result["whois_success"] == 1
    ):
        result["success"] = 1
    else:
        result["success"] = 0

    return result


# ---------------------------------------------------------
# DIRECT TEST
# ---------------------------------------------------------

if __name__ == "__main__":

    test_url = "https://www.abonnement-facturation.com"

    print()
    print("=" * 60)
    print("PHISHGUARD LIVE DNS + WHOIS TEST")
    print("=" * 60)

    print()
    print("URL:")
    print(test_url)

    print()

    domain = get_domain(test_url)

    print("Registered domain:")
    print(domain)

    print()

    features = get_live_features(test_url)

    print("LIVE FEATURES")
    print("-" * 60)

    for key, value in features.items():
        print(f"{key:35}: {value}")

    print()
    print("=" * 60)