import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# The 73 features expected by the backend
FEATURE_COLUMNS = [
    "url_length", "domain_length", "hostname_length", "path_length",
    "first_dir_length", "tld_length", "tld_length_domain", "url_depth",
    "query_length", "path_segments_count", "num_digits", "num_letters",
    "num_special_chars", "num_dots", "num_hyphens", "num_at",
    "num_percent", "num_equals", "num_question", "num_ampersand",
    "num_hash", "num_underscore", "num_special", "num_slash",
    "num_params", "entropy_path", "query_entropy", "ratio_digits",
    "ratio_letters", "ratio_special_chars", "uppercase_ratio",
    "lowercase_ratio", "is_ip_address", "starts_with_ip",
    "is_suspicious_tld", "uses_https", "has_www", "unusual_double_slash",
    "multiple_http", "contains_port_number", "path_has_encoded_chars",
    "query_has_base64", "contains_login", "contains_secure",
    "contains_verify", "contains_account", "contains_update",
    "contains_bank", "contains_cloud", "contains_brand",
    "query_key_count", "query_value_length_avg", "subdomain_length",
    "subdomain_count", "hostname_labels", "hostname_length_calc",
    "success", "dns_resolves", "has_mx_record", "has_txt_record",
    "has_ns_record", "ttl_value", "ip_count", "cname_count",
    "resolves_to_private_ip", "whois_success", "domain_age_days",
    "domain_is_recent", "domain_registered_before_2020",
    "registrar_valid", "name_servers_count", "is_privacy_protected",
    "whois_missing"
]

def generate_synthetic_data(num_samples=1000):
    np.random.seed(42)
    
    # Generate random features for legitimate (target 0) and phishing (target 1)
    data = []
    
    for _ in range(num_samples):
        # 0 = legitimate, 1 = phishing
        target = np.random.choice([0, 1])
        
        row = {}
        for feature in FEATURE_COLUMNS:
            # Add some logical heuristics to make the model meaningful
            if feature in ["url_length", "domain_length", "path_length"]:
                row[feature] = np.random.randint(10, 50) if target == 0 else np.random.randint(40, 200)
            elif feature == "uses_https":
                row[feature] = np.random.choice([1, 1, 1, 0]) if target == 0 else np.random.choice([1, 0, 0, 0])
            elif feature in ["contains_login", "contains_secure", "contains_verify", "contains_account", "contains_bank"]:
                row[feature] = np.random.choice([0, 0, 0, 1]) if target == 0 else np.random.choice([0, 1, 1, 1])
            elif feature == "is_suspicious_tld":
                row[feature] = 0 if target == 0 else np.random.choice([0, 1])
            elif feature == "is_ip_address":
                row[feature] = 0 if target == 0 else np.random.choice([0, 1], p=[0.8, 0.2])
            elif feature == "dns_resolves":
                row[feature] = np.random.choice([1, 0], p=[0.95, 0.05]) if target == 0 else np.random.choice([1, 0], p=[0.7, 0.3])
            elif feature == "domain_age_days":
                row[feature] = np.random.randint(365, 3650) if target == 0 else np.random.randint(1, 365)
            elif feature == "domain_is_recent":
                row[feature] = 0 if target == 0 else np.random.choice([0, 1], p=[0.3, 0.7])
            elif feature in ["entropy_path", "query_entropy"]:
                row[feature] = np.random.uniform(2.0, 4.0) if target == 0 else np.random.uniform(3.5, 5.0)
            else:
                # Random noise for other features
                row[feature] = np.random.uniform(0, 10)
        
        row['target'] = target
        data.append(row)
        
    return pd.DataFrame(data)

if __name__ == "__main__":
    print("Generating synthetic dataset with 1000 samples...")
    df = generate_synthetic_data(1000)
    
    X = df[FEATURE_COLUMNS]
    y = df['target']
    
    print("Training RandomForestClassifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    accuracy = model.score(X, y)
    print(f"Model training complete. Synthetic accuracy: {accuracy * 100:.2f}%")
    
    output_filename = "phishing_model_c.pkl"
    print(f"Saving model to {output_filename}...")
    joblib.dump(model, output_filename)
    
    print("Done!")
