import re
from urllib.parse import urlparse

# Load whitelist domains
with open("data/whitelist_domains.txt", "r") as f:
    whitelist = set(line.strip() for line in f)

def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def contains_suspicious_words(url):
    keywords = ["secure", "verify", "update", "login", "account", "support"]
    return [k for k in keywords if k in url.lower()]

def similar_to_whitelist(domain):
    for safe in whitelist:
        if safe.replace(".", "") in domain.replace(".", ""):
            return safe
    return None

def analyze_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    score = 0
    reasons = []

    # 1. IP-based URLs
    if is_ip_address(domain):
        score += 2
        reasons.append("URL uses an IP address instead of domain")

    # 2. Suspicious keywords in URL
    words = contains_suspicious_words(url)
    if words:
        score += 1
        reasons.append(f"Suspicious keywords found: {', '.join(words)}")

    # 3. Domain looks similar to a known brand
    similar = similar_to_whitelist(domain)
    if similar and similar not in domain:
        score += 2
        reasons.append(f"Domain mimics trusted site: {similar}")

    # 4. Hyphenated confusing domains
    if "-" in domain:
        score += 1
        reasons.append("Domain contains hyphens (common in phishing)")

    # Final verdict
    if score >= 4:
        verdict = "PHISHING"
    elif score >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return verdict, reasons


if __name__ == "__main__":
    print("=== Phishing URL Detector ===")
    url = input("Enter URL to analyze: ")
    verdict, reasons = analyze_url(url)

    print("\nResult:", verdict)
    print("Reasons:")
    for r in reasons:
        print("-", r)

