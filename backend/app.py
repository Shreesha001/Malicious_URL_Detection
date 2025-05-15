from flask import Flask, request, jsonify
import socket
import dns.resolver
import tldextract
from flask_cors import CORS
import re

def is_ip_address(domain):
    ip_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )  # Simple IPv4 pattern
    return bool(ip_pattern.match(domain))


app = Flask(__name__)
CORS(app)

# Blacklist of known malicious domains
BLACKLIST = {
    "malicious-example.com",
    "fakebank-login.com",
    "update-account-security.info",
    "secure-login-paypal.com.fake.xyz",
    "free-gift-card-claim-now.top",
    "verify-your-email-account.net",
    "bankofamerica-secure-login.info",
    "youraccounthasbeensuspended.site",
    "urgent-security-alert.xyz",
    "payment-failed-update-info.online",
}

# Suspicious keywords in domain names
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "bank", "paypal",
    "free", "gift", "alert", "security", "password", "confirm"
]

def extract_domain(url):
    ext = tldextract.extract(url)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"

def resolve_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        pass
    try:
        dns.resolver.resolve(domain, 'A')
        return True
    except:
        return False

def check_blacklist(domain):
    return domain.lower() in BLACKLIST

def check_suspicious_keywords(domain):
    parts = domain.lower().split('.')
    for word in SUSPICIOUS_KEYWORDS:
        if any(word in part for part in parts):
            return True
    return False

def check_length(domain):
    return len(domain) > 30

def check_suspicious_tld(domain):
    suspicious_tlds = ['.xyz', '.top', '.info', '.club', '.online', '.site']
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            return True
    return False

@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    domain = extract_domain(url)
    if not domain:
        return jsonify({"malicious": True, "reason": "Invalid domain format"})

    if check_blacklist(domain):
        return jsonify({"malicious": True, "reason": "Domain is blacklisted"})

    if check_suspicious_keywords(domain):
        return jsonify({"malicious": True, "reason": "Suspicious keyword in domain"})

    if check_length(domain):
        return jsonify({"malicious": True, "reason": "Domain name too long"})

    if check_suspicious_tld(domain):
        if not resolve_domain(domain):
            return jsonify({"malicious": True, "reason": "Suspicious TLD and DNS failed"})
        else:
            return jsonify({"malicious": False, "reason": "Suspicious TLD but DNS resolved"})

    if not resolve_domain(domain):
        return jsonify({"malicious": True, "reason": "DNS resolution failed"})

    return jsonify({"malicious": False, "reason": "Domain passed all checks"})

if __name__ == "__main__":
    app.run(debug=True)
