import socket
import dns.resolver
import tldextract
import re

# Load your blacklist from file (one domain per line)
def load_blacklist(filename="blacklist.txt"):
    try:
        with open(filename, "r") as f:
            lines = f.read().splitlines()
            return set(line.strip().lower() for line in lines if line.strip())
    except FileNotFoundError:
        return set()

# Basic hardcoded suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "bank", "paypal",
    "free", "gift", "alert", "security", "password", "confirm", "ebay",
    "apple", "microsoft", "amazon", "google", "facebook"
]

# Suspicious TLDs commonly abused
SUSPICIOUS_TLDS = ['.xyz', '.top', '.info', '.club', '.online', '.site', '.win', '.bid']

# Suspicious URL path keywords
SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "secure", "account", "update", "confirm", "password", "verify", "wp-login"
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

def check_blacklist(domain, blacklist):
    return domain.lower() in blacklist

def check_suspicious_keywords(domain):
    parts = domain.lower().split('.')
    for word in SUSPICIOUS_KEYWORDS:
        if any(word in part for part in parts):
            return True
    return False

def check_length(domain):
    return len(domain) > 30

def check_suspicious_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False

def is_ip_address(domain):
    ip_pattern = re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )
    return bool(ip_pattern.match(domain))

def check_url_path(url):
    # Extract path part of URL and check suspicious keywords
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path.lower()
        for kw in SUSPICIOUS_PATH_KEYWORDS:
            if kw in path:
                return True
        return False
    except:
        return False
