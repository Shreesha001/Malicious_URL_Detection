from flask import Flask, request, jsonify
from flask_cors import CORS
import utils

app = Flask(__name__)
CORS(app)

# Load blacklist once on startup
BLACKLIST = utils.load_blacklist()

@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"malicious": True, "reason": "No URL provided"})

    domain = utils.extract_domain(url)
    if not domain:
        return jsonify({"malicious": True, "reason": "Invalid domain format"})

    # 1. IP address check
    if utils.is_ip_address(domain):
        return jsonify({"malicious": True, "reason": "URL uses an IP address instead of domain"})

    # 2. Blacklist check
    if utils.check_blacklist(domain, BLACKLIST):
        return jsonify({"malicious": True, "reason": "Domain is blacklisted"})

    # 3. Suspicious keywords in domain
    if utils.check_suspicious_keywords(domain):
        return jsonify({"malicious": True, "reason": "Suspicious keyword in domain"})

    # 4. Suspicious URL path
    if utils.check_url_path(url):
        return jsonify({"malicious": True, "reason": "Suspicious keywords in URL path"})

    # 5. Domain length check
    if utils.check_length(domain):
        return jsonify({"malicious": True, "reason": "Domain name too long"})

    # 6. Suspicious TLD check
    if utils.check_suspicious_tld(domain):
        if not utils.resolve_domain(domain):
            return jsonify({"malicious": True, "reason": "Suspicious TLD and DNS failed"})
        else:
            return jsonify({"malicious": False, "reason": "Suspicious TLD but DNS resolved"})

    # 7. DNS resolution check
    if not utils.resolve_domain(domain):
        return jsonify({"malicious": True, "reason": "DNS resolution failed"})

    # Passed all checks
    return jsonify({"malicious": False, "reason": "Domain passed all checks"})

if __name__ == "__main__":
    app.run(debug=True)
