from flask import Flask, request, jsonify
import socket
import dns.resolver
import tldextract
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

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

@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")
    domain = extract_domain(url)
    if not domain:
        return jsonify({"malicious": True, "reason": "Invalid domain"})

    if resolve_domain(domain):
        return jsonify({"malicious": False, "reason": "DNS resolved"})
    else:
        return jsonify({"malicious": True, "reason": "DNS resolution failed"})

if __name__ == "__main__":
    app.run(debug=True)
