"""
Phishing URL and Email Detection
Educational defensive-security project for the IBM SkillsBuild Cybersecurity Bootcamp.

This tool uses transparent heuristic checks. It is a learning aid, not a guarantee
that a URL/email is safe or malicious. Do not paste confidential emails or secrets.
"""
import re
import ipaddress
from urllib.parse import urlparse, unquote

SUSPICIOUS_TERMS = {
    "verify", "verification", "login", "signin", "secure", "account", "update",
    "password", "wallet", "urgent", "suspended", "confirm", "billing", "payment",
    "recover", "limited", "unlock", "webscr", "authenticate"
}
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly",
    "shorturl.at", "ow.ly", "buff.ly", "rb.gy"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".top", ".xyz", ".click", ".work", ".gq", ".tk"}

def extract_urls(text: str):
    """Return URL-like strings found in text."""
    pattern = re.compile(r"""(?ix)\b((?:https?://|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s<>"']*)?)""")
    return [m.rstrip(".,;:!?)]}") for m in pattern.findall(text or "")]

def analyze_url(raw_url: str):
    """Score one URL using explainable indicators; returns score, label and reasons."""
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return {"url": raw_url, "score": 0, "risk": "Unknown", "reasons": ["No URL supplied."]}
    candidate = raw_url if "://" in raw_url else "http://" + raw_url
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            raise ValueError("missing host")
    except Exception:
        return {"url": raw_url, "score": 0, "risk": "Unknown", "reasons": ["Could not parse the URL."]}

    reasons = []
    score = 0
    decoded = unquote(raw_url).lower()

    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("URL does not use HTTPS.")
    if "@" in parsed.netloc:
        score += 2
        reasons.append("Contains '@' in the authority section, which can obscure the destination.")
    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append("Uses an IP address instead of a domain name.")
    except ValueError:
        pass
    if len(raw_url) > 75:
        score += 1
        reasons.append("Unusually long URL.")
    if host.startswith("xn--") or ".xn--" in host:
        score += 2
        reasons.append("Contains an internationalized/punycode domain label.")
    if host.count(".") >= 4:
        score += 1
        reasons.append("Contains many subdomain levels.")
    if any(shortener == host or host.endswith("." + shortener) for shortener in URL_SHORTENERS):
        score += 2
        reasons.append("Uses a URL-shortening service that hides the final destination.")
    if any(term in decoded for term in SUSPICIOUS_TERMS):
        score += 1
        reasons.append("Contains common account/security urgency terms.")
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        reasons.append("Uses a TLD sometimes seen in suspicious campaigns (not proof of abuse).")
    if parsed.username or parsed.password:
        score += 2
        reasons.append("Contains user-info before the host.")
    if not reasons:
        reasons.append("No configured heuristic indicators were found.")

    if score >= 5:
        risk = "High"
    elif score >= 3:
        risk = "Medium"
    else:
        risk = "Low"
    return {"url": raw_url, "score": score, "risk": risk, "reasons": reasons}

EMAIL_PATTERNS = [
    (re.compile(r"\b(urgent|immediately|within 24 hours|act now|final warning)\b", re.I),
     "Uses urgency or a deadline."),
    (re.compile(r"\b(verify your account|confirm your identity|reset your password|account suspended|account locked)\b", re.I),
     "Requests account verification or password action."),
    (re.compile(r"\b(gift card|wire transfer|crypto(?:currency)?|payment overdue|bank details)\b", re.I),
     "Mentions a payment or financial action."),
    (re.compile(r"\b(click here|open the attachment|enable macros|download now)\b", re.I),
     "Encourages clicking, opening, or downloading."),
    (re.compile(r"\b(password|one[- ]time passcode|OTP|PIN)\b", re.I),
     "Mentions credentials or authentication codes.")
]

def analyze_email(email_text: str):
    """Analyze email text with simple phrase and URL heuristics."""
    email_text = (email_text or "").strip()
    if not email_text:
        return {"score": 0, "risk": "Unknown", "reasons": ["No email text supplied."], "urls": []}
    reasons = []
    score = 0
    for pattern, reason in EMAIL_PATTERNS:
        if pattern.search(email_text):
            score += 1
            reasons.append(reason)
    urls = extract_urls(email_text)
    url_results = [analyze_url(url) for url in urls]
    if any(item["risk"] == "High" for item in url_results):
        score += 2
        reasons.append("At least one extracted URL has a high heuristic risk score.")
    elif any(item["risk"] == "Medium" for item in url_results):
        score += 1
        reasons.append("At least one extracted URL has a medium heuristic risk score.")
    if not reasons:
        reasons.append("No configured email indicators were found.")
    risk = "High" if score >= 4 else "Medium" if score >= 2 else "Low"
    return {"score": score, "risk": risk, "reasons": reasons, "urls": url_results}

def print_report(title, result):
    print(f"\n=== {title} ===")
    print(f"Risk level: {result['risk']} (heuristic score: {result['score']})")
    for reason in result["reasons"]:
        print(f"- {reason}")
    if result.get("urls"):
        print("\nExtracted URL analysis:")
        for item in result["urls"]:
            print(f"\n  URL: {item['url']}\n  Risk: {item['risk']} (score: {item['score']})")
            for reason in item["reasons"]:
                print(f"  - {reason}")

def main():
    print("Phishing URL and Email Detection (educational heuristic tool)")
    print("Do not treat a Low result as proof that content is safe.")
    while True:
        print("\nChoose an option:\n1. Analyze a URL\n2. Analyze email text\n3. Exit")
        choice = input("Enter 1, 2, or 3: ").strip()
        if choice == "1":
            url = input("Paste a URL to analyze: ").strip()
            print_report("URL Analysis", analyze_url(url))
        elif choice == "2":
            print("Paste email text. Finish input with a line containing only END.")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            print_report("Email Analysis", analyze_email("\n".join(lines)))
        elif choice == "3":
            print("Goodbye.")
            break
        else:
            print("Invalid option. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
