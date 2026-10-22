# Phishing URL and Email Detection

**Project type:** Defensive cybersecurity / awareness  
**Language:** Python 3.10+  
**Dependencies:** Python standard library only

## Overview
This command-line learning tool analyzes a URL or pasted email text using transparent, rule-based heuristics. It reports a Low, Medium, or High heuristic risk level and explains the indicators that contributed to the score.

## Features
- URL checks for non-HTTPS schemes, IP-address hosts, long URLs, user-info (`@`), punycode labels, many subdomains, URL shorteners, suspicious wording, and selected high-abuse TLDs.
- Email text checks for urgency, credential requests, financial requests, click/download language, and extracted URLs.
- Explains why each indicator was flagged.
- Uses only Python's standard library.

## Requirements
- Python 3.10 or newer recommended.
- No third-party packages required.

## Run
```bash
python app.py
```
Choose `1` to analyze a URL, `2` to analyze email text, or `3` to exit.

For email analysis, paste the message text and finish by entering `END` on its own line.

## Example test inputs
Use these fictional examples for demonstration. Do not visit suspicious links.

URL:
```text
http://198.51.100.25/verify-account?urgent=1
```

Email:
```text
Subject: Urgent account notice
Your account is suspended. Verify your account immediately at
http://198.51.100.25/verify-account
END
```

`198.51.100.0/24` is a documentation-only IPv4 range; the example is not intended to identify a real service.

## Limitations and safe use
- This is an educational prototype, not a production anti-phishing product.
- Rule-based heuristics can produce false positives and false negatives.
- A Low score does **not** mean a URL or email is safe; a High score does not prove maliciousness.
- HTTPS is not proof of legitimacy, and suspicious-looking TLDs are not proof of abuse.
- The tool does not visit URLs, inspect attachments, verify sender authentication, or query threat-intelligence feeds.
- Do not paste confidential emails, passwords, OTPs, personal data, or proprietary content into this tool.
- Use only for defensive awareness and authorized educational testing.

## Project structure
```text
phishing_url_email_detection/
├── app.py
├── requirements.txt
├── README.md
├── PROJECT_REPORT.md
└── tests/
    └── test_app.py
```

## Future improvements
- Add a small labeled dataset and evaluate precision, recall, and F1-score.
- Add safe integration with reputable threat-intelligence sources.
- Add sender-domain and email-header checks.
- Add a web interface with privacy protections.
- Add automated unit tests and CI.

## Author
Add your name, institute, and bootcamp details before submission.
