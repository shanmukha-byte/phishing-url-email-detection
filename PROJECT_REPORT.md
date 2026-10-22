# Project Report: Phishing URL and Email Detection

**Program:** IBM SkillsBuild Cybersecurity Bootcamp 2026  
**Organization:** BharatCares  
**Student name:** [Enter your full name]  
**Institute:** [Enter institute name]  
**Submission date:** [Enter date]

## 1. Abstract
Phishing is a social-engineering technique that attempts to trick people into disclosing credentials, making payments, or opening harmful content. This project implements a Python command-line prototype that checks URLs and email text for selected suspicious indicators. It applies explainable rules and returns a Low, Medium, or High heuristic risk level with reasons. The system is intended for cybersecurity education and awareness, not as a replacement for enterprise security controls.

## 2. Problem statement
Users may have difficulty recognizing deceptive links and manipulative email wording. A simple, transparent tool can help learners understand common warning signs before interacting with potentially harmful content.

## 3. Objectives
- Build a Python tool that accepts a URL or email text.
- Identify common URL and email warning indicators.
- Provide a risk band and human-readable explanations.
- Demonstrate defensive cybersecurity programming using safe, fictional examples.
- Document limitations and responsible use.

## 4. Scope
The prototype analyzes user-supplied text locally and does not open URLs or download content. It checks a limited set of URL structure features and email phrases. It does not determine the true reputation of a domain, inspect attachments, validate SPF/DKIM/DMARC, or use a machine-learning model.

## 5. Tools and technologies
- Python 3.10 or newer
- Python standard library: `re`, `ipaddress`, `urllib.parse`
- Any text editor or IDE
- Git and GitHub for version control and submission

## 6. Methodology
1. **Input:** The user enters a URL or pastes email text into the command-line interface.
2. **Parsing:** URL text is parsed to inspect the scheme, hostname, and authority section.
3. **Rule checks:** The tool checks for indicators such as a non-HTTPS scheme, IP-address host, unusually long URL, user-info, punycode labels, many subdomain levels, URL shorteners, urgency-related terms, and selected TLDs. Email text is checked for urgency, credential requests, financial requests, click/download language, and extracted URLs.
4. **Scoring:** Each configured indicator adds points. The score is mapped to a Low, Medium, or High risk band.
5. **Explanation:** The program displays the detected indicators so the user can understand why the score was assigned.

## 7. Implementation
The application is implemented in `app.py`. The `analyze_url()` function evaluates a single URL. The `extract_urls()` function extracts URL-like strings from email text. The `analyze_email()` function evaluates email wording and calls the URL analyzer for extracted links. The interface is a simple interactive command-line menu.

## 8. Testing plan and sample cases
Use only fictional, non-live examples and do not visit suspicious links.

| Test case | Input | Expected behavior |
|---|---|---|
| T1 | `https://example.com/` | No configured indicators or a low risk score |
| T2 | `http://198.51.100.25/verify-account?urgent=1` | Flags non-HTTPS, IP host, and suspicious wording |
| T3 | Email text saying “Urgent: verify your account immediately” with the fictional URL above | Flags urgency/account-verification wording and elevated URL indicators |
| T4 | Empty URL/email input | Returns “Unknown” with an explanatory message |
| T5 | URL with `@` in authority section | Flags potentially confusing authority syntax |

Actual results should be confirmed by running the program and recorded before final submission.

## 9. Results and discussion
The prototype demonstrates a transparent rule-based approach and produces human-readable explanations. It can support classroom demonstrations of common phishing signals. It has not been evaluated on a representative labeled dataset, so no accuracy, precision, recall, or F1-score is claimed. The score is a heuristic indicator, not a calibrated probability.

## 10. Limitations
- Heuristics may flag legitimate links or miss sophisticated phishing attempts.
- HTTPS can be used by malicious websites and does not establish trust.
- Keyword and TLD checks are context-sensitive and may be inaccurate.
- Sender identity, email headers, attachments, redirects, page content, and live threat intelligence are not checked.
- The project is not suitable as the sole basis for security decisions.

## 11. Ethical and safety considerations
The project is intended for defensive education. It does not send emails, exploit systems, or visit URLs. Use fictional examples or content you are authorized to analyze. Avoid entering confidential data, passwords, OTPs, or private emails into shared systems. If a message appears suspicious, do not click its links; report it through the appropriate organizational process.

## 12. Future enhancements
- Evaluate against a responsibly sourced, labeled dataset.
- Add automated tests and report measurable metrics.
- Add email header authentication checks.
- Add optional, privacy-conscious threat-intelligence lookups.
- Build a simple web interface with clear warnings and safe handling of user input.

## 13. Conclusion
This project provides a beginner-friendly Python demonstration of phishing awareness using interpretable URL and email heuristics. It meets the learning goal of identifying selected suspicious indicators while clearly communicating that automated scores are imperfect. Additional testing and validation would be required before any real-world deployment.

## 14. References
- Python documentation: https://docs.python.org/3/
- CISA, Recognize and Report Phishing: https://www.cisa.gov/secure-our-world/recognize-and-report-phishing
- Google Safe Browsing: https://safebrowsing.google.com/ (for background on reputation-based protection; not integrated in this prototype)
