import unittest
from app import analyze_url, analyze_email, extract_urls

class PhishingDetectionTests(unittest.TestCase):
    def test_empty_url_is_unknown(self):
        self.assertEqual(analyze_url("")["risk"], "Unknown")

    def test_ip_and_http_url_flags_indicators(self):
        result = analyze_url("http://198.51.100.25/verify-account?urgent=1")
        self.assertGreaterEqual(result["score"], 4)
        self.assertIn(result["risk"], {"Medium", "High"})

    def test_extract_urls(self):
        urls = extract_urls("Visit https://example.com/path and www.example.org")
        self.assertGreaterEqual(len(urls), 2)

    def test_email_detects_urgency_and_url(self):
        result = analyze_email("Urgent! Verify your account immediately at http://198.51.100.25/verify-account")
        self.assertGreater(result["score"], 0)
        self.assertGreaterEqual(len(result["urls"]), 1)

    def test_empty_email_is_unknown(self):
        self.assertEqual(analyze_email("")["risk"], "Unknown")

if __name__ == "__main__":
    unittest.main()
