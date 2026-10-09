import unittest
from app import classify_indicator

class IndicatorTests(unittest.TestCase):
    def test_normalizes_ipv4(self):
        self.assertEqual(classify_indicator("203.0.113.10")["type"], "ip")
    def test_normalizes_domain(self):
        self.assertEqual(classify_indicator("Example.ORG")["indicator"], "example.org")
    def test_hash_lowercase(self):
        self.assertEqual(classify_indicator("A"*64)["indicator"], "a"*64)
    def test_http_has_reason(self):
        result = classify_indicator("http://example.org")
        self.assertIn("unencrypted HTTP", result["reasons"][0])
    def test_rejects_empty(self):
        with self.assertRaises(ValueError): classify_indicator(" ")
    def test_rejects_url_credentials(self):
        with self.assertRaises(ValueError): classify_indicator("https://user:pass@example.org")
    def test_rejects_invalid(self):
        with self.assertRaises(ValueError): classify_indicator("not a valid indicator")

if __name__ == "__main__": unittest.main()
