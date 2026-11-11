import unittest

import app as detector


class ThreatDetectorApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        detector.load_models()

    def setUp(self):
        self.client = detector.app.test_client()

    def test_known_google_and_youtube_urls_are_not_flagged(self):
        for url in ("https://www.youtube.com/", "https://www.google.com/maps"):
            with self.subTest(url=url):
                response = self.client.post("/api/check-url", json={"url": url})
                result = response.get_json()
                self.assertEqual(response.status_code, 200)
                self.assertEqual(result["label"], "legitimate")
                self.assertTrue(result["trusted_domain"])
                self.assertLessEqual(result["probability_malicious"], 0.02)

    def test_lookalike_domain_does_not_inherit_trust(self):
        result = self.client.post(
            "/api/check-url", json={"url": "https://youtube.com.attacker.example/login"}
        ).get_json()
        self.assertFalse(result["trusted_domain"])

    def test_suspicious_phishing_url_is_still_flagged(self):
        result = self.client.post(
            "/api/check-url", json={"url": "http://paypa1-secure-login.tk/verify"}
        ).get_json()
        self.assertEqual(result["label"], "malicious")
        self.assertFalse(result["trusted_domain"])

    def test_embedded_credentials_do_not_inherit_trust(self):
        result = self.client.post(
            "/api/check-url", json={"url": "https://youtube.com@attacker.example/"}
        ).get_json()
        self.assertFalse(result["trusted_domain"])

    def test_batch_scan_returns_each_result(self):
        response = self.client.post(
            "/api/check-urls",
            json={"urls": ["https://www.youtube.com/", "not a url", "https://www.google.com/maps"]},
        )
        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(result["scanned"], 3)
        self.assertEqual(result["invalid"], 1)
        self.assertEqual(result["results"][0]["label"], "legitimate")

    def test_empty_url_is_a_validation_error(self):
        response = self.client.post("/api/check-url", json={"url": ""})
        self.assertEqual(response.status_code, 400)

    def test_batch_scan_enforces_url_limit(self):
        response = self.client.post(
            "/api/check-urls", json={"urls": ["https://example.com"] * 51}
        )
        self.assertEqual(response.status_code, 400)

    def test_message_analysis_includes_explainable_signals(self):
        response = self.client.post(
            "/api/analyze",
            json={"text": "Verify your account immediately at https://www.google.com/maps"},
        )
        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(result["url_module"][0]["label"], "legitimate")
        self.assertTrue(result["email_signals"])
        self.assertIn("analysis_note", result)

    def test_model_lab_reports_dataset_and_evaluation_details(self):
        response = self.client.get("/api/model-stats")
        result = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(result["datasets"][0]["records"], 5572)
        self.assertEqual(result["datasets"][1]["records"], 420464)
        self.assertGreater(result["models"][1]["roc_auc"], 0.9)

    def test_all_workspace_pages_render(self):
        for page in ("/", "/email-analyzer", "/url-scanner", "/security-center", "/model-lab"):
            with self.subTest(page=page):
                self.assertEqual(self.client.get(page).status_code, 200)


if __name__ == "__main__":
    unittest.main()
