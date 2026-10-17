"""
AgentShield - Automated Mock Test Suite
IMPORTANT: These tests use local mock data only.
THEY DO NOT CALL THE REAL DETECTIFAI API AND DO NOT CONSUME ANY API QUOTA.
"""

import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

# Ensure backend directory is in path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from policy import evaluate_action_policy
from detectif_client import analyze_audio_file, load_api_key


class TestAgentShieldPolicy(unittest.TestCase):
    """Verifies AgentShield security policy decisions for all verdicts and failure modes."""

    def test_verdict_fake_holds_all_actions(self):
        """When voice is identified as fake, action must be HOLD."""
        # Low sensitivity action
        res_low = evaluate_action_policy(verdict="fake", score=0.92, action_type="draft_message")
        self.assertEqual(res_low["decision"], "HOLD")
        self.assertIn("Deepfake detected", res_low["reason"])

        # High sensitivity action
        res_high = evaluate_action_policy(verdict="fake", score=0.92, action_type="simulate_purchase")
        self.assertEqual(res_high["decision"], "HOLD")

    def test_verdict_not_sure_holds_actions(self):
        """When voice authenticity is inconclusive (not_sure), action must be HOLD."""
        res = evaluate_action_policy(verdict="not_sure", score=0.48, action_type="draft_message")
        self.assertEqual(res["decision"], "HOLD")
        self.assertIn("inconclusive", res["reason"])

    def test_verdict_real_low_sensitivity_allowed(self):
        """Genuine voice allows low-risk actions like drafting a message."""
        res = evaluate_action_policy(verdict="real", score=0.05, action_type="draft_message")
        self.assertEqual(res["decision"], "ALLOW")

    def test_verdict_real_high_sensitivity_requires_owner_confirmation(self):
        """
        CRITICAL SECURITY CHECK:
        Authenticity != Authorization.
        Even with a real voice verdict, high-sensitivity actions (e.g. simulate_purchase)
        require explicit OWNER_CONFIRMATION_REQUIRED.
        """
        res = evaluate_action_policy(verdict="real", score=0.05, action_type="simulate_purchase")
        self.assertEqual(res["decision"], "OWNER_CONFIRMATION_REQUIRED")
        self.assertIn("authenticity alone does NOT equal authorization", res["reason"])

    def test_fail_closed_on_api_error_or_timeout(self):
        """When API fails or times out, security must fail closed (HOLD)."""
        res = evaluate_action_policy(verdict=None, api_error="Request timed out after 30 seconds", action_type="simulate_purchase")
        self.assertEqual(res["decision"], "HOLD")
        self.assertIn("fail-closed", res["reason"])

    def test_missing_or_malformed_verdict(self):
        """When verdict is empty or invalid, action must be HOLD."""
        res_none = evaluate_action_policy(verdict=None, action_type="draft_message")
        self.assertEqual(res_none["decision"], "HOLD")

        res_unknown = evaluate_action_policy(verdict="unexpected_string", action_type="draft_message")
        self.assertEqual(res_unknown["decision"], "HOLD")


class TestDetectifClientLocalMock(unittest.TestCase):
    """Verifies client input validation and mocked API responses without live network calls."""

    def test_missing_api_key(self):
        """Client should reject calls when API key is missing or is the placeholder."""
        res = analyze_audio_file("nonexistent.wav", api_key="")
        self.assertFalse(res["success"])
        self.assertIn("DETECTIF_API_KEY is missing", res["error"])

        res_placeholder = analyze_audio_file("nonexistent.wav", api_key="your_actual_key_here")
        self.assertFalse(res_placeholder["success"])
        self.assertIn("placeholder", res_placeholder["error"])

    def test_missing_audio_file(self):
        """Client should reject calls when audio file does not exist."""
        res = analyze_audio_file("d:\\definitely_non_existent_file_12345.wav", api_key="test_dummy_key")
        self.assertFalse(res["success"])
        self.assertIn("Audio file not found", res["error"])

    @patch("detectif_client.requests.post")
    def test_mock_successful_real_response_parsing(self, mock_post):
        """MOCK TEST: Simulates a successful 'real' response from DetectifAI."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "request_id": "req_mock_123",
            "operation_id": "op_mock_456",
            "result": {
                "verdict": "real",
                "label": "genuine",
                "is_synthetic": False,
                "score": 0.07,
                "threshold": 0.62,
                "duration_seconds": 6.4
            }
        }
        mock_post.return_value = mock_response

        # Create a small dummy temporary file to pass the local file existence check
        dummy_file = backend_dir / "_temp_dummy_for_test.wav"
        dummy_file.write_bytes(b"RIFFdummydataWAVEfmt ")
        try:
            res = analyze_audio_file(str(dummy_file), api_key="test_dummy_key")
            self.assertTrue(res["success"])
            self.assertEqual(res["status_code"], 200)
            self.assertEqual(res["verdict"], "real")
            self.assertEqual(res["score"], 0.07)
            self.assertEqual(res["request_id"], "req_mock_123")
            self.assertEqual(res["duration_seconds"], 6.4)
        finally:
            if dummy_file.exists():
                dummy_file.unlink()

    @patch("detectif_client.requests.post")
    def test_mock_fake_verdict_response_parsing(self, mock_post):
        """MOCK TEST: Simulates a 'fake' verdict response from DetectifAI."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "request_id": "req_mock_fake_789",
            "result": {
                "verdict": "fake",
                "label": "synthetic",
                "is_synthetic": True,
                "score": 0.89,
                "threshold": 0.62,
                "duration_seconds": 5.1
            }
        }
        mock_post.return_value = mock_response

        dummy_file = backend_dir / "_temp_dummy_for_test.wav"
        dummy_file.write_bytes(b"RIFFdummydataWAVEfmt ")
        try:
            res = analyze_audio_file(str(dummy_file), api_key="test_dummy_key")
            self.assertTrue(res["success"])
            self.assertEqual(res["verdict"], "fake")
            self.assertEqual(res["score"], 0.89)

            # Check that policy holds action
            policy_res = evaluate_action_policy(verdict=res["verdict"], score=res["score"], action_type="simulate_purchase")
            self.assertEqual(policy_res["decision"], "HOLD")
        finally:
            if dummy_file.exists():
                dummy_file.unlink()

    @patch("detectif_client.requests.post")
    def test_mock_timeout_handling(self, mock_post):
        """MOCK TEST: Simulates an HTTP timeout and ensures graceful error handling."""
        import requests
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        dummy_file = backend_dir / "_temp_dummy_for_test.wav"
        dummy_file.write_bytes(b"RIFFdummydataWAVEfmt ")
        try:
            res = analyze_audio_file(str(dummy_file), api_key="test_dummy_key")
            self.assertFalse(res["success"])
            self.assertIn("timed out", res["error"])

            # Ensure policy fails closed
            policy_res = evaluate_action_policy(verdict=None, api_error=res["error"])
            self.assertEqual(policy_res["decision"], "HOLD")
        finally:
            if dummy_file.exists():
                dummy_file.unlink()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Running AgentShield Offline Mock Test Suite")
    print("(Zero external API calls / Zero quota used)")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
