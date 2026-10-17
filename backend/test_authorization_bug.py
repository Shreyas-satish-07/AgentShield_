"""
Comprehensive tests verifying the fix for the authorization bug in Aura Personal AI Agent.

Tests:
1. Exact bug prompt: 'Aura, please draft a friendly message to my engineering team announcing that version 2.0 is ready for release'
   - Generates draft directly with status COMPLETED and decision ALLOW.
   - No authorization prompt, no OWNER_CONFIRMATION_REQUIRED.
2. Canonical action mapping:
   - answer_question -> SAFE, completes with ALLOW directly.
   - summarize_text -> SAFE, completes with ALLOW directly.
   - draft_message -> LOW, completes with ALLOW directly.
   - query_status -> LOW, completes with ALLOW directly.
   - send_email -> MEDIUM, requires authorization.
   - simulate_purchase -> HIGH, requires authorization.
   - transfer_funds -> HIGH, requires authorization.
3. Voice-triggered safe tasks:
   - With REAL voice: completes with ALLOW without authorization prompt.
   - With FAKE voice: strictly blocked (HOLD), no authorization card.
   - With NOT_SURE voice: fails closed (HOLD), no authorization card.
   - With detector/API error: fails closed (HOLD), no authorization card.
4. High-risk actions with voice:
   - Even with REAL voice, high-risk actions (purchase, transfer) CANNOT auto-execute.
   - Must return OWNER_CONFIRMATION_REQUIRED and generate valid auth_token.
   - Secondary owner approval executes sandbox simulation safely.
5. Unknown actions fail closed (HOLD).
"""

import unittest
from unittest.mock import patch

from backend.policy import evaluate_action_policy, ACTION_SENSITIVITY, CANONICAL_ACTIONS
from backend.agent import process_agent_task, authorize_pending_task, parse_intent_and_plan


class TestAuthorizationBugFix(unittest.TestCase):

    def test_reported_bug_prompt_text_only_draft_completes_directly(self):
        """
        Verifies the exact user reported bug:
        'Aura, please draft a friendly message to my engineering team announcing that version 2.0 is ready for release'
        must complete directly without 'NEEDS_AUTHORIZATION' or 'OWNER_CONFIRMATION_REQUIRED'.
        """
        task_text = "Aura, please draft a friendly message to my engineering team announcing that version 2.0 is ready for release"
        result = process_agent_task(task_text)

        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["authorization_required"])
        self.assertIsNone(result.get("authorization_details"))
        self.assertEqual(result["plan"]["action"], "draft_message")
        self.assertEqual(result["plan"]["sensitivity"], "LOW")
        self.assertEqual(result["diagnostics"]["policy_decision"], "ALLOW")
        self.assertIsNotNone(result["execution"])
        self.assertEqual(result["execution"]["type"], "draft_message")
        self.assertIn("Hi Team", result["execution"]["result_text"])
        self.assertIn("version 2.0", result["execution"]["result_text"].lower())

    def test_safe_and_low_actions_canonical_mapping(self):
        """
        Canonical mapping must classify:
        - answer_question: SAFE
        - summarize_text: SAFE
        - draft_message: LOW
        - query_status: LOW
        None of them should default to HIGH.
        """
        self.assertEqual(ACTION_SENSITIVITY.get("answer_question"), "SAFE")
        self.assertEqual(ACTION_SENSITIVITY.get("summarize_text"), "SAFE")
        self.assertEqual(ACTION_SENSITIVITY.get("draft_message"), "LOW")
        self.assertEqual(ACTION_SENSITIVITY.get("query_status"), "LOW")
        self.assertEqual(ACTION_SENSITIVITY.get("send_email"), "MEDIUM")
        self.assertEqual(ACTION_SENSITIVITY.get("simulate_purchase"), "HIGH")
        self.assertEqual(ACTION_SENSITIVITY.get("transfer_funds"), "HIGH")

        # Aliases
        for alias, canon in [
            ("draft", "draft_message"),
            ("answer", "answer_question"),
            ("summarize", "summarize_text"),
            ("status", "query_status"),
            ("buy", "simulate_purchase"),
            ("purchase", "simulate_purchase"),
            ("transfer", "transfer_funds")
        ]:
            self.assertEqual(CANONICAL_ACTIONS.get(alias), canon)

    def test_general_questions_complete_directly(self):
        """Questions like 'What can you do?' must complete directly with ALLOW."""
        result = process_agent_task("What can you do?")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["authorization_required"])
        self.assertEqual(result["plan"]["action"], "answer_question")
        self.assertEqual(result["plan"]["sensitivity"], "SAFE")
        self.assertEqual(result["diagnostics"]["policy_decision"], "ALLOW")

    def test_summarization_completes_directly(self):
        """Summaries like 'Summarize the release notes for Q3' must complete directly."""
        result = process_agent_task("Summarize the release notes for Q3")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertFalse(result["authorization_required"])
        self.assertEqual(result["plan"]["action"], "summarize_text")
        self.assertEqual(result["plan"]["sensitivity"], "SAFE")
        self.assertEqual(result["diagnostics"]["policy_decision"], "ALLOW")

    def test_voice_triggered_draft_with_real_verdict_completes(self):
        """Voice-triggered draft with real DetectifAI verdict completes directly with ALLOW."""
        mock_scan = {
            "success": True,
            "verdict": "real",
            "score": 0.03,
            "request_id": "req_voice_real_123"
        }
        with patch("backend.agent.load_api_key", return_value="det_live_key_valid"), \
             patch("backend.agent.analyze_audio_file", return_value=mock_scan):
            result = process_agent_task(
                "Aura, please draft a memo to the executive team",
                audio_file_path="/mock/audio.wav"
            )
            self.assertEqual(result["status"], "COMPLETED")
            self.assertFalse(result["authorization_required"])
            self.assertEqual(result["diagnostics"]["policy_decision"], "ALLOW")
            self.assertEqual(result["execution"]["type"], "draft_message")

    def test_high_risk_purchase_requires_owner_approval_even_with_real_voice(self):
        """
        High-risk action (purchase) MUST NOT auto-execute, even if voice is verified as REAL.
        Must pause and request OWNER_CONFIRMATION_REQUIRED.
        """
        mock_scan = {
            "success": True,
            "verdict": "real",
            "score": 0.02,
            "request_id": "req_purchase_voice"
        }
        with patch("backend.agent.load_api_key", return_value="det_live_key_valid"), \
             patch("backend.agent.analyze_audio_file", return_value=mock_scan):
            result = process_agent_task(
                "Buy a new developer workstation laptop for $2,500",
                audio_file_path="/mock/audio.wav"
            )
            self.assertEqual(result["status"], "NEEDS_AUTHORIZATION")
            self.assertTrue(result["authorization_required"])
            self.assertEqual(result["diagnostics"]["policy_decision"], "OWNER_CONFIRMATION_REQUIRED")
            self.assertIsNone(result["execution"])
            token = result["authorization_details"]["auth_token"]
            self.assertTrue(token.startswith("auth_"))

            # Approve via secondary owner approval mechanism
            approved_res = authorize_pending_task(token, approve=True)
            self.assertTrue(approved_res["success"])
            self.assertEqual(approved_res["status"], "COMPLETED")
            self.assertTrue(approved_res["execution"]["is_simulated"])

    def test_fake_voice_verdict_strictly_blocks_execution(self):
        """Fake voice verdict must return BLOCKED with HOLD policy decision; no authorization prompt."""
        mock_scan = {
            "success": True,
            "verdict": "fake",
            "score": 0.94,
            "request_id": "req_fake_voice"
        }
        with patch("backend.agent.load_api_key", return_value="det_live_key_valid"), \
             patch("backend.agent.analyze_audio_file", return_value=mock_scan):
            result = process_agent_task(
                "Aura, draft a note",
                audio_file_path="/mock/audio.wav"
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["authorization_required"])
            self.assertEqual(result["diagnostics"]["policy_decision"], "HOLD")
            self.assertIsNone(result["execution"])
            self.assertIn("synthetic", result["assistant_message"].lower())

    def test_uncertain_not_sure_voice_verdict_fails_closed(self):
        """Inconclusive 'not_sure' voice verdict fails closed (HOLD)."""
        mock_scan = {
            "success": True,
            "verdict": "not_sure",
            "score": 0.52,
            "request_id": "req_uncertain"
        }
        with patch("backend.agent.load_api_key", return_value="det_live_key_valid"), \
             patch("backend.agent.analyze_audio_file", return_value=mock_scan):
            result = process_agent_task(
                "Aura, draft a note",
                audio_file_path="/mock/audio.wav"
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["authorization_required"])
            self.assertEqual(result["diagnostics"]["policy_decision"], "HOLD")

    def test_detector_api_failure_fails_closed_never_fabricates_verdict(self):
        """API/network failure must fail closed (HOLD); never treated as successful verification."""
        mock_scan = {
            "success": False,
            "error": "DetectifAI upstream timeout",
            "request_id": None
        }
        with patch("backend.agent.load_api_key", return_value="det_live_key_valid"), \
             patch("backend.agent.analyze_audio_file", return_value=mock_scan):
            result = process_agent_task(
                "Transfer $500 to savings",
                audio_file_path="/mock/audio.wav"
            )
            self.assertEqual(result["status"], "BLOCKED")
            self.assertFalse(result["authorization_required"])
            self.assertEqual(result["diagnostics"]["policy_decision"], "HOLD")

    def test_unknown_action_fails_closed_in_policy(self):
        """Unknown action types fail closed under security policy (HOLD)."""
        res = evaluate_action_policy(verdict="real", score=0.01, action_type="unknown_unregistered_action")
        self.assertEqual(res["decision"], "HOLD")
        self.assertIn("Unknown action", res["reason"])


if __name__ == "__main__":
    unittest.main()
