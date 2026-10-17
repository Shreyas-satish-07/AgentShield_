"""
Personal AI Assistant - Workflow & Security Gate Automated Test Suite
Tests:
1. Safe task workflow (e.g. answering question, drafting, summarization) produces real backend results.
2. Voice input routed through DetectifAI and backend policy.
3. Fake or uncertain verdict strictly blocks execution (HOLD).
4. High-risk actions (simulate_purchase, transfer_funds) require explicit owner confirmation
   even when voice verdict is REAL (Authenticity != Authorization).
5. Server-side execution gate prevents unauthorized execution.
6. Fail-closed behavior on missing verdicts, API errors, and invalid authorization tokens.
"""

import io
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from agent import (
    parse_intent_and_plan,
    process_agent_task,
    authorize_pending_task,
    execute_action_safely,
    SUPPORTED_ACTIONS
)
from test_api_endpoint import generate_wav_bytes


class TestPersonalAIAgentWorkflow(unittest.TestCase):
    """Verifies the Personal AI Assistant task workflow and server-side gate."""

    def test_intent_planning_safe_and_sensitive_actions(self):
        """Test natural language intent classification into appropriate sensitivity tiers."""
        # Safe questions
        plan_q = parse_intent_and_plan("What is your purpose and how do you protect actions?")
        self.assertEqual(plan_q["action"], "answer_question")
        self.assertEqual(plan_q["sensitivity"], "SAFE")

        # Safe summarization
        plan_s = parse_intent_and_plan("Summarize the quarterly cloud infrastructure incident report")
        self.assertEqual(plan_s["action"], "summarize_text")
        self.assertEqual(plan_s["sensitivity"], "SAFE")

        # Low sensitivity drafting
        plan_d = parse_intent_and_plan("Draft a message to the engineering team announcing release v2.0")
        self.assertEqual(plan_d["action"], "draft_message")
        self.assertEqual(plan_d["sensitivity"], "LOW")

        # Low sensitivity system status
        plan_stat = parse_intent_and_plan("Check system status and telemetry metrics")
        self.assertEqual(plan_stat["action"], "query_status")
        self.assertEqual(plan_stat["sensitivity"], "LOW")

        # High sensitivity purchase
        plan_p = parse_intent_and_plan("Purchase a MacBook Pro for ₹180,000 for the new lead")
        self.assertEqual(plan_p["action"], "simulate_purchase")
        self.assertEqual(plan_p["sensitivity"], "HIGH")

        # High sensitivity transfer
        plan_t = parse_intent_and_plan("Transfer ₹25,000 to vendor for annual database subscription")
        self.assertEqual(plan_t["action"], "transfer_funds")
        self.assertEqual(plan_t["sensitivity"], "HIGH")

    def test_safe_task_executes_genuine_backend_result(self):
        """Safe tasks (questions, summaries, drafts) execute genuinely and return results."""
        # Question answering
        res_q = process_agent_task("What can you do to assist me?")
        self.assertEqual(res_q["status"], "COMPLETED")
        self.assertIsNotNone(res_q["execution"])
        self.assertFalse(res_q["execution"]["is_simulated"])
        self.assertIn("Drafting & Writing", res_q["assistant_message"])

        # Message drafting
        res_d = process_agent_task("Draft an update for team regarding deployment")
        self.assertEqual(res_d["status"], "COMPLETED")
        self.assertIsNotNone(res_d["execution"])
        self.assertIn("Hi Team", res_d["assistant_message"])

        # Summarization
        res_s = process_agent_task("Summarize: The server cluster migrated to regional failover.")
        self.assertEqual(res_s["status"], "COMPLETED")
        self.assertIsNotNone(res_s["execution"])
        self.assertIn("Core Topic", res_s["assistant_message"])

    @patch("agent.load_api_key", return_value="dummy_api_key")
    @patch("agent.analyze_audio_file")
    def test_voice_input_with_fake_verdict_blocks_execution(self, mock_scan, mock_key):
        """When voice is flagged as synthetic/fake, server gate strictly blocks execution."""
        mock_scan.return_value = {
            "success": True,
            "request_id": "req_fake_test_1",
            "verdict": "fake",
            "score": 0.94,
            "duration_seconds": 6.5,
            "error": None
        }

        # Attempt low sensitivity draft with fake voice
        res = process_agent_task(
            task_text="Draft a message to engineering",
            audio_file_path="mock_audio.wav",
            audio_duration_seconds=6.5
        )

        self.assertEqual(res["status"], "BLOCKED")
        self.assertIsNone(res["execution"])
        self.assertFalse(res["authorization_required"])
        # Assistant must explain naturally without exposing raw internal verdicts
        self.assertIn("I couldn't safely proceed with this action", res["assistant_message"])
        self.assertEqual(res["diagnostics"]["policy_decision"], "HOLD")

    @patch("agent.load_api_key", return_value="dummy_api_key")
    @patch("agent.analyze_audio_file")
    def test_voice_input_with_uncertain_verdict_fails_closed(self, mock_scan, mock_key):
        """When voice authenticity is inconclusive ('not_sure'), server gate fails closed."""
        mock_scan.return_value = {
            "success": True,
            "request_id": "req_uncertain_test",
            "verdict": "not_sure",
            "score": 0.51,
            "duration_seconds": 5.0,
            "error": None
        }

        res = process_agent_task(
            task_text="Draft a message to engineering",
            audio_file_path="mock_audio.wav"
        )

        self.assertEqual(res["status"], "BLOCKED")
        self.assertIsNone(res["execution"])
        self.assertIn("I couldn't safely proceed with this action", res["assistant_message"])
        self.assertEqual(res["diagnostics"]["policy_decision"], "HOLD")

    @patch("agent.load_api_key", return_value="dummy_api_key")
    @patch("agent.analyze_audio_file")
    def test_high_risk_action_blocked_from_auto_executing_even_when_voice_is_real(self, mock_scan, mock_key):
        """
        CRITICAL SECURITY REQUIREMENT:
        Authenticity != Authorization.
        Even when voice verdict is verified REAL, a high-risk action (simulate_purchase)
        MUST NOT execute automatically. It must be gated for secondary owner authorization.
        """
        mock_scan.return_value = {
            "success": True,
            "request_id": "req_real_test",
            "verdict": "real",
            "score": 0.02,
            "duration_seconds": 6.0,
            "error": None
        }

        res = process_agent_task(
            task_text="Purchase a laptop for ₹80,000 for the new lead",
            audio_file_path="mock_audio.wav"
        )

        # Must NOT be completed automatically
        self.assertEqual(res["status"], "NEEDS_AUTHORIZATION")
        self.assertIsNone(res["execution"])
        self.assertTrue(res["authorization_required"])
        self.assertIn("I need your authorization", res["assistant_message"])

        # Check that authorization details contain a valid server auth token
        auth_details = res["authorization_details"]
        self.assertIn("auth_token", auth_details)
        auth_token = auth_details["auth_token"]
        self.assertTrue(auth_token.startswith("auth_"))

        # Confirm the action is held until genuine owner confirmation is provided
        # 1. Test rejection flow
        reject_res = authorize_pending_task(auth_token, approve=False)
        self.assertEqual(reject_res["status"], "CANCELLED")
        self.assertIsNone(reject_res["execution"])
        self.assertIn("Action cancelled", reject_res["assistant_message"])

        # Token must be invalidated immediately after use
        reuse_res = authorize_pending_task(auth_token, approve=True)
        self.assertFalse(reuse_res["success"])
        self.assertEqual(reuse_res["status"], "BLOCKED")

    @patch("agent.load_api_key", return_value="dummy_api_key")
    @patch("agent.analyze_audio_file")
    def test_owner_approval_flow_executes_sandboxed_simulation(self, mock_scan, mock_key):
        """When owner approves the authorization challenge, the gated action executes in sandbox."""
        mock_scan.return_value = {
            "success": True,
            "request_id": "req_approval_test",
            "verdict": "real",
            "score": 0.01,
            "duration_seconds": 7.0,
            "error": None
        }

        res = process_agent_task(
            task_text="Transfer ₹5,000 to vendor for cloud hosting",
            audio_file_path="mock_audio.wav"
        )
        self.assertEqual(res["status"], "NEEDS_AUTHORIZATION")
        auth_token = res["authorization_details"]["auth_token"]

        # Owner approves
        approval_res = authorize_pending_task(auth_token, approve=True)
        self.assertTrue(approval_res["success"])
        self.assertEqual(approval_res["status"], "COMPLETED")
        self.assertIsNotNone(approval_res["execution"])
        self.assertTrue(approval_res["execution"]["is_simulated"])
        self.assertEqual(approval_res["execution"]["type"], "transfer_funds")
        self.assertIn("Sandbox Simulation Only", approval_res["execution"]["disclaimer"])

    def test_fail_closed_on_detector_error(self):
        """Fails closed safely when provider API errors out."""
        with patch("agent.load_api_key", return_value="dummy_key"), \
             patch("agent.analyze_audio_file", return_value={
                 "success": False,
                 "status_code": 500,
                 "error": "Internal upstream error"
             }):
            res = process_agent_task(
                task_text="Draft a message to team",
                audio_file_path="mock_audio.wav"
            )
            self.assertEqual(res["status"], "BLOCKED")
            self.assertIsNone(res["execution"])
            self.assertIn("I couldn't safely proceed with this action", res["assistant_message"])
            self.assertEqual(res["diagnostics"]["policy_decision"], "HOLD")


if __name__ == "__main__":
    unittest.main(verbosity=2)
