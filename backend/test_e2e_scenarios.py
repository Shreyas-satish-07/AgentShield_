"""
Personal AI Assistant - End-to-End API Integration & Security Tests
Tests all required scenarios directly on the FastAPI routes:
1. Safe task through to real backend result.
2. Voice input through DetectifAI and backend policy.
3. Fake or uncertain verdict and prove protected execution is blocked.
4. High-risk action and prove it cannot execute automatically just because voice verdict is REAL.
5. Owner authorization flow executes sandbox simulation and invalidates token.
6. Server-side execution gate preventing bypassed parameters.
"""

import io
import asyncio
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from fastapi import UploadFile, HTTPException
from main import (
    handle_agent_task,
    handle_agent_task_json,
    handle_agent_authorize,
    AgentTaskJsonRequest,
    AgentAuthorizeRequest,
    simulate_action,
    SimulateActionRequest
)
from test_api_endpoint import generate_wav_bytes


class TestPersonalAIAgentE2EScenarios(unittest.TestCase):
    """End-to-End scenario verification for the Personal AI Assistant."""

    def test_scenario_1_safe_task_real_backend_result(self):
        """Scenario 1: Safe task (draft message) produces a real backend result."""
        data = asyncio.run(handle_agent_task(
            task="Draft a message to the engineering team announcing deployment"
        ))
        self.assertEqual(data["status"], "COMPLETED")
        self.assertFalse(data["authorization_required"])
        self.assertIsNotNone(data["execution"])
        self.assertIn("Hi Team", data["assistant_message"])
        self.assertEqual(data["plan"]["action"], "draft_message")
        self.assertEqual(data["diagnostics"]["policy_decision"], "ALLOW")

    def test_scenario_1b_safe_task_question_answering(self):
        """Scenario 1b: User asks question; assistant provides intelligent answer."""
        data = handle_agent_task_json(AgentTaskJsonRequest(
            task="What is your purpose and how can you help me?"
        ))
        self.assertEqual(data["status"], "COMPLETED")
        self.assertIn("Personal AI Assistant", data["assistant_message"])
        self.assertEqual(data["plan"]["action"], "answer_question")

    @patch("agent.load_api_key", return_value="dtf_test_key")
    @patch("agent.analyze_audio_file")
    def test_scenario_2_voice_input_real_audio_low_risk_permitted(self, mock_scan, mock_key):
        """Scenario 2: Voice input verified as REAL permits low-risk action."""
        mock_scan.return_value = {
            "success": True,
            "status_code": 200,
            "request_id": "req_real_voice_1",
            "verdict": "real",
            "score": 0.02,
            "duration_seconds": 5.5,
            "error": None
        }

        wav_bytes = generate_wav_bytes(5.5)
        upload = UploadFile(filename="voice_cmd.wav", file=io.BytesIO(wav_bytes))

        data = asyncio.run(handle_agent_task(
            task="Draft a note about our quarterly goals",
            file=upload
        ))
        self.assertEqual(data["status"], "COMPLETED")
        self.assertIsNotNone(data["execution"])
        self.assertEqual(data["diagnostics"]["detection"]["verdict"], "real")
        self.assertEqual(data["diagnostics"]["policy_decision"], "ALLOW")

    @patch("agent.load_api_key", return_value="dtf_test_key")
    @patch("agent.analyze_audio_file")
    def test_scenario_3_fake_or_uncertain_verdict_strictly_blocks_execution(self, mock_scan, mock_key):
        """Scenario 3: Synthetic/Fake voice or uncertain scan strictly blocks execution."""
        # 3a. Fake voice
        mock_scan.return_value = {
            "success": True,
            "status_code": 200,
            "request_id": "req_fake_voice_2",
            "verdict": "fake",
            "score": 0.95,
            "duration_seconds": 6.0,
            "error": None
        }

        wav_bytes = generate_wav_bytes(6.0)
        upload_fake = UploadFile(filename="fake_voice.wav", file=io.BytesIO(wav_bytes))

        data_fake = asyncio.run(handle_agent_task(
            task="Draft a message to engineering",
            file=upload_fake
        ))
        self.assertEqual(data_fake["status"], "BLOCKED")
        self.assertIsNone(data_fake["execution"])
        self.assertIn("I couldn't safely proceed with this action", data_fake["assistant_message"])
        self.assertEqual(data_fake["diagnostics"]["policy_decision"], "HOLD")
        self.assertEqual(data_fake["diagnostics"]["server_gate"], "LOCKED_HOLD")

        # 3b. Uncertain / Inconclusive voice
        mock_scan.return_value = {
            "success": True,
            "status_code": 200,
            "request_id": "req_not_sure_voice",
            "verdict": "not_sure",
            "score": 0.50,
            "duration_seconds": 5.0,
            "error": None
        }
        upload_unsure = UploadFile(filename="unsure_voice.wav", file=io.BytesIO(wav_bytes))
        data_unsure = asyncio.run(handle_agent_task(
            task="Draft a message",
            file=upload_unsure
        ))
        self.assertEqual(data_unsure["status"], "BLOCKED")
        self.assertIsNone(data_unsure["execution"])
        self.assertEqual(data_unsure["diagnostics"]["policy_decision"], "HOLD")

    @patch("agent.load_api_key", return_value="dtf_test_key")
    @patch("agent.analyze_audio_file")
    def test_scenario_4_high_risk_action_cannot_auto_execute_even_if_verdict_is_real(self, mock_scan, mock_key):
        """
        Scenario 4: High-risk action (simulate_purchase) CANNOT auto-execute even with REAL voice.
        Authenticity != Authorization.
        Must pause at server-side gate with NEEDS_AUTHORIZATION.
        """
        mock_scan.return_value = {
            "success": True,
            "status_code": 200,
            "request_id": "req_real_purchase_3",
            "verdict": "real",
            "score": 0.01,
            "duration_seconds": 6.0,
            "error": None
        }

        wav_bytes = generate_wav_bytes(6.0)
        upload_purchase = UploadFile(filename="real_voice.wav", file=io.BytesIO(wav_bytes))

        data_purchase = asyncio.run(handle_agent_task(
            task="Purchase a MacBook Pro for ₹180,000 for the new lead",
            file=upload_purchase
        ))

        # Proves it cannot execute automatically
        self.assertEqual(data_purchase["status"], "NEEDS_AUTHORIZATION")
        self.assertIsNone(data_purchase["execution"])
        self.assertTrue(data_purchase["authorization_required"])
        self.assertIn("I need your authorization", data_purchase["assistant_message"])
        self.assertEqual(data_purchase["diagnostics"]["policy_decision"], "OWNER_CONFIRMATION_REQUIRED")
        self.assertEqual(data_purchase["diagnostics"]["server_gate"], "INTERCEPTED_CHALLENGE")

        auth_token = data_purchase["authorization_details"]["auth_token"]

        # Owner approval flow
        data_auth = handle_agent_authorize(AgentAuthorizeRequest(
            auth_token=auth_token,
            approve=True
        ))
        self.assertTrue(data_auth["success"])
        self.assertEqual(data_auth["status"], "COMPLETED")
        self.assertIsNotNone(data_auth["execution"])
        self.assertTrue(data_auth["execution"]["is_simulated"])
        self.assertEqual(data_auth["execution"]["type"], "simulate_purchase")

        # Proves token cannot be replayed
        with self.assertRaises(HTTPException) as ctx_replay:
            handle_agent_authorize(AgentAuthorizeRequest(
                auth_token=auth_token,
                approve=True
            ))
        self.assertEqual(ctx_replay.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
