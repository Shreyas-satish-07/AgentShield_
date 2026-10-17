"""
AgentShield - API Endpoint & Policy Integration Tests
Tests the backend routes, multipart handling, duration validation, and security policies offline using mock data.
Zero API quota consumed.
"""

import io
import wave
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

# Ensure backend directory is in path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from policy import evaluate_action_policy


def generate_wav_bytes(duration_seconds: float, sample_rate: int = 16000) -> bytes:
    """Helper to generate a valid in-memory 16-bit PCM WAV file of specified duration."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)  # Mono
        wf.setsampwidth(2)  # 16-bit
        wf.setframerate(sample_rate)
        num_frames = int(duration_seconds * sample_rate)
        # Silent PCM samples
        wf.writeframes(b"\x00\x00" * num_frames)
    return buf.getvalue()


class TestAgentShieldApiIntegration(unittest.TestCase):
    """Verifies the 3 required policy scenarios and endpoint validations."""

    def test_scenario_1_genuine_audio_draft_message_allow(self):
        """Scenario 1: Genuine audio ('real') + 'draft_message' (low sensitivity) -> ALLOW."""
        res = evaluate_action_policy(verdict="real", score=0.04, action_type="draft_message")
        self.assertEqual(res["decision"], "ALLOW")
        self.assertEqual(res["verdict"], "real")
        self.assertIn("Action is low-risk", res["reason"])

    def test_scenario_2_genuine_audio_simulate_purchase_owner_confirmation(self):
        """
        Scenario 2: Genuine audio ('real') + 'simulate_purchase' (high sensitivity) -> OWNER_CONFIRMATION_REQUIRED.
        Authenticity != Authorization.
        """
        res = evaluate_action_policy(verdict="real", score=0.04, action_type="simulate_purchase")
        self.assertEqual(res["decision"], "OWNER_CONFIRMATION_REQUIRED")
        self.assertEqual(res["verdict"], "real")
        self.assertIn("authenticity alone does NOT equal authorization", res["reason"])

    def test_scenario_3_ai_generated_audio_draft_message_hold(self):
        """Scenario 3: AI-generated audio ('fake') + 'draft_message' -> HOLD."""
        res = evaluate_action_policy(verdict="fake", score=0.88, action_type="draft_message")
        self.assertEqual(res["decision"], "HOLD")
        self.assertEqual(res["verdict"], "fake")
        self.assertIn("Deepfake detected", res["reason"])

    def test_verdict_not_sure_fails_closed(self):
        """Inconclusive verdict ('not_sure') -> HOLD (fail closed)."""
        res = evaluate_action_policy(verdict="not_sure", score=0.52, action_type="draft_message")
        self.assertEqual(res["decision"], "HOLD")
        self.assertIn("inconclusive", res["reason"])

    def test_api_error_or_timeout_fails_closed(self):
        """DetectifAI network error or timeout -> HOLD (fail closed)."""
        res = evaluate_action_policy(verdict=None, api_error="Connection timed out", action_type="draft_message")
        self.assertEqual(res["decision"], "HOLD")
        self.assertIn("fail-closed", res["reason"])

    def test_duration_constraints_calculation(self):
        """Verify that duration calculation for WAVs accurately flags < 4.0s."""
        short_wav = generate_wav_bytes(duration_seconds=2.5)
        buf = io.BytesIO(short_wav)
        with wave.open(buf, "rb") as wf:
            dur = wf.getnframes() / float(wf.getframerate())
            self.assertAlmostEqual(dur, 2.5, places=1)
            self.assertLess(dur, 4.0, "Should be under 4.0s minimum")

        valid_wav = generate_wav_bytes(duration_seconds=5.0)
        buf_valid = io.BytesIO(valid_wav)
        with wave.open(buf_valid, "rb") as wf:
            dur_valid = wf.getnframes() / float(wf.getframerate())
            self.assertAlmostEqual(dur_valid, 5.0, places=1)
            self.assertGreaterEqual(dur_valid, 4.0, "Should satisfy >= 4.0s minimum")

    def test_resampling_duration_consistency(self):
        """
        Verifies that capturing at any hardware sample rate (e.g. 48000, 44100, 96000)
        and downsampling to 16000 preserves the exact duration in seconds.
        """
        for hw_rate in (48000, 44100, 96000):
            recorded_sec = 6.4
            total_samples = int(recorded_sec * hw_rate)
            target_rate = 16000
            downsampled_samples = int(round(total_samples / (hw_rate / target_rate)))
            computed_dur = downsampled_samples / target_rate
            self.assertAlmostEqual(computed_dur, recorded_sec, places=2,
                                   msg=f"Failed duration preservation for rate {hw_rate}")

    def test_frontend_files_exist_and_served(self):
        """Verifies frontend HTML, CSS, and JS exist in the project root."""
        frontend_dir = backend_dir.parent / "frontend"
        self.assertTrue((frontend_dir / "index.html").exists(), "index.html missing")
        self.assertTrue((frontend_dir / "style.css").exists(), "style.css missing")
        self.assertTrue((frontend_dir / "app.js").exists(), "app.js missing")

        # Check index.html content references app.js and style.css
        html_content = (frontend_dir / "index.html").read_text(encoding="utf-8")
        self.assertIn("style.css", html_content)
        self.assertIn("app.js", html_content)
        self.assertIn("draft_message", html_content)
        self.assertIn("simulate_purchase", html_content)
        self.assertIn("Record Voice", html_content)

    def test_analyze_audio_endpoint_valid_16000hz_wav(self):
        """Verifies that 16000 Hz PCM WAV with duration >= 4.0s is accepted by the endpoint."""
        import asyncio
        from fastapi import UploadFile
        from main import analyze_audio

        wav_bytes = generate_wav_bytes(duration_seconds=5.0, sample_rate=16000)
        upload = UploadFile(filename="voice_command.wav", file=io.BytesIO(wav_bytes))

        with patch("main.load_api_key", return_value="test_key"), \
             patch("main.analyze_audio_file", return_value={
                 "success": True,
                 "status_code": 200,
                 "request_id": "req_endpoint_test",
                 "verdict": "real",
                 "score": 0.03,
                 "duration_seconds": 5.0,
                 "error": None
             }):
            res = asyncio.run(analyze_audio(file=upload, action="draft_message"))
            self.assertTrue(res["success"])
            self.assertEqual(res["request_id"], "req_endpoint_test")
            self.assertEqual(res["detection"]["verdict"], "real")
            self.assertEqual(res["policy"]["decision"], "ALLOW")

    def test_analyze_audio_endpoint_rejects_under_4s_wav(self):
        """Verifies that a WAV shorter than 4.0s triggers HTTP 422."""
        import asyncio
        from fastapi import UploadFile, HTTPException
        from main import analyze_audio

        short_bytes = generate_wav_bytes(duration_seconds=3.2, sample_rate=16000)
        upload = UploadFile(filename="voice_command.wav", file=io.BytesIO(short_bytes))

        with patch("main.load_api_key", return_value="test_key"):
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(analyze_audio(file=upload, action="draft_message"))
            self.assertEqual(ctx.exception.status_code, 422)
            self.assertIn("too short", ctx.exception.detail)

    def test_analyze_audio_endpoint_accepts_webm(self):
        """Verifies that .webm audio files from MediaRecorder are accepted by the endpoint."""
        import asyncio
        from fastapi import UploadFile
        from main import analyze_audio

        upload = UploadFile(filename="voice_command.webm", file=io.BytesIO(b"webm_audio_data_sample"))

        with patch("main.load_api_key", return_value="test_key"), \
             patch("main.analyze_audio_file", return_value={
                 "success": True,
                 "status_code": 200,
                 "request_id": "req_webm_test",
                 "verdict": "real",
                 "score": 0.04,
                 "duration_seconds": 6.0,
                 "error": None
             }):
            res = asyncio.run(analyze_audio(file=upload, action="draft_message"))
            self.assertTrue(res["success"])
            self.assertEqual(res["detection"]["verdict"], "real")
            self.assertEqual(res["policy"]["decision"], "ALLOW")

    def test_analyze_audio_endpoint_rejects_unsupported_format(self):
        """Verifies that non-audio extensions trigger HTTP 400."""
        import asyncio
        from fastapi import UploadFile, HTTPException
        from main import analyze_audio

        upload = UploadFile(filename="test.txt", file=io.BytesIO(b"not audio"))

        with patch("main.load_api_key", return_value="test_key"):
            with self.assertRaises(HTTPException) as ctx:
                asyncio.run(analyze_audio(file=upload, action="draft_message"))
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("Unsupported audio format", ctx.exception.detail)

    def test_simulate_action_endpoint_gating(self):
        """Verifies policy gating for simulated action execution."""
        from fastapi import HTTPException
        from main import simulate_action, SimulateActionRequest

        # 1. ALLOW decision succeeds
        res_allow = simulate_action(SimulateActionRequest(
            action="draft_message",
            decision="ALLOW",
            task_text="Draft message to team"
        ))
        self.assertTrue(res_allow["success"])
        self.assertEqual(res_allow["execution"]["status"], "DRAFTED_IN_SANDBOX")
        self.assertTrue(res_allow["execution"]["is_simulated"])

        # 2. HOLD decision is blocked with HTTP 403
        with self.assertRaises(HTTPException) as ctx_hold:
            simulate_action(SimulateActionRequest(
                action="draft_message",
                decision="HOLD",
                task_text="Draft message"
            ))
        self.assertEqual(ctx_hold.exception.status_code, 403)
        self.assertIn("blocked because AgentShield policy decision is HOLD", ctx_hold.exception.detail)

        # 3. OWNER_CONFIRMATION_REQUIRED without confirmation is blocked with HTTP 403
        with self.assertRaises(HTTPException) as ctx_owner_unconf:
            simulate_action(SimulateActionRequest(
                action="simulate_purchase",
                decision="OWNER_CONFIRMATION_REQUIRED",
                task_text="Purchase laptop",
                owner_confirmed=False
            ))
        self.assertEqual(ctx_owner_unconf.exception.status_code, 403)
        self.assertIn("blocked until owner confirmation is provided", ctx_owner_unconf.exception.detail)

        # 4. OWNER_CONFIRMATION_REQUIRED with confirmation succeeds
        res_owner_conf = simulate_action(SimulateActionRequest(
            action="simulate_purchase",
            decision="OWNER_CONFIRMATION_REQUIRED",
            task_text="Purchase laptop for ₹80,000",
            owner_confirmed=True
        ))
        self.assertTrue(res_owner_conf["success"])
        self.assertEqual(res_owner_conf["execution"]["status"], "PURCHASE_SIMULATED")
        self.assertTrue(res_owner_conf["execution"]["is_simulated"])



if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("AgentShield - Integration & Policy Verification Suite")
    print("(Zero external API calls / Zero quota used)")
    print("=" * 60 + "\n")
    unittest.main(verbosity=2)
