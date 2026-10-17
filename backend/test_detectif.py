"""
AgentShield - Standalone CLI Test for DetectifAI Deepfake Detection API
Usage:
    .\\.venv\\Scripts\\python.exe .\\backend\\test_detectif.py "path\\to\\audio.wav"
"""

import sys
from pathlib import Path

# Add backend directory to sys.path so sibling imports work from any cwd
_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from detectif_client import analyze_audio_file, load_api_key
from policy import evaluate_action_policy


def main():
    print("=" * 60)
    print("AgentShield - DetectifAI API Connection Test")
    print("=" * 60)

    # 1. Check CLI Argument
    if len(sys.argv) < 2:
        print("\n[ERROR] Missing audio file path.")
        print("Usage:")
        print("  .\\.venv\\Scripts\\python.exe .\\backend\\test_detectif.py \"<path_to_audio_file>\"")
        print("Example:")
        print("  .\\.venv\\Scripts\\python.exe .\\backend\\test_detectif.py \".\\sample.wav\"")
        sys.exit(1)

    audio_path = sys.argv[1]
    print(f"\n[1] Target Audio File: {audio_path}")

    # 2. Check API Key
    key = load_api_key()
    if not key:
        print("\n[ERROR] DETECTIF_API_KEY is not configured or still contains the placeholder.")
        print("Action required:")
        print("  1. Open the '.env' file in the project root directory (D:\\unclone_AgentShield\\.env)")
        print("  2. Replace 'your_actual_key_here' with your real DetectifAI API key:")
        print("     DETECTIF_API_KEY=your_real_key_here")
        print("  3. Save the file and re-run this script.")
        print("\nNote: Never paste your API key in public chat or commit it to Git.")
        sys.exit(1)

    print("[2] API Key: Detected in .env (hidden for security)")

    # 3. Perform Live API Call to DetectifAI
    print("[3] Contacting DetectifAI endpoint (https://platform.detectif.ai/v1/deepfake/detect)...")
    res = analyze_audio_file(audio_path, api_key=key)

    print("\n" + "-" * 60)
    print("DetectifAI Provider Response:")
    print("-" * 60)

    if not res["success"]:
        print(f"Status: FAILED")
        if res["status_code"]:
            print(f"HTTP Status Code: {res['status_code']}")
        print(f"Error Message: {res['error']}")
        print("\nAgentShield Fail-Closed Evaluation:")
        policy_fail = evaluate_action_policy(None, api_error=res['error'], action_type="simulate_purchase")
        print(f"  Decision : {policy_fail['decision']}")
        print(f"  Reason   : {policy_fail['reason']}")
        sys.exit(1)

    # Live Success Output
    print(f"HTTP Status Code : {res['status_code']}")
    print(f"Request ID       : {res['request_id'] or 'N/A'}")
    print(f"Verdict          : {res['verdict']}")
    print(f"Deepfake Score   : {res['score']}")
    print(f"Audio Duration   : {res['duration_seconds']}s")

    print("\n" + "=" * 60)
    print("AgentShield Policy Evaluation (Simulated Agent Actions):")
    print("=" * 60)

    # Action 1: Draft a message (Low sensitivity)
    policy_msg = evaluate_action_policy(
        verdict=res["verdict"],
        score=res["score"],
        action_type="draft_message"
    )
    print(f"\nAction 1: 'Draft a message' (Low Sensitivity)")
    print(f"  Decision : {policy_msg['decision']}")
    print(f"  Rationale: {policy_msg['reason']}")

    # Action 2: Simulate a purchase (High sensitivity)
    policy_purchase = evaluate_action_policy(
        verdict=res["verdict"],
        score=res["score"],
        action_type="simulate_purchase"
    )
    print(f"\nAction 2: 'Simulate a purchase' (High Sensitivity)")
    print(f"  Decision : {policy_purchase['decision']}")
    print(f"  Rationale: {policy_purchase['reason']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
