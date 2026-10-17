"""
AgentShield Security Policy Module
Evaluates real-time audio authenticity results and determines simulated agent action authorization.
"""

from typing import Dict, Any, Optional

# Canonical action dictionary and pre-defined sensitivity levels
ACTION_SENSITIVITY = {
    "answer_question": "SAFE",
    "summarize_text": "SAFE",
    "draft_message": "LOW",
    "query_status": "LOW",
    "send_email": "MEDIUM",
    "simulate_purchase": "HIGH",
    "transfer_funds": "HIGH",
    "unknown_action": "HIGH",
    "prohibited_action": "PROHIBITED",
}

CANONICAL_ACTIONS = {
    "answer_question": "answer_question",
    "answer": "answer_question",
    "question": "answer_question",
    "ask": "answer_question",
    "summarize_text": "summarize_text",
    "summarize": "summarize_text",
    "summary": "summarize_text",
    "draft_message": "draft_message",
    "draft": "draft_message",
    "message": "draft_message",
    "write_message": "draft_message",
    "query_status": "query_status",
    "status": "query_status",
    "telemetry": "query_status",
    "send_email": "send_email",
    "email": "send_email",
    "simulate_purchase": "simulate_purchase",
    "purchase": "simulate_purchase",
    "buy": "simulate_purchase",
    "transfer_funds": "transfer_funds",
    "transfer": "transfer_funds",
    "prohibited_action": "prohibited_action",
    "unsafe": "prohibited_action",
    "prohibited": "prohibited_action",
    "unknown_action": "unknown_action",
    "unknown": "unknown_action",
}


def evaluate_action_policy(
    verdict: Optional[str],
    score: Optional[float] = None,
    action_type: str = "draft_message",
    api_error: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates whether an agent action can proceed based on audio authenticity
    and action sensitivity.

    AgentShield Policy Rules:
    1. If API failed, timed out, or verdict is missing -> FAIL CLOSED: HOLD action.
    2. If verdict is 'fake' -> HOLD action and flag suspicious synthetic voice.
    3. If verdict is 'not_sure' -> HOLD action; voice cannot be verified.
    4. If verdict is 'real':
       - Real voice is an authenticity signal, NOT proof of speaker identity or authorization.
       - Safe & Low-sensitivity actions (e.g. 'draft_message', 'answer_question', 'summarize_text', 'query_status') -> ALLOW.
       - High/Medium-sensitivity actions (e.g. 'simulate_purchase', 'transfer_funds', 'send_email') -> OWNER_CONFIRMATION_REQUIRED.
       - Unknown actions fail closed -> HOLD.
    """
    normalized_action = (action_type or "draft_message").strip().lower()
    canonical_action = CANONICAL_ACTIONS.get(normalized_action, normalized_action)
    sensitivity = ACTION_SENSITIVITY.get(canonical_action)

    # Rule 0: Prohibited or Unsafe actions are strictly blocked regardless of voice authenticity
    if sensitivity == "PROHIBITED" or canonical_action == "prohibited_action":
        return {
            "action": canonical_action,
            "decision": "HOLD",
            "verdict": verdict or "blocked",
            "score": score,
            "reason": "Unsafe or prohibited action detected. Operation is strictly blocked by AgentShield policy regardless of voice authenticity."
        }

    # Rule 1: Fail closed on API errors or missing verdicts
    if api_error or not verdict:
        return {
            "action": canonical_action,
            "decision": "HOLD",
            "verdict": verdict or "unknown",
            "score": score,
            "reason": f"Security fail-closed triggered: {api_error or 'Detection result missing or invalid.'} Sensitive actions are held."
        }

    normalized_verdict = verdict.strip().lower()

    # Rule 2: Detected Deepfake / Synthetic speech
    if normalized_verdict == "fake":
        return {
            "action": canonical_action,
            "decision": "HOLD",
            "verdict": "fake",
            "score": score,
            "reason": (
                "Deepfake detected: Voice was identified as synthetic / AI-generated. "
                "Action held immediately. Owner identity verification required."
            )
        }

    # Rule 3: Uncertain or inconclusive detection
    if normalized_verdict == "not_sure":
        return {
            "action": canonical_action,
            "decision": "HOLD",
            "verdict": "not_sure",
            "score": score,
            "reason": (
                "Audio authenticity is inconclusive ('not_sure'). "
                "AgentShield fails closed: action is held until clear verification is provided."
            )
        }

    # Rule 4: Genuine / Real voice
    if normalized_verdict == "real":
        # Fail closed on unknown action
        if sensitivity is None or canonical_action == "unknown_action":
            return {
                "action": canonical_action,
                "decision": "HOLD",
                "verdict": "real",
                "score": score,
                "reason": f"Unknown action '{action_type}' (ambiguous or unregistered). Failing closed under security policy."
            }

        # Safe and Low sensitivity actions are permitted with verified authentic voice
        if sensitivity in ("SAFE", "LOW"):
            return {
                "action": canonical_action,
                "decision": "ALLOW",
                "verdict": "real",
                "score": score,
                "reason": (
                    f"Audio verified as genuine. Action is low-risk ('ALLOW') or safe. "
                    f"Action '{canonical_action}' permitted."
                )
            }
        else:
            return {
                "action": canonical_action,
                "decision": "OWNER_CONFIRMATION_REQUIRED",
                "verdict": "real",
                "score": score,
                "reason": (
                    "Audio verified as genuine. However, authenticity alone does NOT equal authorization. "
                    f"'{canonical_action}' is a high-sensitivity action requiring explicit owner confirmation."
                )
            }

    # Fallback for unrecognized verdict
    return {
        "action": action_type,
        "decision": "HOLD",
        "verdict": normalized_verdict,
        "score": score,
        "reason": f"Unrecognized provider verdict '{normalized_verdict}'. Failing closed."
    }
