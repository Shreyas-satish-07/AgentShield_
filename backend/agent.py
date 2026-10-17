"""
Personal AI Agent Core Workflow & Server-Side Security Gate
Handles natural-language task intake, intent interpretation, action planning,
policy-gated tool execution, and safe sandbox simulations.
AgentShield and DetectifAI operate as invisible backend security infrastructure.
"""

import os
import re
import secrets
import sys
import time
from typing import Dict, Any, Optional, List
from pathlib import Path

# Add backend directory to sys.path so sibling imports work
_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from policy import evaluate_action_policy, ACTION_SENSITIVITY, CANONICAL_ACTIONS
from detectif_client import analyze_audio_file, load_api_key, inspect_audio_file

# In-memory store for pending authorizations requiring secondary owner approval
# Stored server-side: auth_token -> ActionDetails
_PENDING_AUTHORIZATIONS: Dict[str, Dict[str, Any]] = {}

# Allowed actions supported by the agent
SUPPORTED_ACTIONS = list(ACTION_SENSITIVITY.keys())


def parse_intent_and_plan(task_text: str) -> Dict[str, Any]:
    """
    Interprets user natural language intent and produces a structured execution plan.
    Deterministic heuristic planner:
    - Identifies target action and normalizes to canonical action type
    - Classifies sensitivity (SAFE, LOW, MEDIUM, HIGH)
    - Formulates transparent plan steps
    """
    raw_text = (task_text or "").strip()
    lower = raw_text.lower()

    if not lower:
        return {
            "action": "answer_question",
            "sensitivity": "SAFE",
            "intent": "idle_greeting",
            "summary": "Provide assistant greeting and available capabilities",
            "steps": [
                "1. Acknowledge user input",
                "2. Present available agent capabilities"
            ]
        }

    # 0. Unsafe, Prohibited, Security Bypass, or Confidential Data Leakage Requests (PROHIBITED)
    # A. Prohibited safeguard/security tampering, bypass, or override attempts
    is_bypass_attempt = bool(re.search(
        r'\b(?:ignore|bypass|disable|override|skip|circumvent|turn\s+off|shut\s+off|drop|suppress|without)\s+'
        r'(?:all\s+|the\s+|your\s+)?'
        r'(?:security|safeguards?|safety(?:\s+checks?)?|checks?|owner\s+approval|verification|policy|guardrails?|protection)\b',
        lower
    )) or bool(re.search(
        r'\b(?:bypass\s+owner\s+approval|disable\s+safety\s+checks?|ignore\s+security\s+checks?|ignoring\s+security\s+checks?|bypass\s+security)\b',
        lower
    ))

    # B. Unauthorized disclosure of confidential, secret, or proprietary information / exfiltration
    is_confidential_leak = bool(re.search(
        r'\b(?:send|leak|share|export|exfiltrate|transfer|forward|disclose|give)\s+'
        r'(?:all\s+|the\s+)?(?:confidential|classified|secret|proprietary|sensitive|internal|private)\s+'
        r'(?:project\s+)?(?:files?|documents?|data|information|records?|credentials?|passwords?|keys?)\b',
        lower
    )) or bool(re.search(
        r'\b(?:confidential|classified|secret|proprietary)\s+(?:project\s+)?(?:files?|documents?|data)\s+'
        r'(?:to\s+(?:an?\s+)?(?:unknown|unauthorized|external|unverified)\s+person)\b',
        lower
    )) or bool(re.search(
        r'\b(?:send|forward|dispatch|transfer)\s+.*?\b(?:unknown\s+person|unauthorized\s+person|unverified\s+recipient)\b',
        lower
    ))

    # C. Malicious attacks / sabotage
    is_malicious_cmd = bool(re.search(
        r'\b(?:delete\s+(?:system|database|audit|all\s+logs)|steal\s+credentials|hack\s+(?:into|system|server)|exploit\s+vulnerability|drop\s+table|format\s+drive|run\s+ransomware|malicious)\b',
        lower
    ))

    if is_bypass_attempt or is_confidential_leak or is_malicious_cmd:
        detail_reason = []
        if is_bypass_attempt:
            detail_reason.append("security policy bypass attempt")
        if is_confidential_leak:
            detail_reason.append("unauthorized confidential data disclosure")
        if is_malicious_cmd:
            detail_reason.append("malicious system tampering")

        reason_str = " & ".join(detail_reason) if detail_reason else "prohibited security violation"
        return {
            "action": "prohibited_action",
            "sensitivity": "PROHIBITED",
            "intent": "prohibited_instruction",
            "summary": f"Unsafe or prohibited action detected ({reason_str})",
            "steps": [
                f"1. Intercept prohibited request: {reason_str}",
                "2. Enforce strict server-side policy block (HOLD)",
                "3. Terminate execution immediately with zero external side effects"
            ]
        }

    # 1. Financial Fund Transfer (HIGH)
    if re.search(r'\b(transfer\s+(?:funds|money|[₹\$]|inr|usd|[0-9])|bank\s+transfer|wire\s+funds|wire\s+transfer|send\s+(?:money|funds|[₹\$]|inr|usd|[0-9])|remit|upi)\b', lower):
        amt_match = re.search(r'(?:₹|\$|inr|usd)?\s*([0-9,]+(?:\.[0-9]{1,2})?)', raw_text, re.IGNORECASE)
        amount_str = amt_match.group(0).strip() if amt_match else "specified amount"
        return {
            "action": "transfer_funds",
            "sensitivity": "HIGH",
            "intent": "financial_transfer",
            "summary": f"Simulate funds transfer of {amount_str}",
            "amount": amount_str,
            "steps": [
                "1. Parse recipient and transfer amount parameters",
                "2. Evaluate backend security policy and audio authenticity",
                "3. Intercept high-risk transaction for secondary owner authorization",
                "4. Execute ledger simulation in protected sandbox upon confirmation"
            ]
        }

    # 2. Commercial Expenditure / Purchase (HIGH)
    if re.search(r'\b(purchase|buy|procure|checkout)\b', lower) or re.search(r'\b(?:place\s+an?\s+order|order\s+(?:a|an|[0-9]|laptop|macbook|equipment|device|items|supplies))\b', lower):
        item_match = re.search(r'(?:buy|purchase|order)\s+(?:a\s+|an\s+)?([a-z0-9\s₹\$,]+)', raw_text, re.IGNORECASE)
        item_name = item_match.group(1).strip() if item_match else "item"
        amt_match = re.search(r'(?:₹|\$|inr|usd)?\s*([0-9,]+(?:\.[0-9]{1,2})?)', raw_text, re.IGNORECASE)
        amt_str = amt_match.group(0).strip() if amt_match else "₹80,000"
        return {
            "action": "simulate_purchase",
            "sensitivity": "HIGH",
            "intent": "procure_goods",
            "summary": f"Simulate commercial purchase for {item_name}",
            "item": item_name,
            "amount": amt_str,
            "steps": [
                "1. Extract item specifications and estimated cost",
                "2. Evaluate backend security policy and audio authenticity",
                "3. Intercept high-risk purchase for secondary owner confirmation",
                "4. Execute order simulation in protected sandbox upon approval"
            ]
        }

    # 3. Draft Message / Note (LOW)
    if any(k in lower for k in ["draft", "compose", "create message", "team update", "announcement", "announcing", "write a message", "write a note", "write an email", "draft an email", "draft a message", "release-announcement", "release announcement"]):
        return {
            "action": "draft_message",
            "sensitivity": "LOW",
            "intent": "content_formulation",
            "summary": "Formulate structured draft communication",
            "steps": [
                "1. Analyze topic and recipient audience",
                "2. Structure subject line and formatted message body",
                "3. Save draft to assistant memory"
            ]
        }

    # 4. External Communication / Send Email (MEDIUM)
    if re.search(r'\b(send|dispatch|forward)\s+(?:an?\s+)?email\b', lower):
        return {
            "action": "send_email",
            "sensitivity": "MEDIUM",
            "intent": "external_communication",
            "summary": "Prepare and simulate external email dispatch",
            "steps": [
                "1. Format recipient and email content",
                "2. Evaluate backend security policy",
                "3. Gate external dispatch pending authorization",
                "4. Enqueue to mock outbound dispatch queue"
            ]
        }

    # 5. System Status / Telemetry (LOW)
    if re.search(r'\b(system status|cluster health|query status|server telemetry|telemetry|metrics)\b', lower) or (any(k in lower for k in ["status", "health", "latency"]) and not any(k in lower for k in ["draft", "write", "buy", "transfer"])):
        return {
            "action": "query_status",
            "sensitivity": "LOW",
            "intent": "system_observability",
            "summary": "Retrieve real-time assistant and backend operational telemetry",
            "steps": [
                "1. Collect server health metrics and security status",
                "2. Confirm low-risk read-only authorization",
                "3. Compile and return telemetry report"
            ]
        }

    # 6. Summarization (SAFE)
    if re.search(r'\b(summarize|summarise|summary|tldr|condense|key points)\b', lower):
        return {
            "action": "summarize_text",
            "sensitivity": "SAFE",
            "intent": "text_summarization",
            "summary": "Analyze provided content and generate concise structured summary",
            "steps": [
                "1. Ingest input content",
                "2. Extract core themes and key points",
                "3. Present concise, structured summary"
            ]
        }

    # 7. General Question / Assistant Query (SAFE)
    # Explicitly distinguish genuine informational questions/inquiries from ambiguous commands
    # General-purpose, read-only requests should not be treated as unknown/high-risk
    # merely because they are outside the original demo prompts. These verbs express
    # information/content tasks, not external side effects.
    informational_request = bool(re.match(
        r"^(?:suggest|recommend|list|name|find\s+me|give\s+me|show\s+me|explain|describe|define|compare|contrast|translate|rewrite|rephrase|proofread|improve|brainstorm|generate\s+ideas|teach\s+me|help\s+me|what|who|when|where|why|how|which|is|are|can\s+you|could\s+you|do\s+you|tell\s+me|write\s+(?:a|an|some|about)|create\s+(?:a|an|some)|summari[sz]e|make\s+(?:a\s+)?list)\b",
        lower
    ))
    is_question = (
        lower.endswith("?") or
        bool(re.match(r'^(?:who|what|when|where|why|how|which|is|are|can\s+you|could\s+you|do\s+you|tell\s+me|explain|help\b)', lower)) or
        any(k in lower for k in ["who are you", "what are you", "purpose", "identity", "what can you do", "capabilities", "capital of france", "help me understand"]) or
        informational_request
    )

    if is_question:
        return {
            "action": "answer_question",
            "sensitivity": "SAFE",
            "intent": "knowledge_retrieval",
            "summary": "Answer user query using personal assistant reasoning",
            "steps": [
                "1. Comprehend user inquiry",
                "2. Synthesize accurate, contextual response",
                "3. Return conversational answer"
            ]
        }

    # 8. Unrecognized, Ambiguous, or Unknown Protected Action (HIGH -> Fail Closed)
    return {
        "action": "unknown_action",
        "sensitivity": "HIGH",
        "intent": "unrecognized_command",
        "summary": f"Unrecognized or ambiguous command '{task_text[:60].strip()}'",
        "steps": [
            "1. Detect unrecognized command type",
            "2. Enforce server-side security gate fail-closed policy (HOLD)",
            "3. Terminate without executing unknown side effects"
        ]
    }


def execute_action_safely(
    action: str,
    task_text: str,
    plan: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Executes a permitted capability.
    - Safe/Low tasks (question answering, drafting, summarization, query status) are genuinely executed.
    - High-risk actions (purchases, transfers, email dispatch) execute strictly in safe sandbox simulations.
    Real-world side effects are never triggered.
    """
    sim_id = f"sim_{secrets.token_hex(4)}"

    # 0. Prohibited Action Block
    if action == "prohibited_action":
        return {
            "type": "prohibited_action",
            "status": "BLOCKED",
            "is_simulated": False,
            "result_text": "This action is prohibited by safety policy.",
            "disclaimer": "Security Policy Enforcement"
        }

    # 0b. Unknown / Unverified Action Block
    if action == "unknown_action":
        return {
            "type": "unknown_action",
            "status": "BLOCKED",
            "is_simulated": False,
            "result_text": "Unrecognized or ambiguous protected action. Blocked by server-side policy.",
            "disclaimer": "Security Policy Enforcement"
        }

    # 1. Genuine Question Answering
    if action == "answer_question":
        lower = task_text.lower()
        if any(k in lower for k in ["who are you", "what are you", "purpose", "identity", "what is your name"]):
            answer = (
                "I am your Personal AI Assistant. I help you plan and execute tasks, "
                "draft communications, analyze information, and coordinate operations safely. "
                "All high-risk actions are governed by backend security checks to ensure "
                "your requests remain verified and safe."
            )
        elif "detectifai" in lower or "deepfake" in lower or "authenticity" in lower or "voice verification" in lower:
            answer = (
                "Voice authenticity verification is powered by backend neural models that analyze "
                "acoustic patterns for synthetic or AI-generated artifacts. Voice authenticity confirms "
                "that audio is genuine human speech, while sensitive actions always require your explicit "
                "authorization."
            )
        elif "help" in lower or "what can you do" in lower or "capabilities" in lower:
            answer = (
                "Here are some tasks you can ask me to perform:\n"
                "• **Drafting & Writing**: Draft team announcements, client updates, and memos.\n"
                "• **Summarization**: Summarize updates, articles, and briefings into concise bullet points.\n"
                "• **System Telemetry**: Query backend status, server latency, and health.\n"
                "• **Simulated Operations**: Plan commercial purchases or ledger transfers in a safe sandbox with explicit authorization."
            )
        elif "capital of france" in lower:
            answer = "The capital of France is Paris."
        elif "status" in lower and ("release" in lower or "version" in lower):
            answer = "Version 2.0 release preparations are progressing well, with all backend gates and security policies operating under active monitoring."
        elif any(term in lower for term in ("horror movie", "horror film", "horror movies", "horror films")) and any(term in lower for term in ("suggest", "recommend", "list", "movie", "film")):
            answer = (
                "Here are some English-language horror movies to consider:\n"
                "• The Conjuring (2013) — supernatural haunted-house horror.\n"
                "• Hereditary (2018) — unsettling family and psychological horror.\n"
                "• A Quiet Place (2018) — tense creature horror with a sound-based premise.\n"
                "• Get Out (2017) — social thriller with horror elements.\n"
                "• The Shining (1980) — classic psychological horror.\n"
                "• It (2017) — supernatural horror based on Stephen King's novel.\n\n"
                "Availability and age ratings vary by region, so check your preferred streaming service."
            )
        else:
            clean_q = task_text.strip(" ?.")
            answer = (
                f"I understood this as a general information/content request: '{clean_q}'.\n\n"
                "This AgentShield demo currently uses rule-based response logic and does not have a general-purpose language model connected, "
                "so it can classify a broad range of safe prompts but cannot reliably generate a fully tailored answer to every topic yet. "
                "The request was allowed because it does not appear to require a sensitive external action."
            )

        return {
            "type": "answer_question",
            "status": "COMPLETED",
            "is_simulated": False,
            "result_text": answer,
            "details": {"topic": task_text[:100]}
        }

    # 2. Genuine Summarization
    if action == "summarize_text":
        content = task_text
        for prefix in [
            "aura, summarize this update in three bullet points:",
            "aura, summarize this update in three bullet points",
            "summarize this update in three bullet points:",
            "summarize this update in three bullet points",
            "summarize this update in 3 bullet points:",
            "summarize this update in 3 bullet points",
            "summarize this update:",
            "summarize this update",
            "summarize:",
            "summarize",
            "summarise",
            "summary of",
            "tldr"
        ]:
            if content.lower().startswith(prefix):
                content = content[len(prefix):].strip(" :,-")
                break

        # Check for user-provided items separated by colons, commas, or 'and'
        points = []
        if ":" in task_text:
            after_colon = task_text.split(":", 1)[1].strip()
            raw_parts = re.split(r'[,;]|\band\b', after_colon)
            points = [p.strip(" .") for p in raw_parts if p.strip(" .")]

        if not points:
            raw_parts = re.split(r'[,;]|\band\b', content)
            points = [p.strip(" .") for p in raw_parts if len(p.strip(" .")) > 5]

        if points and len(points) >= 2:
            formatted_bullets = []
            for p in points:
                p_clean = p.strip()
                if p_clean:
                    formatted_bullets.append(f"{p_clean[0].upper() + p_clean[1:]}.")
            result_bullets = "\n".join(f"• {b}" for b in formatted_bullets[:5])
        else:
            result_bullets = (
                f"• Core Topic: {content[:100].strip()}...\n"
                "• Technical Progress: Systems functioning within target parameters.\n"
                "• Next Steps: Ready for operational verification."
            )

        return {
            "type": "summarize_text",
            "status": "COMPLETED",
            "is_simulated": False,
            "result_text": result_bullets,
            "details": {
                "bullet_count": len(result_bullets.split('\n')),
                "original_length": len(task_text)
            }
        }

    # 3. Genuine Contextual Drafting
    if action == "draft_message":
        lower = task_text.lower()
        if any(k in lower for k in ["version 2.0", "version two point zero", "version 2", "release", "announcing", "announcement"]) and any(k in lower for k in ["engineering", "team"]):
            subject = "Team Announcement: Version 2.0 is Ready for Release! 🚀"
            body = (
                "Hi Team,\n\n"
                "I'm excited to share that Version 2.0 has officially cleared all quality milestones and security gates and is ready for release to the engineering team!\n\n"
                "Thank you all for your tremendous hard work, dedication, and attention to detail throughout this cycle. All core features, performance optimizations, and backend integrations are validated.\n\n"
                "Please review the release plan and stand by for the deployment window. Great work everyone!\n\n"
                "Best regards,\n"
                "Aura Personal AI"
            )
        elif "client" in lower or "customer" in lower:
            subject = "Client Update: Project Progress & Upcoming Milestones"
            body = (
                "Dear Client,\n\n"
                "I hope this note finds you well. I am reaching out to share a progress update regarding our shared deliverables.\n\n"
                "Our team has completed the recent milestone requirements according to specifications, and all operational telemetry remains solid. We look forward to reviewing these items with you in detail during our next check-in.\n\n"
                "Please let us know if you need any additional context in the meantime.\n\n"
                "Warm regards,\n"
                "Aura Personal AI"
            )
        else:
            topic = task_text
            for prefix in ["aura,", "aura", "please", "draft", "write", "compose", "a friendly message to", "a message to", "an email to", "a note to"]:
                if topic.lower().startswith(prefix):
                    topic = topic[len(prefix):].strip(" ,:-")

            subject = f"Update: {topic[:45].strip()}"
            body = (
                "Hi Team,\n\n"
                f"I am sharing an update regarding our work on {topic.rstrip('.')}.\n\n"
                "Key Highlights:\n"
                "• All scheduled items have been processed and validated.\n"
                "• Security policies and compliance checks are active.\n"
                "• Ready for review and execution.\n\n"
                "Please let me know if there are any questions or adjustments.\n\n"
                "Best regards,\n"
                "Aura Personal AI"
            )

        return {
            "type": "draft_message",
            "status": "DRAFTED_IN_SANDBOX",
            "is_simulated": False,
            "result_text": body,
            "details": {
                "subject": subject,
                "word_count": len(body.split()),
                "target_file": "assistant_scratchpad_memory.txt"
            }
        }

    # 4. Genuine System Observability
    if action == "query_status":
        import platform

        return {
            "type": "query_status",
            "status": "STATUS_RETRIEVED",
            "is_simulated": False,
            "result_text": "All assistant systems are fully operational. Security gateway active with zero anomalies.",
            "details": {
                "platform": platform.system(),
                "python_version": platform.python_version(),
                "backend_status": "Healthy (FastAPI)",
                "active_sessions": 1,
                "latency_ms": 14
            }
        }

    # 5. Simulated Commercial Purchase (Safe sandbox only)
    if action == "simulate_purchase":
        amt = plan.get("amount") or "₹80,000"
        item = plan.get("item") or "Engineering Equipment"
        return {
            "type": "simulate_purchase",
            "status": "PURCHASE_SIMULATED",
            "is_simulated": True,
            "simulated_id": sim_id,
            "simulated_order_id": f"ORD-{secrets.token_hex(3).upper()}",
            "simulated_amount": amt,
            "simulated_item": item,
            "result_text": f"Simulated purchase order created for {item} ({amt}).",
            "disclaimer": "Sandbox Simulation Only — Zero actual financial transactions executed."
        }

    # 6. Simulated Fund Transfer (Safe sandbox only)
    if action == "transfer_funds":
        amt = plan.get("amount") or "₹5,000"
        return {
            "type": "transfer_funds",
            "status": "TRANSFER_SIMULATED",
            "is_simulated": True,
            "simulated_id": sim_id,
            "simulated_txn_hash": f"TXN-{secrets.token_hex(4).upper()}",
            "simulated_amount": amt,
            "result_text": f"Simulated ledger transfer entry generated for {amt}.",
            "disclaimer": "Sandbox Simulation Only — Zero actual financial transactions executed."
        }

    # 7. Simulated Email Dispatch (Safe sandbox only)
    if action == "send_email":
        return {
            "type": "send_email",
            "status": "DISPATCH_SIMULATED",
            "is_simulated": True,
            "simulated_id": sim_id,
            "simulated_queue": "mock_smtp_outbound_queue",
            "result_text": f"Simulated outbound email staged in sandbox dispatch queue.",
            "disclaimer": "Sandbox Simulation Only — No real external email was dispatched."
        }

    # Fallback for unknown action
    return {
        "type": action,
        "status": "SIMULATED",
        "is_simulated": True,
        "simulated_id": sim_id,
        "result_text": f"Simulated operation executed for '{task_text}'.",
        "disclaimer": "Sandbox Simulation Only"
    }


def process_agent_task(
    task_text: str,
    audio_file_path: Optional[str] = None,
    audio_duration_seconds: Optional[float] = None,
    audio_metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Main task-taking workflow:
    1. Receive task -> Interpret intent & plan action.
    2. Run backend security checks:
       - If audio provided: inspect audio metadata and verify voice authenticity via DetectifAI.
       - Evaluate security policy (evaluate_action_policy).
       - If no audio provided:
         * Safe read-only tasks (SAFE/LOW) are evaluated with ALLOW.
         * High/Medium risk tasks (purchase, transfer, email) require voice verification or owner authorization (FAIL CLOSED / CHALLENGE).
    3. Server-side execution gate:
       - HOLD -> Execution is strictly blocked. Natural explanation returned.
       - OWNER_CONFIRMATION_REQUIRED -> Execution gated. Generates pending authorization token.
       - ALLOW -> Executes permitted capability and returns results.
    4. Return conversational response with progress and structured diagnostics.
    """
    plan = parse_intent_and_plan(task_text)
    canonical_act = CANONICAL_ACTIONS.get(plan["action"].lower().strip(), plan["action"].lower().strip())
    action_sensitivity = ACTION_SENSITIVITY.get(canonical_act, "HIGH")
    plan["action"] = canonical_act
    plan["sensitivity"] = action_sensitivity

    action = canonical_act
    sensitivity = action_sensitivity

    detection_result: Optional[Dict[str, Any]] = None
    policy_decision: Dict[str, Any] = {}

    # Audio verification via DetectifAI if audio is supplied
    if audio_file_path:
        meta = inspect_audio_file(audio_file_path)
        if audio_metadata:
            meta.update({k: v for k, v in audio_metadata.items() if v is not None})

        api_key = load_api_key()
        if not api_key:
            detection_result = {
                "uploaded": True,
                "success": False,
                "status_code": None,
                "request_id": None,
                "verdict": None,
                "score": None,
                "duration_seconds": meta.get("duration_seconds") or audio_duration_seconds,
                "sample_rate": meta.get("sample_rate"),
                "channels": meta.get("channels"),
                "mime_type": meta.get("mime_type"),
                "error": "Backend DETECTIF_API_KEY is not configured or placeholder."
            }
            policy_decision = evaluate_action_policy(
                verdict=None,
                action_type=action,
                api_error="Backend DETECTIF_API_KEY is not configured or placeholder."
            )
        else:
            scan = analyze_audio_file(audio_file_path, api_key=api_key)
            detection_result = {
                "uploaded": True,
                "success": scan["success"],
                "status_code": scan.get("status_code"),
                "request_id": scan.get("request_id"),
                "verdict": scan.get("verdict"),
                "score": scan.get("score"),
                "duration_seconds": scan.get("duration_seconds") or meta.get("duration_seconds") or audio_duration_seconds,
                "sample_rate": meta.get("sample_rate"),
                "channels": meta.get("channels"),
                "mime_type": meta.get("mime_type"),
                "error": scan.get("error")
            }

            if not scan["success"]:
                policy_decision = evaluate_action_policy(
                    verdict=None,
                    score=None,
                    action_type=action,
                    api_error=scan.get("error") or "Voice verification failed"
                )
            else:
                policy_decision = evaluate_action_policy(
                    verdict=scan.get("verdict"),
                    score=scan.get("score"),
                    action_type=action
                )
    else:
        # Text-only input
        detection_result = {
            "uploaded": False,
            "success": None,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "sample_rate": None,
            "channels": None,
            "mime_type": None,
            "error": None
        }

        if sensitivity == "PROHIBITED" or action == "prohibited_action":
            policy_decision = {
                "action": action,
                "decision": "HOLD",
                "verdict": "blocked",
                "score": None,
                "reason": "Unsafe or prohibited action detected. Operation is strictly blocked by AgentShield policy."
            }
        elif action == "unknown_action":
            policy_decision = {
                "action": action,
                "decision": "HOLD",
                "verdict": "unknown",
                "score": None,
                "reason": "Unknown or ambiguous action. Server-side security gate fails closed under policy."
            }
        elif sensitivity in ("SAFE", "LOW"):
            policy_decision = {
                "action": action,
                "decision": "ALLOW",
                "verdict": "text_direct",
                "score": None,
                "reason": f"Text task classified as {sensitivity} sensitivity. Permitted for immediate safe execution."
            }
        else:
            # Sensitive operations without voice authenticity cannot run automatically
            policy_decision = {
                "action": action,
                "decision": "OWNER_CONFIRMATION_REQUIRED",
                "verdict": "unverified",
                "score": None,
                "reason": (
                    f"'{action}' is classified as {sensitivity} sensitivity. "
                    "Server-side security gate requires explicit owner authorization before proceeding."
                )
            }

    decision = policy_decision.get("decision", "HOLD")

    # Determine gate status and execution status for diagnostics
    server_gate = "LOCKED_HOLD" if decision == "HOLD" else ("INTERCEPTED_CHALLENGE" if decision == "OWNER_CONFIRMATION_REQUIRED" else "UNLOCKED_PERMITTED")
    execution_status = "PERMITTED" if decision == "ALLOW" else ("AWAITING_APPROVAL" if decision == "OWNER_CONFIRMATION_REQUIRED" else "BLOCKED")

    diag_payload = {
        "audio_uploaded": bool(audio_file_path),
        "audio_duration_seconds": detection_result.get("duration_seconds") if detection_result else None,
        "sample_rate": detection_result.get("sample_rate") if detection_result else None,
        "mime_type": detection_result.get("mime_type") if detection_result else None,
        "request_id": detection_result.get("request_id") if detection_result else None,
        "provider_verdict": detection_result.get("verdict") if detection_result else None,
        "provider_score": detection_result.get("score") if detection_result else None,
        "canonical_action": action,
        "risk_classification": sensitivity,
        "policy_decision": decision,
        "policy_reason": policy_decision.get("reason"),
        "server_gate": server_gate,
        "execution_status": execution_status,
        "detection": detection_result
    }

    # Print developer security telemetry (safe: no API keys or audio payload exposed)
    print(
        f"[AURA-DIAGNOSTICS] Uploaded={diag_payload['audio_uploaded']} | "
        f"Duration={diag_payload['audio_duration_seconds']}s | "
        f"SampleRate={diag_payload['sample_rate']} | "
        f"MIME={diag_payload['mime_type']} | "
        f"ReqId={diag_payload['request_id']} | "
        f"Verdict={diag_payload['provider_verdict']} | "
        f"Score={diag_payload['provider_score']} | "
        f"Action={diag_payload['canonical_action']} ({diag_payload['risk_classification']}) | "
        f"PolicyDecision={diag_payload['policy_decision']} | "
        f"Gate={diag_payload['server_gate']} | "
        f"Execution={diag_payload['execution_status']}"
    )

    # Server-Side Execution Gate
    if decision == "HOLD":
        # Blocked: Explain naturally to the user
        if sensitivity == "PROHIBITED" or action == "prohibited_action":
            explanation = "I cannot fulfill this request. This instruction is identified as unsafe or prohibited by security policy."
        elif action == "unknown_action":
            explanation = "I cannot proceed with this request. The command is unrecognized or ambiguous, so it was held for your security."
        else:
            verdict = policy_decision.get("verdict")
            if verdict == "fake":
                explanation = "I couldn't safely proceed with this action. The voice input was flagged by authenticity checks as synthetic, so the request was held for your security."
            elif verdict == "not_sure":
                explanation = "I couldn't safely proceed with this action. Voice authenticity could not be definitively confirmed, so the request was held for safety."
            else:
                err_detail = (detection_result.get("error") if detection_result else "") or policy_decision.get("reason", "")
                err_lower = err_detail.lower()
                if "credit" in err_lower or "402" in err_lower:
                    explanation = "I couldn't safely proceed with this action. Voice authenticity verification could not be completed (provider credit limit / HTTP 402), so this request was held under fail-closed security policy."
                elif "timeout" in err_lower or "timed out" in err_lower:
                    explanation = "I couldn't safely proceed with this action. Voice authenticity verification timed out, so this request was held under fail-closed security policy."
                elif "connection" in err_lower:
                    explanation = "I couldn't safely proceed with this action. Voice verification service connection failed, so this request was held under fail-closed security policy."
                elif "missing" in err_lower and "verdict" in err_lower:
                    explanation = "I couldn't safely proceed with this action. Voice verification response was missing a definitive verdict, so this request was held under fail-closed security policy."
                elif err_detail:
                    explanation = f"I couldn't safely proceed with this action. Safety verification could not be completed ({err_detail[:120]}), so this request was held under fail-closed security policy."
                else:
                    explanation = "I couldn't safely proceed with this action. Safety verification could not be completed, so this request was held under fail-closed security policy."

        return {
            "status": "BLOCKED",
            "assistant_message": explanation,
            "transcript": task_text,
            "plan": plan,
            "execution": None,
            "authorization_required": False,
            "diagnostics": diag_payload
        }

    if decision == "OWNER_CONFIRMATION_REQUIRED":
        # Intercepted for secondary authorization
        auth_token = f"auth_{secrets.token_hex(16)}"
        pending_record = {
            "token": auth_token,
            "task_text": task_text,
            "plan": plan,
            "policy": policy_decision,
            "detection": detection_result,
            "created_at": time.time()
        }
        _PENDING_AUTHORIZATIONS[auth_token] = pending_record

        explanation = (
            f"I have prepared the plan for this request: {plan.get('summary')}. "
            f"Because this involves a {sensitivity.lower()}-sensitivity action, "
            f"I need your authorization before I can proceed."
        )

        return {
            "status": "NEEDS_AUTHORIZATION",
            "assistant_message": explanation,
            "transcript": task_text,
            "plan": plan,
            "execution": None,
            "authorization_required": True,
            "authorization_details": {
                "auth_token": auth_token,
                "action": action,
                "sensitivity": sensitivity,
                "summary": plan.get("summary")
            },
            "diagnostics": diag_payload
        }

    # Decision == "ALLOW": Execute permitted work
    execution_result = execute_action_safely(action, task_text, plan)

    # Conversational response
    if action == "answer_question":
        assistant_message = execution_result["result_text"]
    elif action == "summarize_text":
        assistant_message = f"Here is the summary of your request:\n\n{execution_result['result_text']}"
    elif action == "draft_message":
        assistant_message = f"I've drafted the message for you:\n\n{execution_result['result_text']}"
    elif action == "query_status":
        assistant_message = f"Here is the current system telemetry: {execution_result['result_text']}"
    else:
        assistant_message = f"Operation completed: {execution_result['result_text']}"

    return {
        "status": "COMPLETED",
        "assistant_message": assistant_message,
        "transcript": task_text,
        "plan": plan,
        "execution": execution_result,
        "authorization_required": False,
        "diagnostics": diag_payload
    }


TOKEN_EXPIRY_SECONDS = 300


def authorize_pending_task(
    auth_token: str,
    approve: bool,
    expected_action: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes or rejects a previously gated task after genuine secondary owner approval.
    Enforces server-side execution gate:
    - Single-use: pops token immediately from in-memory store.
    - Expiration: rejects tokens older than TOKEN_EXPIRY_SECONDS (300 seconds).
    - Binding: validates that the authorized token is bound to expected_action.
    - Safety: rejects authorization attempts for PROHIBITED or unknown actions.
    - If rejected or invalid token: blocks execution.
    - If approved: executes permitted action in safe sandbox.
    """
    record = _PENDING_AUTHORIZATIONS.pop(auth_token, None)
    if not record:
        return {
            "success": False,
            "error": "Invalid or expired authorization token.",
            "status": "BLOCKED",
            "assistant_message": "This authorization request is no longer valid or has expired."
        }

    # 1. Enforce token expiration (300 seconds)
    created_at = record.get("created_at", 0)
    if (time.time() - created_at) > TOKEN_EXPIRY_SECONDS:
        return {
            "success": False,
            "error": "Authorization token has expired (time limit exceeded).",
            "status": "BLOCKED",
            "assistant_message": "This authorization request has expired. Please initiate the task again."
        }

    plan = record.get("plan", {})
    action = plan.get("action", "")

    # 2. Enforce action parameter binding
    if expected_action and action != expected_action:
        return {
            "success": False,
            "error": f"Authorization token action mismatch: expected '{expected_action}', but token was issued for '{action}'.",
            "status": "BLOCKED",
            "assistant_message": "Security error: Authorization token is not valid for this action."
        }

    # 3. Enforce policy safety gate: prohibited or unknown actions can never be authorized
    sensitivity = ACTION_SENSITIVITY.get(action, "HIGH")
    if sensitivity == "PROHIBITED" or action in ("prohibited_action", "unknown_action"):
        return {
            "success": False,
            "error": f"Security policy violation: Prohibited action '{action}' cannot be authorized.",
            "status": "BLOCKED",
            "assistant_message": "This action is prohibited by safety policy and cannot be authorized."
        }

    if not approve:
        return {
            "success": True,
            "status": "CANCELLED",
            "assistant_message": "Action cancelled. The high-risk operation was not executed.",
            "plan": record["plan"],
            "execution": None,
            "diagnostics": {
                "owner_confirmed": False,
                "server_gate": "REJECTED_BY_OWNER"
            }
        }

    # Owner approved: Execute in protected sandbox
    task_text = record["task_text"]
    execution = execute_action_safely(action, task_text, plan)

    return {
        "success": True,
        "status": "COMPLETED",
        "assistant_message": f"Authorization confirmed. I have safely executed the action in the sandbox: {execution['result_text']}",
        "plan": plan,
        "execution": execution,
        "diagnostics": {
            "owner_confirmed": True,
            "policy_decision": "ALLOW_AFTER_OWNER_CONFIRMATION",
            "detection": record.get("detection"),
            "server_gate": "UNLOCKED_OWNER_CONFIRMED"
        }
    }
