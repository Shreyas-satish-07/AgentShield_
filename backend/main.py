"""
Personal AI Assistant - FastAPI Backend Server
Serves the Personal AI Assistant interface and handles natural-language task processing,
with invisible backend security powered by AgentShield policy gating and DetectifAI audio authenticity analysis.
"""

import os
import shutil
import tempfile
import sys
import wave
from pathlib import Path
from typing import Optional

# Add backend directory to sys.path so sibling imports work in all contexts
_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from detectif_client import analyze_audio_file, load_api_key, inspect_audio_file
from policy import evaluate_action_policy, ACTION_SENSITIVITY
from agent import process_agent_task, authorize_pending_task, SUPPORTED_ACTIONS
from transcribe import transcribe_audio_file

app = FastAPI(
    title="Personal AI Assistant API",
    description="Personal AI Assistant backend with server-side security checks and simulated sandbox gating",
    version="2.0.0"
)

# Enable CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend directory for static assets
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend_root():
        return FileResponse(frontend_dir / "index.html")

    @app.get("/style.css", include_in_schema=False)
    def serve_frontend_css():
        return FileResponse(frontend_dir / "style.css")

    @app.get("/app.js", include_in_schema=False)
    def serve_frontend_js():
        return FileResponse(frontend_dir / "app.js")


@app.get("/api/health")
def health_check():
    """Health check endpoint to verify backend status, key readiness, and capabilities."""
    has_key = bool(load_api_key())
    return {
        "status": "healthy",
        "service": "Personal AI Assistant",
        "detectifai_key_configured": has_key,
        "supported_actions": list(ACTION_SENSITIVITY.keys()),
        "agent_capabilities": {
            "genuine": ["answer_question", "draft_message", "summarize_text", "query_status"],
            "simulated": ["simulate_purchase", "transfer_funds", "send_email"]
        }
    }


# =========================================================================
# Personal AI Assistant Task Taking Endpoints
# =========================================================================

class AgentTaskJsonRequest(BaseModel):
    task: str = ""


class AgentAuthorizeRequest(BaseModel):
    auth_token: str
    approve: bool = True
    action: Optional[str] = None


@app.post("/api/agent/task")
async def handle_agent_task(
    task: str = Form(""),
    file: Optional[UploadFile] = File(None)
):
    """
    Main personal AI assistant task-taking workflow:
    1. Receives natural language task (via text and/or microphone audio)
    2. Interprets intent and plans actions
    3. Runs backend security checks (DetectifAI for voice authenticity + AgentShield policy)
    4. Enforces server-side execution gate:
       - ALLOW: executes permitted task safely
       - OWNER_CONFIRMATION_REQUIRED: pauses execution and creates authorization challenge
       - HOLD: strictly blocks execution and explains naturally
    """
    temp_file_path = None
    duration_seconds = None

    try:
        # If voice audio is provided, validate and write to temp file
        if file and hasattr(file, "filename") and file.filename:
            filename_lower = file.filename.lower()
            allowed_extensions = (".wav", ".mp3", ".m4a", ".ogg", ".flac", ".webm")
            if not any(filename_lower.endswith(ext) for ext in allowed_extensions):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported audio format. Please upload one of: {', '.join(allowed_extensions)}"
                )

            suffix = Path(file.filename).suffix or ".wav"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_audio:
                temp_file_path = temp_audio.name
                shutil.copyfileobj(file.file, temp_audio)

            if os.path.getsize(temp_file_path) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Uploaded audio file is empty (0 bytes)."
                )

            # Check duration for WAV files
            if filename_lower.endswith(".wav"):
                try:
                    with wave.open(temp_file_path, "rb") as wf:
                        frames = wf.getnframes()
                        rate = wf.getframerate()
                        if rate > 0:
                            duration_seconds = frames / float(rate)
                            if duration_seconds < 4.0:
                                raise HTTPException(
                                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    detail=f"Audio duration ({duration_seconds:.1f}s) is too short. At least 4.0 seconds of speech is required."
                                )
                            if duration_seconds > 120.0:
                                raise HTTPException(
                                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    detail=f"Audio duration ({duration_seconds:.1f}s) exceeds maximum allowed 120.0 seconds."
                                )
                except wave.Error:
                    pass

        # Execute agent workflow with real transcript
        task_text = task.strip()
        if temp_file_path and not task_text:
            stt_result = transcribe_audio_file(temp_file_path)
            if not stt_result["success"]:
                return {
                    "status": "BLOCKED",
                    "assistant_message": f"I couldn't transcribe speech from your voice recording. {stt_result.get('error', 'Please speak clearly and try recording again, or type your request.')}",
                    "transcript": None,
                    "plan": None,
                    "execution": None,
                    "authorization_required": False,
                    "diagnostics": {
                        "policy_decision": "HOLD",
                        "policy_reason": stt_result.get("error", "Speech transcription failed"),
                        "detection": None,
                        "server_gate": "TRANSCRIPTION_FAILED"
                    }
                }
            task_text = stt_result["transcript"]

        if not task_text and not temp_file_path:
            return {
                "status": "BLOCKED",
                "assistant_message": "Please provide a task instruction by typing or speaking.",
                "transcript": None,
                "plan": None,
                "execution": None,
                "authorization_required": False,
                "diagnostics": {
                    "policy_decision": "HOLD",
                    "policy_reason": "No task input or audio provided",
                    "detection": None,
                    "server_gate": "EMPTY_INPUT"
                }
            }

        audio_meta = inspect_audio_file(temp_file_path) if temp_file_path else None
        result = process_agent_task(
            task_text=task_text,
            audio_file_path=temp_file_path,
            audio_duration_seconds=duration_seconds,
            audio_metadata=audio_meta
        )
        return result

    finally:
        # Clean up temp audio file
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass


@app.post("/api/agent/task-json")
def handle_agent_task_json(req: AgentTaskJsonRequest):
    """Convenience JSON endpoint for text-only assistant queries."""
    result = process_agent_task(task_text=req.task)
    return result


@app.post("/api/agent/authorize")
def handle_agent_authorize(req: AgentAuthorizeRequest):
    """
    Secondary owner authorization endpoint.
    Unlocks high-risk tasks that were intercepted by the server-side gate.
    """
    res = authorize_pending_task(
        auth_token=req.auth_token,
        approve=req.approve,
        expected_action=req.action
    )
    if not res.get("success", False) and not res.get("status") == "CANCELLED":
        err_msg = res.get("error", "Invalid or expired authorization token.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err_msg
        )
    return res


# =========================================================================
# Preserved Existing Endpoints (Ensures backwards compatibility & test suite)
# =========================================================================

@app.post("/api/analyze-audio")
async def analyze_audio(
    file: UploadFile = File(..., description="Audio file (recommended: WAV, MP3, 4-120 seconds)"),
    action: str = Form("simulate_purchase", description="Simulated agent action to evaluate policy for")
):
    """
    Accepts an audio upload, calls DetectifAI server-side,
    and applies AgentShield security policy to determine whether the action is permitted.
    Preserved for existing automated tests and diagnostics.
    """
    # 1. Check API Key presence without exposing it
    api_key = load_api_key()
    if not api_key:
        policy_fail = evaluate_action_policy(
            verdict=None,
            action_type=action,
            api_error="Backend DETECTIF_API_KEY is not configured or is placeholder"
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "success": False,
                "error": "DetectifAI API key is not configured in backend .env",
                "policy": policy_fail
            }
        )

    # 2. Validate uploaded file presence and extension
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file selected or uploaded."
        )

    filename_lower = file.filename.lower()
    allowed_extensions = (".wav", ".mp3", ".m4a", ".ogg", ".flac", ".webm")
    if not any(filename_lower.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported audio format. Please upload one of: {', '.join(allowed_extensions)}"
        )

    # 3. Stream upload safely to a temporary file
    temp_file_path = None
    try:
        suffix = Path(file.filename).suffix or ".wav"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_audio:
            temp_file_path = temp_audio.name
            shutil.copyfileobj(file.file, temp_audio)

        # Verify file is not empty
        if os.path.getsize(temp_file_path) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded audio file is empty (0 bytes)."
            )

        # Enforce provider audio duration constraints (4.0s - 120.0s) for WAV files
        if filename_lower.endswith(".wav"):
            try:
                with wave.open(temp_file_path, "rb") as wf:
                    frames = wf.getnframes()
                    rate = wf.getframerate()
                    if rate > 0:
                        duration = frames / float(rate)
                        if duration < 4.0:
                            raise HTTPException(
                                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"Audio duration ({duration:.1f}s) is too short. DetectifAI requires at least 4.0 seconds of speech."
                            )
                        if duration > 120.0:
                            raise HTTPException(
                                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail=f"Audio duration ({duration:.1f}s) exceeds maximum allowed 120.0 seconds."
                            )
            except wave.Error:
                pass  # Fall back to provider validation for non-standard WAV headers

        # 4. Call DetectifAI server-side
        result = analyze_audio_file(temp_file_path, api_key=api_key)

    finally:
        # 5. Clean up temporary file immediately
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass

    # 6. Handle provider errors safely (Fail closed)
    if not result["success"]:
        policy_decision = evaluate_action_policy(
            verdict=None,
            action_type=action,
            api_error=result["error"]
        )
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "success": False,
                "error": result["error"],
                "policy": policy_decision
            }
        )

    # 7. Evaluate security policy on live verdict
    policy_decision = evaluate_action_policy(
        verdict=result["verdict"],
        score=result["score"],
        action_type=action
    )

    return {
        "success": True,
        "request_id": result["request_id"],
        "detection": {
            "verdict": result["verdict"],
            "score": result["score"],
            "duration_seconds": result["duration_seconds"]
        },
        "policy": policy_decision
    }


class SimulateActionRequest(BaseModel):
    action: str
    decision: str
    task_text: Optional[str] = ""
    owner_confirmed: Optional[bool] = False


@app.post("/api/simulate-action")
def simulate_action(req: SimulateActionRequest):
    """
    Simulates executing an authorized agent action in a safe sandbox.
    Fails closed if the policy decision is HOLD or unconfirmed OWNER_CONFIRMATION_REQUIRED.
    All executions are strictly simulated demonstration events.
    """
    normalized_action = req.action.strip().lower()
    sensitivity = ACTION_SENSITIVITY.get(normalized_action, "HIGH")

    # Enforce security gate: Prohibited or unknown actions can NEVER be executed or simulated
    if sensitivity == "PROHIBITED" or normalized_action in ("prohibited_action", "unknown_action"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security gate violation: Action '{normalized_action}' is prohibited or unverified and cannot be executed."
        )

    # Enforce security gate: Cannot execute if decision is HOLD
    if req.decision == "HOLD":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security gate violation: Action execution blocked because AgentShield policy decision is HOLD."
        )

    # Enforce security gate: High/Medium risk requires explicit owner confirmation
    if (sensitivity in ("HIGH", "MEDIUM") or req.decision == "OWNER_CONFIRMATION_REQUIRED") and not req.owner_confirmed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security gate violation: Action '{normalized_action}' ({sensitivity}) execution blocked until owner confirmation is provided."
        )

    # Generate realistic simulated sandbox payloads
    sim_id = f"sim_{os.urandom(4).hex()}"
    if normalized_action == "draft_message":
        result = {
            "type": "draft_message",
            "status": "DRAFTED_IN_SANDBOX",
            "summary": f"Simulated message drafted in agent memory: '{req.task_text or 'Draft message'}'",
            "simulated_id": sim_id,
            "is_simulated": True
        }
    elif normalized_action == "send_email":
        result = {
            "type": "send_email",
            "status": "DISPATCH_SIMULATED",
            "summary": f"Simulated email prepared for mock outbound queue: '{req.task_text or 'Email message'}'",
            "simulated_id": sim_id,
            "is_simulated": True
        }
    elif normalized_action == "simulate_purchase":
        result = {
            "type": "simulate_purchase",
            "status": "PURCHASE_SIMULATED",
            "summary": f"Simulated purchase order created: '{req.task_text or 'Purchase request'}'",
            "simulated_id": sim_id,
            "simulated_amount": "₹80,000 (Mock)",
            "is_simulated": True
        }
    elif normalized_action == "transfer_funds":
        result = {
            "type": "transfer_funds",
            "status": "TRANSFER_SIMULATED",
            "summary": f"Simulated ledger entry generated: '{req.task_text or 'Transfer funds'}'",
            "simulated_id": sim_id,
            "simulated_amount": "₹5,000 (Mock)",
            "is_simulated": True
        }
    else:  # query_status
        result = {
            "type": "query_status",
            "status": "STATUS_RETRIEVED",
            "summary": "Simulated system telemetry: Nodes online, load balanced, zero anomalous events.",
            "simulated_id": sim_id,
            "is_simulated": True
        }

    return {
        "success": True,
        "action": normalized_action,
        "sensitivity": sensitivity,
        "execution": result,
        "disclaimer": "Sandbox Simulation Only — Zero actual financial transactions, messages, or emails executed."
    }
