"""
DetectifAI API Client for AgentShield
Communicates with the official DetectifAI deepfake audio detection endpoint.
"""

import os
import uuid
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from dotenv import load_dotenv

import logging

logger = logging.getLogger("detectif_client")

DEFAULT_DETECTIF_ENDPOINT = "https://platform.detectif.ai/v1/deepfake/detect"
DETECTIF_ENDPOINT = DEFAULT_DETECTIF_ENDPOINT
DEFAULT_TIMEOUT_SECONDS = 120


def get_detectif_endpoint() -> str:
    """
    Returns the configured DetectifAI API endpoint URL.
    Defaults to https://platform.detectif.ai/v1/deepfake/detect if DETECTIF_API_URL is unset.
    """
    override = os.getenv("DETECTIF_API_URL")
    if override and override.strip():
        return override.strip()
    return DEFAULT_DETECTIF_ENDPOINT


def load_api_key() -> Optional[str]:
    """
    Finds and loads the root .env file and retrieves DETECTIF_API_KEY.
    Returns None if missing or unset.
    """
    # Look for .env in current directory and parent directory (project root)
    current_dir = Path(__file__).resolve().parent
    root_env_path = current_dir.parent / ".env"

    if root_env_path.exists():
        load_dotenv(dotenv_path=root_env_path)
    else:
        load_dotenv()  # Fallback to default search

    api_key = os.getenv("DETECTIF_API_KEY")
    if not api_key:
        return None

    cleaned_key = api_key.strip()
    if cleaned_key == "" or cleaned_key == "your_actual_key_here":
        return None

    return cleaned_key


def analyze_audio_file(
    file_path: str,
    api_key: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """
    Sends an audio file to DetectifAI deepfake detection endpoint.

    Returns a dict with:
      - success: bool
      - status_code: Optional[int]
      - request_id: Optional[str]
      - verdict: Optional[str] ('real', 'fake', 'not_sure')
      - score: Optional[float]
      - duration_seconds: Optional[float]
      - raw_result: Optional[dict]
      - error: Optional[str]
    """
    # 1. Verify API Key
    raw_key = api_key if api_key is not None else load_api_key()
    if raw_key:
        cleaned = raw_key.strip()
        key = cleaned if (cleaned and cleaned != "your_actual_key_here") else None
    else:
        key = None

    if not key:
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error": "DETECTIF_API_KEY is missing or contains the default placeholder. Please set your valid key in the root .env file."
        }

    # 2. Verify file exists
    audio_path = Path(file_path).resolve()
    if not audio_path.exists():
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error": f"Audio file not found at path: {file_path}"
        }

    if not audio_path.is_file():
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error": f"Path is not a regular file: {file_path}"
        }

    # Check file size is not empty
    file_size = audio_path.stat().st_size
    if file_size == 0:
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error": "Audio file is empty (0 bytes)."
        }

    # 3. Setup Request headers
    idempotency_key = str(uuid.uuid4())
    headers = {
        "Authorization": f"Bearer {key}",
        "Idempotency-Key": idempotency_key
    }

    # 4. Open and send audio file
    try:
        suffix = audio_path.suffix.lower()
        content_type = "audio/wav"
        if suffix == ".webm":
            content_type = "audio/webm"
        elif suffix == ".ogg":
            content_type = "audio/ogg"
        elif suffix == ".mp3":
            content_type = "audio/mpeg"
        elif suffix == ".m4a":
            content_type = "audio/mp4"
        elif suffix == ".flac":
            content_type = "audio/flac"

        endpoint = get_detectif_endpoint()
        with open(audio_path, "rb") as f:
            files = {
                "file": (audio_path.name, f, content_type)
            }
            response = requests.post(
                endpoint,
                headers=headers,
                files=files,
                timeout=timeout
            )
    except requests.exceptions.Timeout:
        logger.warning(f"[DetectifAI Diagnostics] status_code=None request_id=None response_fields=None error_category=TIMEOUT")
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error_category": "TIMEOUT",
            "error": f"Request timed out after {timeout} seconds. The DetectifAI server took too long to respond."
        }
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"[DetectifAI Diagnostics] status_code=None request_id=None response_fields=None error_category=CONNECTION_ERROR")
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error_category": "CONNECTION_ERROR",
            "error": (
                f"Connection error ({type(e).__name__}): "
                f"{str(e)[:300]}"
            )
        }
    except Exception as e:
        logger.warning(f"[DetectifAI Diagnostics] status_code=None request_id=None response_fields=None error_category=UNEXPECTED_ERROR")
        return {
            "success": False,
            "status_code": None,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error_category": "UNEXPECTED_ERROR",
            "error": f"Unexpected error while sending audio: {type(e).__name__}"
        }

    # 5. Parse response
    status_code = response.status_code

    try:
        data = response.json()
        response_fields = list(data.keys()) if isinstance(data, dict) else []
    except Exception:
        logger.warning(f"[DetectifAI Diagnostics] status_code={status_code} request_id=None response_fields=None error_category=NON_JSON_RESPONSE")
        return {
            "success": False,
            "status_code": status_code,
            "request_id": None,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error_category": "NON_JSON_RESPONSE",
            "error": f"Server returned status {status_code} with non-JSON response."
        }

    # Handle HTTP error statuses safely without exposing sensitive info
    if status_code != 200:
        error_msg = data.get("message") or data.get("error") or f"HTTP status {status_code}"
        request_id = data.get("request_id")
        if status_code == 402:
            error_cat = "INSUFFICIENT_CREDITS"
        elif status_code in (401, 403):
            error_cat = "AUTHENTICATION_ERROR"
        elif 400 <= status_code < 500:
            error_cat = "PROVIDER_CLIENT_ERROR"
        else:
            error_cat = "PROVIDER_SERVER_ERROR"

        logger.warning(f"[DetectifAI Diagnostics] status_code={status_code} request_id={request_id} response_fields={response_fields} error_category={error_cat}")
        return {
            "success": False,
            "status_code": status_code,
            "request_id": request_id,
            "verdict": None,
            "score": None,
            "duration_seconds": None,
            "error_category": error_cat,
            "error": f"DetectifAI API error (HTTP {status_code}): {error_msg}"
        }

    # 6. Extract result data
    result = data.get("result")
    if not isinstance(result, dict):
        result = data

    raw_verdict = result.get("verdict") or data.get("verdict")
    score = result.get("score") if result.get("score") is not None else data.get("score")
    duration_seconds = result.get("duration_seconds") or data.get("duration_seconds")
    request_id = data.get("request_id") or result.get("request_id")

    # Strict validation of provider verdict:
    # Missing verdict, malformed response, or unrecognized verdict MUST fail closed
    if not raw_verdict:
        logger.warning(f"[DetectifAI Diagnostics] status_code={status_code} request_id={request_id} response_fields={response_fields} error_category=MISSING_VERDICT")
        return {
            "success": False,
            "status_code": status_code,
            "request_id": request_id,
            "verdict": None,
            "score": score,
            "duration_seconds": duration_seconds,
            "raw_result": result,
            "error_category": "MISSING_VERDICT",
            "error": "DetectifAI response missing required 'verdict' field."
        }

    normalized_verdict = str(raw_verdict).strip().lower()
    if normalized_verdict not in ("real", "fake", "not_sure"):
        logger.warning(f"[DetectifAI Diagnostics] status_code={status_code} request_id={request_id} response_fields={response_fields} error_category=UNRECOGNIZED_VERDICT")
        return {
            "success": False,
            "status_code": status_code,
            "request_id": request_id,
            "verdict": None,
            "score": score,
            "duration_seconds": duration_seconds,
            "raw_result": result,
            "error_category": "UNRECOGNIZED_VERDICT",
            "error": f"DetectifAI returned unrecognized verdict value: '{raw_verdict}'."
        }

    logger.info(f"[DetectifAI Diagnostics] status_code={status_code} request_id={request_id} response_fields={response_fields} error_category=NONE")
    return {
        "success": True,
        "status_code": status_code,
        "request_id": request_id,
        "verdict": normalized_verdict,
        "score": float(score) if score is not None else None,
        "duration_seconds": float(duration_seconds) if duration_seconds is not None else None,
        "raw_result": result,
        "error_category": None,
        "error": None
    }


def inspect_audio_file(file_path: str) -> Dict[str, Any]:
    """
    Inspects audio file metadata without reading entire file into memory.
    Extracts duration, sample rate, channels, bit depth, encoding, and MIME type.
    """
    import wave

    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        return {
            "exists": False,
            "error": "File does not exist",
            "mime_type": "unknown",
            "file_size_bytes": 0,
            "sample_rate": None,
            "channels": None,
            "duration_seconds": None
        }

    file_size = path.stat().st_size
    suffix = path.suffix.lower()
    mime_map = {
        ".wav": "audio/wav",
        ".webm": "audio/webm",
        ".mp3": "audio/mpeg",
        ".m4a": "audio/mp4",
        ".ogg": "audio/ogg",
        ".flac": "audio/flac"
    }
    mime_type = mime_map.get(suffix, "application/octet-stream")

    meta: Dict[str, Any] = {
        "exists": True,
        "filename": path.name,
        "file_size_bytes": file_size,
        "mime_type": mime_type,
        "extension": suffix,
        "sample_rate": None,
        "channels": None,
        "sampwidth": None,
        "duration_seconds": None,
        "is_valid_wav_format": False,
        "error": None
    }

    if suffix == ".wav":
        try:
            with wave.open(str(path), "rb") as wf:
                meta["channels"] = wf.getnchannels()
                meta["sampwidth"] = wf.getsampwidth()
                meta["sample_rate"] = wf.getframerate()
                nframes = wf.getnframes()
                if meta["sample_rate"] > 0:
                    meta["duration_seconds"] = round(nframes / float(meta["sample_rate"]), 3)
                meta["is_valid_wav_format"] = True
        except wave.Error as e:
            meta["error"] = f"Invalid WAV header: {e}"
        except Exception as e:
            meta["error"] = f"Error reading audio: {e}"

    return meta

