"""
Speech-to-Text Transcription Module for Aura Personal AI Agent.
Converts recorded user voice audio into text using SpeechRecognition.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import speech_recognition as sr


def transcribe_audio_file(file_path: str) -> Dict[str, Any]:
    """
    Transcribes speech from an audio file into text.
    
    Returns a dict with:
      - success: bool
      - transcript: Optional[str]
      - error: Optional[str]
    """
    audio_path = Path(file_path).resolve()
    if not audio_path.exists() or not audio_path.is_file():
        return {
            "success": False,
            "transcript": None,
            "error": f"Audio file not found: {file_path}"
        }

    if audio_path.stat().st_size == 0:
        return {
            "success": False,
            "transcript": None,
            "error": "Audio file is empty (0 bytes). Please record your speech and try again."
        }

    # Optional test mock override for hermetic testing
    mock_env = os.getenv("AURA_TEST_TRANSCRIPT")
    if mock_env:
        return {
            "success": True,
            "transcript": mock_env.strip(),
            "error": None
        }

    recognizer = sr.Recognizer()
    try:
        with sr.AudioFile(str(audio_path)) as source:
            # Adjust for ambient noise and record
            audio_data = recognizer.record(source)

        transcript = recognizer.recognize_google(audio_data)
        cleaned_transcript = (transcript or "").strip()
        if not cleaned_transcript:
            return {
                "success": False,
                "transcript": None,
                "error": "Speech was not recognized or audio was unclear. Please speak clearly and try recording again, or type your request."
            }

        return {
            "success": True,
            "transcript": cleaned_transcript,
            "error": None
        }

    except sr.UnknownValueError:
        return {
            "success": False,
            "transcript": None,
            "error": "Speech was not recognized or audio was unclear. Please speak clearly and try recording again, or type your request."
        }
    except sr.RequestError as e:
        return {
            "success": False,
            "transcript": None,
            "error": f"Speech transcription service could not be reached ({str(e)}). Please check your connection or type your task."
        }
    except Exception as e:
        return {
            "success": False,
            "transcript": None,
            "error": f"Speech transcription error: {str(e)}. Please try recording again or type your task."
        }
