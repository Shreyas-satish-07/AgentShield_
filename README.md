# AgentShield 🛡️

**AgentShield** is an AI security layer built for the "UNCLONE AGENTS" hackathon track. It protects autonomous AI agents from voice impersonation and audio deepfake attacks.

When an AI agent receives a voice command, AgentShield analyzes the audio recording in real time using the **DetectifAI** deepfake detection API (`https://platform.detectif.ai/v1/deepfake/detect`). It then enforces a **fail-closed security policy** to determine whether simulated agent actions should be **allowed**, **held**, or require **explicit owner authorization**.

---

## 🔒 Security Principles

1. **Authenticity != Authorization**:
   - A genuine voice verdict (`real`) only proves the voice is not synthetic; it does NOT prove the speaker's identity or authorize sensitive actions.
   - Low-risk actions (e.g., *Draft a message*) can be permitted on genuine voice.
   - High-risk actions (e.g., *Simulate a purchase*, *Transfer funds*) always require secondary owner confirmation even if the voice is authentic.
2. **Fail Closed**:
   - If DetectifAI returns `fake`, `not_sure`, times out, or encounters a network error, AgentShield immediately **HOLDS** sensitive actions.
   - Never report audio as authentic when the API is unreachable.
3. **Zero Secrets in Code or Frontend**:
   - API keys are kept strictly in backend `.env` and are never logged, returned in responses, or exposed to the frontend.

---

## 📁 Project Structure

```text
D:\unclone_AgentShield\
├── .env                       # Local secret configuration (ignored by git)
├── .env.example               # Template for required environment variables
├── .gitignore                 # Protects .env, .venv, and audio files from git
├── README.md                  # This documentation
├── .venv/                     # Python virtual environment
├── frontend/
│   ├── index.html             # Live microphone recording & defense dashboard UI
│   ├── style.css              # Dark mode styling & responsive layout
│   └── app.js                 # Web Audio API 16-bit PCM WAV recorder & client
└── backend/
    ├── requirements.txt       # Python dependencies (requests, fastapi, uvicorn, etc.)
    ├── detectif_client.py     # Clean client for DetectifAI POST /v1/deepfake/detect
    ├── policy.py              # AgentShield security policy evaluation engine
    ├── test_detectif.py       # Standalone CLI test tool for live audio files
    ├── test_policy_mock.py    # Zero-quota offline unit & mock test suite
    ├── test_api_endpoint.py   # API integration & duration constraint test suite
    └── main.py                # FastAPI backend serving API & frontend dashboard
```

---

## 🚀 Getting Started (Beginner Guide)

### 1. Prerequisites & Environment

All commands are run from the project root folder (`D:\unclone_AgentShield`) in PowerShell.
Because PowerShell blocks virtual environment activation by default, run Python directly via:

```powershell
.\.venv\Scripts\python.exe <command>
```

To install required dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

*(Or minimal dependencies: `.\.venv\Scripts\python.exe -m pip install requests python-dotenv`)*

---

### 2. Configure Your DetectifAI API Key Locally

1. Open the `.env` file in the project root: `D:\unclone_AgentShield\.env`.
2. Find the line:
   ```env
   DETECTIF_API_KEY=your_actual_key_here
   ```
3. Replace `your_actual_key_here` with your real DetectifAI API key:
   ```env
   DETECTIF_API_KEY=det_live_xxxxxxxxxxxxxxxxxxxxxxxx
   ```
4. Save the file.
> ⚠️ **Important**: Never paste your API key in chat, emails, public repositories, or GitHub commits. The `.gitignore` file automatically excludes `.env`.

---

### 3. Run Offline Mock Tests (Zero Quota Used)

Before spending any API credits, verify the entire policy engine and client response handlers locally:

```powershell
.\.venv\Scripts\python.exe .\backend\test_policy_mock.py
```

**Expected output:**
```text
test_fail_closed_on_api_error_or_timeout ... ok
test_verdict_fake_holds_all_actions ... ok
test_verdict_not_sure_holds_actions ... ok
test_verdict_real_high_sensitivity_requires_owner_confirmation ... ok
test_verdict_real_low_sensitivity_allowed ... ok
...
Ran 11 tests in 0.02s
OK
```

---

### 4. Test Live Audio with the CLI Tool

Once your API key is in `.env`, test a real audio file (WAV, MP3, 4 to 120 seconds):

```powershell
.\.venv\Scripts\python.exe .\backend\test_detectif.py ".\clip.wav"
```

**What a successful run looks like:**
```text
============================================================
AgentShield - DetectifAI API Connection Test
============================================================

[1] Target Audio File: .\clip.wav
[2] API Key: Detected in .env (hidden for security)
[3] Contacting DetectifAI endpoint (https://platform.detectif.ai/v1/deepfake/detect)...

------------------------------------------------------------
DetectifAI Provider Response:
------------------------------------------------------------
HTTP Status Code : 200
Request ID       : req_01j7xyz...
Verdict          : real
Deepfake Score   : 0.04
Audio Duration   : 6.2s

============================================================
AgentShield Policy Evaluation (Simulated Agent Actions):
============================================================

Action 1: 'Draft a message' (Low Sensitivity)
  Decision : ALLOW
  Rationale: Audio verified as genuine. Action is low-risk ('ALLOW').

Action 2: 'Simulate a purchase' (High Sensitivity)
  Decision : OWNER_CONFIRMATION_REQUIRED
  Rationale: Audio verified as genuine. However, authenticity alone does NOT equal authorization. 'simulate_purchase' is a high-sensitivity action requiring explicit owner confirmation.
============================================================
```

---

### 5. Start the FastAPI Backend Server

To start the backend server for frontend communication:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

- Interactive Swagger API Docs: `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/api/health`

#### Backend Endpoint Details

- **Endpoint**: `POST /api/analyze-audio`
- **Form Data**:
  - `file`: Audio file (`.wav`, `.mp3`, etc.)
  - `action`: Simulated agent action (e.g. `simulate_purchase`, `draft_message`)
- **Sample JSON Response**:
```json
{
  "success": true,
  "request_id": "req_12345",
  "detection": {
    "verdict": "real",
    "score": 0.06,
    "duration_seconds": 5.8
  },
  "policy": {
    "action": "simulate_purchase",
    "decision": "OWNER_CONFIRMATION_REQUIRED",
    "reason": "Audio verified as genuine. However, authenticity alone does NOT equal authorization. 'simulate_purchase' is a high-sensitivity action requiring explicit owner confirmation."
  }
}
```

---

## 🛠️ Common Errors & Troubleshooting

| Error Code / Symptom | Probable Cause | How to Fix |
|---|---|---|
| **`DETECTIF_API_KEY is not configured...`** | `.env` has the placeholder or key is missing. | Open `.env` and set `DETECTIF_API_KEY=your_key`. |
| **`HTTP 401 Unauthorized`** | Invalid or expired DetectifAI API key. | Check your API key in the DetectifAI dashboard. |
| **`HTTP 403 Forbidden`** | Account lacks access or subscription expired. | Check account quota / permissions with DetectifAI. |
| **`HTTP 422 Unprocessable Entity`** | Audio length under 4 seconds or over 120s, or unsupported format. | Provide a 16kHz WAV or MP3 audio between 4s and 120s. |
| **`HTTP 429 Too Many Requests`** | API rate limit reached. | Wait a few moments before sending another request. |
| **`Request timed out after 30s`** | Network or server connectivity issue. | Check your internet connection. AgentShield fails closed to keep agents safe. |

---

## 🎙️ Live Microphone Security Dashboard

AgentShield includes a live microphone recording and analysis dashboard served directly by FastAPI.

### Starting the Server & Dashboard:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser to:
👉 **`http://127.0.0.1:8000`**

### Live Recording Workflow:
1. **Choose an Action**: Select an agent action (e.g., *Draft a message* for low sensitivity, or *Simulate a purchase* for high sensitivity).
2. **Click Record Voice**: Browser prompts for microphone permission.
3. **Speak for 4 to 120 seconds**: Real-time oscilloscope visualizes audio signal.
4. **Click Stop Recording**: Client-side Web Audio API encodes the stream into genuine 16-bit PCM RIFF WAV (`audio/wav`).
5. **Review Playback**: Listen to your recorded audio and verify the duration.
6. **Click Analyze Voice**: Sends `FormData` directly to `POST /api/analyze-audio`.
7. **View Results**:
   - **DetectifAI Verdict**: `REAL`, `FAKE`, or `NOT SURE` with deepfake score meter and request ID.
   - **AgentShield Policy Decision**: `ALLOW`, `HOLD`, or `OWNER_CONFIRMATION_REQUIRED`.
   - **Simulated Agent Execution**: Real-time demonstration state.

# AgentShield


## Generalized prompt handling update

The intent parser now treats common read-only information and content requests (for example, suggest, recommend, explain, compare, translate, rewrite, and list) as safe general requests instead of classifying them as unknown high-risk commands. Explicit financial transfers and purchases remain gated, outbound email remains authorization-sensitive, and destructive/ambiguous actions continue to fail closed. A small rule-based horror-movie example is included for the reported test case.

**Important limitation:** this project does not currently connect a general-purpose language model for open-ended answer generation. This update broadens safe prompt classification and adds a sample response; it does not make every possible prompt answerable with high quality. For genuinely general responses, configure an LLM provider on the backend and keep AgentShield policy/authorization checks server-side, separate from the model's generated text.

Run focused regression tests from `backend/` with `python -m unittest test_generalization.py`.
