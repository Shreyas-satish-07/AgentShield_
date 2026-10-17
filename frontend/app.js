/**
 * Aura — Personal AI Assistant Frontend Controller
 * Manages conversation stream, task planning, microphone recording (16000 Hz PCM WAV),
 * backend agent communication with invisible DetectifAI & AgentShield security,
 * and developer diagnostics.
 */

(() => {
    // 1. API Configuration
    const API_BASE_URL = (window.location.protocol === "http:" || window.location.protocol === "https:") && window.location.port === "8000"
        ? ""
        : "http://127.0.0.1:8000";

    const MIN_DURATION_SECONDS = 4.0;
    const MAX_DURATION_SECONDS = 120.0;

    // 2. DOM Elements
    const systemHealthDot = document.getElementById("systemHealthDot");
    const systemHealthText = document.getElementById("systemHealthText");
    const assistantStatusText = document.getElementById("assistantStatusText");
    const btnToggleDiagnostics = document.getElementById("btnToggleDiagnostics");
    const btnCloseDrawer = document.getElementById("btnCloseDrawer");
    const diagnosticsDrawer = document.getElementById("diagnosticsDrawer");

    // Header Navigation Elements
    const btnNavHome = document.getElementById("btnNavHome");
    const btnNavNewChat = document.getElementById("btnNavNewChat");

    // Conversation History Storage (preserved across new chats)
    const storedConversations = [];
    let currentSessionId = 1;

    // Conversation Elements
    const conversationFeed = document.getElementById("conversationFeed");
    const welcomeCard = document.getElementById("welcomeCard");
    const promptChips = document.querySelectorAll(".prompt-chip");

    // Composer Elements
    const taskInput = document.getElementById("taskInput");
    const btnSendTask = document.getElementById("btnSendTask");
    const btnRecordVoice = document.getElementById("btnRecordVoice");

    // Voice Attachment Elements
    const voiceAttachmentPreview = document.getElementById("voiceAttachmentPreview");
    const attachmentDurationText = document.getElementById("attachmentDurationText");
    const attachmentAudioPlayer = document.getElementById("attachmentAudioPlayer");
    const btnRemoveVoiceAttachment = document.getElementById("btnRemoveVoiceAttachment");

    // Audio Recording Floating Studio Elements
    const recordingDock = document.getElementById("recordingDock");
    const dockTimer = document.getElementById("dockTimer");
    const dockWaveformCanvas = document.getElementById("dockWaveformCanvas");
    const btnDockCancel = document.getElementById("btnDockCancel");
    const btnDockDone = document.getElementById("btnDockDone");
    const dockDurationHint = document.getElementById("dockDurationHint");

    // Diagnostics Telemetry Elements
    const diagVerdictBadge = document.getElementById("diagVerdictBadge");
    const diagScoreVal = document.getElementById("diagScoreVal");
    const diagRequestIdVal = document.getElementById("diagRequestIdVal");
    const diagTargetAction = document.getElementById("diagTargetAction");
    const diagDecisionBadge = document.getElementById("diagDecisionBadge");
    const diagGateStatus = document.getElementById("diagGateStatus");
    const diagRationaleText = document.getElementById("diagRationaleText");
    const auditLogFeed = document.getElementById("auditLogFeed");
    const btnClearAuditLog = document.getElementById("btnClearAuditLog");

    // 3. Audio & Recording State
    let mediaStream = null;
    let mediaRecorder = null;
    let audioContext = null;
    let sourceNode = null;
    let analyserNode = null;
    let recordedChunks = [];
    let isRecording = false;
    let recordingStartTime = 0;
    let timerInterval = null;
    let animFrameId = null;
    let recordedAudioBlob = null;
    let recordedDurationSeconds = 0;
    let recordedFileExtension = "wav";
    let activeSpeechRecognizer = null;
    let recognizedSpeechText = "";

    // 4. Activity & Diagnostics Audit Logger
    function logAudit(tag, msg) {
        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        const item = document.createElement("div");
        item.className = "audit-log-item";
        item.innerHTML = `<span class="audit-log-time">${timeStr}</span><span class="audit-log-tag">[${tag}]</span>${escapeHtml(msg)}`;
        auditLogFeed.appendChild(item);
        auditLogFeed.scrollTop = auditLogFeed.scrollHeight;
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    if (btnClearAuditLog) {
        btnClearAuditLog.addEventListener("click", () => {
            auditLogFeed.innerHTML = "";
            logAudit("SYSTEM", "Diagnostics audit log cleared.");
        });
    }

    // 5. Drawer Toggle
    btnToggleDiagnostics.addEventListener("click", () => {
        diagnosticsDrawer.classList.toggle("open");
    });

    btnCloseDrawer.addEventListener("click", () => {
        diagnosticsDrawer.classList.remove("open");
    });

    // 6. Navigation Controls (Home & New Chat)
    function navigateHome() {
        if (welcomeCard) {
            welcomeCard.style.display = "block";
            conversationFeed.scrollTo({ top: 0, behavior: "smooth" });
        }
        if (btnNavHome) btnNavHome.classList.add("active");
        assistantStatusText.textContent = "Online • Ready for your next task";
        logAudit("NAV_HOME", "Returned to assistant welcome screen.");
    }

    function startNewChat() {
        // 1. Archive existing conversation without deleting stored history
        const existingRows = conversationFeed.querySelectorAll(".message-row");
        if (existingRows.length > 0) {
            const messages = Array.from(existingRows).map(row => ({
                isUser: row.classList.contains("user-row"),
                text: row.innerText.trim(),
                html: row.innerHTML
            }));
            storedConversations.push({
                sessionId: currentSessionId,
                timestamp: new Date().toISOString(),
                messagesCount: messages.length,
                messages: messages
            });
            logAudit("SESSION_ARCHIVED", `Archived conversation session #${currentSessionId} (${messages.length} messages preserved).`);
            
            // 2. Clear current conversation UI
            existingRows.forEach(row => row.remove());
        }

        // 3. Clear task input and voice attachments
        taskInput.value = "";
        taskInput.style.height = "auto";
        btnSendTask.disabled = false;
        clearVoiceAttachment();

        // 4. Restore welcome screen
        if (welcomeCard) {
            welcomeCard.style.display = "block";
            conversationFeed.scrollTop = 0;
        }

        currentSessionId++;
        assistantStatusText.textContent = "Online • Ready for your next task";
        if (btnNavHome) btnNavHome.classList.add("active");
        logAudit("NEW_CHAT", `Started fresh conversation session #${currentSessionId}.`);
    }

    if (btnNavHome) {
        btnNavHome.addEventListener("click", navigateHome);
    }

    if (btnNavNewChat) {
        btnNavNewChat.addEventListener("click", startNewChat);
    }

    // 7. Check Backend Health
    async function checkBackendHealth() {
        try {
            const res = await fetch(`${API_BASE_URL}/api/health`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            
            systemHealthDot.className = "pill-dot";
            systemHealthText.textContent = "Online";
            assistantStatusText.textContent = "Online • Ready for your next task";
            logAudit("HEALTH", `Connected to backend. Key ready: ${data.detectifai_key_configured}`);
        } catch (err) {
            systemHealthDot.className = "pill-dot offline";
            systemHealthText.textContent = "Offline";
            assistantStatusText.textContent = "Offline • Cannot reach backend";
            logAudit("HEALTH_ERROR", `Failed connecting to backend: ${err.message}`);
        }
    }

    // 7. Conversation Stream Helpers
    function appendUserMessage(text, hasVoice = false, voiceDuration = 0) {
        const row = document.createElement("div");
        row.className = "message-row user-row";

        let voiceBadgeHtml = "";
        if (hasVoice) {
            voiceBadgeHtml = `
                <div class="user-voice-badge">
                    <svg viewBox="0 0 24 24" fill="currentColor" style="width:12px;height:12px;">
                        <path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z"/>
                    </svg>
                    Voice Command (${voiceDuration.toFixed(1)}s)
                </div>
            `;
        }

        row.innerHTML = `
            <div class="message-bubble">
                ${voiceBadgeHtml}
                <div class="user-message-text">${escapeHtml(text || (hasVoice ? "Transcribing voice command..." : "Task request"))}</div>
            </div>
        `;
        conversationFeed.appendChild(row);
        conversationFeed.scrollTop = conversationFeed.scrollHeight;
        return row;
    }

    function appendAssistantLoading() {
        const row = document.createElement("div");
        row.className = "message-row assistant-row assistant-loading-row";
        row.innerHTML = `
            <div class="assistant-avatar-small">✨</div>
            <div class="message-bubble">
                <div style="display:flex;align-items:center;gap:8px;color:var(--text-secondary);font-size:13.5px;">
                    <span class="live-pulse-dot"></span>
                    <span>Interpreting task and checking safety protocols...</span>
                </div>
            </div>
        `;
        conversationFeed.appendChild(row);
        conversationFeed.scrollTop = conversationFeed.scrollHeight;
        return row;
    }

    function renderAssistantResponse(data) {
        const row = document.createElement("div");
        row.className = "message-row assistant-row";

        const plan = data.plan || {};
        const execution = data.execution;
        const status = data.status || "COMPLETED";
        const message = data.assistant_message || "Task processed.";
        const action = plan.action || "general_task";

        let stepsHtml = "";
        if (plan.steps && plan.steps.length) {
            const stepsList = plan.steps.map(s => `
                <li class="plan-step-item">
                    <span class="step-bullet"></span>
                    <span>${escapeHtml(s)}</span>
                </li>
            `).join("");

            const isChallenge = plan.sensitivity === 'HIGH' || plan.sensitivity === 'MEDIUM';
            const badgeClass = isChallenge ? 'badge-challenge' : 'badge-allow';

            stepsHtml = `
                <div class="plan-progress-box">
                    <div class="plan-progress-header">
                        <span class="plan-action-label">Action Plan: ${escapeHtml(action)}</span>
                        <span class="badge ${badgeClass}">${plan.sensitivity || 'SAFE'}</span>
                    </div>
                    <ul class="plan-steps-list">
                        ${stepsList}
                    </ul>
                </div>
            `;
        }

        let outputContentHtml = "";
        const policyDecision = (data.diagnostics && data.diagnostics.policy_decision) || "";

        // Status: NEEDS_AUTHORIZATION (Only when backend policy explicitly requires owner confirmation)
        if (status === "NEEDS_AUTHORIZATION" && (policyDecision === "OWNER_CONFIRMATION_REQUIRED" || data.authorization_required)) {
            const authDetails = data.authorization_details || {};
            const authToken = authDetails.auth_token;
            outputContentHtml = `
                <div class="auth-challenge-card" id="authCard_${authToken}">
                    <div class="auth-challenge-header">
                        <span class="auth-key-icon">🔑</span>
                        <h4>Authorization Required</h4>
                    </div>
                    <p class="auth-challenge-desc">
                        ${escapeHtml(message)}
                    </p>
                    <div class="auth-actions-row">
                        <button type="button" class="btn-authorize" data-token="${authToken}" data-action="${escapeHtml(authDetails.action || '')}">
                            Authorize Action (Owner Approval)
                        </button>
                        <button type="button" class="btn-decline" data-token="${authToken}">
                            Decline & Cancel
                        </button>
                    </div>
                </div>
            `;
        } else if (status === "BLOCKED" || policyDecision === "HOLD") {
            // Status: BLOCKED
            outputContentHtml = `
                <div class="blocked-card">
                    <span class="blocked-icon">🛡️</span>
                    <div class="blocked-text">${escapeHtml(message)}</div>
                </div>
            `;
        } else if (execution) {
            // Status: COMPLETED with Execution Output
            if (action === "draft_message") {
                outputContentHtml = `
                    <div class="result-card draft-result">
                        <div class="result-header">
                            <span class="result-title">📝 Draft Formulated</span>
                            <button type="button" class="btn-copy" onclick="navigator.clipboard.writeText(this.getAttribute('data-text'))" data-text="${escapeHtml(execution.result_text)}">Copy Draft</button>
                        </div>
                        <div class="draft-content-text">${escapeHtml(execution.result_text)}</div>
                    </div>
                `;
            } else if (execution.is_simulated) {
                // Simulated Action (Purchase, Transfer, Send Email)
                outputContentHtml = `
                    <div class="sim-receipt-box">
                        <div class="sim-receipt-header">
                            <span style="font-weight:600;font-size:13px;color:var(--emerald-primary);">Sandbox Simulation Result</span>
                            <span class="sim-tag">SIMULATED SANDBOX</span>
                        </div>
                        <p style="font-size:13.5px;color:var(--text-primary);margin-bottom:8px;">${escapeHtml(execution.result_text)}</p>
                        <div class="sim-data-grid">
                            <div class="sim-data-item">
                                <span>Sandbox ID:</span>
                                <code>${execution.simulated_id || "sim_demo"}</code>
                            </div>
                            <div class="sim-data-item">
                                <span>Reference:</span>
                                <code>${execution.simulated_order_id || execution.simulated_txn_hash || execution.simulated_queue || "sim_ref"}</code>
                            </div>
                        </div>
                        <div class="sim-disclaimer">
                            ${escapeHtml(execution.disclaimer || "Sandbox Simulation Only — Zero actual financial transactions or emails executed.")}
                        </div>
                    </div>
                `;
            } else {
                // General text / Summary / Telemetry
                outputContentHtml = `
                    <div class="result-card">
                        <div style="font-size:14px;color:var(--text-primary);white-space:pre-wrap;line-height:1.6;">${escapeHtml(message)}</div>
                    </div>
                `;
            }
        } else {
            outputContentHtml = `
                <div style="margin-top:10px;font-size:14px;line-height:1.6;">${escapeHtml(message)}</div>
            `;
        }

        row.innerHTML = `
            <div class="assistant-avatar-small">✨</div>
            <div class="message-bubble">
                ${stepsHtml}
                ${outputContentHtml}
            </div>
        `;

        conversationFeed.appendChild(row);
        conversationFeed.scrollTop = conversationFeed.scrollHeight;

        // Attach Authorization Listeners if card was rendered
        attachAuthorizationHandlers(row);

        // Update Developer Diagnostics Drawer
        updateDeveloperDiagnostics(data);
    }

    function attachAuthorizationHandlers(container) {
        const btnAuth = container.querySelector(".btn-authorize");
        const btnDec = container.querySelector(".btn-decline");

        if (btnAuth) {
            btnAuth.addEventListener("click", async () => {
                const token = btnAuth.getAttribute("data-token");
                btnAuth.disabled = true;
                btnAuth.textContent = "Authorizing...";
                logAudit("OWNER_AUTH", `Owner submitted secondary approval for token: ${token.substring(0, 10)}...`);

                try {
                    const action = btnAuth.getAttribute("data-action");
                    const res = await fetch(`${API_BASE_URL}/api/agent/authorize`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ auth_token: token, approve: true, action: action || undefined })
                    });
                    const data = await res.json();
                    
                    const card = container.querySelector(`#authCard_${token}`);
                    if (card && data.execution) {
                        card.innerHTML = `
                            <div style="color:var(--emerald-primary);font-size:13.5px;font-weight:600;margin-bottom:8px;">
                                ✓ Authorization Confirmed
                            </div>
                            <p style="font-size:13.5px;color:var(--text-primary);margin-bottom:8px;">${escapeHtml(data.execution.result_text)}</p>
                            <div class="sim-disclaimer">${escapeHtml(data.execution.disclaimer || "Sandbox Simulation Only")}</div>
                        `;
                    }
                    updateDeveloperDiagnostics({
                        diagnostics: {
                            policy_decision: "ALLOW_AFTER_OWNER_CONFIRMATION",
                            server_gate: "UNLOCKED_OWNER_CONFIRMED"
                        }
                    });
                } catch (err) {
                    console.error("Authorization error:", err);
                    btnAuth.disabled = false;
                    btnAuth.textContent = "Retry Authorization";
                }
            });
        }

        if (btnDec) {
            btnDec.addEventListener("click", async () => {
                const token = btnDec.getAttribute("data-token");
                btnDec.disabled = true;
                logAudit("OWNER_DECLINE", `Owner declined authorization for token: ${token.substring(0, 10)}...`);

                try {
                    const res = await fetch(`${API_BASE_URL}/api/agent/authorize`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ auth_token: token, approve: false })
                    });
                    const data = await res.json();
                    const card = container.querySelector(`#authCard_${token}`);
                    if (card) {
                        card.innerHTML = `
                            <div style="color:var(--rose-primary);font-size:13.5px;font-weight:600;">
                                ✕ Action Cancelled by Owner
                            </div>
                        `;
                    }
                    updateDeveloperDiagnostics({
                        diagnostics: {
                            policy_decision: "HOLD_USER_CANCELLED",
                            server_gate: "REJECTED_BY_OWNER"
                        }
                    });
                } catch (err) {
                    console.error("Decline error:", err);
                }
            });
        }
    }

    // 8. Update Developer Diagnostics Panel (Hidden from ordinary users)
    function updateDeveloperDiagnostics(data) {
        const diag = data.diagnostics || {};
        const detection = diag.detection || {};
        const policyDecision = diag.policy_decision || "ALLOW";
        const gate = diag.server_gate || "UNLOCKED";
        const reason = diag.policy_reason || "Safe permitted action.";
        const targetAct = (data.plan && data.plan.action) || "task";

        // DetectifAI details
        if (detection.uploaded) {
            if (detection.verdict) {
                const v = detection.verdict.toLowerCase();
                diagVerdictBadge.textContent = detection.verdict.toUpperCase();
                diagVerdictBadge.className = `badge ${v === 'real' ? 'badge-allow' : v === 'fake' ? 'badge-hold' : 'badge-challenge'}`;
                diagScoreVal.textContent = typeof detection.score === "number" ? detection.score.toFixed(4) : "N/A";
                diagRequestIdVal.textContent = detection.request_id || "req_live";
                logAudit("DETECTIFAI_SCAN", `Verdict: ${detection.verdict}, Score: ${detection.score}, Req: ${detection.request_id}`);
            } else {
                diagVerdictBadge.textContent = "AUDIO ERROR (FAIL CLOSED)";
                diagVerdictBadge.className = "badge badge-hold";
                diagScoreVal.textContent = "—";
                diagRequestIdVal.textContent = detection.request_id || "error";
                logAudit("DETECTIFAI_ERROR", `Audio verification failed closed: ${detection.error || "Provider error"}`);
            }
        } else {
            diagVerdictBadge.textContent = "TEXT INPUT (NO AUDIO)";
            diagVerdictBadge.className = "badge";
            diagScoreVal.textContent = "—";
            diagRequestIdVal.textContent = "—";
        }

        // AgentShield policy details
        diagTargetAction.textContent = targetAct;
        diagDecisionBadge.textContent = policyDecision;
        diagDecisionBadge.className = `badge ${policyDecision === 'ALLOW' || policyDecision.startsWith('ALLOW') ? 'badge-allow' : policyDecision === 'HOLD' ? 'badge-hold' : 'badge-challenge'}`;
        diagGateStatus.textContent = gate;
        diagRationaleText.textContent = reason;

        logAudit("POLICY_GATE", `Decision: ${policyDecision}, Gate: ${gate}`);
    }

    // 9. Dispatch Task to Backend Agent
    async function submitTask(taskText) {
        let cleanedText = (taskText || "").trim();
        if (!cleanedText && recognizedSpeechText) {
            cleanedText = recognizedSpeechText.trim();
        }
        if (!cleanedText && !recordedAudioBlob) return;

        // Hide welcome card upon first task and deactivate home button state
        if (welcomeCard) welcomeCard.style.display = "none";
        if (btnNavHome) btnNavHome.classList.remove("active");

        // Show user message in conversation
        const userRow = appendUserMessage(cleanedText, Boolean(recordedAudioBlob), recordedDurationSeconds);

        // Preserve audio attachment references before resetting inputs
        const activeRecordedBlob = recordedAudioBlob;
        const activeRecordedDuration = recordedDurationSeconds;
        const activeRecordedExt = recordedFileExtension || "wav";

        // Clear composer input and recognized speech
        taskInput.value = "";
        taskInput.style.height = "auto";
        btnSendTask.disabled = true;
        recognizedSpeechText = "";

        // Show assistant loading state
        const loadingRow = appendAssistantLoading();
        assistantStatusText.textContent = "Planning & executing...";
        logAudit("TASK_START", `User prompt: "${cleanedText}"`);

        try {
            const formData = new FormData();
            formData.append("task", cleanedText);

            if (activeRecordedBlob) {
                formData.append("file", activeRecordedBlob, `voice_task.${activeRecordedExt}`);
                logAudit("AUDIO_DISPATCH", `Submitting audio (${activeRecordedDuration.toFixed(1)}s) to backend...`);
            }

            const res = await fetch(`${API_BASE_URL}/api/agent/task`, {
                method: "POST",
                body: formData
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || `Server error (HTTP ${res.status})`);
            }

            const data = await res.json();
            loadingRow.remove();

            // If backend transcribed voice speech, reflect the real transcript in the user row
            if (data.transcript && userRow) {
                const textEl = userRow.querySelector(".user-message-text");
                if (textEl) {
                    textEl.textContent = data.transcript;
                }
            }

            renderAssistantResponse(data);
        } catch (err) {
            console.error("Task dispatch error:", err);
            loadingRow.remove();
            renderAssistantResponse({
                status: "BLOCKED",
                assistant_message: `I couldn't safely proceed with this action. An error occurred (${err.message}).`,
                diagnostics: {
                    policy_decision: "HOLD",
                    server_gate: "LOCKED_ERROR",
                    policy_reason: err.message
                }
            });
            logAudit("ERROR", `Task dispatch failed: ${err.message}`);
        } finally {
            btnSendTask.disabled = false;
            assistantStatusText.textContent = "Online • Ready for your next task";
            // Clear voice attachment after dispatch
            clearVoiceAttachment();
        }
    }

    // 10. Quick Suggestion Prompt Chips
    promptChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const task = chip.getAttribute("data-task");
            submitTask(task);
        });
    });

    // 11. Send Task on Button Click or Enter Key
    btnSendTask.addEventListener("click", () => {
        submitTask(taskInput.value);
    });

    taskInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
            e.preventDefault();
            submitTask(taskInput.value);
        }
    });

    taskInput.addEventListener("input", () => {
        taskInput.style.height = "auto";
        taskInput.style.height = `${Math.min(taskInput.scrollHeight, 120)}px`;
    });

    // 12. Voice Recording Flow (Microphone + MediaRecorder + WAV Downsampling)
    btnRecordVoice.addEventListener("click", async () => {
        if (isRecording) {
            stopRecording(true);
            return;
        }

        try {
            mediaStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                }
            });
        } catch (err) {
            console.error("Microphone error:", err);
            logAudit("MIC_ERROR", `Microphone error: ${err.message}`);
            alert(`Microphone access error: ${err.message}. Please allow microphone permissions.`);
            return;
        }

        startRecording();
    });

    function startRecording() {
        recordedChunks = [];
        const options = { mimeType: "audio/webm;codecs=opus" };
        try {
            mediaRecorder = new MediaRecorder(mediaStream, options);
        } catch (e) {
            mediaRecorder = new MediaRecorder(mediaStream);
        }

        mediaRecorder.ondataavailable = (e) => {
            if (e.data && e.data.size > 0) {
                recordedChunks.push(e.data);
            }
        };

        mediaRecorder.onstop = () => {
            processRecordedAudio();
        };

        // Initialize Web Audio visualizer
        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            audioContext = new AudioCtx();
            if (audioContext.state === "suspended") {
                audioContext.resume();
            }
            sourceNode = audioContext.createMediaStreamSource(mediaStream);
            analyserNode = audioContext.createAnalyser();
            analyserNode.fftSize = 256;
            sourceNode.connect(analyserNode);
        } catch (e) {
            console.warn("Visualizer warning:", e);
        }

        mediaRecorder.start(200);
        isRecording = true;
        recordingStartTime = performance.now();
        recognizedSpeechText = "";
        logAudit("RECORD_START", "Microphone recording started.");

        // Start live browser speech recognition if supported
        try {
            const SpeechRec = window.SpeechRecognition || window.webkitSpeechRecognition;
            if (SpeechRec) {
                activeSpeechRecognizer = new SpeechRec();
                activeSpeechRecognizer.continuous = true;
                activeSpeechRecognizer.interimResults = true;
                activeSpeechRecognizer.lang = "en-US";
                activeSpeechRecognizer.onresult = (event) => {
                    let fullText = "";
                    for (let i = 0; i < event.results.length; ++i) {
                        fullText += event.results[i][0].transcript + " ";
                    }
                    const trimmed = fullText.trim();
                    if (trimmed) {
                        recognizedSpeechText = trimmed;
                        taskInput.value = trimmed;
                        taskInput.style.height = `${Math.min(taskInput.scrollHeight, 120)}px`;
                        dockDurationHint.textContent = `Recognized: "${trimmed}"`;
                    }
                };
                activeSpeechRecognizer.onerror = (e) => {
                    console.warn("SpeechRecognition notice:", e.error);
                };
                activeSpeechRecognizer.start();
            }
        } catch (sttErr) {
            console.warn("Browser SpeechRecognition unavailable:", sttErr);
        }

        recordingDock.style.display = "block";
        dockTimer.textContent = "00:00";
        dockDurationHint.textContent = "Requires at least 4.0 seconds of speech for authenticity verification.";
        dockDurationHint.style.color = "var(--text-muted)";

        timerInterval = setInterval(() => {
            const elapsed = (performance.now() - recordingStartTime) / 1000;
            const mins = Math.floor(elapsed / 60).toString().padStart(2, "0");
            const secs = Math.floor(elapsed % 60).toString().padStart(2, "0");
            dockTimer.textContent = `${mins}:${secs}`;

            if (elapsed >= MIN_DURATION_SECONDS) {
                dockDurationHint.textContent = "Valid duration reached. Click 'Done Speaking' when finished.";
                dockDurationHint.style.color = "var(--emerald-primary)";
            }

            if (elapsed >= MAX_DURATION_SECONDS) {
                stopRecording(true);
            }
        }, 150);

        drawDockWaveform();
    }

    function stopRecording(saveAudio = true) {
        if (!isRecording) return;
        isRecording = false;

        clearInterval(timerInterval);
        if (animFrameId) cancelAnimationFrame(animFrameId);

        if (mediaRecorder && mediaRecorder.state !== "inactive") {
            try {
                mediaRecorder.stop();
            } catch (e) {
                console.error(e);
            }
        }

        if (activeSpeechRecognizer) {
            try {
                activeSpeechRecognizer.stop();
            } catch (e) {}
            activeSpeechRecognizer = null;
        }

        if (sourceNode) sourceNode.disconnect();
        if (analyserNode) analyserNode.disconnect();
        if (mediaStream) {
            mediaStream.getTracks().forEach(t => t.stop());
            mediaStream = null;
        }
        if (audioContext && audioContext.state !== "closed") {
            audioContext.close();
            audioContext = null;
        }

        recordingDock.style.display = "none";
        clearDockCanvas();

        if (!saveAudio) {
            recordedChunks = [];
            logAudit("RECORD_CANCEL", "Recording discarded by user.");
        }
    }

    btnDockCancel.addEventListener("click", () => {
        stopRecording(false);
    });

    btnDockDone.addEventListener("click", () => {
        const elapsed = (performance.now() - recordingStartTime) / 1000;
        if (elapsed < MIN_DURATION_SECONDS) {
            alert(`Please record at least 4.0 seconds of audio. Current: ${elapsed.toFixed(1)}s`);
            return;
        }
        stopRecording(true);
    });

    // 13. Process & Convert Audio into 16-bit 16000 Hz PCM WAV
    async function processRecordedAudio() {
        if (!recordedChunks.length) return;

        const rawBlob = new Blob(recordedChunks, { type: "audio/webm" });
        const elapsedSec = (performance.now() - recordingStartTime) / 1000;

        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            const decodeCtx = new AudioCtx();
            const arrayBuf = await rawBlob.arrayBuffer();
            const audioBuffer = await decodeCtx.decodeAudioData(arrayBuf);
            decodeCtx.close();

            const targetSampleRate = 16000;
            const channelData = audioBuffer.getChannelData(0);
            const downsampled = downsampleAudio(channelData, audioBuffer.sampleRate, targetSampleRate);
            const wavBuffer = encodeWavBuffer(downsampled, targetSampleRate);

            recordedAudioBlob = new Blob([wavBuffer], { type: "audio/wav" });
            recordedDurationSeconds = downsampled.length / targetSampleRate;
            recordedFileExtension = "wav";
        } catch (convErr) {
            console.warn("WAV downsampling fallback:", convErr);
            recordedAudioBlob = rawBlob;
            recordedDurationSeconds = Math.round(elapsedSec * 10) / 10;
            recordedFileExtension = "webm";
        }

        logAudit("AUDIO_READY", `Audio encoded: ${recordedDurationSeconds.toFixed(1)}s (16-bit PCM WAV)`);

        // Show attachment in composer
        if (attachmentAudioPlayer.src && attachmentAudioPlayer.src.startsWith("blob:")) {
            URL.revokeObjectURL(attachmentAudioPlayer.src);
        }
        attachmentAudioPlayer.src = URL.createObjectURL(recordedAudioBlob);
        attachmentDurationText.textContent = `Voice Audio Attached (${recordedDurationSeconds.toFixed(1)}s)`;
        voiceAttachmentPreview.style.display = "flex";

        if (!taskInput.value.trim()) {
            taskInput.placeholder = "Add optional notes or click Send to execute voice command...";
        }
    }

    function clearVoiceAttachment() {
        recordedAudioBlob = null;
        recordedChunks = [];
        recordedDurationSeconds = 0;
        if (attachmentAudioPlayer.src && attachmentAudioPlayer.src.startsWith("blob:")) {
            URL.revokeObjectURL(attachmentAudioPlayer.src);
        }
        attachmentAudioPlayer.src = "";
        voiceAttachmentPreview.style.display = "none";
        taskInput.placeholder = "Ask Aura anything or give a task...";
    }

    btnRemoveVoiceAttachment.addEventListener("click", () => {
        clearVoiceAttachment();
        logAudit("AUDIO_REMOVE", "Voice audio attachment removed.");
    });

    // 14. Audio Math: Downsampling & WAV Encoding
    function downsampleAudio(buffer, inputRate, outputRate) {
        if (!inputRate || inputRate === outputRate) return buffer;
        const ratio = inputRate / outputRate;
        const newLength = Math.round(buffer.length / ratio);
        const result = new Float32Array(newLength);
        let offsetResult = 0;
        let offsetBuffer = 0;

        while (offsetResult < result.length) {
            const nextOffsetBuffer = Math.round((offsetResult + 1) * ratio);
            let accum = 0, count = 0;
            for (let i = offsetBuffer; i < nextOffsetBuffer && i < buffer.length; i++) {
                accum += buffer[i];
                count++;
            }
            result[offsetResult] = count > 0 ? accum / count : 0;
            offsetResult++;
            offsetBuffer = nextOffsetBuffer;
        }
        return result;
    }

    function encodeWavBuffer(samples, sampleRate) {
        const numChannels = 1;
        const bitsPerSample = 16;
        const bytesPerSample = bitsPerSample / 8;
        const dataLength = samples.length * bytesPerSample;
        const buffer = new ArrayBuffer(44 + dataLength);
        const view = new DataView(buffer);

        writeString(view, 0, "RIFF");
        view.setUint32(4, 36 + dataLength, true);
        writeString(view, 8, "WAVE");

        writeString(view, 12, "fmt ");
        view.setUint32(16, 16, true);
        view.setUint16(20, 1, true); // PCM
        view.setUint16(22, numChannels, true);
        view.setUint32(24, sampleRate, true);
        view.setUint32(28, sampleRate * numChannels * bytesPerSample, true);
        view.setUint16(32, numChannels * bytesPerSample, true);
        view.setUint16(34, bitsPerSample, true);

        writeString(view, 36, "data");
        view.setUint32(40, dataLength, true);

        let pcmOffset = 44;
        for (let i = 0; i < samples.length; i++) {
            const s = Math.max(-1, Math.min(1, samples[i]));
            view.setInt16(pcmOffset, s < 0 ? s * 0x8000 : s * 0x7FFF, true);
            pcmOffset += 2;
        }
        return buffer;
    }

    function writeString(view, offset, string) {
        for (let i = 0; i < string.length; i++) {
            view.setUint8(offset + i, string.charCodeAt(i));
        }
    }

    // 15. Oscilloscope Visualizer
    function drawDockWaveform() {
        if (!analyserNode || !isRecording) return;
        const canvasCtx = dockWaveformCanvas.getContext("2d");
        const bufferLength = analyserNode.frequencyBinCount;
        const dataArray = new Uint8Array(bufferLength);
        analyserNode.getByteTimeDomainData(dataArray);

        const width = dockWaveformCanvas.width;
        const height = dockWaveformCanvas.height;

        canvasCtx.fillStyle = "#050810";
        canvasCtx.fillRect(0, 0, width, height);

        canvasCtx.lineWidth = 2;
        canvasCtx.strokeStyle = "#38BDF8";
        canvasCtx.beginPath();

        const sliceWidth = width / bufferLength;
        let x = 0;

        for (let i = 0; i < bufferLength; i++) {
            const v = dataArray[i] / 128.0;
            const y = (v * height) / 2;
            if (i === 0) {
                canvasCtx.moveTo(x, y);
            } else {
                canvasCtx.lineTo(x, y);
            }
            x += sliceWidth;
        }

        canvasCtx.lineTo(width, height / 2);
        canvasCtx.stroke();

        animFrameId = requestAnimationFrame(drawDockWaveform);
    }

    function clearDockCanvas() {
        const canvasCtx = dockWaveformCanvas.getContext("2d");
        canvasCtx.fillStyle = "#050810";
        canvasCtx.fillRect(0, 0, dockWaveformCanvas.width, dockWaveformCanvas.height);
    }

    // 16. Initialize Application
    checkBackendHealth();
    logAudit("APP_INIT", "Aura Personal AI Assistant frontend initialized.");
})();
