const isDev = location.port === "5173" || location.port === "5174";
const apiHost = isDev ? "127.0.0.1:3001" : location.host;
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const httpProtocol = location.protocol === "https:" ? "https:" : "http:";

const layout = document.querySelector("#layout");
const update = document.querySelector("#update");
const adminTokenInput = document.querySelector("#adminToken");
const statusMessage = document.querySelector("#statusMessage");
const eventDurationInput = document.querySelector("#eventDuration");
const adminTimerPreview = document.querySelector("#adminTimerPreview");

// Load token from sessionStorage if previously saved
const savedToken = sessionStorage.getItem("ctf_admin_token");
if (savedToken) {
    adminTokenInput.value = savedToken;
}

let socket = null;
let currentTimerEnd = null;
let timerTicker = null;

function formatRemaining(ms) {
    if (ms <= 0) return "00:00:00 (Expired)";
    const totalSecs = Math.floor(ms / 1000);
    const h = String(Math.floor(totalSecs / 3600)).padStart(2, "0");
    const m = String(Math.floor((totalSecs % 3600) / 60)).padStart(2, "0");
    const s = String(totalSecs % 60).padStart(2, "0");
    return `${h}:${m}:${s}`;
}

function updateTimerPreview() {
    if (!adminTimerPreview) return;
    if (!currentTimerEnd) {
        adminTimerPreview.textContent = "No timer active";
        adminTimerPreview.style.color = "rgba(255, 255, 255, 0.5)";
        return;
    }
    const rem = currentTimerEnd - Date.now();
    if (rem <= 0) {
        adminTimerPreview.textContent = "Timer: 00:00:00 (Expired / Event Ended)";
        adminTimerPreview.style.color = "#f87171";
    } else {
        adminTimerPreview.textContent = `Timer running: ${formatRemaining(rem)} remaining (ends ${new Date(currentTimerEnd).toLocaleTimeString()})`;
        adminTimerPreview.style.color = "#38bdf8";
    }
}

function setStatus(msg, isError = false) {
    if (statusMessage) {
        statusMessage.textContent = msg;
        statusMessage.style.color = isError ? "#f87171" : "#4ade80";
    }
}

function handleStateMessage(data) {
    if (data.error) {
        setStatus(`Error: ${data.error}`, true);
        return;
    }
    if (data.layout) {
        layout.value = data.layout;
    }
    currentTimerEnd = data.timerEnd || null;
    updateTimerPreview();
    if (data.layout) {
        setStatus(`Current event state: ${data.layout}${currentTimerEnd ? ` | Timer active (${formatRemaining(currentTimerEnd - Date.now())})` : ""}`);
    }
}

function connect() {
    socket = new WebSocket(`${wsProtocol}//${apiHost}`);

    socket.addEventListener("open", () => {
        setStatus("Connected to server.");
    });

    socket.addEventListener("message", event => {
        try {
            const data = JSON.parse(event.data);
            handleStateMessage(data);
        } catch {}
    });

    socket.addEventListener("close", () => {
        setStatus("Disconnected from server. Reconnecting in 3s...", true);
        setTimeout(connect, 3000);
    });

    socket.addEventListener("error", () => {
        setStatus("Connection error.", true);
    });
}

connect();
if (!timerTicker) {
    timerTicker = setInterval(updateTimerPreview, 1000);
}

function isValidDuration(str) {
    if (!str) return true;
    const trimmed = str.trim();
    if (trimmed.toLowerCase() === "clear" || trimmed === "0" || trimmed === "00:00:00") return true;
    return /^([0-9]{1,2}):([0-5][0-9]):([0-5][0-9])$/.test(trimmed) || /^([0-5]?[0-9]):([0-5][0-9])$/.test(trimmed) || /^\d+$/.test(trimmed);
}

function isNonNullDuration(str) {
    if (!str) return false;
    const trimmed = str.trim();
    if (!trimmed || trimmed === "0" || trimmed === "00:00:00" || trimmed.toLowerCase() === "clear") return false;
    return isValidDuration(trimmed);
}

if (eventDurationInput) {
    eventDurationInput.addEventListener("input", () => {
        const val = eventDurationInput.value.trim();
        if (isNonNullDuration(val)) {
            layout.value = "start";
        }
    });
}

if (layout) {
    layout.addEventListener("change", () => {
        const val = eventDurationInput ? eventDurationInput.value.trim() : "";
        if (isNonNullDuration(val) && layout.value !== "start") {
            setStatus("If event duration is set, the only state that can be set is 'start'. Clear duration to choose Wait or End.", true);
        } else {
            setStatus("");
        }
    });
}

update.addEventListener("click", async () => {
    const token = adminTokenInput.value.trim();
    if (!token) {
        setStatus("Please enter the admin secret token.", true);
        adminTokenInput.focus();
        return;
    }

    const durationStr = eventDurationInput ? eventDurationInput.value.trim() : "";
    if (durationStr && !isValidDuration(durationStr)) {
        setStatus("Invalid duration format. Use HH:MM:SS (e.g. 01:30:00).", true);
        eventDurationInput.focus();
        return;
    }

    const requestedLayout = layout.value;

    // Constraint: if the event duration value isn't null, the only state that can be set is start
    if (isNonNullDuration(durationStr) && requestedLayout !== "start") {
        setStatus("If event duration is set, the only state that can be set is 'start'.", true);
        layout.focus();
        return;
    }

    sessionStorage.setItem("ctf_admin_token", token);

    update.disabled = true;
    setStatus("Updating state & timer...");

    const payload = {
        layout: requestedLayout,
        token
    };
    if (durationStr) {
        payload.duration = durationStr;
    }

    // Try WebSocket first
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(payload));
        setTimeout(() => { update.disabled = false; }, 400);
        return;
    }

    // Fallback to HTTP endpoint
    try {
        const response = await fetch(`${httpProtocol}//${apiHost}/admin/state`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-Admin-Token": token
            },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (response.ok && result.success) {
            handleStateMessage(result.state || { layout: requestedLayout });
            setStatus(`State updated to ${requestedLayout} successfully.`);
        } else {
            setStatus(`Update failed: ${result.error || "Unauthorized"}`, true);
        }
    } catch (err) {
        setStatus("Could not connect to server.", true);
    } finally {
        update.disabled = false;
    }
});
