const isDev = location.port === "5173" || location.port === "5174";
const apiHost = isDev ? "127.0.0.1:3001" : location.host;
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const httpProtocol = location.protocol === "https:" ? "https:" : "http:";

const layout = document.querySelector("#layout");
const update = document.querySelector("#update");
const adminTokenInput = document.querySelector("#adminToken");
const statusMessage = document.querySelector("#statusMessage");

// Load token from sessionStorage if previously saved
const savedToken = sessionStorage.getItem("ctf_admin_token");
if (savedToken) {
    adminTokenInput.value = savedToken;
}

let socket = null;

function setStatus(msg, isError = false) {
    if (statusMessage) {
        statusMessage.textContent = msg;
        statusMessage.style.color = isError ? "#f87171" : "#4ade80";
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
            if (data.error) {
                setStatus(`Error: ${data.error}`, true);
            } else if (data.layout) {
                layout.value = data.layout;
                setStatus(`Current event state: ${data.layout}`);
            }
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

update.addEventListener("click", async () => {
    const token = adminTokenInput.value.trim();
    if (!token) {
        setStatus("Please enter the admin secret token.", true);
        adminTokenInput.focus();
        return;
    }

    sessionStorage.setItem("ctf_admin_token", token);
    const requestedLayout = layout.value;

    update.disabled = true;
    setStatus("Updating state...");

    // Try WebSocket first
    if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({
            layout: requestedLayout,
            token
        }));
        setTimeout(() => { update.disabled = false; }, 300);
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
            body: JSON.stringify({ layout: requestedLayout })
        });

        const result = await response.json();
        if (response.ok && result.success) {
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
