import { challenges, getVisibleChallenges } from "./challenges.js";

const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? `http://${location.hostname}:3001` : "";
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const wsHost = isDev ? `${location.hostname}:3001` : location.host;

let socket = null;
let currentLayout = null;
let solvedChallengeIds = getSolvedChallengeIdsFromCookie();
let timerCheckInterval = null;

function setupStateTimer(timerEnd) {
    if (timerCheckInterval) {
        clearInterval(timerCheckInterval);
        timerCheckInterval = null;
    }
    if (timerEnd && typeof timerEnd === "number") {
        timerCheckInterval = setInterval(() => {
            if (Date.now() >= timerEnd && currentLayout === "start") {
                clearInterval(timerCheckInterval);
                timerCheckInterval = null;
                render({ layout: "end" });
            }
        }, 500);
    }
}

function getSolvedChallengeIdsFromCookie() {
    for (const cookie of document.cookie.split(";")) {
        const [key, ...value] = cookie.trim().split("=");
        if (key === "ctf_progress") {
            try {
                const parsed = JSON.parse(decodeURIComponent(value.join("=")));
                if (parsed && Array.isArray(parsed.solved)) {
                    return new Set(parsed.solved);
                }
            } catch {
                return new Set();
            }
        }
    }
    return new Set();
}

async function refreshProgress() {
    try {
        const response = await fetch(`${apiBase}/progress`, {
            credentials: "include"
        });
        if (!response.ok) return;
        const progress = await response.json();
        if (progress) {
            const pointsEl = document.getElementById("navPoints");
            if (pointsEl && typeof progress.points === "number") {
                pointsEl.textContent = progress.points;
            }
            if (Array.isArray(progress.solved)) {
                const prevIds = [...solvedChallengeIds].sort().join(",");
                const newIds = [...progress.solved].sort().join(",");
                solvedChallengeIds = new Set(progress.solved);
                if (prevIds !== newIds && currentLayout === "start") {
                    renderChallenges();
                }
            }
        }
    } catch (err) {
        console.error("Could not fetch progress:", err);
    }
}

async function checkSession() {
    try {
        const response = await fetch(`${apiBase}/session`, {
            credentials: "include"
        });

        if (!response.ok) {
            window.location.assign("/login.html");
            return false;
        }

        const data = await response.json();
        console.log("Logged in as:", data.teamName);

        const nav = document.getElementById("ctfNavbar");
        if (nav) {
            const teamEl = document.getElementById("navTeamName");
            const pointsEl = document.getElementById("navPoints");
            if (teamEl) teamEl.textContent = data.teamName || "";
            if (pointsEl) pointsEl.textContent = data.points ?? 0;
            nav.style.display = "flex";
        }

        return true;
    } catch (error) {
        console.error(error);
        window.location.assign("/login.html");
        return false;
    }
}

function setupLogout() {
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", async () => {
            logoutBtn.disabled = true;
            try {
                const bc = new BroadcastChannel("ctf_progress");
                bc.postMessage({ type: "auth_change", loggedIn: false });
                bc.close();
            } catch {}
            try {
                await fetch(`${apiBase}/logout`, {
                    method: "POST",
                    credentials: "include"
                });
            } catch (err) {
                console.error("Logout network error:", err);
            }
            document.cookie = "session=; Max-Age=0; path=/;";
            document.cookie = "ctf_progress=; Max-Age=0; path=/;";
            window.location.replace("/login.html");
        });
    }
}

function connectWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        return;
    }

    socket = new WebSocket(`${wsProtocol}//${wsHost}`);

    socket.addEventListener("open", () => {
        console.log("Connected to CTF event stream");
        try {
            socket.send(JSON.stringify({ type: "identify" }));
        } catch {}
    });

    socket.addEventListener("message", event => {
        try {
            const state = JSON.parse(event.data);
            if (state && state.type === "progress") {
                const pointsEl = document.getElementById("navPoints");
                if (pointsEl && typeof state.points === "number") {
                    pointsEl.textContent = state.points;
                }
                if (Array.isArray(state.solved)) {
                    const prevIds = [...solvedChallengeIds].sort().join(",");
                    const newIds = [...state.solved].sort().join(",");
                    solvedChallengeIds = new Set(state.solved);
                    if (prevIds !== newIds && currentLayout === "start") {
                        renderChallenges();
                    }
                }
                return;
            }
            if (state && typeof state.layout === "string") {
                setupStateTimer(state.timerEnd);
                render(state);
            }
        } catch (err) {
            console.error("Malformed state payload:", err);
        }
    });

    socket.addEventListener("close", () => {
        console.log("Disconnected from server. Reconnecting in 3 seconds...");
        setTimeout(connectWebSocket, 3000);
    });

    socket.addEventListener("error", err => {
        console.error("WebSocket connection error:", err);
    });
}

function renderChallenges() {
    const app = document.querySelector(".main_bg");
    if (!app || currentLayout !== "start") return;

    app.replaceChildren();

    const title = document.createElement("h1small");
    title.textContent = "Challenges? We've got plenty.";

    const mainFlexbox = document.createElement("div");
    mainFlexbox.classList.add("mainFlexbox");

    const visibleChallenges = getVisibleChallenges(challenges, solvedChallengeIds);

    let i = 0;
    for (const challenge of visibleChallenges) {
        const details = document.createElement("details");

        details.style.setProperty("--gradient-start", `${50 - i * 20}%`);
        details.style.setProperty("--gradient-mid", `${100 - i * 30}%`);
        details.style.setProperty("--border-gradient-degree", `${(i * 60 + 45) % 360}deg`);

        details.dataset.id = challenge.id;
        details.dataset.category = challenge.category || "General";

        const summary = document.createElement("summary");

        const titleSpan = document.createElement("span");
        titleSpan.classList.add("challengeTitle");
        // Dynamically name sequentially as revealed (Challenge 1, Challenge 2, ...)
        titleSpan.textContent = `Challenge ${i + 1}`;

        // Category tag placed inside summary so it is visible even when details tag is closed
        const categoryTag = document.createElement("span");
        categoryTag.classList.add("categoryTag");
        categoryTag.textContent = challenge.category || "General";

        summary.append(titleSpan, categoryTag);

        const content = document.createElement("p");
        content.textContent = challenge.description;

        const challengeLink = document.createElement("a");
        challengeLink.textContent = "Try me ↗";
        challengeLink.href = challenge.link;

        details.append(summary, content, challengeLink);
        mainFlexbox.append(details);

        i++;
    }

    app.append(title, mainFlexbox);
}

function render(state) {
    if (!state || !state.layout) return;
    if (currentLayout === state.layout && state.layout !== "start") return; // Prevent unnecessary DOM churn
    currentLayout = state.layout;

    const app = document.querySelector(".main_bg");
    if (!app) return;

    if (state.layout === "wait") {
        app.classList.remove("start");
        app.replaceChildren();

        const title = document.createElement("h1");
        title.textContent = "Hello There!";

        const message = document.createElement("subtitle");
        message.textContent = "Hang tight, the event starts shortly.";

        app.append(title, message);
    } else if (state.layout === "start") {
        app.classList.add("start");
        renderChallenges();
    } else if (state.layout === "end") {
        app.classList.remove("start");
        app.replaceChildren();

        const title = document.createElement("h1");
        title.textContent = "The event has ended.";

        app.append(title);
    }
}

async function start() {
    // Show default initial lobby state immediately while verifying session
    render({ layout: "wait" });

    const loggedIn = await checkSession();
    if (!loggedIn) {
        return;
    }

    await refreshProgress();
    setupLogout();
    connectWebSocket();

    // Listen to local BroadcastChannel for instant cross-tab score/progress synchronization
    try {
        const bc = new BroadcastChannel("ctf_progress");
        bc.onmessage = (event) => {
            if (event.data && event.data.type === "auth_change") {
                if (!event.data.loggedIn) {
                    window.location.replace("/login.html");
                    return;
                }
                checkSession();
                refreshProgress();
            }
            if (event.data && typeof event.data.points === "number") {
                const pointsEl = document.getElementById("navPoints");
                if (pointsEl) pointsEl.textContent = event.data.points;
            }
            if (event.data && Array.isArray(event.data.solved)) {
                const prevIds = [...solvedChallengeIds].sort().join(",");
                const newIds = [...event.data.solved].sort().join(",");
                solvedChallengeIds = new Set(event.data.solved);
                if (prevIds !== newIds && currentLayout === "start") {
                    renderChallenges();
                }
            }
        };
    } catch {}

    // Periodic background sync and on tab focus
    setInterval(refreshProgress, 4000);
    window.addEventListener("focus", refreshProgress);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) {
            refreshProgress();
        }
    });
}

start();
