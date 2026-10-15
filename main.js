import { challenges } from "./challenges.js";

const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? `http://${location.hostname}:3001` : "";
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const wsHost = isDev ? `${location.hostname}:3001` : location.host;

let socket = null;
let currentLayout = null;

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
        return true;
    } catch (error) {
        console.error(error);
        window.location.assign("/login.html");
        return false;
    }
}

function connectWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        return;
    }

    socket = new WebSocket(`${wsProtocol}//${wsHost}`);

    socket.addEventListener("open", () => {
        console.log("Connected to CTF event stream");
    });

    socket.addEventListener("message", event => {
        try {
            const state = JSON.parse(event.data);
            if (state && typeof state.layout === "string") {
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

async function start() {
    // Show default initial lobby state immediately while verifying session
    render({ layout: "wait" });

    const loggedIn = await checkSession();
    if (!loggedIn) {
        return;
    }

    connectWebSocket();
}

function render(state) {
    if (!state || !state.layout) return;
    if (currentLayout === state.layout) return; // Prevent unnecessary DOM churn
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
        app.replaceChildren();

        const title = document.createElement("h1small");
        title.textContent = "Challenges? We've got plenty.";

        const mainFlexbox = document.createElement("div");
        mainFlexbox.classList.add("mainFlexbox");

        let i = 0;
        for (const challenge of challenges) {
            const details = document.createElement("details");

            details.style.setProperty("--gradient-start", `${50 - i * 20}%`);
            details.style.setProperty("--gradient-mid", `${100 - i * 30}%`);
            details.style.setProperty("--border-gradient-degree", `${(i * 60 + 45) % 360}deg`);

            const summary = document.createElement("summary");
            summary.textContent = challenge.title;

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
    } else if (state.layout === "end") {
        app.classList.remove("start");
        app.replaceChildren();

        const title = document.createElement("h1");
        title.textContent = "The event has ended.";

        app.append(title);
    }
}

start();
