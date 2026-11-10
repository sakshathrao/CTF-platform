const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? `http://${location.hostname}:3001` : "";
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const wsHost = isDev ? `${location.hostname}:3001` : location.host;

let socket = null;
let currentTeam = null;
let timerEnd = null;
let timerInterval = null;
let currentLayout = "wait";

const timerDigits = document.getElementById("timerDigits");
const timerLabel = document.getElementById("timerLabel");
const leaderboardBody = document.getElementById("leaderboardBody");
const emptyMessage = document.getElementById("emptyMessage");

function formatTime(totalSeconds) {
    if (totalSeconds <= 0) return "00:00:00";
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return [
        String(hours).padStart(2, "0"),
        String(minutes).padStart(2, "0"),
        String(seconds).padStart(2, "0")
    ].join(":");
}

function updateCountdown() {
    if (!timerEnd) {
        if (currentLayout === "end") {
            setTimerEnded();
        } else {
            if (timerDigits) {
                timerDigits.textContent = "--:--:--";
                timerDigits.classList.remove("ended");
            }
            if (timerLabel) {
                timerLabel.textContent = "Timer:";
            }
        }
        return;
    }

    const remainingMs = timerEnd - Date.now();
    if (remainingMs <= 0) {
        setTimerEnded();
    } else {
        const remainingSeconds = Math.floor(remainingMs / 1000);
        if (timerDigits) {
            timerDigits.textContent = formatTime(remainingSeconds);
            timerDigits.classList.remove("ended");
        }
        if (timerLabel) {
            timerLabel.textContent = "Time Remaining:";
        }
    }
}

function setTimerEnded() {
    if (timerDigits) {
        timerDigits.textContent = "00:00:00";
        timerDigits.classList.add("ended");
    }
    if (timerLabel) {
        timerLabel.textContent = "Event Ended:";
    }
}

async function fetchLeaderboard() {
    try {
        const res = await fetch(`${apiBase}/api/leaderboard`, { credentials: "include" });
        if (!res.ok) return;

        const data = await res.json();
        if (data.currentTeam) {
            currentTeam = data.currentTeam;
        }
        if (data.layout) {
            currentLayout = data.layout;
        }
        if (data.timerEnd !== undefined) {
            timerEnd = data.timerEnd;
            updateCountdown();
        }

        renderLeaderboard(data.leaderboard || []);
    } catch (err) {
        console.error("Could not fetch leaderboard data:", err);
    }
}

function renderLeaderboard(teams) {
    if (!leaderboardBody) return;
    leaderboardBody.replaceChildren();

    if (!teams || teams.length === 0) {
        if (emptyMessage) emptyMessage.style.display = "block";
        return;
    }

    if (emptyMessage) emptyMessage.style.display = "none";

    for (const team of teams) {
        const tr = document.createElement("tr");
        tr.classList.add("leaderboardRow");
        if (currentTeam && team.name === currentTeam) {
            tr.classList.add("currentUserTeam");
        }

        // Rank cell
        const tdRank = document.createElement("td");
        const rankSpan = document.createElement("span");
        rankSpan.classList.add("rankNum");
        rankSpan.textContent = team.rank;
        tdRank.append(rankSpan);

        // Team cell
        const tdTeam = document.createElement("td");
        const teamWrap = document.createElement("div");

        const teamName = document.createElement("div");
        teamName.classList.add("teamName");
        teamName.textContent = team.name;
        if (currentTeam && team.name === currentTeam) {
            teamName.textContent += " (You)";
        }
        teamWrap.append(teamName);

        if (Array.isArray(team.members) && team.members.length > 0) {
            const members = document.createElement("div");
            members.classList.add("teamMembers");
            members.textContent = team.members.join(" • ");
            teamWrap.append(members);
        }
        tdTeam.append(teamWrap);

        // Solves cell
        const tdSolves = document.createElement("td");
        tdSolves.classList.add("solveCount");
        tdSolves.textContent = team.solveCount;

        // Points cell
        const tdPoints = document.createElement("td");
        tdPoints.classList.add("pointsCount");
        tdPoints.textContent = `${team.points} pts`;

        tr.append(tdRank, tdTeam, tdSolves, tdPoints);
        leaderboardBody.append(tr);
    }
}

function connectWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        return;
    }

    socket = new WebSocket(`${wsProtocol}//${wsHost}`);

    socket.addEventListener("open", () => {
        try {
            socket.send(JSON.stringify({ type: "identify" }));
        } catch {}
    });

    socket.addEventListener("message", (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === "leaderboard_update" || data.type === "progress") {
                fetchLeaderboard();
                return;
            }
            if (data.layout) {
                currentLayout = data.layout;
                if (data.layout === "end") {
                    setTimerEnded();
                }
            }
            if (data.timerEnd !== undefined) {
                timerEnd = data.timerEnd;
                updateCountdown();
            }
        } catch (err) {
            console.error("Malformed WebSocket payload:", err);
        }
    });

    socket.addEventListener("close", () => {
        setTimeout(connectWebSocket, 3000);
    });
}

async function init() {
    await fetchLeaderboard();
    connectWebSocket();

    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(updateCountdown, 1000);

    setInterval(fetchLeaderboard, 4000);

    try {
        const bc = new BroadcastChannel("ctf_progress");
        bc.onmessage = () => {
            fetchLeaderboard();
        };
    } catch {}

    window.addEventListener("focus", fetchLeaderboard);
    document.addEventListener("visibilitychange", () => {
        if (!document.hidden) fetchLeaderboard();
    });
}

init();
