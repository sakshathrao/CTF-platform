import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const publicDir = path.join(rootDir, "public");
const srcPublicDir = path.join(publicDir, "public");

const { challenges } = await import(path.join(rootDir, "challenges.js"));

const NAVBAR_HTML = `  <header id="ctfNavbar" class="navbar" style="display: none;">
    <div class="navLeft">
      <a href="/main.html" class="navHomeLink">
        <span class="navBrand">CTF</span>
        <span class="navDivider">/</span>
        <span class="navTeamLabel">TEAM</span>
        <span class="navTeamName" id="navTeamName"></span>
      </a>
    </div>
    <nav>
      <a href="/main.html" class="navLink">Challenges</a>
      <a href="/leaderboard.html" class="navLink">Leaderboard</a>
      <div class="navPoints">
        <span class="pointsLabel">Points:</span>
        <span class="pointsValue" id="navPoints">0</span>
      </div>
      <button type="button" id="logoutBtn" class="navLogoutBtn">Logout</button>
    </nav>
  </header>`;

for (let id = 1; id <= 31; id++) {
  const srcPath = path.join(srcPublicDir, `challenge${id}.html`);
  if (!fs.existsSync(srcPath)) {
    console.error(`Missing source file: ${srcPath}`);
    continue;
  }

  let html = fs.readFileSync(srcPath, "utf8");
  const chDef = challenges.find(c => c.id === id) || { points: 100 };
  const defaultPoints = chDef.points || 100;

  // 1. Title replacement
  html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>Challenge ${id}</title>`);

  // 2. Adjust body padding in <style>
  if (html.includes("padding: 36px 20px 60px;")) {
    html = html.replace("padding: 36px 20px 60px;", "padding: 110px 20px 60px;");
  } else if (!html.includes("padding-top: 110px")) {
    html = html.replace(/body\s*\{([^}]*)\}/i, (match, bodyRules) => {
      return `body {${bodyRules}\n  padding-top: 110px !important;\n}`;
    });
  }

  // 3. Inject Navbar right after <body>
  if (!html.includes('id="ctfNavbar"')) {
    html = html.replace(/<body([^>]*)>/i, `<body$1>\n\n${NAVBAR_HTML}\n`);
  }

  // 4. Replace <script> with standardized navbar/sync-aware script
  const scriptContent = `
"use strict";

const CHALLENGE_ID = ${id};
const challengeID = ${id};
const DEFAULT_POINTS = ${defaultPoints};
const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? \`http://\${location.hostname}:3001\` : "";
const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
const wsHost = isDev ? \`\${location.hostname}:3001\` : location.host;

let eventStarted = false;
let solved = false;

function getElements() {
  return {
    shell: document.querySelector(".shell, .case-shell, main"),
    closed: document.getElementById("closedView"),
    form: document.getElementById("flagForm") || document.getElementById("f") || document.querySelector("form"),
    input: document.getElementById("flagInput") || document.getElementById("flag") || document.querySelector("form input"),
    button: document.getElementById("submitButton") || document.querySelector("form button"),
    status: document.getElementById("result") || document.getElementById("s") || document.querySelector(".status"),
  };
}

function getProgressCookie() {
  for (const cookie of document.cookie.split(";")) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === "ctf_progress") {
      try {
        return JSON.parse(decodeURIComponent(value.join("=")));
      } catch {
        return null;
      }
    }
  }
  return null;
}

async function getJSON(path) {
  const response = await fetch(\`\${apiBase}\${path}\`, { credentials: "include" });
  if (!response.ok) throw new Error(\`HTTP \${response.status}\`);
  return response.json();
}

function applySolvedState(msg) {
  solved = true;
  const { input, button, status } = getElements();
  if (input) input.disabled = true;
  if (button) button.disabled = true;
  if (status) {
    status.classList.add("ok");
    status.textContent = msg || "YOUR TEAM HAS ALREADY SOLVED THIS CASE.";
  }
}

function renderEventState(state) {
  const { shell, closed, button, status } = getElements();
  eventStarted = Boolean(state && state.layout === "start");

  if (state && typeof state.timerEnd === "number" && Date.now() >= state.timerEnd) {
    eventStarted = false;
  }

  if (!eventStarted) {
    if (shell) shell.style.display = "none";
    if (closed) closed.style.display = "flex";
    if (button && !solved) button.disabled = true;
  } else {
    if (closed) closed.style.display = "none";
    if (shell) shell.style.display = "block";
    if (!solved) {
      if (button) button.disabled = false;
      if (status && (status.textContent === "EVENT NOT STARTED." || status.textContent === "EVENT ENDED.")) {
        status.textContent = "";
      }
    }
  }
}

async function submitFlag(event) {
  event.preventDefault();
  const { input, button, status } = getElements();
  const flag = input ? input.value.trim() : "";

  if (!eventStarted) {
    if (status) {
      status.classList.remove("ok");
      status.textContent = "EVENT NOT CURRENTLY ACCEPTING SUBMISSIONS.";
    }
    return;
  }
  if (!flag) return;

  if (button) button.disabled = true;
  if (status) {
    status.classList.remove("ok");
    status.textContent = "VERIFYING…";
  }

  try {
    const response = await fetch(\`\${apiBase}/solve\`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId: CHALLENGE_ID, flag }),
    });
    const data = await response.json().catch(() => ({}));

    if (response.ok && data.success) {
      const pts = data.totalPoints ?? data.pointsAwarded ?? DEFAULT_POINTS;
      const pointsEl = document.getElementById("navPoints");
      if (pointsEl && typeof data.totalPoints === "number") {
        pointsEl.textContent = data.totalPoints;
      }
      try {
        const bc = new BroadcastChannel("ctf_progress");
        bc.postMessage({ type: "progress", points: data.totalPoints, solved: [CHALLENGE_ID] });
        bc.close();
      } catch {}
      applySolvedState(\`CASE CLOSED — +\${data.pointsAwarded ?? DEFAULT_POINTS} POINTS\`);
      return;
    }
    if (response.status === 401) {
      location.replace("/login.html");
      return;
    }
    if (response.status === 409) {
      applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
      return;
    }
    if (status) status.textContent = data.error || "INCORRECT FLAG — PLEASE TRY AGAIN.";
    if (button) button.disabled = false;
  } catch (err) {
    console.error(err);
    if (status) status.textContent = "SERVER CONNECTION FAILED — PLEASE TRY AGAIN.";
    if (button) button.disabled = false;
  }
}

function connectSocket() {
  const ws = new WebSocket(\`\${wsProtocol}//\${wsHost}\`);

  ws.addEventListener("message", (event) => {
    try {
      const state = JSON.parse(event.data);
      if (state && state.type === "progress") {
        const pointsEl = document.getElementById("navPoints");
        if (pointsEl && typeof state.points === "number") {
          pointsEl.textContent = state.points;
        }
        if (Array.isArray(state.solved) && state.solved.includes(CHALLENGE_ID)) {
          applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
        }
        return;
      }
      renderEventState(state);
    } catch (err) {
      console.error("Invalid event state:", err);
    }
  });

  ws.addEventListener("close", () => {
    setTimeout(connectSocket, 2500);
  });
}

async function checkSession() {
  try {
    const res = await fetch(\`\${apiBase}/session\`, { credentials: "include" });
    if (!res.ok) {
      location.replace("/login.html");
      return false;
    }
    const data = await res.json();
    const nav = document.getElementById("ctfNavbar");
    if (nav) {
      const teamEl = document.getElementById("navTeamName");
      const pointsEl = document.getElementById("navPoints");
      if (teamEl) teamEl.textContent = data.teamName || "";
      if (pointsEl) pointsEl.textContent = data.points ?? 0;
      nav.style.display = "flex";
    }
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
      logoutBtn.onclick = async () => {
        logoutBtn.disabled = true;
        try {
          const bc = new BroadcastChannel("ctf_progress");
          bc.postMessage({ type: "auth_change", loggedIn: false });
          bc.close();
        } catch {}
        try {
          await fetch(\`\${apiBase}/logout\`, { method: "POST", credentials: "include" });
        } catch {}
        document.cookie = "session=; Max-Age=0; path=/;";
        document.cookie = "ctf_progress=; Max-Age=0; path=/;";
        location.replace("/login.html");
      };
    }
    return true;
  } catch {
    location.replace("/login.html");
    return false;
  }
}

async function init() {
  const authed = await checkSession();
  if (!authed) return;

  const cookieProgress = getProgressCookie();
  if (cookieProgress && Array.isArray(cookieProgress.solved) && cookieProgress.solved.includes(CHALLENGE_ID)) {
    solved = true;
  }
  try {
    const progress = await getJSON("/progress");
    if (progress) {
      const pointsEl = document.getElementById("navPoints");
      if (pointsEl && typeof progress.points === "number") {
        pointsEl.textContent = progress.points;
      }
      if (Array.isArray(progress.solved) && progress.solved.includes(CHALLENGE_ID)) {
        solved = true;
      }
    }
  } catch {}

  const { form } = getElements();
  if (form) form.addEventListener("submit", submitFlag);

  if (solved) {
    applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
  }

  try {
    const initialState = await getJSON("/state");
    renderEventState(initialState);
  } catch {}

  connectSocket();

  try {
    const bc = new BroadcastChannel("ctf_progress");
    bc.onmessage = (event) => {
      if (event.data && event.data.type === "auth_change" && !event.data.loggedIn) {
        location.replace("/login.html");
        return;
      }
      if (event.data && typeof event.data.points === "number") {
        const pointsEl = document.getElementById("navPoints");
        if (pointsEl) pointsEl.textContent = event.data.points;
      }
      if (event.data && Array.isArray(event.data.solved) && event.data.solved.includes(CHALLENGE_ID)) {
        applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
      }
    };
  } catch {}
}

init();
`;

  html = html.replace(/<script>[\s\S]*?<\/script>/i, `<script>${scriptContent}</script>`);

  // Write to project root: challenge${id}.html
  const dstRootPath = path.join(rootDir, `challenge${id}.html`);
  fs.writeFileSync(dstRootPath, html, "utf8");

  // Also write to public/challenge${id}.html for static serving fallback
  const dstPublicPath = path.join(publicDir, `challenge${id}.html`);
  fs.writeFileSync(dstPublicPath, html, "utf8");

  console.log(`Integrated challenge ${id} -> challenge${id}.html`);
}

console.log("All 31 challenges integrated successfully.");
