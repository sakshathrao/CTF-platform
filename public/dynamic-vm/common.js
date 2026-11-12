"use strict";
(() => {
  const C = window.NP_VM_CHALLENGE;
  if (!C) throw new Error("Challenge configuration missing");

  const isDev = location.port === "5173" || location.port === "5174";
  const API_BASE = isDev ? `${location.protocol}//${location.hostname}:3001` : "";
  const wsProtocol = location.protocol === "https:" ? "wss:" : "ws:";
  const wsHost = isDev ? `${location.hostname}:3001` : location.host;

  const shell = document.getElementById("challengeShell");
  const closed = document.getElementById("closedView");
  const navbar = document.getElementById("ctfNavbar");
  const navTeam = document.getElementById("navTeamName");
  const navPoints = document.getElementById("navPoints");
  const logoutBtn = document.getElementById("logoutBtn");

  const progressChannel = typeof BroadcastChannel !== "undefined"
    ? new BroadcastChannel("ctf_progress")
    : null;

  let emulator = null;
  let started = false;
  let eventStarted = false;
  let socket = null;
  let retry = null;
  let sending = false;
  let solved = false;
  let justSolvedThisTab = false;

  const escapeHTML = s => String(s).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));

  const activeNotifyKeys = new Set();
  function notify({ title, message, type = "info", duration = 6500, key = null }) {
    const dedupeKey = key || `${title}:${message}`;
    if (activeNotifyKeys.has(dedupeKey)) return;
    activeNotifyKeys.add(dedupeKey);
    setTimeout(() => activeNotifyKeys.delete(dedupeKey), 8000);

    let container = document.getElementById("ctfNotifyContainer");
    if (!container) {
      container = document.createElement("div");
      container.id = "ctfNotifyContainer";
      container.style.cssText = "position: fixed; top: 85px; right: 24px; z-index: 99999; display: flex; flex-direction: column; gap: 12px; max-width: 440px; pointer-events: none;";
      document.body.appendChild(container);
    } else {
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
    }

    const toast = document.createElement("div");
    toast.className = `ctf-toast ctf-toast-${type}`;
    const isBonus = type === "bonus";
    const accentColor = isBonus ? "#f59e0b" : "#10b981";
    const glowColor = isBonus ? "rgba(245, 158, 11, 0.35)" : "rgba(16, 185, 129, 0.3)";

    toast.style.cssText = `
      pointer-events: auto;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid ${accentColor};
      border-left: 5px solid ${accentColor};
      border-radius: 8px;
      padding: 14px 18px;
      color: #f1f5f9;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.6), 0 0 18px ${glowColor};
      backdrop-filter: blur(12px);
      font-family: 'Jost', system-ui, -apple-system, sans-serif;
      transform: translateX(120%);
      opacity: 0;
      transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.35s ease;
    `;

    const header = document.createElement("div");
    header.style.cssText = "display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;";

    const titleEl = document.createElement("strong");
    titleEl.style.cssText = `font-size: 15px; font-weight: 700; color: ${isBonus ? "#fbbf24" : "#34d399"}; letter-spacing: 0.3px;`;
    titleEl.textContent = title;

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.innerHTML = "&times;";
    closeBtn.style.cssText = "background: none; border: none; color: #94a3b8; font-size: 20px; cursor: pointer; padding: 0 4px; line-height: 1;";
    closeBtn.onclick = () => dismiss();

    header.appendChild(titleEl);
    header.appendChild(closeBtn);

    const bodyEl = document.createElement("div");
    bodyEl.style.cssText = "font-size: 13.5px; line-height: 1.5; color: #cbd5e1;";
    bodyEl.textContent = message;

    toast.appendChild(header);
    toast.appendChild(bodyEl);
    container.appendChild(toast);

    requestAnimationFrame(() => {
      toast.style.transform = "translateX(0)";
      toast.style.opacity = "1";
    });

    let timeoutId = setTimeout(dismiss, duration);

    function dismiss() {
      clearTimeout(timeoutId);
      toast.style.transform = "translateX(120%)";
      toast.style.opacity = "0";
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 400);
    }
  }

  function getProgressCookie() {
    for (const part of document.cookie.split(";")) {
      const [key, ...value] = part.trim().split("=");
      if (key === "ctf_progress") {
        try { return JSON.parse(decodeURIComponent(value.join("="))); }
        catch { return null; }
      }
    }
    return null;
  }

  function applySolvedState(message) {
    solved = true;
    const input = document.getElementById("flag");
    const button = document.getElementById("submit");
    const result = document.getElementById("result");
    if (input) {
      input.disabled = true;
      input.placeholder = "Solved";
    }
    if (button) button.disabled = true;
    if (result) {
      result.className = "status-line ok";
      result.textContent = message || "YOUR TEAM HAS ALREADY SOLVED THIS CASE.";
    }
  }

  async function refreshProgress() {
    try {
      const r = await fetch(`${API_BASE}/progress`, { credentials: "include" });
      if (r.ok) {
        const p = await r.json();
        if (Array.isArray(p.solved) && p.solved.includes(C.id)) {
          applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
          return;
        }
      }
    } catch {
      // Fallback to cookie
    }
    const cookieProgress = getProgressCookie();
    if (cookieProgress && Array.isArray(cookieProgress.solved) && cookieProgress.solved.includes(C.id)) {
      applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
    }
  }

  async function checkSession() {
    try {
      const r = await fetch(`${API_BASE}/session`, { credentials: "include" });
      if (!r.ok) {
        location.replace("/login.html");
        return false;
      }
      const data = await r.json().catch(() => ({}));
      // The platform /session endpoint identifies the signed-in team as teamName.
      if (navTeam) navTeam.textContent = data.teamName || "";
      if (navPoints && typeof data.points === "number") {
        navPoints.textContent = String(data.points);
      }
      if (navbar) navbar.style.display = "flex";
      return true;
    } catch (e) {
      console.error("Session check failed:", e);
      location.replace("/login.html");
      return false;
    }
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      logoutBtn.disabled = true;
      // Keep the platform's other open tabs in sync with its normal navbar logout.
      if (progressChannel) {
        progressChannel.postMessage({ type: "auth_change", loggedIn: false });
      }
      try {
        await fetch(`${API_BASE}/logout`, { method: "POST", credentials: "include" });
      } catch (e) {
        console.warn("Logout request failed:", e);
      } finally {
        document.cookie = "ctf_progress=; Max-Age=0; path=/;";
        location.replace("/login.html");
      }
    });
  }

  function stopVM() {
    if (emulator && typeof emulator.stop === "function") {
      try { emulator.stop(); } catch (e) { console.warn("VM stop warning:", e); }
    }
    emulator = null;
    started = false;
  }

  function createVM() {
    if (started || !eventStarted) return;
    const status = document.getElementById("vm-status");
    if (typeof window.V86 !== "function") {
      if (status) {
        status.dataset.state = "error";
        status.textContent = "v86 failed to load. Check /node_modules/v86/build/libv86.js";
      }
      return;
    }
    if (status) status.textContent = "Starting browser-local Linux VM…";
    try {
      const v86Config = {
        wasm_path: "/node_modules/v86/build/v86.wasm",
        memory_size: 64 * 1024 * 1024,
        vga_memory_size: 2 * 1024 * 1024,
        screen_container: document.getElementById("screen_container"),
        bios: { url: "/images/seabios.bin" },
        vga_bios: { url: "/images/vgabios.bin" },
        bzimage: { url: "/images/customBzImage" },
        cdrom: { url: C.iso },
        autostart: true
      };
      emulator = new V86(v86Config);
      started = true;
      if (status) {
        status.dataset.state = "ready";
        status.textContent = "VM started · wait for the Linux shell prompt";
      }
      // Automatically link /dev/sr0 -> /dev/cdrom and mount the attached challenge ISO at /mnt/case
      // via the background ttyS0 shell in customBzImage
      const autoMountCmd = C.stageCommand || (
        "ln -sf /dev/sr0 /dev/cdrom; mkdir -p /mnt/case /home/ctf; " +
        "mount -t iso9660 -o ro /dev/sr0 /mnt/case 2>/dev/null || mount -t iso9660 -o ro /dev/cdrom /mnt/case 2>/dev/null; " +
        "if [ -f /mnt/case/harbor-sync-image.tar ]; then cp -f /mnt/case/harbor-sync-image.tar /home/ctf/harbor-sync-image.tar; fi\n"
      );
      for (const delay of [3500, 6500]) {
        window.setTimeout(() => {
          if (emulator && eventStarted) {
            try { emulator.serial0_send(autoMountCmd); }
            catch (err) { console.warn("Serial auto-mount note:", err); }
          }
        }, delay);
      }
    } catch (e) {
      console.error("VM initialization failed:", e);
      if (status) {
        status.dataset.state = "error";
        status.textContent = "VM initialization failed. See browser console.";
      }
    }
  }

  function renderChallengeDOM() {
    if (shell.dataset.rendered === "true") return;
    shell.dataset.rendered = "true";
    const mountHelp = C.mountHelp || (
      `<strong>Mount the evidence CD-ROM:</strong><br>` +
      `<code>mkdir -p /mnt/case && mount -t iso9660 /dev/cdrom /mnt/case</code><br>` +
      `If <code>/dev/cdrom</code> is unavailable, try <code>/dev/sr0</code> or <code>/dev/hdc</code>, then inspect <code>/mnt/case</code>.`
    );
    const tipsHtml = Array.isArray(C.tips) && C.tips.length
      ? C.tips.map(t => `<p>${t}</p>`).join("")
      : `<p>Use <code>pwd</code> to see your location and <code>ls -la</code> to list files.</p><p>Use <code>cat</code> to read text files.</p>`;

    shell.innerHTML = `
      <div class="vm-topbar">
        <p class="eyebrow">NORTH PIER · DYNAMIC VM ${String(C.id).padStart(3, "0")} · ${escapeHTML(C.category)}</p>
        <a class="back-link" href="/main.html">← Back to Challenges</a>
      </div>
      <header class="vm-header">
        <div>
          <h1>${escapeHTML(C.title)}</h1>
          <p class="vm-subtitle">${escapeHTML(C.summary)}</p>
        </div>
        <span class="vm-badge">${escapeHTML(C.difficulty)} · ${C.points} Points</span>
      </header>
      <section class="case-card">
        <h2>Objective</h2>
        <p>${escapeHTML(C.objective)}</p>
        <p class="small-note">This lab runs locally in your browser VM. Evidence is attached on a read-only ISO9660 CD-ROM.</p>
      </section>
      <div class="vm-layout">
        <section class="terminal-card">
          <div class="vm-toolbar">
            <strong>LOCAL BROWSER VM · LINUX CONSOLE</strong>
            <span id="vm-status" class="vm-status">Waiting for VM…</span>
            <div style="display:flex;gap:8px"><button id="send-ctrl-c" type="button" title="Send SIGINT (Ctrl+C) to VM">Ctrl+C</button><button id="reset-vm" type="button">Reset VM</button></div>
          </div>
          <div id="screen_container" tabindex="0" aria-label="Linux virtual machine console">
            <div id="screen"></div>
            <canvas></canvas>
          </div>
          <div class="terminal-help">${mountHelp}</div>
        </section>
        <aside class="submit-card">
          <h2>Submit Flag</h2>
          <p>Recover the token from the evidence inside the VM. Submissions are verified by the platform server.</p>
          <label for="flag">Flag</label>
          <input id="flag" type="text" spellcheck="false" autocomplete="off" placeholder="CTF{...}">
          <button id="submit" type="button">Submit Flag</button>
          <div id="result" class="status-line" role="status" aria-live="polite"></div>
          <div class="hint-box">
            <h3>Console Quick Reference</h3>
            ${tipsHtml}
            <p class="small-note">Reloading or clicking Reset VM starts a clean session.</p>
          </div>
        </aside>
      </div>`;

    document.getElementById("reset-vm").addEventListener("click", () => location.reload());
    const ctrlCBtn = document.getElementById("send-ctrl-c");
    if (ctrlCBtn) {
      ctrlCBtn.addEventListener("click", () => {
        if (emulator && typeof emulator.keyboard_send_scancodes === "function") {
          emulator.keyboard_send_scancodes([0x1d, 0x2e, 0xae, 0x9d]);
        }
        const sc = document.getElementById("screen_container");
        if (sc) sc.focus();
      });
    }
    const sc = document.getElementById("screen_container");
    if (sc) {
      sc.addEventListener("mousedown", () => sc.focus());
      sc.addEventListener("keydown", e => {
        // Prevent browser native Copy shortcut from swallowing Ctrl+C when terminal is focused and no text is selected
        if (e.ctrlKey && !e.altKey && !e.metaKey && (e.key === "c" || e.key === "C")) {
          const sel = window.getSelection ? String(window.getSelection()) : "";
          if (!sel && emulator && typeof emulator.keyboard_send_scancodes === "function") {
            e.preventDefault();
            e.stopPropagation();
            emulator.keyboard_send_scancodes([0x1d, 0x2e, 0xae, 0x9d]);
          }
        }
      }, true);
    }
    window.addEventListener("blur", () => {
      // Release Left/Right Shift (0xAA, 0xB6), Left Ctrl (0x9D), Left Alt (0xB8) on window blur so modifiers never stick
      if (emulator && typeof emulator.keyboard_send_scancodes === "function") {
        try { emulator.keyboard_send_scancodes([0x9d, 0xaa, 0xb6, 0xb8]); } catch {}
      }
    });
    document.getElementById("submit").addEventListener("click", submitFlag);
    document.getElementById("flag").addEventListener("keydown", e => {
      if (e.key === "Enter") {
        e.preventDefault();
        submitFlag();
      }
    });
    if (solved) {
      applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
    }
  }

  function renderEventState(state) {
    // Ignore non-layout WebSocket broadcasts (e.g., leaderboard/solve updates)
    if (!state || typeof state.layout !== "string") return;
    eventStarted = state.layout === "start";
    if (typeof state.timerEnd === "number" && state.timerEnd > 0 && Date.now() >= state.timerEnd) {
      eventStarted = false;
    }
    if (eventStarted) {
      closed.style.display = "none";
      shell.style.display = "block";
      renderChallengeDOM();
      createVM();
    } else {
      stopVM();
      shell.style.display = "none";
      closed.style.display = "flex";
    }
  }

  async function submitFlag() {
    if (!eventStarted || sending) return;
    if (solved) {
      applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
      return;
    }
    const input = document.getElementById("flag");
    const button = document.getElementById("submit");
    const result = document.getElementById("result");
    const flag = input.value.trim();
    if (!flag) {
      result.className = "status-line";
      result.textContent = "ENTER A VALID FLAG BEFORE SUBMITTING.";
      return;
    }
    sending = true;
    button.disabled = true;
    result.className = "status-line";
    result.textContent = "VERIFYING SUBMISSION...";
    try {
      const r = await fetch(`${API_BASE}/solve`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challengeId: C.id, flag })
      });
      const data = await r.json().catch(() => ({}));
      if (r.ok && data.success) {
        const awarded = data.pointsAwarded ?? C.points;
        const base = data.basePoints ?? C.points;
        const bonusPct = data.bonusPercent ?? 0;
        const bonusPts = awarded - base;
        const hasBonus = bonusPct > 0 && bonusPts > 0;
        const dedupeKey = `solve_${C.id}`;
        justSolvedThisTab = true;

        if (navPoints && typeof data.totalPoints === "number") {
          navPoints.textContent = String(data.totalPoints);
        }

        if (hasBonus) {
          notify({
            key: dedupeKey,
            title: "Marks + Bonus Received! 🎯",
            message: `Your team received marks + bonus: +${awarded} marks (${base} base + ${bonusPts} First Blood bonus [${bonusPct}%])!`,
            type: "bonus"
          });
          applySolvedState(`CASE CLOSED — +${awarded} MARKS (MARKS + BONUS: ${base} BASE + ${bonusPts} BONUS)`);
        } else {
          notify({
            key: dedupeKey,
            title: "Marks Received! 🏁",
            message: `Your team received just marks: +${awarded} marks.`,
            type: "success"
          });
          applySolvedState(`CASE CLOSED — +${awarded} MARKS (JUST MARKS)`);
        }

        if (progressChannel) {
          // main.js listens for these exact fields to update points, first-blood
          // notifications, and the solved challenge set across browser tabs.
          progressChannel.postMessage({
            challengeId: C.id,
            points: data.totalPoints,
            pointsAwarded: awarded,
            basePoints: base,
            bonusPercent: bonusPct,
            solved: Array.isArray(data.solved) ? data.solved : [C.id]
          });
        }
        return;
      }
      if (r.status === 401) {
        location.replace("/login.html");
        return;
      }
      if (r.status === 409) {
        applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
        return;
      }
      if (r.status === 403) {
        result.textContent = "SUBMISSIONS ARE CLOSED RIGHT NOW.";
        return;
      }
      result.textContent = r.status === 400
        ? "INCORRECT FLAG. RE-CHECK THE VM EVIDENCE AND TRY AGAIN."
        : (data.error || "SUBMISSION FAILED.");
    } catch (e) {
      console.error("Flag submission failed:", e);
      result.textContent = "NETWORK ERROR WHILE CONTACTING SERVER.";
    } finally {
      sending = false;
      if (!solved && button) button.disabled = false;
    }
  }

  function connectSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;
    try {
      const ws = new WebSocket(`${wsProtocol}//${wsHost}`);
      socket = ws;
      // Bind this socket to the authenticated team so the platform can deliver
      // team-specific progress updates (the server handles { type: "identify" }).
      ws.addEventListener("open", () => {
        try {
          ws.send(JSON.stringify({ type: "identify" }));
        } catch (err) {
          console.error("WebSocket identity handshake failed:", err);
        }
      });
      ws.addEventListener("message", e => {
        try {
          const state = JSON.parse(e.data);
          if (state.type === "progress") {
            if (navPoints && typeof state.points === "number") {
              navPoints.textContent = String(state.points);
            }
            if (!solved && Array.isArray(state.solved) && state.solved.includes(C.id)) {
              applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
            }
            if (typeof state.pointsAwarded === "number") {
              if (justSolvedThisTab && state.challengeId === C.id) {
                return;
              }
              const awarded = state.pointsAwarded;
              const base = state.basePoints || awarded;
              const bonusPct = state.bonusPercent || 0;
              const bonusPts = awarded - base;
              const hasBonus = bonusPct > 0 && bonusPts > 0;
              const dedupeKey = `solve_${state.challengeId || C.id}`;
              if (hasBonus) {
                notify({
                  key: dedupeKey,
                  title: "Marks + Bonus Received! 🎯",
                  message: `Your team received marks + bonus: +${awarded} marks (${base} base + ${bonusPts} First Blood bonus [${bonusPct}%])!`,
                  type: "bonus"
                });
              } else {
                notify({
                  key: dedupeKey,
                  title: "Marks Received! 🏁",
                  message: `Your team received just marks: +${awarded} marks.`,
                  type: "success"
                });
              }
            }
            return;
          }
          renderEventState(state);
        } catch (err) {
          console.error("Invalid WebSocket payload:", err);
        }
      });
      ws.addEventListener("close", () => {
        if (retry) clearTimeout(retry);
        retry = setTimeout(connectSocket, 2000);
      });
      ws.addEventListener("error", err => console.error("WebSocket error:", err));
    } catch (e) {
      console.error(e);
      retry = setTimeout(connectSocket, 2000);
    }
  }

  if (progressChannel) {
    progressChannel.onmessage = event => {
      const data = event.data || {};
      if (data.type === "auth_change" && data.loggedIn === false) {
        location.replace("/login.html");
        return;
      }
      if (navPoints && typeof data.points === "number") {
        navPoints.textContent = String(data.points);
      }
      if (!solved && Array.isArray(data.solved) && data.solved.includes(C.id)) {
        applySolvedState("YOUR TEAM HAS ALREADY SOLVED THIS CASE.");
      }
      if (!solved && data.challengeId === C.id && typeof data.pointsAwarded === "number") {
        const awarded = data.pointsAwarded;
        const base = data.basePoints || awarded;
        const bonusPct = data.bonusPercent || 0;
        const bonusPts = awarded - base;
        const hasBonus = bonusPct > 0 && bonusPts > 0;
        if (hasBonus) {
          applySolvedState(`CASE CLOSED — +${awarded} MARKS (MARKS + BONUS: ${base} BASE + ${bonusPts} BONUS)`);
        } else {
          applySolvedState(`CASE CLOSED — +${awarded} MARKS (JUST MARKS)`);
        }
      }
      if (typeof data.pointsAwarded === "number") {
        if (justSolvedThisTab && data.challengeId === C.id) {
          return;
        }
        const awarded = data.pointsAwarded;
        const base = data.basePoints || awarded;
        const bonusPct = data.bonusPercent || 0;
        const bonusPts = awarded - base;
        const hasBonus = bonusPct > 0 && bonusPts > 0;
        const dedupeKey = `solve_${data.challengeId || C.id}`;
        if (hasBonus) {
          notify({
            key: dedupeKey,
            title: "Marks + Bonus Received! 🎯",
            message: `Your team received marks + bonus: +${awarded} marks (${base} base + ${bonusPts} First Blood bonus [${bonusPct}%])!`,
            type: "bonus"
          });
        } else {
          notify({
            key: dedupeKey,
            title: "Marks Received! 🏁",
            message: `Your team received just marks: +${awarded} marks.`,
            type: "success"
          });
        }
      }
    };
  }

  window.addEventListener("beforeunload", () => {
    if (retry) clearTimeout(retry);
    stopVM();
    if (socket) {
      try { socket.close(); } catch {}
    }
    if (progressChannel) {
      try { progressChannel.close(); } catch {}
    }
  });

  checkSession().then(async ok => {
    if (!ok) return;
    await refreshProgress();
    connectSocket();
  });
})();
