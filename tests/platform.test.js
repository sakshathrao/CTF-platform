import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import WebSocket from "ws";
import { execSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.join(__dirname, "..");

const TEST_ADMIN_TOKEN = "test-secret-token-12345";
process.env.ADMIN_TOKEN = TEST_ADMIN_TOKEN;
process.env.HOST = "127.0.0.1";
process.env.PORT = "3099";
process.env.SSH_PORT = "2299";

import net from "node:net";

const { server, wss, vmTunnelWss, sshServer, db, state, verifyAdminToken } = await import("../server.js");

function makeRequest(method, urlPath, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: "127.0.0.1",
      port: 3099,
      path: urlPath,
      method: method,
      headers: { ...headers }
    };

    const req = http.request(options, res => {
      let data = "";
      res.on("data", chunk => { data += chunk; });
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data
        });
      });
    });

    req.on("error", reject);
    if (body) {
      req.write(typeof body === "string" ? body : JSON.stringify(body));
    }
    req.end();
  });
}

test.after(() => {
  server.close();
  wss.close();
  if (sshServer && sshServer.listening) {
    sshServer.close();
  }
});

test("Database: schema, teams, and challenges are intact", () => {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map(t => t.name);
  assert.ok(tables.includes("teams"), "teams table exists");
  assert.ok(tables.includes("challenges"), "challenges table exists");
  assert.ok(tables.includes("solves"), "solves table exists");
  assert.ok(tables.includes("sessions"), "sessions table exists");

  const ch1 = db.prepare("SELECT * FROM challenges WHERE id = 1").get();
  assert.ok(ch1, "Challenge 1 exists");
  assert.equal(ch1.flag, "12345-67890", "Challenge 1 flag is preserved");
});

test("HTTP: /session rejects unauthenticated requests", async () => {
  const res = await makeRequest("GET", "/session");
  assert.equal(res.statusCode, 401);
  const data = JSON.parse(res.body);
  assert.equal(data.error, "Not logged in.");
});

test("HTTP: /admin/state rejects requests without valid admin token", async () => {
  const resNoAuth = await makeRequest("POST", "/admin/state", { "Content-Type": "application/json" }, { layout: "start" });
  assert.equal(resNoAuth.statusCode, 401);

  const resBadAuth = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": "wrong-token"
  }, { layout: "start" });
  assert.equal(resBadAuth.statusCode, 401);
});

test("HTTP: /admin/state updates layout with valid admin token", async () => {
  const res = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  assert.equal(res.statusCode, 200);
  const data = JSON.parse(res.body);
  assert.equal(data.success, true);
  assert.equal(state.layout, "start");

  // Reset to wait
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "wait" });
  assert.equal(state.layout, "wait");
});

test("HTTP: Path traversal is blocked (403 Forbidden)", async () => {
  const res1 = await makeRequest("GET", "/../package.json");
  assert.equal(res1.statusCode, 403);

  const res2 = await makeRequest("GET", "/%2e%2e/server.js");
  assert.equal(res2.statusCode, 403);
});

test("HTTP: Static file content negotiation and Vary: Accept-Encoding", async () => {
  // Brotli request
  const resBr = await makeRequest("GET", "/main.html", { "Accept-Encoding": "br, gzip" });
  assert.equal(resBr.statusCode, 200);
  assert.equal(resBr.headers["vary"], "Accept-Encoding");
  assert.equal(resBr.headers["content-type"], "text/html; charset=utf-8");

  // Gzip request
  const resGz = await makeRequest("GET", "/main.html", { "Accept-Encoding": "gzip" });
  assert.equal(resGz.statusCode, 200);
  assert.equal(resGz.headers["vary"], "Accept-Encoding");

  // Uncompressed request
  const resNone = await makeRequest("GET", "/main.html", { "Accept-Encoding": "identity" });
  assert.equal(resNone.statusCode, 200);
  assert.equal(resNone.headers["vary"], "Accept-Encoding");
  assert.equal(resNone.headers["content-encoding"], undefined);
});

test("HTTP: v86 assets, WebAssembly fallback, and CSP wasm-unsafe-eval are accessible", async () => {
  const resWasm = await makeRequest("GET", "/node_modules/v86/build/v86.wasm");
  assert.equal(resWasm.statusCode, 200);
  assert.equal(resWasm.headers["content-type"], "application/wasm");

  const resFallback = await makeRequest("GET", "/node_modules/v86/build/v86-fallback.wasm");
  assert.equal(resFallback.statusCode, 200);
  assert.equal(resFallback.headers["content-type"], "application/wasm");

  const resLib = await makeRequest("GET", "/node_modules/v86/build/libv86.js");
  assert.equal(resLib.statusCode, 200);
  assert.equal(resLib.headers["content-type"], "application/javascript; charset=utf-8");

  // Verify CSP allows wasm compilation
  assert.match(resLib.headers["content-security-policy"] || "", /'wasm-unsafe-eval'/);
});

test("WebSocket: sends initial state and rejects unauthorized changes", async () => {
  const ws = new WebSocket("ws://127.0.0.1:3099");

  const initialMsg = await new Promise(resolve => {
    ws.once("message", data => resolve(JSON.parse(data.toString())));
  });
  assert.ok(initialMsg.layout, "Initial message contains layout");

  // Send unauthorized state change
  ws.send(JSON.stringify({ layout: "start" }));
  const rejectMsg = await new Promise(resolve => {
    ws.once("message", data => resolve(JSON.parse(data.toString())));
  });
  assert.ok(rejectMsg.error, "Rejection message received");
  assert.match(rejectMsg.error, /Unauthorized/);

  // Send authorized state change
  ws.send(JSON.stringify({ layout: "start", token: TEST_ADMIN_TOKEN }));
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(state.layout, "start", "State successfully updated by authorized admin via WebSocket");

  // Reset to wait
  ws.send(JSON.stringify({ layout: "wait", token: TEST_ADMIN_TOKEN }));
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.equal(state.layout, "wait");

  ws.close();
});

test("WebSocket: rejects malformed JSON without crashing", async () => {
  const ws = new WebSocket("ws://127.0.0.1:3099");
  await new Promise(resolve => ws.once("open", resolve));

  ws.send("NOT_A_JSON_STRING{{{");
  const errReply = await new Promise(resolve => {
    ws.once("message", data => {
      // First might be state, wait for error
      const parsed = JSON.parse(data.toString());
      if (parsed.error) resolve(parsed);
      else ws.once("message", d2 => resolve(JSON.parse(d2.toString())));
    });
  });
  assert.equal(errReply.error, "Invalid JSON format");

  ws.close();
});

test("Assets: background PNG preserves exact dimensions and is optimized", () => {
  const bgPath = path.join(projectRoot, "public/assets/file_00000000bd7c81f4aafde805674aabef_upscayl_2x_upscayl-standard-4x.png");
  assert.ok(existsSync(bgPath), "Background image exists");

  const stats = statSync(bgPath);
  assert.ok(stats.size <= 2235707, "Image is optimized (<= 2,235,707 bytes)");

  // Check dimensions using identify or node buffer header inspection
  const out = execSync(`identify "${bgPath}"`).toString();
  assert.match(out, /6716x3748/, "Dimensions are preserved at exactly 6716x3748");
  assert.match(out, /PNG/, "Image format is PNG");
});

test("SSH Proxy: cleanly sends SSH banner and SSH_MSG_DISCONNECT when no tunnel active", async () => {
  const tcpClient = net.createConnection({ host: "127.0.0.1", port: 2299 });
  const data = await new Promise((resolve) => {
    let chunks = Buffer.alloc(0);
    tcpClient.on("data", chunk => { chunks = Buffer.concat([chunks, chunk]); });
    tcpClient.on("end", () => resolve(chunks));
  });

  const banner = data.toString("utf8", 0, data.indexOf("\r\n"));
  assert.equal(banner, "SSH-2.0-CTF_Platform");

  // Verify binary packet starts after \r\n and has message type 1 (SSH_MSG_DISCONNECT)
  const packetStart = data.indexOf("\r\n") + 2;
  const packet = data.subarray(packetStart);
  assert.ok(packet.length >= 8, "Packet length is valid");
  const packetLen = packet.readUInt32BE(0);
  assert.equal(packetLen + 4, packet.length, "Packet length matches buffer");
  const msgType = packet.readUInt8(5);
  assert.equal(msgType, 1, "Message type is SSH_MSG_DISCONNECT (1)");
});

test("VM Tunnel: /vm-tunnel rejects unauthenticated WebSocket connections", async () => {
  const ws = new WebSocket("ws://127.0.0.1:3099/vm-tunnel");
  const statusCode = await new Promise((resolve) => {
    ws.on("unexpected-response", (req, res) => {
      resolve(res.statusCode);
    });
    ws.on("open", () => resolve(200));
    ws.on("error", () => {});
  });
  assert.equal(statusCode, 401, "Rejects unauthenticated upgrade with 401");
});

test("VM Tunnel & SSH Proxy: authenticated tunnel forwards TCP <-> WS", async () => {
  // Set layout to start so VM tunnel is allowed
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  const existingTeam = db.prepare("SELECT name FROM teams LIMIT 1").get();
  assert.ok(existingTeam, "At least one team exists in DB");
  const testToken = "test_tunnel_session_token_" + Date.now();
  db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken, existingTeam.name);

  try {
    const ws = new WebSocket("ws://127.0.0.1:3099/vm-tunnel", {
      headers: { Cookie: `session=${testToken}` }
    });

    await new Promise((resolve, reject) => {
      ws.once("open", resolve);
      ws.once("error", reject);
    });

    // Connect a test TCP client to SSH port (2299)
    const tcpClient = net.createConnection({ host: "127.0.0.1", port: 2299 });
    await new Promise((resolve, reject) => {
      tcpClient.once("connect", resolve);
      tcpClient.once("error", reject);
    });

    // Test TCP -> WS transmission
    const wsReceivedPromise = new Promise(resolve => {
      ws.once("message", data => resolve(data.toString()));
    });
    tcpClient.write("SSH-2.0-TestClient\r\n");
    const wsData = await wsReceivedPromise;
    assert.equal(wsData, "SSH-2.0-TestClient\r\n", "Data forwarded from TCP client to VM tunnel WebSocket");

    // Test WS -> TCP transmission
    const tcpReceivedPromise = new Promise(resolve => {
      tcpClient.once("data", chunk => resolve(chunk.toString()));
    });
    ws.send("SSH-2.0-tinyssh_noversion\r\n");
    const tcpData = await tcpReceivedPromise;
    assert.equal(tcpData, "SSH-2.0-tinyssh_noversion\r\n", "Data forwarded from VM tunnel WebSocket to TCP client");

    tcpClient.destroy();
    ws.close();
  } finally {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(testToken);
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("HTTP: /register rejects duplicate USNs or duplicate member names", async () => {
  // Test duplicate USN between member 1 and member 2
  const resDupUSN12 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
    teamName: "TestTeamDupUSN1",
    password: "Password123!",
    members: [
      { name: "Alice", usn: "1MS21CS001" },
      { name: "Bob", usn: "1ms21cs001" },
      { name: "", usn: "" }
    ]
  });
  assert.equal(resDupUSN12.statusCode, 400);
  assert.equal(JSON.parse(resDupUSN12.body).error, "Member 1 and Member 2 cannot have the same USN.");

  // Test duplicate name between member 1 and member 2
  const resDupName12 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
    teamName: "TestTeamDupName1",
    password: "Password123!",
    members: [
      { name: "Alice", usn: "1MS21CS001" },
      { name: "alice", usn: "1MS21CS002" },
      { name: "", usn: "" }
    ]
  });
  assert.equal(resDupName12.statusCode, 400);
  assert.equal(JSON.parse(resDupName12.body).error, "Member 1 and Member 2 cannot have the same name.");

  // Test duplicate USN between member 1 and member 3
  const resDupUSN13 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
    teamName: "TestTeamDupUSN2",
    password: "Password123!",
    members: [
      { name: "Alice", usn: "1MS21CS001" },
      { name: "Bob", usn: "1MS21CS002" },
      { name: "Charlie", usn: "1MS21CS001" }
    ]
  });
  assert.equal(resDupUSN13.statusCode, 400);
  assert.equal(JSON.parse(resDupUSN13.body).error, "Member 1 and Member 3 cannot have the same USN.");

  // Test duplicate name between member 2 and member 3
  const resDupName23 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
    teamName: "TestTeamDupName2",
    password: "Password123!",
    members: [
      { name: "Alice", usn: "1MS21CS001" },
      { name: "Bob", usn: "1MS21CS002" },
      { name: "Bob", usn: "1MS21CS003" }
    ]
  });
  assert.equal(resDupName23.statusCode, 400);
  assert.equal(JSON.parse(resDupName23.body).error, "Member 2 and Member 3 cannot have the same name.");

  // Test valid registration with distinct members
  const validTeamName = "TestTeamValid_" + Date.now();
  try {
    const resValid = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
      teamName: validTeamName,
      password: "Password123!",
      members: [
        { name: "Alice", usn: "1MS21CS001" },
        { name: "Bob", usn: "1MS21CS002" },
        { name: "Charlie", usn: "1MS21CS003" }
      ]
    });
    assert.equal(resValid.statusCode, 201);
    assert.equal(JSON.parse(resValid.body).success, true);
  } finally {
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(validTeamName);
    db.prepare("DELETE FROM teams WHERE name = ?").run(validTeamName);
  }

  // Test optional member 2 and 3: only member 1 provided
  const soloTeamName = "TestTeamSolo_" + Date.now();
  try {
    const resSolo = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
      teamName: soloTeamName,
      password: "Password123!",
      members: [
        { name: "SoloPlayer", usn: "1MS21CS099" }
      ]
    });
    assert.equal(resSolo.statusCode, 201, "Registration succeeds with only member 1");
    assert.equal(JSON.parse(resSolo.body).success, true);
  } finally {
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(soloTeamName);
    db.prepare("DELETE FROM teams WHERE name = ?").run(soloTeamName);
  }

  // Test optional member 2: name provided without USN
  const partialTeamName = "TestTeamPartial_" + Date.now();
  try {
    const resPartial = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
      teamName: partialTeamName,
      password: "Password123!",
      members: [
        { name: "Alice", usn: "1MS21CS001" },
        { name: "Bob", usn: "" }
      ]
    });
    assert.equal(resPartial.statusCode, 201, "Registration succeeds when member 2 has name but no USN");
    assert.equal(JSON.parse(resPartial.body).success, true);
  } finally {
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(partialTeamName);
    db.prepare("DELETE FROM teams WHERE name = ?").run(partialTeamName);
  }
});

test("Challenges: each challenge has a category and serial unlocking works per category", async () => {
  const { challenges, getVisibleChallenges } = await import("../challenges.js");

  // Every challenge must have a category
  assert.ok(challenges.length > 0, "Challenges array is not empty");
  for (const c of challenges) {
    assert.equal(typeof c.category, "string", `Challenge ${c.id} has category string`);
    assert.ok(c.category.length > 0, `Challenge ${c.id} category is non-empty`);
  }

  // Initial state: exactly 1 challenge per category
  const initialVisible = getVisibleChallenges(challenges, new Set());
  const categories = [...new Set(challenges.map(c => c.category))];
  assert.equal(initialVisible.length, categories.length, "Initially shows exactly 1 challenge per category");

  // Verify that for each category, the initial challenge is the first one in serial order
  for (const cat of categories) {
    const catChallenges = challenges.filter(c => c.category === cat);
    const visibleInCat = initialVisible.filter(c => c.category === cat);
    assert.equal(visibleInCat.length, 1, `Category ${cat} has 1 initial challenge`);
    assert.equal(visibleInCat[0].id, catChallenges[0].id, `Category ${cat} shows its first challenge in serial order`);
  }

  // Solve challenge 1 (from Web category)
  const afterSolve1 = getVisibleChallenges(challenges, new Set([1]));
  const webVisible = afterSolve1.filter(c => c.category === "Web");
  assert.equal(webVisible.length, 2, "Web category shows an additional challenge after solving 1");
  assert.equal(webVisible[0].id, 1);
  assert.equal(webVisible[1].id, 2);

  // Other categories must still show only 1 challenge
  for (const cat of categories.filter(c => c !== "Web")) {
    const visibleInCat = afterSolve1.filter(c => c.category === cat);
    assert.equal(visibleInCat.length, 1, `Category ${cat} is untouched and still shows only 1 challenge`);
  }

  // Solve challenge 3 (from Crypto category) as well
  const afterSolve1And3 = getVisibleChallenges(challenges, new Set([1, 3]));
  const cryptoVisible = afterSolve1And3.filter(c => c.category === "Crypto");
  assert.equal(cryptoVisible.length, 2, "Crypto category shows an additional challenge after solving 3");
  assert.equal(cryptoVisible[0].id, 3);
  assert.equal(cryptoVisible[1].id, 4);

  // Forensics should still show only 1
  const forensicsVisible = afterSolve1And3.filter(c => c.category === "Forensics");
  assert.equal(forensicsVisible.length, 1, "Forensics category still shows only 1 challenge");

  // Verify DB category sync
  const dbCh1 = db.prepare("SELECT category FROM challenges WHERE id = 1").get();
  assert.equal(dbCh1.category, "Web", "DB challenge category is synced");
});

test("HTTP: /logout properly deauthenticates session in database and clears cookies", async () => {
  const existingTeam = db.prepare("SELECT name FROM teams LIMIT 1").get();
  assert.ok(existingTeam, "At least one team exists in DB");

  const testToken = "test_logout_token_" + Date.now();
  db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken, existingTeam.name);

  // Verify session exists in DB
  const sessionBefore = db.prepare("SELECT * FROM sessions WHERE token = ?").get(testToken);
  assert.ok(sessionBefore, "Session exists in DB prior to logout");

  // Verify authenticated /session returns teamName and points
  const resSessionBefore = await makeRequest("GET", "/session", {
    Cookie: `session=${testToken}`
  });
  assert.equal(resSessionBefore.statusCode, 200);
  const sessionData = JSON.parse(resSessionBefore.body);
  assert.equal(sessionData.loggedIn, true);
  assert.equal(sessionData.teamName, existingTeam.name);
  assert.equal(typeof sessionData.points, "number");

  // Call POST /logout
  const resLogout = await makeRequest("POST", "/logout", {
    Cookie: `session=${testToken}`
  });
  assert.equal(resLogout.statusCode, 200);
  const logoutData = JSON.parse(resLogout.body);
  assert.equal(logoutData.success, true);

  // Verify session was strictly DELETED from database
  const sessionAfter = db.prepare("SELECT * FROM sessions WHERE token = ?").get(testToken);
  assert.equal(sessionAfter, undefined, "Session row was deleted from database table in ctf.sqlite");

  // Verify Set-Cookie headers clear the session
  const setCookies = resLogout.headers["set-cookie"] || [];
  const setCookieStr = Array.isArray(setCookies) ? setCookies.join("; ") : setCookies;
  assert.match(setCookieStr, /session=;/);
  assert.match(setCookieStr, /Max-Age=0/);

  // Subsequent request with the token is rejected with 401
  const resSessionAfter = await makeRequest("GET", "/session", {
    Cookie: `session=${testToken}`
  });
  assert.equal(resSessionAfter.statusCode, 401);

  // Test GET /logout also deauthenticates and redirects
  const testToken2 = "test_logout_get_" + Date.now();
  db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken2, existingTeam.name);
  const resGetLogout = await makeRequest("GET", "/logout", {
    Cookie: `session=${testToken2}`
  });
  assert.equal(resGetLogout.statusCode, 302);
  assert.equal(resGetLogout.headers["location"], "/login.html");
  assert.equal(db.prepare("SELECT * FROM sessions WHERE token = ?").get(testToken2), undefined);
});

test("Challenges: challenge2.html through challenge6.html exist and serve with correct challenge IDs", async () => {
  for (let id = 2; id <= 6; id++) {
    const res = await makeRequest("GET", `/challenge${id}.html`);
    assert.equal(res.statusCode, 200, `challenge${id}.html returns 200`);
    assert.match(res.body, new RegExp(`<title>Challenge ${id}</title>`), `challenge${id}.html has correct title`);
    assert.match(res.body, new RegExp(`const challengeID = ${id};`), `challenge${id}.html targets challenge ID ${id}`);
    assert.match(res.body, /id="navPoints"/, `challenge${id}.html has navPoints element`);
    assert.match(res.body, /BroadcastChannel\("ctf_progress"\)/, `challenge${id}.html has instant score sync`);
  }
});

test("HTTP & WS: /solve awards points, returns totalPoints, and pushes real-time WebSocket progress", async () => {
  // Set event state to start so submissions are allowed
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  const testTeam = "SolveTestTeam_" + Date.now();
  const testToken = "solve_token_" + Date.now();

  try {
    // Create team and session
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn) VALUES (?, ?, 0, ?, ?)").run(
      testTeam,
      "hash",
      "TestMember",
      "1MS21CS001"
    );
    db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken, testTeam);

    // Get challenge 1 flag from DB
    const ch1 = db.prepare("SELECT flag, solve_count FROM challenges WHERE id = 1").get();
    assert.ok(ch1 && ch1.flag, "Challenge 1 exists with flag in DB");

    // Connect WebSocket as this team
    const ws = new WebSocket("ws://127.0.0.1:3099", {
      headers: {
        Cookie: `session=${testToken}`
      }
    });

    const receivedWsMessages = [];
    ws.on("message", (data) => {
      try {
        receivedWsMessages.push(JSON.parse(data.toString()));
      } catch {}
    });

    // Wait for connection to open
    await new Promise((resolve) => ws.once("open", resolve));
    ws.send(JSON.stringify({ type: "identify" }));
    await new Promise((resolve) => setTimeout(resolve, 50));

    // Submit correct flag for challenge 1
    const resSolve = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, {
      challengeId: 1,
      flag: ch1.flag
    });

    assert.equal(resSolve.statusCode, 200, "Flag submission returns 200");
    const solveData = JSON.parse(resSolve.body);
    assert.equal(solveData.success, true);
    assert.ok(solveData.pointsAwarded > 0, "Points awarded > 0");
    assert.equal(solveData.totalPoints, solveData.pointsAwarded, "totalPoints matches awarded points");
    assert.ok(solveData.solved.includes(1), "Solved array includes challenge 1");

    // Wait briefly for WebSocket push
    await new Promise((resolve) => setTimeout(resolve, 100));

    const progressMsg = receivedWsMessages.find((m) => m.type === "progress");
    assert.ok(progressMsg, "Received WebSocket progress message in real time");
    assert.equal(progressMsg.points, solveData.totalPoints, "WS progress points match totalPoints");
    assert.ok(progressMsg.solved.includes(1), "WS progress solved array includes challenge 1");

    ws.close();
  } finally {
    db.prepare("DELETE FROM solves WHERE team_name = ?").run(testTeam);
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(testTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(testTeam);

    // Reset admin state to wait
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("Leaderboard: GET /api/leaderboard returns logged-in teams sorted by points descending", async () => {
  const teamAlpha = "AlphaTeam_" + Date.now();
  const teamBeta = "BetaTeam_" + Date.now();
  const teamGhost = "GhostTeam_" + Date.now();

  try {
    // teamAlpha: logged in with 100 points
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn, has_logged_in) VALUES (?, ?, 100, 'A', '1MS21CS001', 1)").run(teamAlpha, "h");
    // teamBeta: logged in with 250 points
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn, has_logged_in) VALUES (?, ?, 250, 'B', '1MS21CS002', 1)").run(teamBeta, "h");
    // teamGhost: has NOT logged in (has_logged_in = 0, no session)
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn, has_logged_in) VALUES (?, ?, 50, 'G', '1MS21CS003', 0)").run(teamGhost, "h");

    const res = await makeRequest("GET", "/api/leaderboard");
    assert.equal(res.statusCode, 200);

    const data = JSON.parse(res.body);
    assert.ok(Array.isArray(data.leaderboard), "Leaderboard is an array");

    const names = data.leaderboard.map(t => t.name);
    assert.ok(names.includes(teamAlpha), "teamAlpha is included in leaderboard");
    assert.ok(names.includes(teamBeta), "teamBeta is included in leaderboard");
    assert.equal(names.includes(teamGhost), false, "teamGhost (who never logged in) is excluded from leaderboard");

    // Verify ordering by points DESC
    const idxBeta = names.indexOf(teamBeta);
    const idxAlpha = names.indexOf(teamAlpha);
    assert.ok(idxBeta < idxAlpha, "teamBeta (250 pts) ranks above teamAlpha (100 pts)");

    // Verify ranks are 1-indexed sequential integers
    for (let i = 0; i < data.leaderboard.length; i++) {
      assert.equal(data.leaderboard[i].rank, i + 1, `Rank is sequential: ${i + 1}`);
    }
  } finally {
    db.prepare("DELETE FROM teams WHERE name IN (?, ?, ?)").run(teamAlpha, teamBeta, teamGhost);
  }
});

test("Admin & Timer: duration in HH:MM:SS sets event timer and automatically ends event on expiry", async () => {
  const { parseDuration } = await import("../server.js");

  // Test parser
  assert.equal(parseDuration("01:30:00"), 5400000, "01:30:00 parses to 5,400,000 ms");
  assert.equal(parseDuration("00:05:00"), 300000, "00:05:00 parses to 300,000 ms");
  assert.equal(parseDuration("00:00:02"), 2000, "00:00:02 parses to 2,000 ms");
  assert.equal(parseDuration("clear"), null, "clear parses to null");

  // Set event state to start with 500ms duration
  const resAdmin = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, {
    layout: "start",
    duration: "00:00:01"
  });

  assert.equal(resAdmin.statusCode, 200);
  const dataAdmin = JSON.parse(resAdmin.body);
  assert.equal(dataAdmin.success, true);
  assert.equal(dataAdmin.state.layout, "start");
  assert.ok(typeof dataAdmin.state.timerEnd === "number", "timerEnd timestamp is returned");
  assert.ok(dataAdmin.state.timerEnd > Date.now(), "timerEnd is in the future");

  // Wait for the timer to expire on the server (1.1 seconds)
  await new Promise(resolve => setTimeout(resolve, 1150));

  // Verify server automatically ended the event
  const resStateAfter = await makeRequest("GET", "/state");
  assert.equal(resStateAfter.statusCode, 200);
  const stateAfter = JSON.parse(resStateAfter.body);
  assert.equal(stateAfter.layout, "end", "Event layout automatically transitioned to 'end' when timer expired");
  assert.equal(stateAfter.timerEnd, null, "timerEnd was cleared upon event end");

  // Reset to wait
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "wait" });
});

test("Leaderboard: leaderboard.html serves with 200 and includes top-right timer", async () => {
  const res = await makeRequest("GET", "/leaderboard.html");
  assert.equal(res.statusCode, 200);
  assert.match(res.body, /CTF - Leaderboard/);
  assert.match(res.body, /topRightTimer/);
  assert.match(res.body, /timerDigits/);
  assert.match(res.body, /leaderboardTable/);
});

test("Routing: clean URLs without .html extension resolve properly (e.g. /leaderboard)", async () => {
  const res = await makeRequest("GET", "/leaderboard");
  assert.equal(res.statusCode, 200, "GET /leaderboard returns 200");
  assert.match(res.body, /CTF - Leaderboard/, "Serves leaderboard.html");
});

test("Security & Flow: locked challenges cannot be solved out of order (403 Forbidden)", async () => {
  // Start event
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  const testTeam = "LockTestTeam_" + Date.now();
  const testToken = "lock_token_" + Date.now();

  try {
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn) VALUES (?, 'h', 0, 'Alice', '1MS21CS001')").run(testTeam);
    db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken, testTeam);

    const ch1 = db.prepare("SELECT flag FROM challenges WHERE id = 1").get();
    const ch2 = db.prepare("SELECT flag FROM challenges WHERE id = 2").get();
    const ch4 = db.prepare("SELECT flag FROM challenges WHERE id = 4").get();

    // Attempt to solve challenge 2 (Web category) without solving challenge 1
    const resSolve2 = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 2, flag: ch2.flag });

    assert.equal(resSolve2.statusCode, 403, "Challenge 2 is locked before Challenge 1 is solved");
    assert.match(JSON.parse(resSolve2.body).error, /locked/i);

    // Attempt to solve challenge 4 (Crypto category) without solving challenge 3
    const resSolve4 = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 4, flag: ch4.flag });

    assert.equal(resSolve4.statusCode, 403, "Challenge 4 is locked before Challenge 3 is solved");

    // Now solve challenge 1 (initial Web challenge)
    const resSolve1 = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 1, flag: ch1.flag });

    assert.equal(resSolve1.statusCode, 200, "Challenge 1 succeeds");

    // Now challenge 2 is unlocked and can be solved
    const resSolve2After = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 2, flag: ch2.flag });

    assert.equal(resSolve2After.statusCode, 200, "Challenge 2 now succeeds after Challenge 1 is solved");
  } finally {
    db.prepare("DELETE FROM solves WHERE team_name = ?").run(testTeam);
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(testTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(testTeam);
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("Atomicity & Concurrency: simultaneous duplicate flag submissions record only 1 solve and points once", async () => {
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  const raceTeam = "RaceTeam_" + Date.now();
  const raceToken = "race_token_" + Date.now();

  try {
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn) VALUES (?, 'h', 0, 'Racer', '1MS21CS001')").run(raceTeam);
    db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(raceToken, raceTeam);

    const ch3 = db.prepare("SELECT flag, solve_count FROM challenges WHERE id = 3").get();
    const initialSolveCount = ch3.solve_count;

    // Send two simultaneous submissions for challenge 3
    const [res1, res2] = await Promise.all([
      makeRequest("POST", "/solve", {
        "Content-Type": "application/json",
        Cookie: `session=${raceToken}`
      }, { challengeId: 3, flag: ch3.flag }),
      makeRequest("POST", "/solve", {
        "Content-Type": "application/json",
        Cookie: `session=${raceToken}`
      }, { challengeId: 3, flag: ch3.flag })
    ]);

    const statusCodes = [res1.statusCode, res2.statusCode].sort();
    assert.deepEqual(statusCodes, [200, 409], "Exactly one solve succeeded (200) and the duplicate was rejected (409)");

    // Verify DB: exactly 1 solve recorded in solves table
    const solves = db.prepare("SELECT * FROM solves WHERE team_name = ? AND challenge_id = 3").all(raceTeam);
    assert.equal(solves.length, 1, "Exactly 1 solve entry in database");

    // Verify DB: solve_count incremented by exactly 1
    const updatedCh3 = db.prepare("SELECT solve_count FROM challenges WHERE id = 3").get();
    assert.equal(updatedCh3.solve_count, initialSolveCount + 1, "Global solve_count incremented by exactly 1");

    // Verify points: awarded only once
    const teamDb = db.prepare("SELECT points FROM teams WHERE name = ?").get(raceTeam);
    const successBody = JSON.parse(res1.statusCode === 200 ? res1.body : res2.body);
    assert.equal(teamDb.points, successBody.pointsAwarded, "Team points strictly equal awarded points (no double award)");
  } finally {
    db.prepare("DELETE FROM solves WHERE team_name = ?").run(raceTeam);
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(raceTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(raceTeam);
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("Sync: database, /session, /progress, and /api/leaderboard are strictly identical", async () => {
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "start" });

  const syncTeam = "SyncTeam_" + Date.now();
  const syncToken = "sync_token_" + Date.now();

  try {
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn, has_logged_in) VALUES (?, 'h', 0, 'SyncUser', '1MS21CS001', 1)").run(syncTeam);
    db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(syncToken, syncTeam);

    const ch5 = db.prepare("SELECT flag FROM challenges WHERE id = 5").get();

    // Submit solve for challenge 5 (initial Forensics challenge)
    const solveRes = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${syncToken}`
    }, { challengeId: 5, flag: ch5.flag });

    assert.equal(solveRes.statusCode, 200);
    const solveData = JSON.parse(solveRes.body);
    const expectedPoints = solveData.totalPoints;

    // 1. Direct DB check
    const dbTeam = db.prepare("SELECT points FROM teams WHERE name = ?").get(syncTeam);
    assert.equal(dbTeam.points, expectedPoints, "DB points match solve response");

    // 2. /session check
    const sessionRes = await makeRequest("GET", "/session", { Cookie: `session=${syncToken}` });
    assert.equal(sessionRes.statusCode, 200);
    assert.equal(JSON.parse(sessionRes.body).points, expectedPoints, "/session points match DB");

    // 3. /progress check
    const progressRes = await makeRequest("GET", "/progress", { Cookie: `session=${syncToken}` });
    assert.equal(progressRes.statusCode, 200);
    assert.equal(JSON.parse(progressRes.body).points, expectedPoints, "/progress points match DB");

    // 4. /api/leaderboard check
    const lbRes = await makeRequest("GET", "/api/leaderboard", { Cookie: `session=${syncToken}` });
    assert.equal(lbRes.statusCode, 200);
    const lbData = JSON.parse(lbRes.body);
    const teamInLb = lbData.leaderboard.find(t => t.name === syncTeam);
    assert.ok(teamInLb, "Team appears on leaderboard");
    assert.equal(teamInLb.points, expectedPoints, "Leaderboard points match DB");
  } finally {
    db.prepare("DELETE FROM solves WHERE team_name = ?").run(syncTeam);
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(syncTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(syncTeam);
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("Database: registration with duplicate team name returns 409 Conflict", async () => {
  const dupTeam = "DupNameTeam_" + Date.now();

  try {
    const res1 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
      teamName: dupTeam,
      password: "Password123!",
      members: [{ name: "Player1", usn: "1MS21CS001" }]
    });
    assert.equal(res1.statusCode, 201, "First registration succeeds");

    const res2 = await makeRequest("POST", "/register", { "Content-Type": "application/json" }, {
      teamName: dupTeam,
      password: "Password123!",
      members: [{ name: "Player2", usn: "1MS21CS002" }]
    });
    assert.equal(res2.statusCode, 409, "Duplicate team registration returns 409 Conflict");
    assert.equal(JSON.parse(res2.body).error, "Team name already exists.");
  } finally {
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(dupTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(dupTeam);
  }
});

test("Event Control & Enforcment: /solve, /vm-tunnel, and SSH proxy strictly reject when event is not running", async () => {
  // Ensure state is wait
  await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, { layout: "wait" });

  const testTeam = "EnforceTestTeam_" + Date.now();
  const testToken = "enforce_token_" + Date.now();

  try {
    db.prepare("INSERT INTO teams (name, password_hash, points, member1_name, member1_usn) VALUES (?, 'h', 0, 'Enforce', '1MS21CS001')").run(testTeam);
    db.prepare("INSERT INTO sessions (token, team_name) VALUES (?, ?)").run(testToken, testTeam);

    // 1. /solve must return 403 when event is 'wait'
    const resSolveWait = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 1, flag: "12345-67890" });
    assert.equal(resSolveWait.statusCode, 403, "/solve returns 403 when layout is wait");

    // 2. /vm-tunnel WebSocket must return 403 when event is 'wait'
    const wsWaitStatus = await new Promise((resolve) => {
      const ws = new WebSocket("ws://127.0.0.1:3099/vm-tunnel", {
        headers: { Cookie: `session=${testToken}` }
      });
      ws.on("unexpected-response", (req, res) => resolve(res.statusCode));
      ws.on("open", () => { ws.close(); resolve(200); });
      ws.on("error", () => {});
    });
    assert.equal(wsWaitStatus, 403, "/vm-tunnel returns 403 when layout is wait");

    // 3. SSH proxy must send disconnect packet when event is 'wait'
    const tcpClient = net.createConnection({ host: "127.0.0.1", port: 2299 });
    const sshData = await new Promise((resolve) => {
      let chunks = Buffer.alloc(0);
      tcpClient.on("data", chunk => { chunks = Buffer.concat([chunks, chunk]); });
      tcpClient.on("end", () => resolve(chunks));
    });
    assert.match(sshData.toString("utf8"), /CTF event is not running/, "SSH proxy disconnects with event not running message");

    // 4. Change state to 'end' and verify /solve still returns 403
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "end" });

    const resSolveEnd = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 1, flag: "12345-67890" });
    assert.equal(resSolveEnd.statusCode, 403, "/solve returns 403 when layout is end");

    // 5. Expired timer triggers auto-end and rejection in /solve
    state.layout = "start";
    state.timerEnd = Date.now() - 5000; // 5 seconds in the past

    const resSolveExpired = await makeRequest("POST", "/solve", {
      "Content-Type": "application/json",
      Cookie: `session=${testToken}`
    }, { challengeId: 1, flag: "12345-67890" });
    assert.equal(resSolveExpired.statusCode, 403, "/solve returns 403 when timer is expired");
    assert.equal(state.layout, "end", "Expired timer automatically forced event state to 'end'");
    assert.equal(state.timerEnd, null, "timerEnd cleared");
  } finally {
    db.prepare("DELETE FROM sessions WHERE team_name = ?").run(testTeam);
    db.prepare("DELETE FROM teams WHERE name = ?").run(testTeam);
    await makeRequest("POST", "/admin/state", {
      "Content-Type": "application/json",
      "X-Admin-Token": TEST_ADMIN_TOKEN
    }, { layout: "wait" });
  }
});

test("Admin & State Constraint: if event duration is non-null, the only state that can be set is 'start'", async () => {
  // 1. Attempting to set layout='wait' with non-null duration returns 400 Bad Request
  const resWaitWithDuration = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, {
    layout: "wait",
    duration: "01:00:00"
  });
  assert.equal(resWaitWithDuration.statusCode, 400, "Rejects layout='wait' with non-null duration");
  assert.match(JSON.parse(resWaitWithDuration.body).error, /only state that can be set is 'start'/i);

  // 2. Attempting to set layout='end' with non-null duration returns 400 Bad Request
  const resEndWithDuration = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, {
    layout: "end",
    duration: "00:30:00"
  });
  assert.equal(resEndWithDuration.statusCode, 400, "Rejects layout='end' with non-null duration");
  assert.match(JSON.parse(resEndWithDuration.body).error, /only state that can be set is 'start'/i);

  // 3. Setting duration without specifying layout automatically sets layout to 'start'
  const resOnlyDuration = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, {
    duration: "00:05:00"
  });
  assert.equal(resOnlyDuration.statusCode, 200, "Accepts duration and defaults state to 'start'");
  const onlyDurationData = JSON.parse(resOnlyDuration.body);
  assert.equal(onlyDurationData.state.layout, "start", "State is 'start' when duration is set");
  assert.ok(onlyDurationData.state.timerEnd > Date.now(), "timerEnd is active");

  // 4. Setting layout='wait' with duration='clear' (null duration) succeeds
  const resClearWithWait = await makeRequest("POST", "/admin/state", {
    "Content-Type": "application/json",
    "X-Admin-Token": TEST_ADMIN_TOKEN
  }, {
    layout: "wait",
    duration: "clear"
  });
  assert.equal(resClearWithWait.statusCode, 200, "Setting layout='wait' with duration='clear' succeeds");
  const clearData = JSON.parse(resClearWithWait.body);
  assert.equal(clearData.state.layout, "wait");
  assert.equal(clearData.state.timerEnd, null);

  // 5. WebSocket admin: rejects layout='wait' when duration is non-null
  const ws = new WebSocket("ws://127.0.0.1:3099");
  await new Promise(resolve => ws.once("open", resolve));

  const wsRejectPromise = new Promise(resolve => {
    ws.on("message", data => {
      try {
        const parsed = JSON.parse(data.toString());
        if (parsed.error) resolve(parsed);
      } catch {}
    });
  });

  ws.send(JSON.stringify({
    layout: "wait",
    duration: "01:00:00",
    token: TEST_ADMIN_TOKEN
  }));

  const wsReply = await wsRejectPromise;
  assert.match(wsReply.error, /only state that can be set is 'start'/i, "WebSocket returns error when duration is set with layout='wait'");
  ws.close();
});
