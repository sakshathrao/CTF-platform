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
  }
});
