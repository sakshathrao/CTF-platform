import http from "node:http";
import net from "node:net";
import os from "node:os";
import crypto from "node:crypto";
import path from "node:path";
import { existsSync, mkdirSync, readFileSync, statSync, createReadStream, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import WebSocket, {
    WebSocketServer
} from "ws";

import { challenges } from "./challenges.js";


// ============================================================
// Database & Configuration
// ============================================================

const __filename =
    fileURLToPath(import.meta.url);

const __dirname =
    path.dirname(__filename);

// Robust database path resolution:
// 1. Explicit DB_PATH env var
// 2. ../CTF_data/ctf.sqlite (default location in parent dir)
// 3. ./CTF_data/ctf.sqlite (fallback in current dir)
const candidateDbPaths = [
    process.env.DB_PATH,
    path.join(__dirname, "../CTF_data/ctf.sqlite"),
    path.join(__dirname, "CTF_data/ctf.sqlite")
].filter(Boolean);

const dbPath = candidateDbPaths.find(p => existsSync(p)) || candidateDbPaths[1] || candidateDbPaths[0];
const dbDir = path.dirname(dbPath);
if (!existsSync(dbDir)) {
    mkdirSync(dbDir, { recursive: true });
}

// Ensure v86 runtime assets exist in dist if dist directory exists
const distDir = path.join(__dirname, "dist");
const distV86Dir = path.join(distDir, "node_modules", "v86", "build");
const srcV86Dir = path.join(__dirname, "node_modules", "v86", "build");
if (existsSync(distDir) && existsSync(srcV86Dir)) {
    try {
        if (!existsSync(distV86Dir)) {
            mkdirSync(distV86Dir, { recursive: true });
        }
        for (const file of ["libv86.js", "libv86.mjs", "v86.wasm", "v86-fallback.wasm"]) {
            const srcFile = path.join(srcV86Dir, file);
            const dstFile = path.join(distV86Dir, file);
            if (existsSync(srcFile) && !existsSync(dstFile)) {
                copyFileSync(srcFile, dstFile);
            }
        }

        // Ensure kernel and bios images exist in dist/images
        const distImagesDir = path.join(distDir, "images");
        const srcImagesDir = path.join(__dirname, "public", "images");
        if (existsSync(srcImagesDir)) {
            if (!existsSync(distImagesDir)) {
                mkdirSync(distImagesDir, { recursive: true });
            }
            for (const file of ["bzImageSSH", "customBzImage", "seabios.bin", "vgabios.bin"]) {
                const srcFile = path.join(srcImagesDir, file);
                const dstFile = path.join(distImagesDir, file);
                if (existsSync(srcFile) && !existsSync(dstFile)) {
                    copyFileSync(srcFile, dstFile);
                }
            }
        }
    } catch {
        // Ignore packaging sync errors during boot
    }
}

const db = new DatabaseSync(dbPath);

db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA journal_mode = WAL;");

// Initialize tables if they do not exist
db.exec(`
CREATE TABLE IF NOT EXISTS teams (
    name TEXT PRIMARY KEY,
    points INTEGER NOT NULL DEFAULT 0,
    member1_name TEXT NOT NULL,
    member1_usn TEXT NOT NULL,
    member2_name TEXT,
    member2_usn TEXT,
    member3_name TEXT,
    member3_usn TEXT,
    password_hash TEXT,
    password_salt TEXT
);

CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY,
    solve_count INTEGER NOT NULL DEFAULT 0,
    flag TEXT,
    category TEXT
);

CREATE TABLE IF NOT EXISTS solves (
    team_name TEXT NOT NULL,
    challenge_id INTEGER NOT NULL,
    PRIMARY KEY (team_name, challenge_id),
    FOREIGN KEY (team_name) REFERENCES teams(name),
    FOREIGN KEY (challenge_id) REFERENCES challenges(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    team_name TEXT NOT NULL,
    FOREIGN KEY (team_name) REFERENCES teams(name)
);
`);

try {
    db.exec("ALTER TABLE challenges ADD COLUMN category TEXT;");
} catch {}

// Seed any challenges from challenges.js missing from the database
try {
    const existingChallenges = new Set(
        db.prepare("SELECT id FROM challenges").all().map(c => c.id)
    );
    const insertChallenge = db.prepare(
        "INSERT INTO challenges (id, flag, solve_count, category) VALUES (?, ?, 0, ?)"
    );
    const updateCategory = db.prepare(
        "UPDATE challenges SET category = ? WHERE id = ?"
    );
    for (const c of challenges) {
        if (!existingChallenges.has(c.id)) {
            insertChallenge.run(c.id, c.flag ?? null, c.category || "General");
        } else {
            updateCategory.run(c.category || "General", c.id);
            if (c.flag) {
                db.prepare("UPDATE challenges SET flag = ? WHERE id = ?").run(c.flag, c.id);
            }
        }
    }
} catch (err) {
    console.warn("Could not sync challenges:", err.message);
}

// Admin Token: environment variable or random secure token
const ADMIN_TOKEN = (process.env.ADMIN_TOKEN && process.env.ADMIN_TOKEN.trim()) || "ctf-admin-secret-" + crypto.randomBytes(16).toString("hex");

function verifyAdminToken(providedToken) {
    if (!providedToken || typeof providedToken !== "string") return false;
    const provided = Buffer.from(providedToken);
    const expected = Buffer.from(ADMIN_TOKEN);
    if (provided.length !== expected.length) return false;
    return crypto.timingSafeEqual(provided, expected);
}


// ============================================================
// CTF state
// ============================================================

const state = {
    layout: "wait"
};

// Rate limiting: track requests per team/session
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 30; // max requests per window
const FLAG_RATE_LIMIT_MAX = 10; // max flag submissions per window

function checkRateLimit(key, max) {
    const now = Date.now();
    const record = rateLimitMap.get(key) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
    
    if (now > record.resetAt) {
        record.count = 0;
        record.resetAt = now + RATE_LIMIT_WINDOW;
    }
    
    record.count++;
    rateLimitMap.set(key, record);
    
    // Cleanup old entries periodically
    if (rateLimitMap.size > 1000) {
        for (const [k, v] of rateLimitMap) {
            if (v.resetAt < now) rateLimitMap.delete(k);
        }
    }
    
    return record.count <= max;
}

// Simple HTML escaper for XSS prevention
function escapeHTML(str) {
    if (typeof str !== 'string') return str;
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#x27;');
}

// Validate team name: alphanumeric, hyphens, underscores, 1-32 chars
function validateTeamName(name) {
    if (typeof name !== 'string') return false;
    return /^[a-zA-Z0-9_-]{1,32}$/.test(name);
}

// Validate USN: exactly 10 digits
function validateUSN(usn) {
    if (typeof usn !== 'string') return false;
    return /^\d{10}$/.test(usn);
}

// CSRF token generation and validation
function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

const csrfTokenStore = new Map(); // teamName -> csrfToken

function validateCSRFToken(teamName, token) {
    const stored = csrfTokenStore.get(teamName);
    if (!stored || stored !== token) return false;
    csrfTokenStore.delete(teamName); // Single use
    return true;
}


// ============================================================
// Helpers
// ============================================================

function sendJSON(
    res,
    status,
    data
) {

    res.writeHead(
        status,
        {
            "Content-Type":
                "application/json"
        }
    );

    res.end(
        JSON.stringify(data)
    );
}


function getCookie(
    req,
    name
) {

    const cookieHeader =
        req.headers.cookie;

    if (!cookieHeader) {
        return null;
    }

    for (
        const part
        of cookieHeader.split(";")
    ) {

        const [
            key,
            ...value
        ] =
            part.trim().split("=");

        if (key === name) {

            return decodeURIComponent(
                value.join("=")
            );
        }
    }

    return null;
}


function makeCookie(
    name,
    value
) {

    return (
        `${name}=${encodeURIComponent(value)}; ` +
        "SameSite=Strict; " +
        "Path=/"
    );
}


function setSecurityHeaders(
    res
) {
    // Prevent clickjacking
    res.setHeader("X-Frame-Options", "DENY");
    // XSS protection for older browsers
    res.setHeader("X-XSS-Protection", "0");
    // Prevent MIME-type sniffing
    res.setHeader("X-Content-Type-Options", "nosniff");
    // Referrer policy
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    // Content Security Policy - restrict script sources to self
    // Note: v86 loads scripts from node_modules and requires wasm compilation
    res.setHeader("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' blob: data:; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: blob:; " +
        "connect-src 'self' ws: wss:; " +
        "font-src 'self' data:; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'");
}

function setCORS(
    req,
    res
) {

    setSecurityHeaders(res);

    const origin =
        req.headers.origin;

    if (origin) {

        try {

            const originURL =
                new URL(origin);

            const serverHost =
                req.headers.host
                    .split(":")[0];

            if (
                originURL.protocol === "http:" &&
                originURL.hostname === serverHost
            ) {

                res.setHeader(
                    "Access-Control-Allow-Origin",
                    origin
                );

                res.setHeader(
                    "Access-Control-Allow-Credentials",
                    "true"
                );

                res.setHeader(
                    "Vary",
                    "Origin"
                );
            }

        } catch {
            // Invalid Origin.
        }
    }

    res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
    );

    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type"
    );
}


function readRequestBody(req) {

    return new Promise(
        (resolve, reject) => {

            let body = "";

            req.on(
                "data",
                chunk => {

                    body += chunk;

                    if (
                        body.length >
                        1024 * 1024
                    ) {

                        reject(
                            new Error(
                                "Request body too large"
                            )
                        );

                        req.destroy();
                    }
                }
            );

            req.on(
                "end",
                () => {
                    resolve(body);
                }
            );

            req.on(
                "error",
                reject
            );
        }
    );
}


function hashPassword(
    password,
    salt
) {

    return crypto.scryptSync(
        password,
        salt,
        64
    );
}


function passwordMatches(
    password,
    saltHex,
    hashHex
) {

    const salt =
        Buffer.from(
            saltHex,
            "hex"
        );

    const storedHash =
        Buffer.from(
            hashHex,
            "hex"
        );

    const submittedHash =
        hashPassword(
            password,
            salt
        );

    return (
        submittedHash.length ===
        storedHash.length &&
        crypto.timingSafeEqual(
            submittedHash,
            storedHash
        )
    );
}


function createSession(
    teamName
) {

    const sessionID =
        crypto
            .randomBytes(32)
            .toString("hex");

    db.prepare(`
        INSERT INTO sessions (
            token,
            team_name
        )
        VALUES (?, ?)
    `).run(
        sessionID,
        teamName
    );

    return sessionID;
}


function getTeamFromSession(
    req
) {

    const sessionID =
        getCookie(
            req,
            "session"
        );

    if (!sessionID) {
        return null;
    }

    const session =
        db.prepare(`
            SELECT team_name
            FROM sessions
            WHERE token = ?
        `).get(sessionID);

    if (!session) {
        return null;
    }

    return session.team_name;
}


function getTeamProgress(
    teamName
) {

    const team =
        db.prepare(`
            SELECT points
            FROM teams
            WHERE name = ?
        `).get(teamName);

    const solves =
        db.prepare(`
            SELECT challenge_id
            FROM solves
            WHERE team_name = ?
            ORDER BY challenge_id
        `).all(teamName);

    return {
        points: team?.points ?? 0,
        solved: solves.map(
            solve => solve.challenge_id
        )
    };
}


function progressCookie(
    teamName
) {

    const progress =
        getTeamProgress(
            teamName
        );

    return makeCookie(
        "ctf_progress",
        JSON.stringify(progress)
    );
}


// ============================================================
// HTTP server
// ============================================================

const server =
    http.createServer(
        async (req, res) => {

            setCORS(
                req,
                res
            );


            // ------------------------------------------------
            // CORS preflight
            // ------------------------------------------------

            if (
                req.method ===
                "OPTIONS"
            ) {

                res.writeHead(204);
                res.end();

                return;
            }


            // =================================================
            // REGISTER
            // =================================================

            if (
                req.method === "POST" &&
                req.url === "/register"
            ) {

                let data;

                try {

                    const body =
                        await readRequestBody(
                            req
                        );

                    data =
                        JSON.parse(body);

                } catch {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Invalid request."
                        }
                    );

                    return;
                }


                const teamNameRaw =
                    typeof data.teamName ===
                    "string"
                        ? data.teamName.trim()
                        : "";
                
                // Validate team name format (alphanumeric, hyphens, underscores only)
                if (!validateTeamName(teamNameRaw)) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Invalid team name. Use only letters, numbers, hyphens, and underscores (1-32 characters)."
                        }
                    );

                    return;

                }

                const teamName = teamNameRaw;

                const password =
                    typeof data.password ===
                    "string"
                        ? data.password
                        : "";

                const members =
                    Array.isArray(data.members)
                        ? data.members
                        : [];


                if (
                    !teamName ||
                    !password ||
                    members.length < 1 ||
                    members.length > 3
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Missing or invalid fields."
                        }
                    );

                    return;
                }


                if (
                    password.length < 8
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Password must be at least 8 characters."
                        }
                    );

                    return;
                }


                const memberValues =
                    [];


                for (
                    let i = 0;
                    i < 3;
                    i++
                ) {

                    const member =
                        members[i] ?? {};

                    const name =
                        typeof member.name ===
                        "string"
                            ? member.name.trim()
                            : "";

                    const usn =
                        typeof member.usn ===
                        "string"
                            ? member.usn.trim()
                            : "";


                    if (
                        usn &&
                        usn.length !== 10
                    ) {

                        sendJSON(
                            res,
                            400,
                            {
                                error:
                                    "Invalid USN."
                            }
                        );

                        return;
                    }


                    memberValues.push(
                        name || null,
                        usn || null
                    );
                }


                if (
                    !memberValues[0] ||
                    !memberValues[1]
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Team member 1 is required."
                        }
                    );

                    return;
                }


                const enteredNames = [];
                const enteredUSNs = [];
                for (let i = 0; i < 3; i++) {
                    const name = memberValues[i * 2];
                    const usn = memberValues[i * 2 + 1];
                    if (name) enteredNames.push({ index: i + 1, name });
                    if (usn) enteredUSNs.push({ index: i + 1, usn });
                }

                for (let i = 0; i < enteredNames.length; i++) {
                    for (let j = i + 1; j < enteredNames.length; j++) {
                        if (enteredNames[i].name.toLowerCase() === enteredNames[j].name.toLowerCase()) {
                            sendJSON(
                                res,
                                400,
                                {
                                    error:
                                        `Member ${enteredNames[i].index} and Member ${enteredNames[j].index} cannot have the same name.`
                                }
                            );

                            return;
                        }
                    }
                }

                for (let i = 0; i < enteredUSNs.length; i++) {
                    for (let j = i + 1; j < enteredUSNs.length; j++) {
                        if (enteredUSNs[i].usn.toUpperCase() === enteredUSNs[j].usn.toUpperCase()) {
                            sendJSON(
                                res,
                                400,
                                {
                                    error:
                                        `Member ${enteredUSNs[i].index} and Member ${enteredUSNs[j].index} cannot have the same USN.`
                                }
                            );

                            return;
                        }
                    }
                }


                const salt =
                    crypto.randomBytes(16);

                const passwordHash =
                    hashPassword(
                        password,
                        salt
                    );


                try {

                    db.exec("BEGIN");


                    db.prepare(`
                        INSERT INTO teams (
                            name,
                            password_hash,
                            password_salt,
                            points,
                            member1_name,
                            member1_usn,
                            member2_name,
                            member2_usn,
                            member3_name,
                            member3_usn
                        )
                        VALUES (
                            ?,
                            ?,
                            ?,
                            0,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?,
                            ?
                        )
                    `).run(
                        teamName,
                        passwordHash.toString("hex"),
                        salt.toString("hex"),
                        ...memberValues
                    );


                    const sessionID =
                        createSession(
                            teamName
                        );


                    db.exec("COMMIT");


                    res.writeHead(
                        201,
                        {
                            "Content-Type":
                                "application/json",

                            "Set-Cookie": [
                                makeCookie(
                                    "session",
                                    sessionID
                                ) +
                                "; HttpOnly",

                                progressCookie(
                                    teamName
                                )
                            ]
                        }
                    );

                    res.end(
                        JSON.stringify({
                            success: true
                        })
                    );

                } catch (error) {

                    try {
                        db.exec(
                            "ROLLBACK"
                        );
                    } catch {}

                    if (
                        error?.code?.startsWith(
                            "SQLITE_CONSTRAINT"
                        )
                    ) {

                        sendJSON(
                            res,
                            409,
                            {
                                error:
                                    "Team name already exists."
                            }
                        );

                        return;
                    }

                    console.error(error);

                    sendJSON(
                        res,
                        500,
                        {
                            error:
                                "Could not register team."
                        }
                    );
                }

                return;
            }


            // =================================================
            // LOGIN
            // =================================================

            if (
                req.method === "POST" &&
                req.url === "/login"
            ) {

                let data;

                try {

                    const body =
                        await readRequestBody(
                            req
                        );

                    data =
                        JSON.parse(body);

                } catch {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Invalid request."
                        }
                    );

                    return;
                }


                const teamName =
                    typeof data.teamName ===
                    "string"
                        ? data.teamName.trim()
                        : "";

                const password =
                    typeof data.password ===
                    "string"
                        ? data.password
                        : "";


                if (
                    !teamName ||
                    !password
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Team name and password are required."
                        }
                    );

                    return;
                }


                const team =
                    db.prepare(`
                        SELECT
                            name,
                            password_hash,
                            password_salt
                        FROM teams
                        WHERE name = ?
                    `).get(teamName);


                if (!team) {

                    sendJSON(
                        res,
                        401,
                        {
                            error:
                                "Invalid team name or password."
                        }
                    );

                    return;
                }


                let valid = false;

                try {

                    valid =
                        passwordMatches(
                            password,
                            team.password_salt,
                            team.password_hash
                        );

                } catch {

                    valid = false;
                }


                if (!valid) {

                    sendJSON(
                        res,
                        401,
                        {
                            error:
                                "Invalid team name or password."
                        }
                    );

                    return;
                }


                try {

                    const sessionID =
                        createSession(
                            teamName
                        );


                    res.writeHead(
                        200,
                        {
                            "Content-Type":
                                "application/json",

                            "Set-Cookie": [
                                makeCookie(
                                    "session",
                                    sessionID
                                ) +
                                "; HttpOnly",

                                progressCookie(
                                    teamName
                                )
                            ]
                        }
                    );

                    res.end(
                        JSON.stringify({
                            success: true
                        })
                    );

                } catch (error) {

                    console.error(error);

                    sendJSON(
                        res,
                        500,
                        {
                            error:
                                "Could not log in."
                        }
                    );
                }

                return;
            }


            // =================================================
            // SESSION CHECK
            // =================================================

            if (
                req.method === "GET" &&
                req.url === "/session"
            ) {

                const teamName =
                    getTeamFromSession(
                        req
                    );

                if (!teamName) {

                    sendJSON(
                        res,
                        401,
                        {
                            error:
                                "Not logged in."
                        }
                    );

                    return;
                }


                const team = db.prepare(`
                    SELECT points
                    FROM teams
                    WHERE name = ?
                `).get(teamName);

                sendJSON(
                    res,
                    200,
                    {
                        loggedIn: true,
                        teamName,
                        points: team?.points ?? 0
                    }
                );

                return;
            }


            // =================================================
            // LOGOUT
            // =================================================

            if (
                (req.method === "POST" || req.method === "GET") &&
                req.url === "/logout"
            ) {

                const sessionID =
                    getCookie(
                        req,
                        "session"
                    );

                if (sessionID) {
                    const session =
                        db.prepare(
                            "SELECT team_name FROM sessions WHERE token = ?"
                        ).get(sessionID);

                    if (session?.team_name) {
                        const tunnel =
                            activeTunnels.get(
                                session.team_name
                            );

                        if (tunnel) {
                            try {
                                tunnel.close();
                            } catch {}
                            activeTunnels.delete(
                                session.team_name
                            );
                        }
                    }

                    db.prepare(
                        "DELETE FROM sessions WHERE token = ?"
                    ).run(sessionID);
                }

                res.writeHead(
                    req.method === "GET" ? 302 : 200,
                    {
                        "Content-Type":
                            "application/json",

                        ...(req.method === "GET" ? { "Location": "/login.html" } : {}),

                        "Set-Cookie": [
                            makeCookie("session", "") + "; Max-Age=0; HttpOnly",
                            makeCookie("ctf_progress", "") + "; Max-Age=0"
                        ]
                    }
                );

                res.end(
                    JSON.stringify({
                        success: true,
                        message: "Logged out."
                    })
                );

                return;
            }


            // =================================================
            // PROGRESS
            //
            // The database is the source of truth.
            // This endpoint refreshes the UI cookie.
            // =================================================

            if (
                req.method === "GET" &&
                req.url === "/progress"
            ) {

                const teamName =
                    getTeamFromSession(
                        req
                    );

                if (!teamName) {

                    sendJSON(
                        res,
                        401,
                        {
                            error:
                                "Not logged in."
                        }
                    );

                    return;
                }


                const progress =
                    getTeamProgress(
                        teamName
                    );


                res.writeHead(
                    200,
                    {
                        "Content-Type":
                            "application/json",

                        "Set-Cookie":
                            progressCookie(
                                teamName
                            )
                    }
                );

                res.end(
                    JSON.stringify(
                        progress
                    )
                );

                return;
            }


            // =================================================
            // EVENT STATE
            // =================================================

            if (
                req.method === "GET" &&
                req.url === "/state"
            ) {

                sendJSON(
                    res,
                    200,
                    state
                );

                return;
            }


            // =================================================
            // FLAG SUBMISSION
            // =================================================

                        if (
                req.method === "POST" &&
                req.url === "/solve"
            ) {

                const teamName =
                    getTeamFromSession(
                        req
                    );

                if (!teamName) {

                    sendJSON(
                        res,
                        401,
                        {
                            error:
                                "Not logged in."
                        }
                    );

                    return;
                }

                // Rate limiting per team for flag submissions
                if (!checkRateLimit('solve:' + teamName, FLAG_RATE_LIMIT_MAX)) {
                    sendJSON(
                        res,
                        429,
                        { error: 'Too many flag submissions. Please wait before trying again.' }
                    );
                    return;
                }

                // Don't allow submissions while
                // the event isn't running.

                if (
                    state.layout !==
                    "start"
                ) {

                    sendJSON(
                        res,
                        403,
                        {
                            error:
                                "The event is not currently running."
                        }
                    );

                    return;
                }

                let data;

                try {

                    const body =
                        await readRequestBody(
                            req
                        );

                    data =
                        JSON.parse(body);

                } catch {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Invalid request."
                        }
                    );

                    return;
                }


                const challengeID =
                    Number(
                        data.challengeId
                    );

                const submittedFlag =
                    typeof data.flag ===
                    "string"
                        ? data.flag.trim()
                        : "";


                if (
                    !Number.isInteger(
                        challengeID
                    ) ||
                    !submittedFlag
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Invalid challenge or flag."
                        }
                    );

                    return;
                }


                // Get the authoritative challenge
                // information from SQLite.

                const challenge =
                    db.prepare(`
                        SELECT
                            id,
                            flag,
                            solve_count
                        FROM challenges
                        WHERE id = ?
                    `).get(
                        challengeID
                    );


                if (!challenge) {

                    sendJSON(
                        res,
                        404,
                        {
                            error:
                                "Challenge not found."
                        }
                    );

                    return;
                }


                // Check whether this team already
                // solved this challenge.

                const alreadySolved =
                    db.prepare(`
                        SELECT 1
                        FROM solves
                        WHERE team_name = ?
                        AND challenge_id = ?
                    `).get(
                        teamName,
                        challengeID
                    );


                if (alreadySolved) {

                    sendJSON(
                        res,
                        409,
                        {
                            error:
                                "Challenge already solved."
                        }
                    );

                    return;
                }


                // Check flag.

                if (
                    submittedFlag !==
                    challenge.flag
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                "Incorrect flag."
                        }
                    );

                    return;
                }


                // Find base points from server-side
                // challenge metadata.

                const challengeInfo =
                    challenges.find(
                        challenge =>
                            challenge.id ===
                            challengeID
                    );


                if (!challengeInfo) {

                    sendJSON(
                        res,
                        500,
                        {
                            error:
                                "Challenge configuration missing."
                        }
                    );

                    return;
                }


                /*
                 * IMPORTANT:
                 *
                 * Everything from here through COMMIT
                 * happens inside one transaction.
                 *
                 * solve_count:
                 *
                 * 0 -> 130%
                 * 1 -> 120%
                 * 2 -> 110%
                 * 3+ -> 100%
                 */

                try {

                    db.exec(
                        "BEGIN IMMEDIATE"
                    );


                    // Re-check inside the transaction.
                    //
                    // This protects against two requests
                    // arriving almost simultaneously.

                    const solvedInsideTransaction =
                        db.prepare(`
                            SELECT 1
                            FROM solves
                            WHERE team_name = ?
                            AND challenge_id = ?
                        `).get(
                            teamName,
                            challengeID
                        );


                    if (
                        solvedInsideTransaction
                    ) {

                        db.exec(
                            "ROLLBACK"
                        );

                        sendJSON(
                            res,
                            409,
                            {
                                error:
                                    "Challenge already solved."
                            }
                        );

                        return;
                    }


                    const currentChallenge =
                        db.prepare(`
                            SELECT
                                flag,
                                solve_count
                            FROM challenges
                            WHERE id = ?
                        `).get(
                            challengeID
                        );


                    if (
                        !currentChallenge ||
                        currentChallenge.flag !==
                            submittedFlag
                    ) {

                        db.exec(
                            "ROLLBACK"
                        );

                        sendJSON(
                            res,
                            400,
                            {
                                error:
                                    "Incorrect flag."
                            }
                        );

                        return;
                    }


                    const solveCount =
                        currentChallenge.solve_count;


                    let multiplier;
                    let bonusPercent = 0;


                    if (
                        solveCount === 0
                    ) {

                        multiplier = 1.30;
                        bonusPercent = 30;

                    } else if (
                        solveCount === 1
                    ) {

                        multiplier = 1.20;
                        bonusPercent = 20;

                    } else if (
                        solveCount === 2
                    ) {

                        multiplier = 1.10;
                        bonusPercent = 10;

                    } else {

                        multiplier = 1.00;
                        bonusPercent = 0;
                    }


                    const pointsAwarded =
                        Math.floor(
                            challengeInfo.points *
                            multiplier
                        );


                    // Record the solve.
                    //
                    // The PRIMARY KEY
                    // (team_name, challenge_id)
                    // prevents duplicate solves.

                    db.prepare(`
                        INSERT INTO solves (
                            team_name,
                            challenge_id
                        )
                        VALUES (?, ?)
                    `).run(
                        teamName,
                        challengeID
                    );


                    // Increment global solve count.

                    db.prepare(`
                        UPDATE challenges
                        SET solve_count =
                            solve_count + 1
                        WHERE id = ?
                    `).run(
                        challengeID
                    );


                    // Award points.

                    db.prepare(`
                        UPDATE teams
                        SET points =
                            points + ?
                        WHERE name = ?
                    `).run(
                        pointsAwarded,
                        teamName
                    );


                    db.exec(
                        "COMMIT"
                    );


                    // Get fresh progress AFTER commit.

                    const progress =
                        getTeamProgress(
                            teamName
                        );


                    // This cookie is ONLY UI state.
                    //
                    // The database remains authoritative.

                    res.writeHead(
                        200,
                        {
                            "Content-Type":
                                "application/json",

                            "Set-Cookie":
                                progressCookie(
                                    teamName
                                )
                        }
                    );

                    res.end(
                        JSON.stringify({
                            success: true,
                            bonusPercent,
                            pointsAwarded,
                            totalPoints:
                                progress.points,
                            solved:
                                progress.solved
                        })
                    );

                    // Broadcast real-time score and progress update to any connected sockets for this team
                    const progressBroadcast = JSON.stringify({
                        type: "progress",
                        points: progress.points,
                        solved: progress.solved
                    });
                    for (const client of wss.clients) {
                        if (client.readyState === WebSocket.OPEN && client.teamName === teamName) {
                            client.send(progressBroadcast);
                        }
                    }


                    console.log(
                        `${teamName} solved challenge ${challengeID} for ${pointsAwarded} points`
                    );

                } catch (error) {

                    try {
                        db.exec(
                            "ROLLBACK"
                        );
                    } catch {}

                    console.error(error);

                    sendJSON(
                        res,
                        500,
                        {
                            error:
                                "Could not submit flag."
                        }
                    );
                }

                return;
            }


            // =================================================
            // ADMIN STATE (HTTP endpoint)
            // =================================================

            if (
                req.method === "POST" &&
                req.url === "/admin/state"
            ) {
                const authHeader = req.headers.authorization || "";
                const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
                const headerToken = req.headers["x-admin-token"] || bearerToken;

                let bodyData = {};
                try {
                    const body = await readRequestBody(req);
                    bodyData = body ? JSON.parse(body) : {};
                } catch {
                    sendJSON(res, 400, { error: "Invalid JSON request body." });
                    return;
                }

                const token = headerToken || bodyData.token || bodyData.adminToken;
                if (!verifyAdminToken(token)) {
                    sendJSON(res, 401, { error: "Unauthorized: Invalid or missing admin token." });
                    return;
                }

                const newLayout = bodyData.layout;
                if (newLayout !== "wait" && newLayout !== "start" && newLayout !== "end") {
                    sendJSON(res, 400, { error: "Invalid layout. Must be 'wait', 'start', or 'end'." });
                    return;
                }

                state.layout = newLayout;
                console.log("State updated via HTTP admin to:", state);

                const broadcastMsg = JSON.stringify(state);
                for (const client of wss.clients) {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(broadcastMsg);
                    }
                }

                sendJSON(res, 200, { success: true, state });
                return;
            }


            // =================================================
            // Static file serving (dist/)
            // =================================================

            if (req.method === "GET" || req.method === "HEAD") {
                const distDir = path.join(__dirname, "dist");
                const staticDir = existsSync(distDir) ? distDir : __dirname;
                let urlPath;
                try {
                    urlPath = decodeURIComponent(req.url.split("?")[0]);
                } catch {
                    res.writeHead(400);
                    res.end("Bad Request");
                    return;
                }

                if (urlPath === "/favicon.ico" && !existsSync(path.join(staticDir, "favicon.ico"))) {
                    res.writeHead(204);
                    res.end();
                    return;
                }

                if (urlPath.includes("..") || urlPath.startsWith("/..")) {
                    res.writeHead(403);
                    res.end("Forbidden");
                    return;
                }

                let cleanPath = urlPath.startsWith("/") ? urlPath.slice(1) : urlPath;
                if (cleanPath === "" || cleanPath === "/") {
                    cleanPath = "main.html";
                }

                // Prevent access to server code, DBs, and configs if falling back to project root
                if (staticDir === __dirname) {
                    const normalized = cleanPath.toLowerCase();
                    if (
                        normalized.startsWith(".") ||
                        normalized.startsWith("server") ||
                        normalized.startsWith("tests") ||
                        normalized.includes("package") ||
                        normalized.endsWith(".sqlite") ||
                        normalized.endsWith(".db") ||
                        normalized.endsWith(".env") ||
                        normalized.endsWith(".md")
                    ) {
                        res.writeHead(403);
                        res.end("Forbidden");
                        return;
                    }
                }

                let filePath = path.join(staticDir, cleanPath);
                let resolvedPath = path.resolve(filePath);
                const resolvedStatic = path.resolve(staticDir);

                // Auto-sync missing runtime assets (node_modules or images) if staticDir is dist
                if (!existsSync(resolvedPath) && staticDir === distDir) {
                    let sourcePath = null;
                    if (cleanPath.startsWith("node_modules/")) {
                        sourcePath = path.resolve(path.join(__dirname, cleanPath));
                    } else if (cleanPath.startsWith("images/")) {
                        sourcePath = path.resolve(path.join(__dirname, "public", cleanPath));
                    }
                    const rootDir = path.resolve(__dirname);
                    if (sourcePath && (sourcePath.startsWith(rootDir + path.sep) || sourcePath === rootDir) && existsSync(sourcePath)) {
                        try {
                            mkdirSync(path.dirname(resolvedPath), { recursive: true });
                            copyFileSync(sourcePath, resolvedPath);
                        } catch {}
                    }
                }

                if ((resolvedPath.startsWith(resolvedStatic + path.sep) || resolvedPath === resolvedStatic) && existsSync(resolvedPath)) {
                    try {
                        const stats = statSync(resolvedPath);
                        if (!stats.isDirectory()) {
                            const ext = path.extname(resolvedPath).toLowerCase();
                            const MIME_TYPES = {
                                ".html": "text/html; charset=utf-8",
                                ".css": "text/css; charset=utf-8",
                                ".js": "application/javascript; charset=utf-8",
                                ".mjs": "application/javascript; charset=utf-8",
                                ".json": "application/json",
                                ".png": "image/png",
                                ".jpg": "image/jpeg",
                                ".jpeg": "image/jpeg",
                                ".gif": "image/gif",
                                ".webp": "image/webp",
                                ".svg": "image/svg+xml",
                                ".ico": "image/x-icon",
                                ".wasm": "application/wasm",
                                ".bin": "application/octet-stream",
                                ".img": "application/octet-stream",
                                ".iso": "application/x-iso9660-image"
                            };
                            const contentType = MIME_TYPES[ext] || "application/octet-stream";

                            res.setHeader("Accept-Ranges", "bytes");

                            // HTTP Range request support (essential for v86 chunked VM image loading)
                            const rangeHeader = req.headers["range"];
                            if (rangeHeader && req.method === "GET") {
                                const totalSize = stats.size;
                                const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
                                if (match) {
                                    const start = parseInt(match[1], 10);
                                    const end = match[2] ? parseInt(match[2], 10) : totalSize - 1;

                                    if (start < totalSize && end >= start) {
                                        const endClamped = Math.min(end, totalSize - 1);
                                        const chunkSize = (endClamped - start) + 1;
                                        res.setHeader("Content-Type", contentType);
                                        res.setHeader("Content-Range", `bytes ${start}-${endClamped}/${totalSize}`);
                                        res.setHeader("Content-Length", chunkSize);
                                        res.setHeader("Cache-Control", "public, max-age=3600");
                                        res.writeHead(206);
                                        createReadStream(resolvedPath, { start, end: endClamped }).pipe(res);
                                        return;
                                    } else {
                                        res.setHeader("Content-Range", `bytes */${totalSize}`);
                                        res.writeHead(416);
                                        res.end();
                                        return;
                                    }
                                }
                            }

                            // Content negotiation
                            const acceptEncoding = (req.headers["accept-encoding"] || "")
                                .split(",")
                                .map(e => e.trim().split(";")[0].toLowerCase());

                            let servePath = resolvedPath;
                            let encoding = null;

                            if (acceptEncoding.includes("br") && existsSync(resolvedPath + ".br")) {
                                servePath = resolvedPath + ".br";
                                encoding = "br";
                            } else if (acceptEncoding.includes("gzip") && existsSync(resolvedPath + ".gz")) {
                                servePath = resolvedPath + ".gz";
                                encoding = "gzip";
                            }

                            res.setHeader("Vary", "Accept-Encoding");
                            res.setHeader("Content-Type", contentType);

                            if (encoding) {
                                res.setHeader("Content-Encoding", encoding);
                            }

                            if (cleanPath.startsWith("assets/") && /\-[A-Za-z0-9_-]{8,}\.(js|css|png|webp|svg)$/.test(cleanPath)) {
                                res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
                            } else if (cleanPath.endsWith(".html")) {
                                res.setHeader("Cache-Control", "no-cache");
                            } else {
                                res.setHeader("Cache-Control", "public, max-age=3600");
                            }

                            if (req.method === "HEAD") {
                                res.setHeader("Content-Length", statSync(servePath).size);
                                res.writeHead(200);
                                res.end();
                                return;
                            }

                            res.writeHead(200);
                            res.end(readFileSync(servePath));
                            return;
                        }
                    } catch (err) {
                        console.error("Static file error:", err);
                    }
                }
            }


            // =================================================
            // Unknown request
            // =================================================

            res.writeHead(404);

            res.end(
                "Not found"
            );
        }
    );


// ============================================================
// WebSocket
// ============================================================

const wss =
    new WebSocketServer({
        noServer: true,
        maxPayload: 4096 // Limit message payload to 4KB to prevent DoS
    });

const vmTunnelWss =
    new WebSocketServer({
        noServer: true,
        maxPayload: 65536
    });

// Periodic heartbeat to prevent dead socket leaks
const heartbeatInterval = setInterval(() => {
    for (const client of wss.clients) {
        if (client.isAlive === false) {
            client.terminate();
            continue;
        }
        client.isAlive = false;
        client.ping();
    }
}, 30000);

wss.on("close", () => {
    clearInterval(heartbeatInterval);
});

// Map of teamName -> active WebSocket tunnel
const activeTunnels = new Map();

vmTunnelWss.on("connection", (socket, request, teamName) => {
    console.log(`VM tunnel WebSocket connected for team: ${teamName}`);
    activeTunnels.set(teamName, socket);

    socket.on("close", () => {
        console.log(`VM tunnel WebSocket closed for team: ${teamName}`);
        if (activeTunnels.get(teamName) === socket) {
            activeTunnels.delete(teamName);
        }
    });

    socket.on("error", (err) => {
        console.error(`VM tunnel WebSocket error for team ${teamName}:`, err.message);
    });
});

// Upgrade handling for HTTP server: route /vm-tunnel (authenticated) vs event state
server.on("upgrade", (request, socket, head) => {
    let pathname = "";
    try {
        pathname = new URL(request.url, `http://${request.headers.host || "localhost"}`).pathname;
    } catch {
        socket.destroy();
        return;
    }

    if (pathname === "/vm-tunnel") {
        const teamName = getTeamFromSession(request);
        if (!teamName) {
            socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
            socket.destroy();
            return;
        }
        vmTunnelWss.handleUpgrade(request, socket, head, (ws) => {
            vmTunnelWss.emit("connection", ws, request, teamName);
        });
    } else {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit("connection", ws, request);
        });
    }
});

wss.on(
    "connection",
    (socket, request) => {
        socket.isAlive = true;
        socket.on("pong", () => { socket.isAlive = true; });

        const remoteAddress =
            request.socket.remoteAddress;

        console.log(
            `WebSocket connection from ${remoteAddress}`
        );

        // Bind team name if connected with an authenticated session cookie
        const teamName = getTeamFromSession(request);
        if (teamName) {
            socket.teamName = teamName;
        }

        // Origin check when header is present
        const origin = request.headers.origin;
        if (origin) {
            try {
                const originURL = new URL(origin);
                const hostHeader = request.headers.host || "";
                const hostName = hostHeader.split(":")[0];
                const allowed = (
                    originURL.hostname === hostName ||
                    originURL.hostname === "localhost" ||
                    originURL.hostname === "127.0.0.1"
                );
                if (!allowed) {
                    console.warn(`WebSocket blocked for untrusted origin: ${origin}`);
                    socket.close(1008, "Origin not allowed");
                    return;
                }
            } catch {
                socket.close(1008, "Invalid origin");
                return;
            }
        }

        // Rate limiting: max 30 messages per 10-second window per socket
        let msgCount = 0;
        let windowReset = Date.now() + 10000;

        // Everyone receives current event state on connect
        socket.send(
            JSON.stringify(
                state
            )
        );

        socket.on(
            "message",
            message => {
                const now = Date.now();
                if (now > windowReset) {
                    msgCount = 0;
                    windowReset = now + 10000;
                }
                msgCount++;
                if (msgCount > 30) {
                    socket.send(JSON.stringify({ error: "Rate limit exceeded" }));
                    return;
                }

                let payload;
                try {
                    payload = JSON.parse(message.toString());
                } catch {
                    socket.send(JSON.stringify({ error: "Invalid JSON format" }));
                    return;
                }

                if (!payload || typeof payload !== "object") {
                    socket.send(JSON.stringify({ error: "Invalid payload format" }));
                    return;
                }

                // Client can identify or re-bind session token
                if (payload.type === "identify") {
                    const authenticatedTeam = getTeamFromSession(request);
                    if (authenticatedTeam) {
                        socket.teamName = authenticatedTeam;
                    }
                    return;
                }

                // Privileged admin action: layout state modification
                if (payload.layout !== undefined) {
                    const token = payload.token || payload.adminToken;
                    if (!verifyAdminToken(token)) {
                        console.warn(`Rejected unauthorized state change from ${remoteAddress}`);
                        socket.send(JSON.stringify({ error: "Unauthorized: Invalid admin token" }));
                        return;
                    }

                    if (
                        payload.layout !== "wait" &&
                        payload.layout !== "start" &&
                        payload.layout !== "end"
                    ) {
                        socket.send(JSON.stringify({ error: "Invalid layout" }));
                        return;
                    }

                    state.layout = payload.layout;
                    console.log("State changed by admin to:", state);

                    // Broadcast state to everyone
                    const broadcastMsg = JSON.stringify(state);
                    for (const client of wss.clients) {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(broadcastMsg);
                        }
                    }
                }
            }
        );

        socket.on("error", err => {
            console.error("WebSocket client error:", err.message);
        });

        socket.on("close", () => {
            console.log(`WebSocket client disconnected: ${remoteAddress}`);
        });
    }
);


// ============================================================
// In-Browser VM SSH TCP Proxy (127.0.0.1 loopback only)
// ============================================================

const isHostArg = process.argv.includes("--host") || process.env.HOST === "0.0.0.0";
const HOST = process.env.HOST || (isHostArg ? "0.0.0.0" : "127.0.0.1");
const PORT = Number(process.env.PORT) || 3001;

const SSH_PORT = Number(process.env.SSH_PORT) || 2222;
const SSH_HOST = process.env.SSH_HOST || (HOST === "0.0.0.0" ? "0.0.0.0" : "127.0.0.1");

function makeSSHDisconnectPacket(reason) {
    const reasonBuf = Buffer.from(reason, "utf8");
    const payloadLen = 1 + 4 + 4 + reasonBuf.length + 4;
    const unpadded = 5 + payloadLen;
    let padLen = 8 - (unpadded % 8);
    if (padLen < 4) padLen += 8;
    const packetLen = 1 + payloadLen + padLen;

    const buf = Buffer.alloc(4 + packetLen);
    let offset = 0;
    buf.writeUInt32BE(packetLen, offset); offset += 4;
    buf.writeUInt8(padLen, offset); offset += 1;
    buf.writeUInt8(1, offset); offset += 1; // SSH_MSG_DISCONNECT
    buf.writeUInt32BE(11, offset); offset += 4; // SSH_DISCONNECT_BY_APPLICATION
    buf.writeUInt32BE(reasonBuf.length, offset); offset += 4;
    reasonBuf.copy(buf, offset); offset += reasonBuf.length;
    buf.writeUInt32BE(0, offset);
    return buf;
}

const sshServer = net.createServer((clientSocket) => {
    console.log(`SSH TCP client connected from ${clientSocket.remoteAddress}:${clientSocket.remotePort}`);

    // Find active VM tunnel (in single-team mode, find any active tunnel)
    let targetWs = null;
    let targetTeam = null;
    for (const [tName, ws] of activeTunnels.entries()) {
        if (ws.readyState === WebSocket.OPEN) {
            targetWs = ws;
            targetTeam = tName;
            break;
        }
    }

    if (!targetWs) {
        console.warn("SSH client connected but no in-browser VM tunnel is active");
        clientSocket.write("SSH-2.0-CTF_Platform\r\n");
        clientSocket.write(makeSSHDisconnectPacket("No challenge VM tunnel is connected in the browser. Please open the challenge page."));
        clientSocket.end();
        return;
    }

    console.log(`Bridging SSH client to VM tunnel for team: ${targetTeam}`);

    // Forward TCP -> WebSocket binary
    clientSocket.on("data", (chunk) => {
        if (targetWs.readyState === WebSocket.OPEN) {
            targetWs.send(chunk);
        }
    });

    // Forward WebSocket binary -> TCP
    const onWsMessage = (data) => {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        clientSocket.write(buf);
    };

    targetWs.on("message", onWsMessage);

    const cleanup = () => {
        targetWs.off("message", onWsMessage);
        clientSocket.destroy();
    };

    clientSocket.on("error", cleanup);
    clientSocket.on("close", cleanup);
    targetWs.on("close", cleanup);
});

sshServer.on("error", (err) => {
    console.error("SSH proxy server error:", err.message);
});

// Start SSH server if not disabled (e.g. during specific unit tests)
if (process.env.DISABLE_SSH_SERVER !== "1") {
    sshServer.listen(SSH_PORT, SSH_HOST, () => {
        console.log(`In-browser VM SSH proxy listening on ${SSH_HOST}:${SSH_PORT}`);
    });
}

server.on("close", () => {
    clearInterval(heartbeatInterval);
    if (sshServer.listening) {
        sshServer.close();
    }
});

server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
        console.error(`Error: Port ${PORT} is already in use. Stop the existing server process before starting a new one.`);
    } else {
        console.error("Server error:", err.message);
    }
    process.exit(1);
});


// ============================================================
// Start server (loopback only)
// ============================================================

server.listen(
    PORT,
    HOST,
    () => {
        console.log(`\n  \x1b[32m➜\x1b[0m  \x1b[1mLocal:\x1b[0m   http://localhost:${PORT}/`);

        const interfaces = os.networkInterfaces();
        const networkIps = [];
        for (const name of Object.keys(interfaces)) {
            for (const iface of interfaces[name] || []) {
                if (iface.family === "IPv4" && !iface.internal) {
                    networkIps.push(iface.address);
                }
            }
        }

        if (HOST === "0.0.0.0") {
            for (const ip of networkIps) {
                console.log(`  \x1b[32m➜\x1b[0m  \x1b[1mNetwork:\x1b[0m http://${ip}:${PORT}/`);
            }
        } else {
            console.log(`  \x1b[33m➜\x1b[0m  \x1b[2mNetwork: use --host to expose to LAN\x1b[0m`);
        }

        console.log(`\n  \x1b[36m➜\x1b[0m  \x1b[1mSSH Proxy:\x1b[0m ${SSH_HOST}:${SSH_PORT}`);
        console.log(`  \x1b[35m➜\x1b[0m  \x1b[1mAdmin Token:\x1b[0m ${ADMIN_TOKEN}`);
        console.log(`  \x1b[90mDatabase: ${dbPath}\x1b[0m\n`);
    }
);

export { server, wss, vmTunnelWss, sshServer, db, state, ADMIN_TOKEN, verifyAdminToken };
