import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import WebSocket, { WebSocketServer } from "ws";


// ============================================================
// Database
// ============================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new DatabaseSync(
    path.join(__dirname, "../CTF_data/ctf.sqlite")
);

db.exec("PRAGMA foreign_keys = ON");


// ============================================================
// CTF state
// ============================================================

const state = {
    layout: "wait"
};


// ============================================================
// Helpers
// ============================================================

function sendJSON(res, status, data) {

    res.writeHead(status, {
        "Content-Type": "application/json"
    });

    res.end(JSON.stringify(data));
}


function getCookie(req, name) {

    const cookieHeader = req.headers.cookie;

    if (!cookieHeader) {
        return null;
    }

    for (const part of cookieHeader.split(";")) {

        const [key, ...value] =
            part.trim().split("=");

        if (key === name) {
            return decodeURIComponent(
                value.join("=")
            );
        }
    }

    return null;
}


function setCORS(req, res) {

    const origin = req.headers.origin;

    if (origin) {

        try {

            const originURL = new URL(origin);
            const serverHost =
                req.headers.host.split(":")[0];

            if (
                originURL.protocol === "http:" &&
                originURL.hostname === serverHost 
                // originURL.port === "5173"
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
            // Ignore invalid Origin headers.
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

    return new Promise((resolve, reject) => {

        let body = "";

        req.on("data", chunk => {

            body += chunk;

            if (body.length > 1024 * 1024) {
                reject(
                    new Error("Request body too large")
                );

                req.destroy();
            }
        });

        req.on("end", () => {
            resolve(body);
        });

        req.on("error", reject);
    });
}


function hashPassword(password, salt) {

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

    const salt = Buffer.from(
        saltHex,
        "hex"
    );

    const storedHash = Buffer.from(
        hashHex,
        "hex"
    );

    const submittedHash =
        hashPassword(password, salt);

    return (
        submittedHash.length ===
        storedHash.length &&
        crypto.timingSafeEqual(
            submittedHash,
            storedHash
        )
    );
}


function createSession(teamName) {

    const sessionID =
        crypto.randomBytes(32).toString("hex");

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


// ============================================================
// HTTP server
// ============================================================

const server = http.createServer(
    async (req, res) => {

        setCORS(req, res);


        // ----------------------------------------------------
        // CORS preflight
        // ----------------------------------------------------

        if (req.method === "OPTIONS") {

            res.writeHead(204);
            res.end();

            return;
        }


        // ====================================================
        // REGISTER
        // ====================================================

        if (
            req.method === "POST" &&
            req.url === "/register"
        ) {

            let data;

            try {

                const body =
                    await readRequestBody(req);

                data = JSON.parse(body);

            } catch {

                sendJSON(
                    res,
                    400,
                    {
                        error: "Invalid request."
                    }
                );

                return;
            }


            const teamName =
                typeof data.teamName === "string"
                    ? data.teamName.trim()
                    : "";

            const password =
                typeof data.password === "string"
                    ? data.password
                    : "";

            const members =
                Array.isArray(data.members)
                    ? data.members
                    : [];


            // ------------------------------------------------
            // Validate
            // ------------------------------------------------

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
                        error: "Missing or invalid fields."
                    }
                );

                return;
            }


            if (password.length < 8) {

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


            const memberValues = [];


            for (let i = 0; i < 3; i++) {

                const member =
                    members[i] ?? {};

                const name =
                    typeof member.name === "string"
                        ? member.name.trim()
                        : "";

                const usn =
                    typeof member.usn === "string"
                        ? member.usn.trim()
                        : "";


                // One supplied but not the other.

                if (
                    (name && !usn) ||
                    (!name && usn)
                ) {

                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                `Member ${i + 1} needs both name and USN.`
                        }
                    );

                    return;
                }

                if(usn && usn.length !== 10)
                {
                    sendJSON(
                        res,
                        400,
                        {
                            error:
                                `Invalid USN.`
                        }
                    );
                    return;
                }

                memberValues.push(
                    name || null,
                    usn || null
                );
            }


            // Member 1 is mandatory.

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


            // ------------------------------------------------
            // Hash password
            // ------------------------------------------------

            const salt =
                crypto.randomBytes(16);

            const passwordHash =
                hashPassword(
                    password,
                    salt
                );


            // ------------------------------------------------
            // Database transaction
            // ------------------------------------------------

            try {

                db.exec("BEGIN");


                // Create team.

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


                // Create login session.

                const sessionID =
                    createSession(teamName);


                db.exec("COMMIT");


                // Give browser its cookie.

                res.writeHead(201, {

                    "Content-Type":
                        "application/json",

                    "Set-Cookie":
                        `session=${encodeURIComponent(sessionID)}; ` +
                        `HttpOnly; ` +
                        `SameSite=Strict; ` +
                        `Path=/`
                });


                res.end(JSON.stringify({
                    success: true
                }));


                console.log(
                    `Registered team: ${teamName}`
                );

            } catch (error) {

                try {
                    db.exec("ROLLBACK");
                } catch {
                    // Ignore rollback errors.
                }


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


        // ====================================================
        // LOGIN
        // ====================================================

        if (
            req.method === "POST" &&
            req.url === "/login"
        ) {

            let data;

            try {

                const body =
                    await readRequestBody(req);

                data = JSON.parse(body);

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
                typeof data.teamName === "string"
                    ? data.teamName.trim()
                    : "";

            const password =
                typeof data.password === "string"
                    ? data.password
                    : "";


            if (!teamName || !password) {

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


            // Find team.

            const team = db.prepare(`
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


            // Verify password.

            let valid = false;

            try {

                valid = passwordMatches(
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


            // Create new session.

            try {

                const sessionID =
                    createSession(teamName);


                res.writeHead(200, {

                    "Content-Type":
                        "application/json",

                    "Set-Cookie":
                        `session=${encodeURIComponent(sessionID)}; ` +
                        `HttpOnly; ` +
                        `SameSite=Strict; ` +
                        `Path=/`
                });


                res.end(JSON.stringify({
                    success: true
                }));


                console.log(
                    `Logged in: ${teamName}`
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


        // ====================================================
        // SESSION CHECK
        // ====================================================

        if (
            req.method === "GET" &&
            req.url === "/session"
        ) {

            const sessionID =
                getCookie(
                    req,
                    "session"
                );


            if (!sessionID) {

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


            const session =
                db.prepare(`
                    SELECT team_name
                    FROM sessions
                    WHERE token = ?
                `).get(sessionID);


            if (!session) {

                sendJSON(
                    res,
                    401,
                    {
                        error:
                            "Invalid session."
                    }
                );

                return;
            }


            sendJSON(
                res,
                200,
                {
                    loggedIn: true,
                    teamName:
                        session.team_name
                }
            );

            return;
        }


        // ====================================================
        // Unknown HTTP request
        // ====================================================

        res.writeHead(404);
        res.end("Not found");
    }
);


// ============================================================
// WebSocket
// ============================================================

const wss = new WebSocketServer({
    server
});


wss.on(
    "connection",
    (socket, request) => {

        const remoteAddress =
            request.socket.remoteAddress;


        console.log(
            `WebSocket connection from ${remoteAddress}`
        );


        const isLocal =
            remoteAddress === "127.0.0.1" ||
            remoteAddress === "::1" ||
            remoteAddress === "::ffff:127.0.0.1";


        // Everyone receives state.

        socket.send(
            JSON.stringify(state)
        );


        socket.on(
            "message",
            message => {

                // Only local admin can modify state.

                if (!isLocal) {

                    console.log(
                        `Rejected state change from ${remoteAddress}`
                    );

                    return;
                }


                let newState;

                try {

                    newState =
                        JSON.parse(message);

                } catch {

                    console.log(
                        "Invalid JSON"
                    );

                    return;
                }


                if (
                    !newState ||
                    typeof newState.layout !==
                        "string"
                ) {

                    console.log(
                        "Invalid state"
                    );

                    return;
                }


                if (
                    newState.layout !== "wait" &&
                    newState.layout !== "start" &&
                    newState.layout !== "end"
                ) {

                    console.log(
                        "Invalid layout"
                    );

                    return;
                }


                state.layout =
                    newState.layout;


                console.log(
                    "State changed:",
                    state
                );


                // Broadcast.

                for (
                    const client
                    of wss.clients
                ) {

                    if (
                        client.readyState ===
                        WebSocket.OPEN
                    ) {

                        client.send(
                            JSON.stringify(state)
                        );
                    }
                }
            }
        );
    }
);


// ============================================================
// Start server
// ============================================================

server.listen(
    3001,
    "0.0.0.0",
    () => {

        console.log(
            "HTTP + WebSocket server running on port 3001"
        );

        console.log(
            "Database:",
            path.join(
                __dirname,
                "../CTF_data/ctf.sqlite"
            )
        );
    }
);
