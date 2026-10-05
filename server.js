import http from "node:http";
import crypto from "node:crypto";
import WebSocket, { WebSocketServer } from "ws";


// ============================================================
// Temporary storage
// ============================================================

const teams = new Map();
// teamName -> team data

const sessions = new Map();
// sessionID -> teamName


// ============================================================
// CTF state
// ============================================================

let state = {
    layout: "wait"
};


// ============================================================
// HTTP server
// ============================================================

const server = http.createServer((req, res) => {

    // --------------------------------------------------------
    // CORS
    // --------------------------------------------------------
    const origin = req.headers.origin;

    if (origin) {

        try {

            const originURL = new URL(origin);
            const serverHost = req.headers.host.split(":")[0];

            if (
                originURL.protocol === "http:" &&
                originURL.hostname === serverHost &&
                originURL.port === "5173"
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
            // Invalid Origin header.
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


    // Browser's preflight request
    if (req.method === "OPTIONS") {

        res.writeHead(204);
        res.end();

        return;
    }


    // --------------------------------------------------------
    // Team login
    // --------------------------------------------------------

    if (req.method === "POST" && req.url === "/login") {

        let body = "";

        req.on("data", chunk => {
            body += chunk;
        });

        req.on("end", () => {

            let data;

            try {
                data = JSON.parse(body);
            } catch {

                res.writeHead(400, {
                    "Content-Type": "application/json"
                });

                res.end(JSON.stringify({
                    error: "Invalid JSON"
                }));

                return;
            }


            const teamName = data.teamName;
            const members = data.members;


            // ------------------------------------------------
            // Basic validation
            // ------------------------------------------------

            if (!teamName || !Array.isArray(members)) {

                res.writeHead(400, {
                    "Content-Type": "application/json"
                });

                res.end(JSON.stringify({
                    error: "Invalid team data"
                }));

                return;
            }


            // ------------------------------------------------
            // Temporary duplicate check
            // ------------------------------------------------

            if (teams.has(teamName)) {

                res.writeHead(409, {
                    "Content-Type": "application/json"
                });

                res.end(JSON.stringify({
                    error: "Team already exists"
                }));

                return;
            }


            // ------------------------------------------------
            // Create team
            // ------------------------------------------------

            teams.set(teamName, {
                name: teamName,
                members: members,
                points: 0
            });


            // ------------------------------------------------
            // Create session ID
            // ------------------------------------------------

            const sessionID = crypto
                .randomBytes(32)
                .toString("hex");

            sessions.set(sessionID, teamName);


            // ------------------------------------------------
            // Send cookie
            // ------------------------------------------------

            res.writeHead(200, {

                "Content-Type":
                    "application/json",

                "Set-Cookie":
                    `session=${sessionID}; HttpOnly; SameSite=Strict`
            });

            res.end(JSON.stringify({
                success: true
            }));

            console.log(`Team logged in: ${teamName}`);
        });

        return;
    }


    // --------------------------------------------------------
    // Temporary test endpoint
    // --------------------------------------------------------

    if (req.method === "GET" && req.url === "/session") {

        const cookieHeader = req.headers.cookie;

        if (!cookieHeader) {

            res.writeHead(401, {
                "Content-Type": "application/json"
            });

            res.end(JSON.stringify({
                error: "Not logged in"
            }));

            return;
        }

        const cookies = Object.fromEntries(
            cookieHeader
                .split(";")
                .map(cookie => {
                    const [name, ...value] = cookie.trim().split("=");
                    return [name, value.join("=")];
                })
        );

        const sessionID = cookies.session;

        const teamName = sessions.get(sessionID);

        if (!teamName) {

            res.writeHead(401, {
                "Content-Type": "application/json"
            });

            res.end(JSON.stringify({
                error: "Invalid session"
            }));

            return;
        }

        res.writeHead(200, {
            "Content-Type": "application/json"
        });

        res.end(JSON.stringify({
            loggedIn: true,
            teamName
        }));

        return;
    }

    // --------------------------------------------------------
    // Unknown HTTP request
    // --------------------------------------------------------

    res.writeHead(404);
    res.end("Not found");
});


// ============================================================
// WebSocket server
// ============================================================

const wss = new WebSocketServer({
    server: server
});


wss.on("connection", (socket, request) => {

    const remoteAddress =
        request.socket.remoteAddress;

    console.log(
        `WebSocket connection from ${remoteAddress}`
    );


    // --------------------------------------------------------
    // Is this the local admin?
    // --------------------------------------------------------

    const isLocal =
        remoteAddress === "127.0.0.1" ||
        remoteAddress === "::1" ||
        remoteAddress === "::ffff:127.0.0.1";


    // Give everyone the current state.

    socket.send(JSON.stringify(state));


    // --------------------------------------------------------
    // Messages
    // --------------------------------------------------------

    socket.on("message", message => {

        // ONLY localhost can modify state.

        if (!isLocal) {

            console.log(
                `Rejected state change from ${remoteAddress}`
            );

            return;
        }


        let newState;

        try {
            newState = JSON.parse(message);
        } catch {

            console.log("Invalid JSON");

            return;
        }


        // Only allow valid layouts.

        if (
            !newState ||
            typeof newState.layout !== "string"
        ) {
            console.log("Invalid state");

            return;
        }


        if (
            newState.layout !== "wait" &&
            newState.layout !== "start" &&
            newState.layout !== "end"
        ) {
            console.log("Invalid layout");

            return;
        }


        // Change state.

        state = newState;

        console.log(
            "State changed:",
            state
        );


        // Broadcast to everyone.

        for (const client of wss.clients) {

            if (client.readyState === WebSocket.OPEN) {
                client.send(
                    JSON.stringify(state)
                );
            }
        }
    });


    socket.on("close", () => {

        console.log(
            `WebSocket disconnected: ${remoteAddress}`
        );
    });
});


// ============================================================
// Start everything
// ============================================================

server.listen(3001, "0.0.0.0", () => {

    console.log(
        "HTTP server: http://localhost:3001"
    );

    console.log(
        "WebSocket server: ws://localhost:3001"
    );
});
