import http from "node:http";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import WebSocket, {
    WebSocketServer
} from "ws";

import { challenges } from "./challenges.js";


// ============================================================
// Database
// ============================================================

const __filename =
    fileURLToPath(import.meta.url);

const __dirname =
    path.dirname(__filename);

const db =
    new DatabaseSync(
        path.join(
            __dirname,
            "../CTF_data/ctf.sqlite"
        )
    );

db.exec(
    "PRAGMA foreign_keys = ON"
);


// ============================================================
// CTF state
// ============================================================

const state = {
    layout: "wait"
};


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


function setCORS(
    req,
    res
) {

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


                sendJSON(
                    res,
                    200,
                    {
                        loggedIn: true,
                        teamName
                    }
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


                    if (
                        solveCount === 0
                    ) {

                        multiplier = 1.30;

                    } else if (
                        solveCount === 1
                    ) {

                        multiplier = 1.20;

                    } else if (
                        solveCount === 2
                    ) {

                        multiplier = 1.10;

                    } else {

                        multiplier = 1.00;
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
                            pointsAwarded,
                            totalPoints:
                                progress.points,
                            solved:
                                progress.solved
                        })
                    );


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
            remoteAddress ===
                "127.0.0.1" ||
            remoteAddress ===
                "::1" ||
            remoteAddress ===
                "::ffff:127.0.0.1";


        // Everyone receives event state.

        socket.send(
            JSON.stringify(
                state
            )
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
                        JSON.parse(
                            message
                        );

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


                // Broadcast state to everyone.

                for (
                    const client
                    of wss.clients
                ) {

                    if (
                        client.readyState ===
                        WebSocket.OPEN
                    ) {

                        client.send(
                            JSON.stringify(
                                state
                            )
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
