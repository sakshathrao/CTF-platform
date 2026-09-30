import { WebSocketServer } from "ws";

const wss = new WebSocketServer({
    port: 8080
});

let state = {
    title: "Hello there!",
    message: "Welcome to the website.",
    layout: "default"
};

wss.on("connection", socket => {
    console.log("Client connected");

    // Immediately give the new client the current state
    socket.send(JSON.stringify(state));

    socket.on("message", message => {
        const newState = JSON.parse(message);

        state = newState;

        // Tell every connected browser about the change
        for (const client of wss.clients) {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(state));
            }
        }
    });

    socket.on("close", () => {
        console.log("Client disconnected");
    });
});

console.log("WebSocket server running on ws://localhost:8080");
