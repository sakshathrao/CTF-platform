const socket = new WebSocket(`ws://127.0.0.1:3001`);

// const title = document.querySelector("#title");
// const message = document.querySelector("#message");
const layout= document.querySelector("#layout");
const update = document.querySelector("#update");
update.addEventListener("click", () => {

    if (socket.readyState !== WebSocket.OPEN) {
        alert("Not connected to server.");
        return;
    }

    const state = {
        layout: layout.value
    };

    socket.send(JSON.stringify(state));
});
