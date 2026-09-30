const socket = new WebSocket("ws://localhost:8080");

const title = document.querySelector("#title");
const message = document.querySelector("#message");
const layout= document.querySelector("#layout");
const update = document.querySelector("#update");

update.addEventListener("click", () => {
    const state = {
        title: title.value,
        message: message.value,
        layout: layout.value
    };

    socket.send(JSON.stringify(state));
});
