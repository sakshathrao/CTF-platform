const socket = new WebSocket("ws://localhost:8080");

socket.addEventListener("open", () => {
    console.log("Connected to server");
});

socket.addEventListener("message", event => {
    const state = JSON.parse(event.data);

    render(state);
});

socket.addEventListener("close", () => {
    console.log("Disconnected from server");
});

function render(state) {
    if(state.layout === "default") {
        const app = document.querySelector(".main_bg");

        app.replaceChildren();

        const title = document.createElement("h1");
        title.textContent = "Hello There!"

        const message = document.createElement("subtitle");
        message.textContent = "The event starts shortly.";

        app.append(title, message);
    }
    else
    {
        const app = document.querySelector(".main_bg");

        app.replaceChildren();

        const title = document.createElement("h1");
        title.textContent = "Non, default, state"

        const message = document.createElement("subtitle");
        message.textContent = "The event starts shortly.";

        app.append(title, message);
    }
}
