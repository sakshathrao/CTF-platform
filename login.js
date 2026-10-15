const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? `http://${location.hostname}:3001` : "";

const loginButton = document.getElementById("login");

loginButton.addEventListener("click", async () => {
    const inputs = document.querySelectorAll(".dialogBox input");
    const teamName = inputs[0].value.trim();
    const password = inputs[1].value;

    if (!teamName || !password) {
        alert("Please enter your team name and password.");
        return;
    }

    loginButton.disabled = true;
    const originalText = loginButton.textContent;
    loginButton.textContent = "Logging in...";

    try {
        const response = await fetch(`${apiBase}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                teamName,
                password
            })
        });

        const result = await response.json();

        if (!response.ok) {
            alert(result.error ?? "Login failed.");
            loginButton.disabled = false;
            loginButton.textContent = originalText;
            return;
        }

        window.location.replace("/main.html");
    } catch (error) {
        console.error(error);
        alert("Could not connect to the CTF server.");
        loginButton.disabled = false;
        loginButton.textContent = originalText;
    }
});
