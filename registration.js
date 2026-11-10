const isDev = location.port === "5173" || location.port === "5174";
const apiBase = isDev ? `http://${location.hostname}:3001` : "";

const registerButton = document.getElementById("register");

registerButton.addEventListener("click", async (event) => {
    event.preventDefault();

    const inputs = document.querySelectorAll(".dialogBox input");
    const teamName = inputs[0].value.trim();
    const member1Name = inputs[1].value.trim();
    const member1USN = inputs[2].value.trim();
    const member2Name = inputs[3].value.trim();
    const member2USN = inputs[4].value.trim();
    const member3Name = inputs[5].value.trim();
    const member3USN = inputs[6].value.trim();
    const password = inputs[7].value;
    const confirmPassword = inputs[8].value;

    if (!teamName || !member1Name || !member1USN) {
        alert("Please fill in the required fields (Team name, Member 1 name, Member 1 USN).");
        return;
    }

    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(teamName)) {
        alert("Invalid team name. Use only letters, numbers, hyphens, and underscores (1-32 characters).");
        inputs[0].focus();
        return;
    }

    if (member1USN.length !== 10) {
        alert("Member 1 USN must be exactly 10 characters.");
        inputs[2].focus();
        return;
    }

    if (member2USN && member2USN.length !== 10) {
        alert("Member 2 USN must be exactly 10 characters.");
        inputs[4].focus();
        return;
    }

    if (member3USN && member3USN.length !== 10) {
        alert("Member 3 USN must be exactly 10 characters.");
        inputs[6].focus();
        return;
    }

    // Check that entered names are distinct
    const names = [
        { index: 1, value: member1Name, input: inputs[1] },
        { index: 2, value: member2Name, input: inputs[3] },
        { index: 3, value: member3Name, input: inputs[5] }
    ].filter(m => m.value);

    for (let i = 0; i < names.length; i++) {
        for (let j = i + 1; j < names.length; j++) {
            if (names[i].value.toLowerCase() === names[j].value.toLowerCase()) {
                alert(`Member ${names[i].index} and Member ${names[j].index} cannot have the same name.`);
                names[j].input.focus();
                return;
            }
        }
    }

    // Check that entered USNs are distinct
    const usns = [
        { index: 1, value: member1USN, input: inputs[2] },
        { index: 2, value: member2USN, input: inputs[4] },
        { index: 3, value: member3USN, input: inputs[6] }
    ].filter(m => m.value);

    for (let i = 0; i < usns.length; i++) {
        for (let j = i + 1; j < usns.length; j++) {
            if (usns[i].value.toUpperCase() === usns[j].value.toUpperCase()) {
                alert(`Member ${usns[i].index} and Member ${usns[j].index} cannot have the same USN.`);
                usns[j].input.focus();
                return;
            }
        }
    }

    if (!password) {
        alert("Please enter a password.");
        inputs[7].focus();
        return;
    }

    if (password.length < 8) {
        alert("Password must be at least 8 characters long.");
        inputs[7].focus();
        return;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        inputs[8].focus();
        return;
    }

    const team = {
        teamName,
        password,
        members: [
            { name: member1Name, usn: member1USN },
            { name: member2Name, usn: member2USN },
            { name: member3Name, usn: member3USN }
        ]
    };

    registerButton.disabled = true;
    const originalText = registerButton.textContent;
    registerButton.textContent = "Registering...";

    try {
        const response = await fetch(`${apiBase}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify(team)
        });

        const result = await response.json();

        if (!response.ok) {
            alert(result.error ?? "Failed to register team.");
            registerButton.disabled = false;
            registerButton.textContent = originalText;
            return;
        }

        alert(`Team "${teamName}" registered successfully!`);
        window.location.replace("/main.html");
    } catch (error) {
        console.error(error);
        alert("Could not connect to the CTF server.");
        registerButton.disabled = false;
        registerButton.textContent = originalText;
    }
});
