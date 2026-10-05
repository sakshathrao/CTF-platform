const loginButton = document.getElementById("login");

loginButton.addEventListener("click", async () => {

    const inputs = document.querySelectorAll(".dialogBox input");

    const teamName = inputs[0].value.trim();

    const member1Name = inputs[1].value.trim();
    const member1USN = inputs[2].value.trim();

    const member2Name = inputs[3].value.trim();
    const member2USN = inputs[4].value.trim();

    const member3Name = inputs[5].value.trim();
    const member3USN = inputs[6].value.trim();

    // Basic client-side validation.
    if (!teamName || !member1Name || !member1USN) {
        alert("Please fill in the required fields.");
        return;
    }

    const team = {
        teamName,

        members: [
            {
                name: member1Name,
                usn: member1USN
            },
            {
                name: member2Name,
                usn: member2USN
            },
            {
                name: member3Name,
                usn: member3USN
            }
        ]
    };

    try {

        const response = await fetch(
            `http://${location.hostname}:3001/login`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                credentials: "include",

                body: JSON.stringify(team)
            }
        );

        if (!response.ok) {
            const result = await response.json();

            alert(result.error ?? "Failed to create team.");
            return;
        }
        alert(`Team "${teamName}" created!`);

        window.location.replace("/main.html");

    } catch (error) {

        console.error(error);
        alert("Could not connect to the CTF server.");

    }
});
