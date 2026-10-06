const registerButton =
    document.getElementById("register");


registerButton.addEventListener(
    "click",
    async (event) => {
        event.preventDefault();

        const inputs =
            document.querySelectorAll(
                ".dialogBox input"
            );


        const teamName =
            inputs[0].value.trim();


        const member1Name =
            inputs[1].value.trim();

        const member1USN =
            inputs[2].value.trim();


        const member2Name =
            inputs[3].value.trim();

        const member2USN =
            inputs[4].value.trim();


        const member3Name =
            inputs[5].value.trim();

        const member3USN =
            inputs[6].value.trim();


        const password =
            inputs[7].value;

        const confirmPassword =
            inputs[8].value;


        // Basic validation.

        if (
            !teamName ||
            !member1Name ||
            !member1USN
        ) {

            alert(
                "Please fill in the required fields."
            );

            return;
        }


        if (!password) {

            alert(
                "Please enter a password."
            );

            return;
        }


        if (password !== confirmPassword) {

            alert(
                "Passwords do not match."
            );

            return;
        }


        const team = {

            teamName,

            password,

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

            const response =
                await fetch(
                    `http://${location.hostname}:3001/register`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        credentials:
                            "include",

                        body:
                            JSON.stringify(team)
                    }
                );


            const result =
                await response.json();


            if (!response.ok) {

                alert(
                    result.error ??
                    "Failed to register team."
                );

                return;
            }


            alert(
                `Team "${teamName}" registered!`
            );


            window.location.replace(
                "/main.html"
            );

        } catch (error) {

            console.error(error);

            alert(
                "Could not connect to the CTF server."
            );
        }
    }
);
