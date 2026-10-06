const loginButton =
    document.getElementById("login");


loginButton.addEventListener(
    "click",
    async () => {

        const inputs =
            document.querySelectorAll(
                ".dialogBox input"
            );


        const teamName =
            inputs[0].value.trim();

        const password =
            inputs[1].value;


        if (!teamName || !password) {

            alert(
                "Please enter your team name and password."
            );

            return;
        }


        try {

            const response =
                await fetch(
                    `http://${location.hostname}:3001/login`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        credentials:
                            "include",

                        body:
                            JSON.stringify({
                                teamName,
                                password
                            })
                    }
                );


            const result =
                await response.json();


            if (!response.ok) {

                alert(
                    result.error ??
                    "Login failed."
                );

                return;
            }


            alert(
                `Welcome back, ${teamName}!`
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
