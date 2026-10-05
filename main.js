async function checkSession() {

    try {

        const response =
            await fetch(
                `http://${location.hostname}:3001/session`,
                {
                    credentials: "include"
                }
            );


        if (!response.ok) {

            window.location.assign(
                "/login.html"
            );

            return false;
        }


        const data =
            await response.json();


        console.log(
            "Logged in as:",
            data.teamName
        );


        return true;

    } catch (error) {

        console.error(error);

        window.location.assign(
            "/login.html"
        );

        return false;
    }
}


async function start() {

    const loggedIn =
        await checkSession();


    if (!loggedIn) {
        return;
    }


    const socket =
        new WebSocket(
            `ws://${location.hostname}:3001`
        );


    socket.addEventListener(
        "open",
        () => {
            console.log(
                "Connected to server"
            );
        }
    );


    socket.addEventListener(
        "message",
        event => {

            const state =
                JSON.parse(event.data);

            render(state);
        }
    );


    socket.addEventListener(
        "close",
        () => {

            console.log(
                "Disconnected from server"
            );
        }
    );
}


function render(state) {

    if (state.layout === "wait") {

        const app =
            document.querySelector(
                ".main_bg"
            );

        app.classList.remove("start");

        app.replaceChildren();


        const title =
            document.createElement("h1");

        title.textContent =
            "Hello There!";


        const message =
            document.createElement("subtitle");

        message.textContent =
            "Hang tight, the event starts shortly.";


        app.append(
            title,
            message
        );
    }

    else if (
        state.layout === "start"
    ) {

        const app =
            document.querySelector(
                ".main_bg"
            );

        app.classList.add("start");

        app.replaceChildren();


        const title =
            document.createElement(
                "h1small"
            );

        title.textContent =
            "Challenges? We've got plenty.";


        const mainFlexbox =
            document.createElement("div");

        mainFlexbox.classList.add(
            "mainFlexbox"
        );


        const challenges = [

            {
                title: "Challenge 1",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            },

            {
                title: "Challenge 2",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            },

            {
                title: "Challenge 3",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            },

            {
                title: "Challenge 4",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            },

            {
                title: "Challenge 5",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            },

            {
                title: "Challenge 6",

                description:
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",

                link: "challenge1.html",
                points: 12
            }
        ];


        let i = 0;


        for (
            const challenge
            of challenges
        ) {

            const details =
                document.createElement(
                    "details"
                );


            details.style.setProperty(
                "--gradient-start",
                `${50 - i * 20}%`
            );


            details.style.setProperty(
                "--gradient-mid",
                `${100 - i * 30}%`
            );


            details.style.setProperty(
                "--border-gradient-degree",
                `${Math.random() * 360}deg`
            );


            const summary =
                document.createElement(
                    "summary"
                );

            summary.textContent =
                challenge.title;


            const content =
                document.createElement("p");

            content.textContent =
                challenge.description;


            const challengeLink =
                document.createElement("a");

            challengeLink.textContent =
                "Try me ↗";

            challengeLink.href =
                challenge.link;


            details.append(
                summary,
                content,
                challengeLink
            );

            mainFlexbox.append(
                details
            );


            i++;
        }


        app.append(
            title,
            mainFlexbox
        );
    }

    else if (
        state.layout === "end"
    ) {

        const app =
            document.querySelector(
                ".main_bg"
            );

        app.classList.remove("start");

        app.replaceChildren();


        const title =
            document.createElement("h1");

        title.innerHTML =
            "The event has <br> ended.";


        app.append(title);
    }
}


start();
