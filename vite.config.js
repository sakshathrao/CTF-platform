import { defineConfig } from "vite";

const challengeInputs = {};
for (let i = 1; i <= 31; i++) {
    challengeInputs[`challenge${i}`] = `challenge${i}.html`;
}

export default defineConfig({
    build: {
        rollupOptions: {
            input: {
                main: "main.html",
                login: "login.html",
                registration: "registration.html",
                leaderboard: "leaderboard.html",
                admin: "admin.html",
                ...challengeInputs,
            },
        },
    },
});
