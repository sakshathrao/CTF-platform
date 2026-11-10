import { defineConfig } from "vite";

export default defineConfig({
    build: {
        rollupOptions: {
            input: {
                main: "main.html",
                login: "login.html",
                registration: "registration.html",
                challenge1: "challenge1.html",
                challenge2: "challenge2.html",
                challenge3: "challenge3.html",
                challenge4: "challenge4.html",
                challenge5: "challenge5.html",
                challenge6: "challenge6.html",
                leaderboard: "leaderboard.html",
                admin: "admin.html",
            },
        },
    },
});
