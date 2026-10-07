import { defineConfig } from "vite";

export default defineConfig({
    build: {
        rollupOptions: {
            input: {
                main: "main.html",
                login: "login.html",
                registration: "registration.html",
                challenge1: "challenge1.html",
                admin: "admin.html",
            },
        },
    },
});
