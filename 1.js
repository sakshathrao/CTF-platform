import { V86Starter } from "v86";

new V86Starter({
    wasm_path: "/v86.wasm",

    memory_size: 32 * 1024 * 1024,
    vga_memory_size: 2 * 1024 * 1024,

    screen_container: document.getElementById("screen_container"),

    bios: {
        url: "./seabios.bin"
    },

    vga_bios: {
        url: "./vgabios.bin"
    },

    cdrom: {
        url: "./linux.iso"
    },

    autostart: true
});
