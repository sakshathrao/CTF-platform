#!/usr/bin/env python3
"""Safely and idempotently apply the Dynamic VM Challenges 032–042 integration."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(rel):
    path = ROOT / rel
    if not path.is_file():
        raise RuntimeError(f"Required platform file not found: {rel}")
    return path, path.read_text()


def main():
    # Read and validate every target before writing any of them. If the branch has
    # diverged, fail closed rather than leaving a partially integrated checkout.
    challenges_path, challenges_text = read("challenges.js")
    vite_path, vite_text = read("vite.config.js")
    server_path, server_text = read("server.js")

    # Public registry: this module is imported by main.js and is browser-visible.
    import_line = 'import { challenges032To042 } from "./challenges_032_042.js";'
    array_anchor = "export const challenges = ["
    if "...challenges032To042" not in challenges_text:
        if array_anchor not in challenges_text:
            raise RuntimeError("Could not locate challenges array in challenges.js")
        if "id: 32" in challenges_text or "id: 42" in challenges_text:
            raise RuntimeError("Some 032–042 IDs already exist in challenges.js; inspect before integrating")
        if import_line not in challenges_text:
            challenges_text = challenges_text.replace(array_anchor, import_line + "\n" + array_anchor, 1)
        start = challenges_text.find(array_anchor)
        close = challenges_text.find("];", start)
        if close < 0:
            raise RuntimeError("Could not locate end of challenges array")
        challenges_text = challenges_text[:close] + "  ...challenges032To042,\n" + challenges_text[close:]
    elif import_line not in challenges_text:
        raise RuntimeError("Challenge registry spread exists without its import")

    # Multi-page production build.
    old_loop = "for (let i = 1; i <= 31; i++) {"
    new_loop = "for (let i = 1; i <= 42; i++) {"
    if old_loop in vite_text:
        vite_text = vite_text.replace(old_loop, new_loop, 1)
    elif new_loop not in vite_text:
        raise RuntimeError("Could not find the challenge input loop in vite.config.js")
    fs_deny = 'deny: [".env", ".env.*", "*.{crt,pem}", "**/.git/**", "**/.server-private/**"],'
    if fs_deny not in vite_text:
        if "    server:" in vite_text:
            raise RuntimeError("vite.config.js already has a server block; add fs.deny for **/.server-private/** manually")
        vite_anchor = "export default defineConfig({"
        if vite_anchor not in vite_text:
            raise RuntimeError("Could not locate defineConfig in vite.config.js")
        vite_text = vite_text.replace(
            vite_anchor,
            vite_anchor + '\n    server: { fs: { ' + fs_deny + ' } },',
            1,
        )

    # Server-only flags. Never add flags to challenges.js; it is imported by the browser.
    challenge_import = 'import { challenges, getVisibleChallenges } from "./challenges.js";'
    flags_import = 'import { CHALLENGE_FLAGS_032_042 } from "./.server-private/challenge_flags_032_042.js";'
    if flags_import not in server_text:
        if challenge_import not in server_text:
            raise RuntimeError("Could not locate challenge import in server.js")
        server_text = server_text.replace(challenge_import, challenge_import + "\n" + flags_import, 1)
    append_line = "AUTHORITATIVE_CHALLENGES.push(...CHALLENGE_FLAGS_032_042);"
    if append_line not in server_text:
        marker = "const AUTHORITATIVE_CHALLENGES = ["
        start = server_text.find(marker)
        close = server_text.find("];", start)
        if start < 0 or close < 0:
            raise RuntimeError("Could not locate AUTHORITATIVE_CHALLENGES array in server.js")
        close += 2
        server_text = server_text[:close] + "\n" + append_line + server_text[close:]
    if flags_import not in server_text or append_line not in server_text:
        raise RuntimeError("Server authoritative flag integration is incomplete")

    # Persist only after all transformations have passed their anchor checks.
    challenges_path.write_text(challenges_text)
    print("Updated challenges.js")
    vite_path.write_text(vite_text)
    print("Updated vite.config.js")
    server_path.write_text(server_text)
    print("Updated server.js")
    print("Compatibility integration applied. No Git staging or commit was performed.")


if __name__ == "__main__":
    main()
