# Dynamic VM Challenges 032–042 — platform compatibility bundle

This bundle is adapted for the `sakshathrao/CTF-platform` `development` branch.
It intentionally preserves the supplied `public/dynamic-vm/common.js`, all eleven
read-only challenge ISOs, and the supplied `public/images/customBzImage` kernel.

## What was fixed

- The pages now use the platform navbar markup and IDs: `navTeamName`, `navPoints`,
  and `logoutBtn`, with the existing `navbar`, `navLeft`, `navHomeLink`, `navLink`,
  `navPoints`, and `navLogoutBtn` classes from `main.css`.
- `common.js` now reads `teamName` and `points` from the platform `/session` response.
- The shared WebSocket helper sends `{ type: "identify" }` on every connection/reconnection, binding the authenticated team for team-specific progress broadcasts.
- Logout broadcasts the platform's `auth_change` event to other tabs.
- Successful solves broadcast `points`, `pointsAwarded`, `basePoints`, `bonusPercent`,
  and `solved`, matching the existing `main.js` BroadcastChannel listener.
- Added public registry metadata for IDs 32–42 without exposing flags in browser-imported code.
- Added server-only authoritative flags so `server.js` will not overwrite migrated flags
  with `null` on startup. The private flag module and optional SQL migration live under
  `.server-private/`, which is excluded from Vite access and blocked by the platform static-file handler.
- Vite's multi-page input range is extended from 31 to 42.
- Replaced the invalid SQL `points` column with the actual platform schema and preserved
  existing `solve_count` values on conflict.

## Install into the platform repository

1. Extract this ZIP into the root of your platform repository, preserving the directory
   structure. It adds `challenge32.html`–`challenge42.html`, `challenges_032_042.js`,
   `.server-private/challenge_flags_032_042.js`, and the new `public/` files.
2. **Keep `public/images/customBzImage` from this bundle.** It is the matching custom kernel
   expected by the supplied VM helper, and it intentionally replaces the platform's existing
   file at that path. The helper still uses the platform's existing SeaBIOS, VGA BIOS, and v86
   runtime assets.
3. From the project root, run the idempotent compatibility script:

   ```sh
   python3 integration/apply_compatibility.py
   ```

   It updates only `challenges.js`, `vite.config.js`, and `server.js`. It checks for the expected
   anchors before editing and can safely be run again. It does not stage or commit anything.

4. The registry integration imports `challenges032To042` and spreads it after challenge 31. The
   registry contains only titles, categories, descriptions, links, and points. **Do not put flags
   in `challenges.js`**: `main.js` imports that module into the browser bundle.
5. The backend imports `CHALLENGE_FLAGS_032_042` from `.server-private/challenge_flags_032_042.js`
   and appends it to `AUTHORITATIVE_CHALLENGES`. Keep this import on the backend only. Both private
   files are under `.server-private/`; Vite explicitly denies that directory while retaining its
   usual sensitive-file deny patterns, and the platform static-file handler blocks hidden paths.
   Do not rename them or move them under `public/`.
6. Run `npm run build`. The full Vite config in `integration/vite.config.js.replacement` also
   denies the hidden server-only directory while retaining the default sensitive-file deny patterns;
   use it if you prefer replacing the existing config.
7. Restart `server.js`. Its existing authoritative seeding code will insert/update IDs 32–42,
   including their flags and categories, without resetting solve counts.

## Equivalent manual edits

- In `challenges.js`, import `challenges032To042` from `./challenges_032_042.js` and spread it
  after the existing challenge 31 entry in the `challenges` array.
- In `vite.config.js`, change the dynamic challenge input loop's upper bound from `31` to `42`.
- In `server.js`, import `CHALLENGE_FLAGS_032_042` from
  `./.server-private/challenge_flags_032_042.js` and append it to `AUTHORITATIVE_CHALLENGES` immediately
  after the existing array declaration and before the SQLite seeding transaction.

## Optional manual database migration

`.server-private/set_flags_032_042.sql` is a corrected one-time migration for the platform's current
`challenges(id, solve_count, flag, category)` schema. It is optional when the server-side
seeding patch is installed. It does not change points and preserves solve counts on conflict.
Keep organizer materials private.

## Validation performed on this bundle

- 11 challenge pages and their inline configuration objects checked.
- All 11 ISO paths exist and all ISO files contain valid ISO9660 descriptors.
- All challenge HTML files and `common.js` pass JavaScript syntax checks.
- The WebSocket identity handshake is present and matches the platform server handler.
- Public registry contains no flags; flags live only in the backend module and organizer SQL.
- The custom kernel is retained byte-for-byte from the supplied ZIP.

A full browser v86 boot, interactive mount, and live flag-submission run still needs to be
performed on the target laptop. This bundle does not change the VM architecture or the UART
boot/mount timing strategy.
