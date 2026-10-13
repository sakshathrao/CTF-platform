# CTF Platform — Hardening and Reliability TODO

Tracking checklist for the audit/hardening effort on `development`.
Intentional CTF challenge vulnerabilities are preserved on purpose.

## Tasks

- [ ] **WebSocket admin authorization**
      Never trust the WS `Origin` header or client-side UI as authentication.
      Require server-side authorization for admin state changes
      (event layout `wait`/`start`/`end`); validate message types and
      sizes; handle malformed messages, rate limits, connection cleanup,
      and backpressure.

- [ ] **HTTP authentication / request security**
      Review session cookies (HttpOnly/SameSite), CSRF where applicable,
      input validation on `/register`, `/login`, `/solve`, rate limiting,
      security headers, secrets handling, and DoS exposure.

- [ ] **Production server integration**
      `server.prod.js` serves `dist/` with Brotli/gzip negotiation;
      `server.js` is the API + WS server. Reconcile into one coherent
      production entry point; keep the API server loopback-only and off
      the LAN.

- [ ] **Brotli/gzip correctness**
      Verify `Content-Encoding`, `Content-Type`, `Vary: Accept-Encoding`,
      uncompressed fallback for skipped assets (`.iso`, >10 MB), caching,
      and no double compression; round-trip decompression must be
      byte-identical.

- [ ] **Frontend correctness**
      `main.js`, `admin.js`, `challenge1.html`: stale state on load,
      unsafe `innerHTML`, WS reconnection handling, malformed input,
      navigation and dynamic-layout edge cases.

- [ ] **Build and asset optimization**
      `vite build` + `scripts/compress-assets.js`; reduce bundle/output
      size; report before/after JS/CSS/gzip/Brotli sizes; consider
      untracking `node_modules` and runtime `CTF_data/` via `.gitignore`.

- [ ] **Background image / UI polish**
      Optimize the background PNG byte size without changing resolution,
      dimensions, composition, or appearance. Subtle transitions/hover
      states only; respect `prefers-reduced-motion` and keyboard
      accessibility.

- [ ] **v86 guest SSH/FTP feasibility**
      Research v86 networking first: `relay_url` has no host-to-guest
      port forwarding. If supported, run SSH/FTP servers inside the guest
      image and forward via loopback-only host bindings
      (`127.0.0.1:2222`→22, `127.0.0.1:2121`→21) with a narrow passive
      FTP range, real auth, no LAN exposure. Otherwise document the
      precise limitation. Note: plain FTP is cleartext — recommend SFTP.

- [ ] **Three-pass verification and PR**
      Pass 1 functional, pass 2 security, pass 3 independent final diff
      review; reinstall from lockfile; repeat critical tests; record
      commands as PASS/FAIL/BLOCKED; then open PR from `development`
      (never touch `main` directly).
