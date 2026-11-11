# North Pier CTF (Challenges 001–031) — Organizer Solutions & Flags

# ORGANIZER ONLY — Challenge 001: The Excellent One

## Source challenge

Adapted from **Finding Artifacts 1**, UIUCTF 2023 (author credited in the public listing as David).

- Public listing: https://ctf42.online/ctfs/uiuctf/2023/finding-artifacts-1/
- Community writeup: https://github.com/ibrahimesseddyq/writeups/blob/main/uiuctf/2023/finding-artifacts-1.md
- Independent writeup: https://ctftime.org/writeup/37378
- Official target record: https://rubinmuseum.org/collection/c2005-16-20/

The original challenge asks teams to identify which New York museum holds a bronze statue called the “Excellent One.” Its documented solve uses a web search for the quoted phrase and finds the Rubin Museum's Mahakala collection record.

## Adaptation

This version preserves the original online museum-OSINT research pattern, but changes the final question from “which museum?” to “what is the exact museum object number?” and adds a local case-file handout.

Exhibit A is an AI-generated illustrative reconstruction based on the public description. It is labelled clearly and is not a copy of the actual Rubin Museum photograph. Exhibits B and C are local text handouts written for this adaptation.

## Authoritative answer

Official museum record:
https://rubinmuseum.org/collection/c2005-16-20/

The record identifies the artwork as “Mahakala, the Excellent One” and lists:
- Credit line: Rubin Museum of Himalayan Art
- Object number: C2005.16.20
- HAR number: 65443

Local flag:
`CTF{c2005_16_20}`

Do not accept the HAR number (`65443`) or the museum name as the flag.

## Intended solving path

1. Read Exhibit B. Extract the distinctive description: Himalayan bronze protector figure; fierce expression; heavy coat and boots; club held in front; phrase “The Excellent One.”
2. Search the web for the exact phrase plus bronze / Himalayan / statue. A simple query such as `"The Excellent One" bronze statue` points to the UIUCTF solution pattern and/or the Rubin Museum record.
3. Open the official Rubin Museum collection page and compare the written attributes with the case note and visual reconstruction.
4. Read the `Object number` field in the Artwork Details section.
5. Normalize `C2005.16.20` to lowercase and replace periods with underscores.
6. Submit `CTF{c2005_16_20}`.

## Hint ladder

Hint 1: Search the exact quoted phrase from the recovered note together with the word “bronze”.

Hint 2: The object is a Himalayan protector deity. The museum record uses a two-word title beginning with the object's name.

Hint 3: In the official collection record, look under “Artwork Details.” The requested value is labelled “Object number,” not “HAR Number.”

## Asset and licensing notes

The local reconstruction image was generated specifically for this adaptation. It is not a photograph of the original artifact and is not derived from the Rubin Museum's photograph.

The official Rubin Museum collection text and artwork data are used as factual research references. The museum's terms state that its images and data are protected and that image reproductions require permission for uses beyond their limited noncommercial educational/personal-use terms. This package therefore does not redistribute the museum's original artwork photograph.

Rubin image rights information:
https://rubinmuseum.org/about-us/terms-conditions/
https://api.rubinmuseum.org/rights

# ORGANIZER ONLY — Challenge 002: The Quiet Download

## Inspiration / source pattern

Adapted from the beginner packet-capture exercise **“Follow the Leader”** in CTF Academy's Network Forensics challenges:
https://ctfacademy.github.io/network/challenge1/index.htm

The source exercise asks participants to inspect a filtered PCAP in Wireshark, identify the protocol and recover a flag. The original downloadable PCAP could not be fetched in this environment, so this event version recreates the same beginner TCP-stream analysis pattern with an original, self-contained capture and case narrative. It is not a copy of the source capture or flag.

Reference methodology:
https://wiki.athena-ctf.com/docs/forensics/pcap-analysis

## Flag

`CTF{follow_the_stream_01}`

## Intended solve path

1. Open `gateway_capture.pcap` in Wireshark.
2. Apply display filter `http`.
3. Inspect the HTTP requests. The relevant path is `/exports/shift-report.txt`.
4. Select a packet in that conversation.
5. Right-click → Follow → TCP Stream.
6. Read the reconstructed HTTP response body.
7. Recover the token `CTF{follow_the_stream_01}`.

Alternative command-line approach:
- `tshark -r gateway_capture.pcap -Y 'http.request' -T fields -e http.request.uri`
- `strings gateway_capture.pcap | grep 'CTF{'`

The intended learning path is Wireshark stream reconstruction. The `strings` shortcut is possible but should not be hinted as the primary path.

## Hints

1. The capture contains several HTTP requests. Start by filtering with `http`.
2. Look for the request path that mentions a shift report rather than the health endpoint.
3. Follow the TCP stream for `/exports/shift-report.txt`; the server response contains a plain-text report.

## Capture details

- Ethernet PCAP, 19 packets.
- Workstation: `10.10.4.21`
- Gateway: `192.0.2.44`
- HTTP service: TCP/80
- Decoy: `/health` request
- Target: `/exports/shift-report.txt`
- Unrelated request: `/favicon.ico`

The capture uses documentation-only address ranges and does not contain live credentials or a real target.

# ORGANIZER ONLY — Challenge 003: The Unseen Build

## Inspiration

This challenge adapts the beginner web inspection pattern from **“Insp3ct0r”**, picoCTF 2019. The original teaches participants to inspect the HTML source, then open the linked CSS and JavaScript files to locate three separate flag fragments.

References:
- picoCTF practice challenge: https://play.picoctf.org/practice/challenge/18
- Cajac's picoCTF 2019 writeup: https://github.com/Cajac/picoCTF-Writeups/blob/main/picoCTF_2019/Web_Exploitation/Insp3ct0r.md
- Recent explanation of the same three-file workflow: https://picoctfsolutions.com/picoctf-2019-insp3ct0r

The event's story, portal UI, source files and flag are original. The source challenge's exact flag fragments, page source and assets are not copied.

## Local flag

`CTF{look_beyond_rendered_pages_inspect_the_sources}`

## Fragment locations

1. `player/public/challenges/web_001/portal/index.html`
   - HTML comment at the bottom:
   - `CTF{look_beyond_`

2. `player/public/challenges/web_001/portal/css/field-notes.css`
   - CSS comment near the top:
   - `rendered_pages_`

3. `player/public/challenges/web_001/portal/js/portal.js`
   - JavaScript comment at the bottom:
   - `inspect_the_sources}`

Combined in this order:
`CTF{look_beyond_` + `rendered_pages_` + `inspect_the_sources}`
= `CTF{look_beyond_rendered_pages_inspect_the_sources}`

## Intended solving path

1. Download Exhibit A (`portal_snapshot.zip`) and extract it into a working folder.
2. Open the extracted `index.html` and use Ctrl+U (or View Page Source) to inspect the HTML. Find the first segment in an HTML comment.
3. Open the extracted `css/field-notes.css` stylesheet and find the second segment in a CSS comment.
4. Open the extracted `js/portal.js` file and find the third segment in a JavaScript comment.
5. Concatenate the three segments in order and submit.

## Hints

1. The visible page is only what the browser renders. Inspect the original response sent by the server.
2. The page links to a separate stylesheet and a JavaScript file. Open those files directly.
3. Look for developer comments in all three source files. Join the three segments in order.

## Deployment

- Challenge ID: 3
- Points: 100
- Page: `/challenges/web_001/index.html`
- Local target: `/challenges/web_001/portal/index.html`
- Flag: `CTF{look_beyond_rendered_pages_inspect_the_sources}`

The public `portal_snapshot.zip` contains the complete target source. The flag is necessarily recoverable from the public source assets; do not store an authoritative answer elsewhere in client-side code. Validate submissions only through the server `/solve` endpoint.

# ORGANIZER ONLY — Challenge 004: A Few Missing Bytes

## Inspiration and source

This challenge is adapted from the beginner forensics pattern in picoMini by CMU-Africa, **“Corrupted file”**. The original pattern teaches players to identify a JPEG from internal markers, inspect its damaged magic bytes, repair the header, and view the recovered image.

References:
- Challenge writeup: https://github.com/amyy45/CTF-Writeups/blob/main/CTFs/Forensics/corruptedFile.md
- Additional writeup: https://github.com/Shaker-maker/ctf-writeups/blob/main/picoctf/forensics/file-corruption.md
- Related file signature explanation: https://picoctfsolutions.com/picomini-by-cmu-africa-corrupted-file

This event version contains a new evidence scene and a new flag. It does not reuse the original picoMini asset or flag.

## Flag

`CTF{restore_the_header_04}`

## Intended solve path

1. Run `file recovered_photo.bin`. It reports generic `data`.
2. Run `xxd -l 16 recovered_photo.bin`.
3. The first bytes are `5c 78 ff e0 ...`; the ASCII pair `5c 78` is the literal text `\x`.
4. The next bytes include `ff e0` and the printable marker `JFIF`, indicating a JPEG image whose SOI marker is damaged.
5. A JPEG begins with `ff d8 ff`; this file starts with `5c 78 ff e0`. Replace the first two bytes with `ff d8` in a copy of the file.
6. Save the repaired file as `restored.jpg`.
7. Open `restored.jpg`. The evidence tag in the photograph contains `CTF{restore_the_header_04}`.

Example safe repair command (Linux):
`(printf '\xff\xd8'; tail -c +3 recovered_photo.bin) > restored.jpg`

Alternative:
- Use a hex editor to replace byte 0 with `FF` and byte 1 with `D8`.
- Verify with `file restored.jpg` before opening the image.

## Hint ladder

1. The examiner found a `JFIF` marker in the data. What common image format uses this marker?
2. A JPEG file starts with `FF D8 FF`. Compare those bytes with the first bytes shown by `xxd`.
3. Replace the first two bytes `5C 78` with `FF D8` in a copy, then open the restored image.

## Validation

The distributed file was generated as a valid JPEG, then only its first two bytes were replaced with the ASCII bytes `5C 78`. Repairing those two bytes restores the original JPEG. The player page, metadata and text evidence do not contain the flag; the flag is visible only inside the recovered image after repair.

# ORGANIZER ONLY — Challenge 005: The Half-Turn Message

## Inspiration / source challenge

Adapted from picoCTF 2019 Cryptography challenge **“13”**. The original challenge supplies a ROT13 ciphertext and asks participants to recognize the cipher. Its writeups explicitly identify ROT13 and recommend an online decoder such as CyberChef.

References:
- Challenge listing/writeup: https://yorzaren.github.io/ctf/picoctf-2019/13/
- Original description and ciphertext: https://github.com/kevinjycui/picoCTF-2019-writeup/blob/master/Cryptography/13/README.md
- CyberChef ROT13: https://gchq.github.io/CyberChef/

This adaptation keeps the same simple ROT13 learning objective but uses a new narrative, ciphertext, evidence page, visual handout and flag. The original picoCTF ciphertext and flag are not reused.

## Local flag

`CTF{the_key_was_in_plain_sight_05}`

## Ciphertext in participant materials

`PGS{gur_xrl_jnf_va_cynva_fvtug_05}`

## Intended solution

ROT13 rotates each Latin letter by 13 positions. Since the alphabet contains 26 letters, applying the same transformation again reverses it. Digits, underscores and braces remain unchanged.

The margin note says the rotation is half of a complete alphabet, indicating 13.

Use CyberChef with the ROT13 operation, a local ROT13 decoder, or:
`echo 'PGS{gur_xrl_jnf_va_cynva_fvtug_05}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'`

The decoded output is the local flag shown above.

## Hint ladder

1. The note mentions a rotation equal to half of a complete alphabet. How many letters are in the English alphabet?
2. A rotation by 13 letters is commonly called ROT13.
3. ROT13 is its own inverse. Apply it to the entire text, including the uppercase letters.

## Deployment

- Challenge ID: 5
- Points: 100
- Page: `/challenge5.html`
- Evidence: `/challenges/crypto_001/assets/`
- Flag storage: server-side SQLite, ID 5

Participants can solve offline. The CyberChef link is optional convenience only.

# ORGANIZER ONLY — Challenge 006: The Maintenance Console

## Inspiration / source pattern

This challenge uses the beginner C-binary reverse-engineering workflow described by the public **Flag Hunt** starter challenge set and HackBlue's first crackme guide:
- Flag Hunt: https://github.com/0x57Origin/Flag_Hunt
- HackBlue: https://hackblue.org/learn/ctf-first-crackme-reversing

The shared learning pattern is: identify an ELF, inspect strings, locate a password validation function in Ghidra, reverse a simple XOR comparison, run the program with the recovered input. The event-specific binary, case story, source code, password and flag are original.

## Expected access code

`ORBIT-27`

## Final flag

`CTF{trace_the_check_06}`

## Intended solution

1. Download and identify the file:
   `file northstar_console`
   It is an ELF 64-bit x86-64 Linux executable.

2. Inspect strings:
   `strings northstar_console`
   Visible strings include `validate_code`, `ACCESS ACCEPTED`, and the prompt, but not the access code or flag.

3. Open the executable in Ghidra and analyze it.
4. Find `main`, then follow the call to `validate_code`.
5. The validation loop uses a repeating key:
   `N0RTH`
6. The encrypted comparison bytes are:
   `0x01, 0x62, 0x10, 0x1d, 0x1c, 0x63, 0x02, 0x65
7. Each byte is calculated as:
   `input[i] XOR access_key[i % 5]`
8. Reverse the operation by XORing each stored byte with the corresponding repeating key byte.
9. The recovered access code is:
   `ORBIT-27`
10. Run:
    `./northstar_console`
    Enter the recovered code. The program prints `ACCESS ACCEPTED` and reveals:
    `CTF{trace_the_check_06}`

The final flag is emitted by `reveal_flag()` using a byte-wise XOR with constant `0x37`. It is not stored as plaintext in the binary.

## Source code

The organizer-only source file `northstar_console.c` is included for auditing and reproducible builds. It must not be distributed to participants.

## Hint ladder

1. `strings` shows useful labels, but the code itself does not appear as a readable string. Look for the function called by `main`.
2. In `validate_code`, note that every input byte is XORed with an element of `access_key`.
3. The key repeats every five characters. XOR each byte in `encrypted_code` with the matching byte in `access_key` to recover the input.

## Build reproduction

Compile with:
`gcc -O0 -fno-inline -fno-stack-protector -no-pie -o northstar_console northstar_console.c`

The build retains readable function names and an uncomplicated control flow for beginner analysis.

# ORGANIZER ONLY — Challenge 007: The Hidden Handover

## Inspiration / source challenge

Adapted from the beginner hidden-file lesson in **OverTheWire Bandit Level 3 → Level 4**. The original task teaches that dot-prefixed files do not appear in a normal `ls` listing and can be revealed with `ls -a`.

References:
- Official Bandit Level 3 page: https://overthewire.org/wargames/bandit/bandit4.html
- picoCTF Primer, “First Find”: https://primer.picoctf.org/
- Beginner writeup: https://dev.to/ctfdojo/overthewire-bandit-level-3-writeup-find-a-hidden-dotfile-5doa

The event version packages a local workspace archive with nested directories and decoy files. It uses a new incident story, folder structure and flag. It does not reuse OverTheWire's password or filesystem assets.

## Flag

`CTF{dotfiles_are_still_files_07}`

## Intended solve path

1. Download and extract `recovered_workspace.zip`:
   `unzip recovered_workspace.zip`
2. Navigate:
   `cd recovered_workspace/dispatch/active`
3. A normal `ls` does not show the hidden handover folder.
4. Use:
   `ls -la`
5. Inspect the hidden directory:
   `ls -la .handover`
6. Read:
   `cat .handover/.handover_note.txt`
7. Submit:
   `CTF{dotfiles_are_still_files_07}`

Alternative:
`find . -type f -name '.*'`

## Hint ladder

1. Navigate to `recovered_workspace/dispatch/active` first.
2. Linux directory listings hide names beginning with a dot. Try `ls -la`.
3. The hidden directory is `.handover`; inside it, read `.handover_note.txt`.

## Deployment

- Challenge ID: 7
- Points: 100
- Page: `/challenge7.html`
- Evidence: `/challenges/linux_001/assets/`
- Flag: `CTF{dotfiles_are_still_files_07}` stored server-side in SQLite.

# ORGANIZER ONLY — Challenge 008: The Red Tag

## Inspiration
This uses the common beginner PNG LSB pattern documented in:
- zsteg: https://github.com/zed-0xff/zsteg
- Athena CTF Wiki: https://wiki.athena-ctf.com/docs/steganography/image-steg/lsb
- Aperi'Solve: https://www.aperisolve.com/wiki/techniques/images
- HackBlue: https://hackblue.org/learn/ctf-steganography-basics

The local image, case story, evidence notes and flag are original event materials.

## Flag
`CTF{the_red_tag_marks_the_secret_08}`

## Extraction
Payload is embedded in the red channel's least-significant bit, in row-major pixel order, one bit per pixel, most-significant bit first, null-terminated.

Command:
`zsteg -E 'b1,r,lsb,xy' exhibit_A_storage_photo.png`

Or scan:
`zsteg -a exhibit_A_storage_photo.png`

Expected decoded text:
`CTF{the_red_tag_marks_the_secret_08}`

## Intended path
1. Read the case note and notice the red tag / warning-colour clue.
2. Inspect PNG pixel data rather than only metadata.
3. Use zsteg to scan bit planes.
4. Extract red-channel LSB data.
5. Submit the recovered flag.

## Hint ladder
1. The image is a PNG, so inspect its pixel data as well as metadata.
2. The examiner's note refers to the warning colour visible in the photograph. Check that colour channel.
3. Use `zsteg -E 'b1,r,lsb,xy' exhibit_A_storage_photo.png`.

## Validation
Only red-channel LSB values were changed, by at most 1. Green and blue are unchanged. The payload was independently decoded from the saved PNG pixels. The assembled flag is absent from player HTML, text and metadata.


## Participant tool setup added after audit

The player ZIP now links a quickstart with the zsteg install command, a user-install fallback, Windows/WSL2 guidance, and the exact extraction command `zsteg -E 'b1,r,lsb,xy' exhibit_A_storage_photo.png`. The underlying payload was independently decoded from the saved PNG pixels during package QA; this environment did not have the zsteg executable available, so the zsteg CLI itself was not run here.

# ORGANIZER ONLY — Challenge 009: The Sealed Handover

## Inspiration and source patterns

This challenge combines two common beginner CTF techniques:
- **CanYouSee (picoCTF)**: inspect EXIF metadata, locate a Base64-encoded field and decode it.
  Reference: https://tan-junwei.github.io/CTF-Writeups/PicoCTF/Forensics/CanYouSee
- **JPEG with appended ZIP data**: use file-structure analysis / binwalk to detect a ZIP archive stored after the JPEG data.
  Reference: https://0xjams.com/blog/forensics-beginner-challenges-pt3/
- Supporting file-analysis method: https://ctf.support/forensics/file-analysis/

This adaptation uses an original generated image, new evidence story, password-protected archive and flag. It does not copy the reference challenges' assets or answers.

## Final flag

`CTF{follow_each_layer_09}`

## Archive password

`redwax-archive-09`

## EXIF metadata value

The `UserComment` field contains:
`cmVkd2F4LWFyY2hpdmUtMDk=`

Base64 decoding yields the archive password.

## Intended solve path

1. Inspect the image:
   `file archive_photo.jpg`
2. Read EXIF metadata:
   `exiftool archive_photo.jpg`
3. Find `User Comment`; it is Base64 text.
4. Decode:
   `echo 'cmVkd2F4LWFyY2hpdmUtMDk=' | base64 -d`
5. This yields password:
   `redwax-archive-09`
6. Identify ZIP data appended after the JPEG's end marker using:
   `binwalk archive_photo.jpg`
7. Extract the appended archive:
   `unzip -P 'redwax-archive-09' archive_photo.jpg`
8. Some Info-ZIP versions print a warning that extra JPEG bytes precede the ZIP archive, but still extract the handover note. The warning is expected.
9. Read `handover_note.txt` and recover the final flag.

If a ZIP utility cannot open the appended archive directly, use the offset reported by `binwalk` to carve the ZIP segment, then run `unzip -P` on the carved file.

## Hint ladder

1. The image is a JPEG. Check its EXIF fields, especially the user comment.
2. The user comment looks like Base64. Decode it; it is not the flag, but it is useful for the next step.
3. A ZIP archive is appended after the JPEG. Use the decoded text as the archive password.

## Validation

- The JPEG has valid EXIF metadata and opens normally.
- The UserComment is exactly the Base64 encoding of the password.
- A password-protected ZIP archive is appended after the JPEG EOI marker.
- `unzip -P <password> archive_photo.jpg` extracts `handover_note.txt`.
- The final flag appears only in the encrypted archive's note, not in participant metadata or text evidence.


## Beginner tool support added after audit

The player package now includes exact commands for `exiftool`, `base64 -d`, `binwalk`, and `unzip -P`, plus Windows/WSL2 notes and a fallback for ZIP utilities that cannot open prepended JPEG data.

# ORGANIZER ONLY — Challenge 010: The Forgotten Cookie

## Source challenge and inspiration

Adapted from picoCTF's beginner web challenge **“Cookies”**. The original task uses a numeric browser cookie (`name`) to choose among cookie records; participants inspect and change the cookie value until the flag is returned.

References:
- CTFDojo walkthrough: https://ctfdojo.com/writeups/picoctf-cookies-writeup
- picoCTF 2021 Cookies solution: https://picoctfsolutions.com/picoctf-2021-cookies
- HackBlue beginner web methodology (cookies and browser devtools): https://hackblue.org/learn/ctf-web-challenge-methodology

This adaptation retains the cookie-manipulation learning objective but uses a new archive portal, record set, case narrative and flag. No picoCTF application code, data, flag, or graphic has been reused.

## Local flag

`CTF{cookies_are_client_controlled_10}`

## Intended solve path

1. Open the challenge page and launch Exhibit A.
2. The portal loads public record 00 and sets a browser cookie named `vault_record` with value `0`.
3. Open browser Developer Tools → Application (Chrome/Edge) or Storage (Firefox) → Cookies → local host.
4. Locate `vault_record`.
5. Change its numeric value and refresh the page. The portal reads this cookie and fetches the matching JSON record.
6. Test the sequential slots. Values 0–17 return ordinary public notices.
7. Value `18` returns the restricted recovery bulletin containing:
   `CTF{cookies_are_client_controlled_10}`

## Why this is a static simulation

This is an offline browser exercise. The local portal intentionally simulates the insecure pattern of using a client-controlled cookie value as a record selector. Because it is served as static files, all JSON records are client-retrievable; the security lesson is the predictable cookie-controlled lookup, not a claim that a production server-side authorisation boundary has been bypassed. The platform's authoritative solve validation remains on `/solve`.

## Hints

1. The portal says the current archive slot is maintained by the browser. Look at the browser's stored cookies.
2. Find the cookie that contains a number. Change it and refresh the page.
3. Try the sequential record slots. The restricted bulletin is returned by slot `18`.

## Deployment

- ID: 10
- Points: 125
- Difficulty: Easy-Medium
- Page: `/challenge10.html`
- Target portal: `/challenges/web_002/portal/index.html`
- Flag: `CTF{cookies_are_client_controlled_10}`

Merge the player's `public/` directory into the Vite `public/` directory. Add the ID 10 registry entry, configure the server-side flag in SQLite, and test `/session`, `/progress`, WebSocket state, and `/solve`.


## Audit disposition — direct JSON disclosure

This challenge is intentionally framed as client-side data exposure. The portal is static, and each JSON record is a public static resource. The `vault_record` cookie only selects which record the UI requests; it is not an authorization boundary. The flag remaining in `entries/18.json` is therefore part of the lesson: after changing the cookie to `18`, inspect the Network panel and confirm that the restricted resource is publicly retrievable. Do not describe this as bypassing a server-side authorization boundary. The CTF scoring endpoint remains separately server-validated.

# ORGANIZER ONLY — Challenge 011: The Last Download

## Inspiration / source patterns

This challenge adapts the beginner browser-forensics exercise pattern found in:
- MetaCTF — “Browser, Wowser”: analysis of a browser-history SQLite database to identify suspicious activity.
  https://metactf.com/blog/flash-ctf-browser-wowser/
- CyberSkyline — “History”: analysis of Firefox's `places.sqlite` using SQLite queries.
  https://trove.cyberskyline.com/038f8feecbf4489a9ee68d8c2131b49c
- Browser artifact analysis reference:
  https://github.com/grandoou/ctf-skills20260416/blob/main/ctf-forensics/linux-forensics.md

The event-specific North Pier profile database, browsing records, downloads, narrative, and answer are synthetic and authored for this package. No source challenge database or flag is reused.

## Final flag

`CTF{files.northpier.example_20251014_2142}`

## Expected evidence

The target download row has:
- `target_path`: `/Users/operator/Downloads/northpier_manifest.csv`
- `tab_url`: `https://files.northpier.example/drop/receive?id=NP-117`
- `site_url`: `https://files.northpier.example/`
- UTC start time: `2025-10-14 21:42:00`

The requested host component is:
`files.northpier.example`

The normalized timestamp component is:
`20251014_2142`

## Intended query

```sql
SELECT
  target_path,
  tab_url,
  datetime(start_time / 1000000 - 11644473600, 'unixepoch') AS start_utc
FROM downloads
WHERE target_path LIKE '%northpier_manifest.csv';
```

Expected result:
`/Users/operator/Downloads/northpier_manifest.csv`
`https://files.northpier.example/drop/receive?id=NP-117`
`2025-10-14 21:42:00`

The Chrome `downloads` table is the direct source for `target_path`, `tab_url` and `start_time`; the `urls` and `visits` tables provide supporting timeline context.

## Hint ladder

1. The History file is a SQLite database. Start with `.tables` and inspect the `downloads` schema.
2. Query the download record using the filename from the case note. `tab_url` records the page that initiated it.
3. Chromium timestamps count microseconds since 1601-01-01. Use:
   `datetime(start_time/1000000 - 11644473600, 'unixepoch')`
   Then normalize UTC time to `YYYYMMDD_HHMM`.

## Validation

- The `History` file opens as a valid SQLite 3 database.
- It contains 14 synthetic URL records, visit records, and 3 downloads.
- Only one download target matches `northpier_manifest.csv`.
- The derived host and timestamp match the flag.
- The flag is not stored in the participant database or text evidence; it is derived from the relevant download row.

## Deployment

- Challenge ID: 11
- Points: 125
- Page: `/challenge11.html`
- Evidence: `/challenges/forensics_002/assets/`
- Server-side flag: `CTF{files.northpier.example_20251014_2142}`


## Beginner scaffolding added after audit

The player package now includes a ready-to-run SQL query filtering for `northpier_manifest.csv` and the exact WebKit/Chromium timestamp conversion formula. Participants can use DB Browser's Execute SQL tab or run the same query with `sqlite3`.

# ORGANIZER ONLY — Challenge 012: The Telegraph Ledger

## Inspiration / source challenge

Adapted from the Vigenère cipher challenge in picoCTF 2022. The original exercise uses a repeating key to decrypt a ciphertext and public writeups demonstrate using online Vigenère decoders.

References:
- picoCTF practice challenge: https://play.picoctf.org/practice/challenge/316
- TeachDian writeup: https://github.com/TeachDian/picoCTF-writeups/blob/main/picoCTF_2022/Cryptography/Vigenere.md
- CTFtime writeup: https://ctftime.org/writeup/32848
- picoCTF Primer: https://primer.picoctf.org/

This version uses a new telegram narrative, local evidence, a different key, ciphertext and flag. The original picoCTF ciphertext and flag are not reused.

## Final flag

`CTF{the_old_code_still_turns_12}`

## Recovered key

`NORTHPIER`

The memo states that the station call-sign was NORTH PIER and spaces were removed before it was used as a repeating word.

## Ciphertext

`PHW{mot_wpu_pcux_ziqpc_giigz_12}`

## Intended solve path

1. Read Exhibit C and recover the station call-sign: NORTH PIER.
2. Remove the space to obtain `NORTHPIER`.
3. Recognize the repeating-key alphabetic cipher as Vigenère.
4. Use CyberChef / dCode in Vigenère decrypt mode with key NORTHPIER.
5. Keep punctuation, underscores and digits unchanged.
6. The decoded text is `CTF{the_old_code_still_turns_12}`.

## Hint ladder

1. The memo says the operator used the station call-sign as a repeating word. Remove its space.
2. The message uses a repeating-key alphabetic cipher. The classic cipher name is associated with a 16th-century French cryptographer.
3. Use Vigenère decryption with key `NORTHPIER`. Leave non-letters unchanged.

## Technical notes

The cipher advances the key index only when encountering ASCII alphabetic characters. Letter case is preserved; punctuation, braces, underscores and digits pass through unchanged.

## Deployment

- Challenge ID: 12
- Points: 125
- Page: `/challenge12.html`
- Evidence: `/challenges/crypto_002/assets/`
- Flag: `CTF{the_old_code_still_turns_12}` stored server-side in SQLite.

# ORGANIZER ONLY — Challenge 013: The First Footprint

## Source challenge pattern

Adapted from the archived-website investigation in **TryHackMe — Digital Footprint**, Task 2 ("Archived Company Website"). That beginner OSINT task asks participants to use the Wayback Machine to establish when a specific website was first published.

References:
- TryHackMe Digital Footprint: https://tryhackme.com/room/osintchallengeiv
- Internet Archive official guide: https://archivesupport.zendesk.com/hc/en-us/articles/360004651732-Using-The-Wayback-Machine
- Internet Archive Search guide: https://archivesupport.zendesk.com/hc/en-us/articles/360018359991-Search-A-Basic-Guide

The event version uses a different target (a specific historical Python 1.5 documentation path), a local archive-desk case narrative, new evidence materials and a new answer. It does not reuse TryHackMe wording, files, or answers.

## Exact research target

`http://www.python.org/1.5/`

The task is scoped to this exact page, not the python.org root domain.

## Expected first successful capture

- First successful capture timestamp: `19980119015021`
- UTC: `1998-01-19 01:50:21`
- Status: 200
- MIME type: text/html
- First snapshot URL:
  `https://web.archive.org/web/19980119015021/http://www.python.org:80/1.5/`

This first-capture record is shown by a Wayback CDX-backed archive index result. The flag uses the 14-digit timestamp embedded in the actual Wayback snapshot URL.

## Flag

`CTF{19980119015021}`

## Intended solve path

1. Read the recovered reference card and examiner note.
2. Copy the exact target URL `http://www.python.org/1.5/`.
3. Open the Wayback calendar:
   `https://web.archive.org/web/*/http://www.python.org/1.5/`
4. Inspect captures for that path and find the earliest successful page capture.
5. Exclude 3xx redirects and 4xx/5xx errors; prefer the earliest 200/blue capture.
6. Open the earliest capture. The Wayback URL contains the timestamp:
   `19980119015021`
7. Submit `CTF{19980119015021}`.

## Important distinction

Do not use the first capture of `python.org` or `www.python.org/`. The requested target is specifically `/1.5/`. The earliest record for a domain homepage may be different. Likewise, do not use a redirect-only result as the first successful HTML page capture.

## Hint ladder

1. The question is about the exact `/1.5/` page, not the Python website homepage.
2. In the Wayback calendar, look for the earliest successful capture. A blue capture indicates an HTTP 2xx response; green indicates a redirect.
3. The timestamp is the 14-digit number in the middle of the archived URL. The official format is `YYYYMMDDHHMMSS`.

## Verification / deployment

- Challenge ID: 13
- Points: 125
- Difficulty: Easy-Medium
- Page: `/challenge13.html`
- Evidence: `/challenges/osint_002/assets/`
- Flag: `CTF{19980119015021}`

Merge the player's `public/` directory into the Vite public directory. Add the ID 13 registry entry and set the authoritative flag in SQLite. Internet Archive is a third-party public service, so rehearse the challenge before the event; the local evidence itself remains available offline.


## Audit operations fix — offline fallback

An organizer-only snapshot is provided under `author_only/fallback/` with release instructions. Keep it out of the normal player distribution and release it only if the Wayback Machine is unavailable to teams during the event.

# ORGANIZER ONLY — 014 The Resolver's Receipt

Flag: `CTF{txt_records_tell_the_story_14}`

Intended path: Filter the PCAP to DNS responses. Locate the TXT answer for the verification name and Base64-decode its text.

Solution detail: The TXT answer in the verification DNS response contains Base64 of the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 015 The Duplicate Address

Flag: `CTF{mac_66}`

Intended path: Filter ARP packets. Find two MAC addresses claiming 10.20.4.1, compare them with the inventory, then use the unauthorized MAC's final octet in CTF{mac_<octet>} format.

Solution detail: An unauthorized MAC 02:00:00:00:00:66 also claims gateway IP 10.20.4.1. The inventory identifies the legitimate gateway MAC.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 016 The Crawler's Blind Spot

Flag: `CTF{the_crawler_found_the_gap_16}`

Intended path: Open robots.txt, follow the disallowed archive path, then decode the Base64 record found there.

Solution detail: robots.txt disallows /internal/archive/. The index there contains Base64 of the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 017 The Redacted Export

Flag: `CTF{redaction_is_not_deletion_17}`

Intended path: Use pdftotext or select/copy the PDF text. The drawn redaction bars do not remove the underlying text layer.

Solution detail: The PDF text layer retains the flag beneath a black rectangle. pdftotext recovers it.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 018 The Handover Call

Flag: `CTF{the_operator_called_at_dawn_18}`

Intended path: Use Audacity's Plot Spectrum and the supplied DTMF chart. Each character is represented by three decimal ASCII digits.

Solution detail: The WAV encodes each flag character as three DTMF digits representing its decimal ASCII code.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 019 The Small Exponent

Flag: `CTF{small_exponent_big_mistake_19}`

Intended path: Search small k values until c+k*n is a perfect cube. The recovered plaintext is the flag body; wrap it in CTF{...}. The organizer starter script demonstrates integer cube roots.

Solution detail: The exact cube is c+4n (k=4). The recovered plaintext is the flag body; wrap it in CTF{...}.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 020 The Quiet Diagnostic

Flag: `CTF{diagnostic_mode_reveals_all_20}`

Intended path: Use Linux x86-64 or WSL2. Run chmod +x, inspect strings and try --recover with the supplied hex input.

Solution detail: The binary's undocumented --recover mode XORs each input byte with 0x2a and prints the recovered flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 021 The Orphaned Worker

Flag: `CTF{the_worker_left_its_environment_21}`

Intended path: Inspect the NUL-separated procfs environ file and Base64-decode NORTHPIER_HANDOVER.

Solution detail: NORTHPIER_HANDOVER in proc/4321/environ is Base64 of the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 022 The Unpublished Revision

Flag: `CTF{unreachable_does_not_mean_deleted_22}`

Intended path: Extract the webroot archive, run git fsck --no-reflogs --unreachable, then inspect the dangling commit with git show.

Solution detail: The tarball contains a Git repository with a dangling commit; git fsck locates it and git show reveals the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 023 The Map Left Behind

Flag: `CTF{the_map_remembers_the_source_23}`

Intended path: Inspect sourceMappingURL, open the map's sourcesContent and decode the embedded value.

Solution detail: The source map's sourcesContent contains Base64 of the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 024 The Prefix Behind the Portal

Flag: `CTF{github_as36459}`

Intended path: Match the prefix in the RDAP snapshot, then correlate the BGP origin ASN. Build the flag as CTF{<registered organization slug>_as<ASN>} using lowercase and underscores.

Solution detail: The offline RDAP object identifies GitHub, Inc.; BGP snapshot gives origin AS36459 for 140.82.112.0/20.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 025 The Mailbox Fragment

Flag: `CTF{the_header_holds_the_fragment_25}`

Intended path: Parse the MBOX, find X-Northpier-Record and Base64-decode its value.

Solution detail: The fifth MBOX message has X-Northpier-Record containing Base64 of the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 026 The Reused Pad

Flag: `CTF{never_reuse_a_one_time_pad_26}`

Intended path: XOR C1 with the known plaintext to recover key bytes, then XOR C2 with the recovered key.

Solution detail: C1 XOR known plaintext recovers key bytes; C2 XOR that stream yields the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 027 The Timer's Last Tick

Flag: `CTF{the_timer_woke_the_worker_27}`

Intended path: Trace the 02:17 journal event to the timer, service and EnvironmentFile in the supplied tarball.

Solution detail: The timer references northpier-reconcile.service; the service reads /etc/northpier/reconcile.env; decode its variable.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 028 The Glass Harbor

Flag: `CTF{north_pier}`

Intended path: Read the 5×7 letters from the spectrogram. Combine the recovered direction word with the site name North Pier, lowercase and join with an underscore inside CTF{...}.

Solution detail: The spectrogram spells NORTH; the supplied readme maps NORTH to the event flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 029 The Name Before Encryption

Flag: `CTF{vault_northpier_example}`

Intended path: Inspect the TLS ClientHello server_name (SNI) extension. Convert the captured hostname to lowercase, replace dots with underscores and wrap it in CTF{...}.

Solution detail: The ClientHello SNI is vault.northpier.example; hostname_lookup.txt maps it to the flag.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 030 The Three-Key Cabinet

Flag: `CTF{three_shares_open_the_cabinet_30}`

Intended path: Use any three shares and modular Lagrange interpolation at x=0. A starter script is supplied.

Solution detail: Lagrange interpolation at zero reconstructs each byte; all ten 3-of-5 combinations should agree.

Validation: See release QA report. Player package excludes author_only.

# ORGANIZER ONLY — 031 The Logon That Stayed

Flag: `CTF{the_logon_started_the_process_31}`

Intended path: Match the Security 4624 TargetLogonId with Sysmon Event 1 LogonId, then decode Base64 as UTF-16LE.

Solution detail: Security 4624 and Sysmon Event 1 share LogonId 0x77A1; Base64 UTF-16LE command reveals the flag.

Validation: See release QA report. Player package excludes author_only.

