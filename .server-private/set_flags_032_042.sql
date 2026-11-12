-- Optional one-time migration for Dynamic VM Challenges 032–042.
-- Compatible with the platform schema: challenges(id, solve_count, flag, category).
-- Base points belong in challenges.js, not in SQLite.
-- Existing solve_count values are preserved on conflict.
BEGIN IMMEDIATE;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (32, 'CTF{whiteouts_are_not_secure_deletes}', 0, 'Digital Forensics') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (33, 'CTF{dotfiles_are_still_files}', 0, 'Linux Fundamentals') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (34, 'CTF{chmod_640_verified}', 0, 'Linux Fundamentals') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (35, 'CTF{follow_the_link}', 0, 'Linux Fundamentals') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (36, 'CTF{192.0.2.77}', 0, 'Digital Forensics') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (37, 'CTF{parcel_checked}', 0, 'Digital Forensics') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (38, 'CTF{decode_before_you_trust}', 0, 'Cryptography & Encoding') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (39, 'CTF{shift_the_letters}', 0, 'Cryptography & Encoding') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (40, 'CTF{cdn-sync.northpier.invalid}', 0, 'Network Forensics') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (41, 'CTF{trace_the_script}', 0, 'Reverse Engineering & Shell Debugging') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
INSERT INTO challenges (id, flag, solve_count, category) VALUES (42, 'CTF{process_args_matter}', 0, 'Linux Process Investigation') ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category;
COMMIT;
