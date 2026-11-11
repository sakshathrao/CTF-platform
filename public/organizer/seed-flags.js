#!/usr/bin/env node
/**
 * Seeds authoritative flags for Challenges 001-031 into the CTF platform SQLite database.
 * Usage: node organizer/seed-flags.js [optional-path-to-db]
 */
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");

const candidates = [
  process.argv[2],
  process.env.DB_PATH,
  path.join(rootDir, "data.db"),
  path.join(rootDir, "..", "CTF_data", "ctf.sqlite"),
  path.join(rootDir, "CTF_data", "ctf.sqlite"),
].filter(Boolean);

let dbPath = candidates.find((p) => existsSync(p)) || path.join(rootDir, "data.db");
console.log(`Seeding Challenges 001-031 flags into: ${dbPath}`);

const db = new DatabaseSync(dbPath);
db.exec(`
  CREATE TABLE IF NOT EXISTS challenges (
    id INTEGER PRIMARY KEY,
    solve_count INTEGER NOT NULL DEFAULT 0,
    flag TEXT,
    category TEXT
  );
`);

const rows = [
  {
    "id": 1,
    "category": "OSINT",
    "flag": "CTF{c2005_16_20}"
  },
  {
    "id": 2,
    "category": "Forensics",
    "flag": "CTF{follow_the_stream_01}"
  },
  {
    "id": 3,
    "category": "Web",
    "flag": "CTF{look_beyond_rendered_pages_inspect_the_sources}"
  },
  {
    "id": 4,
    "category": "Forensics",
    "flag": "CTF{restore_the_header_04}"
  },
  {
    "id": 5,
    "category": "Cryptography",
    "flag": "CTF{the_key_was_in_plain_sight_05}"
  },
  {
    "id": 6,
    "category": "Reverse Engineering",
    "flag": "CTF{trace_the_check_06}"
  },
  {
    "id": 7,
    "category": "Linux",
    "flag": "CTF{dotfiles_are_still_files_07}"
  },
  {
    "id": 8,
    "category": "Steganography",
    "flag": "CTF{the_red_tag_marks_the_secret_08}"
  },
  {
    "id": 9,
    "category": "Multi-stage",
    "flag": "CTF{follow_each_layer_09}"
  },
  {
    "id": 10,
    "category": "Web",
    "flag": "CTF{cookies_are_client_controlled_10}"
  },
  {
    "id": 11,
    "category": "Forensics",
    "flag": "CTF{files.northpier.example_20251014_2142}"
  },
  {
    "id": 12,
    "category": "Cryptography",
    "flag": "CTF{the_old_code_still_turns_12}"
  },
  {
    "id": 13,
    "category": "OSINT",
    "flag": "CTF{19980119015021}"
  },
  {
    "id": 14,
    "category": "Network Analysis",
    "flag": "CTF{txt_records_tell_the_story_14}"
  },
  {
    "id": 15,
    "category": "Network Analysis",
    "flag": "CTF{mac_66}"
  },
  {
    "id": 16,
    "category": "Web",
    "flag": "CTF{the_crawler_found_the_gap_16}"
  },
  {
    "id": 17,
    "category": "Forensics",
    "flag": "CTF{redaction_is_not_deletion_17}"
  },
  {
    "id": 18,
    "category": "Forensics",
    "flag": "CTF{the_operator_called_at_dawn_18}"
  },
  {
    "id": 19,
    "category": "Cryptography",
    "flag": "CTF{small_exponent_big_mistake_19}"
  },
  {
    "id": 20,
    "category": "Reverse Engineering",
    "flag": "CTF{diagnostic_mode_reveals_all_20}"
  },
  {
    "id": 21,
    "category": "Linux",
    "flag": "CTF{the_worker_left_its_environment_21}"
  },
  {
    "id": 22,
    "category": "Forensics",
    "flag": "CTF{unreachable_does_not_mean_deleted_22}"
  },
  {
    "id": 23,
    "category": "Web",
    "flag": "CTF{the_map_remembers_the_source_23}"
  },
  {
    "id": 24,
    "category": "OSINT",
    "flag": "CTF{github_as36459}"
  },
  {
    "id": 25,
    "category": "Forensics",
    "flag": "CTF{the_header_holds_the_fragment_25}"
  },
  {
    "id": 26,
    "category": "Cryptography",
    "flag": "CTF{never_reuse_a_one_time_pad_26}"
  },
  {
    "id": 27,
    "category": "Linux",
    "flag": "CTF{the_timer_woke_the_worker_27}"
  },
  {
    "id": 28,
    "category": "Steganography",
    "flag": "CTF{north_pier}"
  },
  {
    "id": 29,
    "category": "Network Analysis",
    "flag": "CTF{vault_northpier_example}"
  },
  {
    "id": 30,
    "category": "Cryptography",
    "flag": "CTF{three_shares_open_the_cabinet_30}"
  },
  {
    "id": 31,
    "category": "Forensics",
    "flag": "CTF{the_logon_started_the_process_31}"
  }
];

const stmt = db.prepare(`
  INSERT INTO challenges (id, flag, solve_count, category)
  VALUES (?, ?, 0, ?)
  ON CONFLICT(id) DO UPDATE SET flag = excluded.flag, category = excluded.category
`);

db.exec("BEGIN IMMEDIATE");
for (const r of rows) {
  stmt.run(r.id, r.flag, r.category);
}
db.exec("COMMIT");
console.log(`Successfully seeded ${rows.length} challenges (IDs 1-31).`);
