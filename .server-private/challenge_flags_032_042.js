// Server-only authoritative flags for Dynamic VM Challenges 032–042.
// Do not import this module from browser-facing code or move it under public/.
export const CHALLENGE_FLAGS_032_042 = [
  { id: 32, category: "Digital Forensics", flag: "CTF{whiteouts_are_not_secure_deletes}" },
  { id: 33, category: "Linux Fundamentals", flag: "CTF{dotfiles_are_still_files}" },
  { id: 34, category: "Linux Fundamentals", flag: "CTF{chmod_640_verified}" },
  { id: 35, category: "Linux Fundamentals", flag: "CTF{follow_the_link}" },
  { id: 36, category: "Digital Forensics", flag: "CTF{192.0.2.77}" },
  { id: 37, category: "Digital Forensics", flag: "CTF{parcel_checked}" },
  { id: 38, category: "Cryptography & Encoding", flag: "CTF{decode_before_you_trust}" },
  { id: 39, category: "Cryptography & Encoding", flag: "CTF{shift_the_letters}" },
  { id: 40, category: "Network Forensics", flag: "CTF{cdn-sync.northpier.invalid}" },
  { id: 41, category: "Reverse Engineering & Shell Debugging", flag: "CTF{trace_the_script}" },
  { id: 42, category: "Linux Process Investigation", flag: "CTF{process_args_matter}" },
];
