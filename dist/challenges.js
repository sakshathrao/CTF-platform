// CTF Platform Challenge Registry (Challenges 001–031)
// Adapted for sakshathrao/CTF-platform (development branch)
import { challenges032To042 } from "./challenges_032_042.js";

export const challenges = [
  {
    title: "The Excellent One",
    id: 1,
    category: "OSINT",
    description: "Identify a Himalayan bronze figure from a recovered case file and locate its official museum object number.",
    link: "challenge1.html",
    points: 100,
  },
  {
    title: "The Quiet Download",
    id: 2,
    category: "Forensics",
    description: "Analyze a packet capture, identify an HTTP report download, and recover the token from its TCP stream.",
    link: "challenge2.html",
    points: 100,
  },
  {
    title: "The Unseen Build",
    id: 3,
    category: "Web",
    description: "Inspect a recovered portal's HTML, CSS and JavaScript to reconstruct a deployment marker left in client-side source.",
    link: "challenge3.html",
    points: 100,
  },
  {
    title: "A Few Missing Bytes",
    id: 4,
    category: "Forensics",
    description: "Repair a corrupted image header and inspect the restored evidence photograph to recover a key.",
    link: "challenge4.html",
    points: 100,
  },
  {
    title: "The Half-Turn Message",
    id: 5,
    category: "Cryptography",
    description: "Identify a half-alphabet substitution and decode a recovered dispatch using ROT13.",
    link: "challenge5.html",
    points: 100,
  },
  {
    title: "The Maintenance Console",
    id: 6,
    category: "Reverse Engineering",
    description: "Reverse a small Linux executable, recover its access code from a repeating XOR check, and retrieve the recovery record.",
    link: "challenge6.html",
    points: 100,
  },
  {
    title: "The Hidden Handover",
    id: 7,
    category: "Linux",
    description: "Explore a recovered Linux workspace and locate a hidden handover note using basic filesystem commands.",
    link: "challenge7.html",
    points: 100,
  },
  {
    title: "The Red Tag",
    id: 8,
    category: "Steganography",
    description: "Examine a recovered CCTV image, identify its hidden red-channel LSB payload, and recover the evidence marker.",
    link: "challenge8.html",
    points: 100,
  },
  {
    title: "The Sealed Handover",
    id: 9,
    category: "Multi-stage",
    description: "Decode an image metadata clue, recover a password, and extract an appended archive to find a hidden handover marker.",
    link: "challenge9.html",
    points: 100,
  },
  {
    title: "The Forgotten Cookie",
    id: 10,
    category: "Web",
    description: "Inspect a recovered archive portal's browser cookie and test whether changing its numeric record slot reveals a restricted bulletin.",
    link: "challenge10.html",
    points: 125,
  },
  {
    title: "The Last Download",
    id: 11,
    category: "Forensics",
    description: "Analyze a recovered Chromium SQLite history database to identify the source page and UTC time of a suspicious download.",
    link: "challenge11.html",
    points: 125,
  },
  {
    title: "The Telegraph Ledger",
    id: 12,
    category: "Cryptography",
    description: "Recover a telegraph operator's repeating key and decrypt a Vigenere-encrypted dispatch.",
    link: "challenge12.html",
    points: 125,
  },
  {
    title: "The First Footprint",
    id: 13,
    category: "OSINT",
    description: "Use the Internet Archive to find the earliest successful capture of a historical documentation page and recover its timestamp.",
    link: "challenge13.html",
    points: 125,
  },
  {
    title: "The Resolver's Receipt",
    id: 14,
    category: "Network Analysis",
    description: "An internal resolver returned an unusual TXT answer during a routine lookup.",
    link: "challenge14.html",
    points: 125,
  },
  {
    title: "The Duplicate Address",
    id: 15,
    category: "Network Analysis",
    description: "Two devices appear to claim the same gateway address.",
    link: "challenge15.html",
    points: 125,
  },
  {
    title: "The Crawler's Blind Spot",
    id: 16,
    category: "Web",
    description: "A public service left a crawler policy file behind.",
    link: "challenge16.html",
    points: 100,
  },
  {
    title: "The Redacted Export",
    id: 17,
    category: "Forensics",
    description: "A PDF report was visually redacted before release.",
    link: "challenge17.html",
    points: 125,
  },
  {
    title: "The Handover Call",
    id: 18,
    category: "Forensics",
    description: "A recorded handover contains keypad tones.",
    link: "challenge18.html",
    points: 125,
  },
  {
    title: "The Small Exponent",
    id: 19,
    category: "Cryptography",
    description: "A legacy RSA service used exponent 3 and a small modulus.",
    link: "challenge19.html",
    points: 150,
  },
  {
    title: "The Quiet Diagnostic",
    id: 20,
    category: "Reverse Engineering",
    description: "A Linux diagnostic utility contains an undocumented recovery mode.",
    link: "challenge20.html",
    points: 150,
  },
  {
    title: "The Orphaned Worker",
    id: 21,
    category: "Linux",
    description: "A process snapshot was recovered after a worker disappeared.",
    link: "challenge21.html",
    points: 125,
  },
  {
    title: "The Unpublished Revision",
    id: 22,
    category: "Forensics",
    description: "A portal source archive is missing its latest note.",
    link: "challenge22.html",
    points: 125,
  },
  {
    title: "The Map Left Behind",
    id: 23,
    category: "Web",
    description: "A minified portal bundle references a source map.",
    link: "challenge23.html",
    points: 125,
  },
  {
    title: "The Prefix Behind the Portal",
    id: 24,
    category: "OSINT",
    description: "An incident report lists an IP prefix and autonomous system number.",
    link: "challenge24.html",
    points: 150,
  },
  {
    title: "The Mailbox Fragment",
    id: 25,
    category: "Forensics",
    description: "A mailbox export contains routine messages and one unusual handover.",
    link: "challenge25.html",
    points: 125,
  },
  {
    title: "The Reused Pad",
    id: 26,
    category: "Cryptography",
    description: "Two messages were encrypted with the same XOR key stream.",
    link: "challenge26.html",
    points: 150,
  },
  {
    title: "The Timer's Last Tick",
    id: 27,
    category: "Linux",
    description: "A host snapshot contains systemd journal excerpts and a scheduled timer.",
    link: "challenge27.html",
    points: 125,
  },
  {
    title: "The Glass Harbor",
    id: 28,
    category: "Steganography",
    description: "A North Pier harbor recording contains a frequency pattern. View the audio spectrogram and read the 5×7 character grid from left to right.",
    link: "challenge28.html",
    points: 125,
  },
  {
    title: "The Name Before Encryption",
    id: 29,
    category: "Network Analysis",
    description: "A TLS capture was taken at the beginning of a suspicious connection.",
    link: "challenge29.html",
    points: 125,
  },
  {
    title: "The Three-Key Cabinet",
    id: 30,
    category: "Cryptography",
    description: "An escrow secret was split into five shares with a threshold of three.",
    link: "challenge30.html",
    points: 150,
  },
  {
    title: "The Logon That Stayed",
    id: 31,
    category: "Forensics",
    description: "Windows event XML exports record a successful logon and a process launch.",
    link: "challenge31.html",
    points: 125,
  },
  ...challenges032To042,
];

export function getVisibleChallenges(allChallenges = challenges, solvedIds = new Set()) {
    const rawIds = solvedIds instanceof Set ? Array.from(solvedIds) : (solvedIds || []);
    const solvedSet = new Set(rawIds.map(id => Number(id)));

    const categoryMap = new Map();
    for (const challenge of allChallenges) {
        const cat = challenge.category || "General";
        if (!categoryMap.has(cat)) {
            categoryMap.set(cat, []);
        }
        categoryMap.get(cat).push(challenge);
    }

    const visibleSet = new Set();
    for (const [, chList] of categoryMap.entries()) {
        if (!chList.length) continue;
        const firstChallenge = chList[0];
        const isCategoryUnlocked = solvedSet.has(Number(firstChallenge.id)) || chList.some(c => solvedSet.has(Number(c.id)));
        if (isCategoryUnlocked) {
            for (const ch of chList) {
                visibleSet.add(Number(ch.id));
            }
        } else {
            visibleSet.add(Number(firstChallenge.id));
        }
    }

    return allChallenges.filter(c => visibleSet.has(Number(c.id)));
}
