export const challenges = [
    {
        title: "Challenge 1",
        id: 1,
        category: "Web",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge1.html",
        points: 10
    },

    {
        title: "Challenge 2",
        id: 2,
        category: "Web",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge2.html",
        points: 10
    },

    {
        title: "Challenge 3",
        id: 3,
        category: "Crypto",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge3.html",
        points: 10
    },

    {
        title: "Challenge 4",
        id: 4,
        category: "Crypto",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge4.html",
        points: 10
    },

    {
        title: "Challenge 5",
        id: 5,
        category: "Forensics",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge5.html",
        points: 10
    },

    {
        title: "Challenge 6",
        id: 6,
        category: "Forensics",
        description:
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident.",
        link: "challenge6.html",
        points: 10
    }
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
        const solvedCount = chList.filter(c => solvedSet.has(Number(c.id))).length;
        const countToShow = Math.min(chList.length, 1 + solvedCount);
        for (let i = 0; i < countToShow; i++) {
            visibleSet.add(Number(chList[i].id));
        }
    }

    return allChallenges.filter(c => visibleSet.has(Number(c.id)));
}
