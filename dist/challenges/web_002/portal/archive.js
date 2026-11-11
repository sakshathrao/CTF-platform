"use strict";

const COOKIE_NAME = "vault_record";
const recordRoot = "entries/";
const recordEl = document.getElementById("record");
const slotEl = document.getElementById("slotValue");

function readCookie(name) {
  const prefix = `${name}=`;
  const match = document.cookie.split(";").map(value => value.trim()).find(value => value.startsWith(prefix));
  return match ? decodeURIComponent(match.slice(prefix.length)) : null;
}

function writeCookie(name, value) {
  document.cookie = `${name}=${encodeURIComponent(value)}; Path=/; SameSite=Lax`;
}

async function loadRecord() {
  let slot = readCookie(COOKIE_NAME);
  if (slot === null) {
    slot = "0";
    writeCookie(COOKIE_NAME, slot);
  }

  slotEl.textContent = slot;

  if (!/^\d{1,2}$/.test(slot)) {
    showError("The archive slot format is invalid.");
    return;
  }

  try {
    const response = await fetch(`${recordRoot}${slot.padStart(2, "0")}.json`, { cache: "no-store" });
    if (!response.ok) {
      showError("No released record exists for this archive slot.");
      return;
    }
    const record = await response.json();
    recordEl.replaceChildren();

    const number = document.createElement("div");
    number.className = "record-number";
    number.textContent = `ENTRY ${String(record.slot).padStart(2, "0")} / ${record.classification}`;

    const title = document.createElement("h3");
    title.textContent = record.title;

    const body = document.createElement("p");
    body.textContent = record.body;

    const badge = document.createElement("span");
    badge.className = record.classification === "RESTRICTED" ? "badge restricted" : "badge";
    badge.textContent = record.status.toUpperCase();

    recordEl.append(number, title, body, badge);
  } catch (error) {
    console.error("Archive lookup failed:", error);
    showError("The archive mirror could not load this entry.");
  }
}

function showError(message) {
  recordEl.replaceChildren();
  const heading = document.createElement("h3");
  heading.textContent = "Entry unavailable";
  const body = document.createElement("p");
  body.textContent = message;
  recordEl.append(heading, body);
}

loadRecord();
