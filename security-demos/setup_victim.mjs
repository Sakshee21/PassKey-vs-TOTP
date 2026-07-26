// Provisions a throwaway, FULLY-registered victim account for attack_sim.py
// to target. This is Node/Puppeteer (not Python) because registration's
// third step is a real WebAuthn ceremony, which only a browser can perform -
// attack_sim.py itself never touches passkeys at all, it only needs an
// account where is_fully_registered is already true so /totp/verify will
// actually hand out a password_token instead of bouncing to "finish signing
// up first".
//
// Usage:
//   node setup_victim.mjs [--base-url http://localhost:5173] [--out victim.json]
//
// Always prints the result JSON to stdout. With --out, ALSO writes it to that
// path itself via fs.writeFileSync (plain UTF-8, no BOM) - use --out rather
// than shell redirection (`> victim.json`): PowerShell's `>` writes UTF-16,
// which silently produces a file attack_sim.py's `--from-file` can't parse.
// Requires: npm install puppeteer-core   (and a local Chrome/Chromium install)

import crypto from "node:crypto";
import fs from "node:fs";
import puppeteer from "puppeteer-core";

const VICTIM_PASSWORD = "Summer2024!"; // must match an entry in common_passwords.txt

function findChrome() {
  const candidates = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
  ];
  for (const path of candidates) {
    if (fs.existsSync(path)) return path;
  }
  return candidates[0];
}

function base32Decode(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of base32.replace(/=+$/, "")) {
    const val = alphabet.indexOf(char.toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substring(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totpCode(secretBase32) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  return ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1e6).toString().padStart(6, "0");
}
async function clickText(page, text) {
  const clicked = await page.evaluate((t) => {
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === t);
    if (!btn) return false;
    btn.click();
    return true;
  }, text);
  if (!clicked) throw new Error(`button not found: ${text}`);
}

const baseUrlArgIndex = process.argv.indexOf("--base-url");
const baseUrl = baseUrlArgIndex !== -1 ? process.argv[baseUrlArgIndex + 1] : "http://localhost:5173";
const outArgIndex = process.argv.indexOf("--out");
const outPath = outArgIndex !== -1 ? process.argv[outArgIndex + 1] : null;

const browser = await puppeteer.launch({
  executablePath: findChrome(),
  headless: true,
  args: ["--window-size=520,900"],
});
const page = await browser.newPage();
await page.setViewport({ width: 520, height: 900 });

let capturedSecret = null;
page.on("response", async (response) => {
  if (response.url().endsWith("/register/totp/setup")) {
    try {
      capturedSecret = (await response.json()).secret;
    } catch {
      /* ignore */
    }
  }
});

const client = await page.target().createCDPSession();
await client.send("WebAuthn.enable");
await client.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

const email = `attack-sim-victim-${Date.now()}@example.com`;

await page.goto(baseUrl, { waitUntil: "networkidle0" });
await clickText(page, "Register");
await page.type('input[type="email"]', email, { delay: 5 });
await page.type('input[type="password"]', VICTIM_PASSWORD, { delay: 5 });
await clickText(page, "Continue");
await page.waitForSelector('img[alt="TOTP QR code"]', { timeout: 10000 });
await page.type('input[inputmode="numeric"]', totpCode(capturedSecret), { delay: 10 });
await clickText(page, "Confirm code");
await page.waitForFunction(() => document.body.innerText.includes("backup codes"), {
  timeout: 10000,
});
await clickText(page, "I've saved my backup codes — continue");
await page.waitForFunction(() => document.body.innerText.includes("Register passkey"), {
  timeout: 10000,
});
await clickText(page, "Register passkey");
await page.waitForFunction(() => document.body.innerText.includes("Welcome back"), {
  timeout: 15000,
});
await clickText(page, "Log out");
await page.waitForFunction(() => document.body.innerText.includes("Sign in"), { timeout: 10000 });

await browser.close();

const result = JSON.stringify({ email, password: VICTIM_PASSWORD, totp_secret: capturedSecret }, null, 2);
console.log(result);
if (outPath) {
  fs.writeFileSync(outPath, result, "utf8");
  console.error(`(also wrote ${outPath} as plain UTF-8)`);
}
