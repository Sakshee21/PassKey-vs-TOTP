// Captures ONE real, validly-signed WebAuthn authentication assertion by
// actually driving a passkey registration + login through a real browser
// (Chrome via CDP, with a virtual authenticator standing in for a real
// security key/platform authenticator - py_webauthn has no client-side
// simulator, only a browser/authenticator can produce a genuine signature).
//
// This is the "attacker" side of the origin-binding proof: it captures
// exactly what a network-level eavesdropper (or a malicious relying party
// the user was tricked into visiting) would see. verify_origin_binding.py
// then takes this SAME captured assertion and shows py_webauthn's real
// verification function accepts it for the origin it was signed for, and
// rejects it for any other - no bypass to find, that's the point.
//
// Usage:
//   node capture_assertion.mjs [--base-url http://localhost:5173] [--out captured_assertion.json]
//
// Always prints the result JSON to stdout. With --out, ALSO writes it to that
// path itself via fs.writeFileSync (plain UTF-8, no BOM) - use --out rather
// than shell redirection (`> captured_assertion.json`): PowerShell's `>`
// writes UTF-16, which silently produces a file verify_origin_binding.py
// can't parse.
//
// Requires: npm install puppeteer-core (and a local Chrome/Chromium install)

import crypto from "node:crypto";
import fs from "node:fs";
import puppeteer from "puppeteer-core";

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

let capturedTotpSecret = null;
let capturedOptions = null; // the /webauthn/authenticate/options response body
let capturedVerifyBody = null; // the {email, credential} POSTed to /webauthn/authenticate/verify

page.on("response", async (response) => {
  const url = response.url();
  if (url.endsWith("/register/totp/setup")) {
    try {
      capturedTotpSecret = (await response.json()).secret;
    } catch {
      /* ignore */
    }
  }
  if (url.endsWith("/webauthn/authenticate/options")) {
    try {
      capturedOptions = await response.json();
    } catch {
      /* ignore */
    }
  }
});
page.on("request", (request) => {
  if (request.url().endsWith("/webauthn/authenticate/verify")) {
    try {
      capturedVerifyBody = JSON.parse(request.postData());
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

const email = `origin-proof-${Date.now()}@example.com`;
const password = "TestPass123!";

await page.goto(baseUrl, { waitUntil: "networkidle0" });
await clickText(page, "Register");
await page.type('input[type="email"]', email, { delay: 5 });
await page.type('input[type="password"]', password, { delay: 5 });
await clickText(page, "Continue");
await page.waitForSelector('img[alt="TOTP QR code"]', { timeout: 10000 });
await page.type('input[inputmode="numeric"]', totpCode(capturedTotpSecret), { delay: 10 });
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

// --- Now the actual authentication ceremony we're capturing ---
const realOrigin = await page.evaluate(() => window.location.origin);
await page.type('input[type="email"]', email, { delay: 5 });
await clickText(page, "Sign in with passkey");
await page.waitForFunction(() => document.body.innerText.includes("Welcome back"), {
  timeout: 15000,
});

await browser.close();

if (!capturedOptions || !capturedVerifyBody) {
  console.error("Failed to capture the authentication ceremony - re-run.");
  process.exit(1);
}

const output = {
  origin: realOrigin,
  rp_id: capturedOptions.rpId,
  challenge_b64url: capturedOptions.challenge,
  email: capturedVerifyBody.email,
  credential: capturedVerifyBody.credential,
};

const result = JSON.stringify(output, null, 2);
console.log(result);
if (outPath) {
  fs.writeFileSync(outPath, result, "utf8");
  console.error(`(also wrote ${outPath} as plain UTF-8)`);
}
