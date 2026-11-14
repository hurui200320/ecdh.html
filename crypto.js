"use strict";
/* =====================================================================
 * ecdh.html v1 — DOM-free crypto core, shared by index.html (loaded as a
 * plain script before the UI code) and tests/crypto.test.js (required
 * directly under Node). No dependencies; everything is Web Crypto.
 *
 * Protocol: envelope = base64(0x01 | ephPub[32] | iv[12] | AESGCM ct||tag)
 *           key = HKDF-SHA256(X25519(eph, recip), salt=ephPub||recipPub,
 *                              info="ecdh.html/v1", 32)
 * See README.md for the pinned threat model and byte-exact spec.
 * ===================================================================== */

/* ---------- tiny format helpers ---------- */
function b64enc(u8){
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}
function b64dec(str){
  const clean = str.replace(/\s+/g, "");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64decSafe(str){
  const u = b64dec(str);
  if (u.length !== 32) throw new Error("Expected 32 bytes after base64 decoding.");
  return u;
}
function hex(u8){
  let s = "";
  for (const b of u8) s += b.toString(16).padStart(2, "0");
  return s;
}
function cat(...arrs){
  const n = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs){ out.set(a, o); o += a.length; }
  return out;
}
function isZero(u8){ for (const b of u8) if (b) return false; return true; }
const TE = new TextEncoder();
const TD = new TextDecoder();

/* ---------- crypto core ---------- */
const INFO = TE.encode("ecdh.html/v1");
const VER = 1;
const PBKDF2_ITER = 800000;

// DER wrappers so raw 32-byte X25519 keys go through WebCrypto untouched.
const PKCS8_X25519 = new Uint8Array(
  [0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20]);
const X25519_BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })(); // u=9

async function genKeyPair(){
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pk8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  if (pk8.length !== 48) throw new Error("Unexpected private key encoding.");
  return { priv: pk8.slice(16), pub };
}
async function importPriv(rawScalar){
  if (rawScalar.length !== 32) throw new Error("Private scalar must be exactly 32 bytes.");
  return crypto.subtle.importKey("pkcs8", cat(PKCS8_X25519, rawScalar),
    { name: "X25519" }, false, ["deriveBits"]);
}
async function importPub(raw){
  if (raw.length !== 32) throw new Error("Public key must be exactly 32 bytes.");
  return crypto.subtle.importKey("raw", raw, { name: "X25519" }, false, []);
}
async function x25519(privScalar, peerPubRaw){
  let out;
  try {
    out = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPub(peerPubRaw) },
      await importPriv(privScalar), 256));
  } catch {
    // Some backends (e.g. Chromium) reject small-order/invalid points with an
    // empty error; Firefox returns an all-zero secret instead (caught below).
    throw new Error("Key agreement failed — invalid key material (backend rejected a key, or all-zero shared secret).");
  }
  if (out.length !== 32) throw new Error("Unexpected shared secret length.");
  return out;
}
async function pubFromPriv(scalar){ return x25519(scalar, X25519_BASE); }
async function hkdf32(ikm, salt){
  const km = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: INFO }, km, 256));
}
async function sha256(bytes){
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
async function x25519Supported(){
  try {
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch { return false; }
}

/* ---------- messages (envelope v1) ---------- */
async function encryptTo(recipPubRaw, text){
  // Ephemeral keypair stays non-extractable inside WebCrypto: the private
  // scalar is never exported, imported, or visible to page script.
  const kp = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const ephPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  let ss;
  try {
    ss = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPub(recipPubRaw) }, kp.privateKey, 256));
  } catch {
    // Same small-order/invalid-point quirk as x25519() above.
    throw new Error("Key agreement failed — invalid key material (backend rejected a key, or all-zero shared secret).");
  }
  if (isZero(ss)) throw new Error("Recipient public key is invalid (zero shared secret).");
  const key = await hkdf32(ss, cat(ephPub, recipPubRaw));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aes = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 }, aes, TE.encode(text)));
  return b64enc(cat(new Uint8Array([VER]), ephPub, iv, ct));
}
async function decryptWith(privScalar, ownPubRaw, envStr){
  let u;
  try { u = b64dec(envStr); }
  catch { throw new Error("Envelope is not valid base64."); }
  if (u.length < 1 + 32 + 12 + 16) throw new Error("Envelope is truncated or malformed.");
  if (u[0] !== VER) throw new Error("Unknown envelope version: " + u[0] + " — this page only reads v1.");
  const ephPub = u.slice(1, 33);
  const iv = u.slice(33, 45);
  const ct = u.slice(45);
  const ss = await x25519(privScalar, ephPub);
  if (isZero(ss)) throw new Error("Envelope's sender key is invalid (zero shared secret).");
  const key = await hkdf32(ss, cat(ephPub, ownPubRaw));
  let pt;
  try {
    const aes = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
    pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, aes, ct);
  } catch {
    throw new Error("Decryption failed — wrong key, or envelope was tampered with.");
  }
  return TD.decode(pt);
}

/* ---------- passphrase wrapper (storage + export use the same record) ---------- */
async function aesKeyFromPass(pass, salt, iter, usages){
  const base = await crypto.subtle.importKey("raw", TE.encode(pass), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, base,
    { name: "AES-GCM", length: 256 }, false, usages);
}
async function wrapScalar(pass, scalar, iter){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await aesKeyFromPass(pass, salt, iter, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, k, scalar));
  return { salt, iv, ct };
}
async function unwrapScalar(pass, rec){
  if (rec.v !== 1 || rec.type !== "x25519-private") throw new Error("Not an ecdh.html v1 key record.");
  if (rec.kdf !== "PBKDF2-HMAC-SHA256" || rec.cipher !== "AES-256-GCM")
    throw new Error("Record uses an unsupported KDF/cipher.");
  let salt, iv, ct, iter;
  try {
    salt = b64dec(rec.salt); iv = b64dec(rec.iv); ct = b64dec(rec.ct);
    iter = rec.iter | 0;
  } catch { throw new Error("Record is corrupted (bad base64 fields)."); }
  if (salt.length !== 16 || iv.length !== 12 || ct.length !== 48 || !(iter > 0))
    throw new Error("Record is corrupted (bad field sizes).");
  let pt;
  try {
    const k = await aesKeyFromPass(pass, salt, iter, ["decrypt"]);
    pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, k, ct));
  } catch { throw new Error("Wrong passphrase or corrupted record."); }
  if (pt.length !== 32) throw new Error("Record is corrupted (bad plaintext size).");
  return pt;
}

/* Import-side validation: the spec requires the pub field, verified against
 * the private scalar. Returns the canonical record to store/export (extra
 * fields dropped, iter normalized to the integer actually used). */
async function recordFromImport(rec, scalar){
  if (!rec || typeof rec !== "object") throw new Error("Not an ecdh.html v1 key record.");
  if (typeof rec.pub !== "string") throw new Error("Record is missing the required 'pub' field.");
  const recPub = b64decSafe(rec.pub);
  const derivedPub = await pubFromPriv(scalar);
  if (hex(recPub) !== hex(derivedPub))
    throw new Error("Record is internally inconsistent (pub does not match private key).");
  return {
    v: 1, type: "x25519-private", pub: b64enc(derivedPub),
    kdf: rec.kdf, iter: rec.iter | 0, cipher: rec.cipher,
    salt: rec.salt, iv: rec.iv, ct: rec.ct,
  };
}

/* ---------- fingerprints: sha256 -> 72 bits -> 12 emoji ---------- */
const EMOJI = ["🍎","🍌","🐻","🐝","🚲","🐦","⛵","🎂","🐱","🌵","🐊","🌙","☕","🎲","🐬","🥚",
  "🐘","👀","🦊","🐸","🍇","🎸","🐹","🎩","🏠","🧊","🧥","🪁","🍋","🦁","🥭","🎵",
  "🐭","🌊","🐙","🦉","🐧","🍕","🐰","🚀","🐑","🐌","🌻","🐯","🌲","🦄","🎻",
  "🌋","🍉","🐋","🦓","⚓","🍺","🧲","🌽","🍯","🐍","🌴","🥑","🐛","🥨","🦇","🍁","🐢"];
async function fpOf(pubRaw){
  const d = await sha256(pubRaw);
  let v = 0n;
  for (let i = 0; i < 9; i++) v = (v << 8n) | BigInt(d[i]);
  const em = [];
  for (let i = 0; i < 12; i++){ em.push(EMOJI[Number(v & 63n)]); v >>= 6n; }
  return { emoji: em.join(" "), hexs: hex(d) };
}

/* Node export for the test harness; inert in the browser. */
if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
  module.exports = { b64enc, b64dec, b64decSafe, hex, cat, isZero, INFO, VER, PBKDF2_ITER,
    PKCS8_X25519, X25519_BASE, EMOJI, genKeyPair, importPriv, importPub, x25519, pubFromPriv,
    hkdf32, sha256, x25519Supported, encryptTo, decryptWith, aesKeyFromPass, wrapScalar,
    unwrapScalar, recordFromImport, fpOf };
}
