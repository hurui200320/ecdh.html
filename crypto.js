"use strict";
/* =====================================================================
 * ecdh.html v1 — DOM-free crypto core, shared by index.html (loaded as a
 * plain script before the UI code) and tests/crypto.test.js (required
 * directly under Node). No dependencies; everything is Web Crypto.
 *
 * Protocol: envelope bytes = 0x01 | ephPub[32] | iv[12] | AESGCM ct||tag
 *           text form      = TAG || codec(envelope bytes); tag A = base64
 *                            (planned: B = base85, a CJK tag = base4096)
 *           key = HKDF-SHA256(X25519(eph, recip), salt=ephPub||recipPub,
 *                              info="ecdh.html/v1", 32)
 * Public keys are shared as hex (0-9a-f only — IM software can mangle
 * base64's alphabet into emoji). encryptTo() takes raw plaintext bytes and
 * returns raw envelope bytes; decryptWith() takes the tagged text form and
 * returns raw plaintext bytes — the text encoding is a swappable layer.
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
function hex(u8){
  let s = "";
  for (const b of u8) s += b.toString(16).padStart(2, "0");
  return s;
}
function hexdec(str){
  const s = str.replace(/\s+/g, "");
  if (!/^(?:[0-9a-f]{2})+$/i.test(s)) throw new Error("Not a valid hex string.");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
/* Public keys travel between humans, so the string form is hex — 0-9a-f
 * only, nothing an IM can autocorrect into emoji. Canonical form is 64
 * lowercase chars; decoding also tolerates uppercase and IM line-wraps. */
function pubEnc(u8){ return hex(u8); }
function pubDec(str){
  const u = hexdec(str);
  if (u.length !== 32) throw new Error("Public key must be 64 hex chars (32 bytes).");
  return u;
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
/* The text form of an envelope is a one-char encoding tag followed by the
 * tagged codec's rendering of the envelope bytes. The tag says how the bytes
 * are spelled and is orthogonal to the version byte (0x01) inside, which says
 * what they mean. Tags are matched strictly (case-sensitive, no untagged
 * fallback); all decoders strip whitespace first (IM line-wraps). Table:
 *   A — base64, standard alphabet with padding (today's default)
 *   B — base85 (planned)      <CJK char> — base4096 (planned; the tag is
 *                               chosen from the same visual class so the
 *                               whole string blends in)
 * The null prototype keeps pasted first-chars like "constructor" from
 * resolving to inherited properties. */
const CODECS = Object.assign(Object.create(null),
  { A: { name: "base64", enc: b64enc, dec: b64dec } });
function encodeEnv(u8, tag){
  tag = tag || "A";
  const codec = CODECS[tag];
  if (!codec) throw new Error("Unknown envelope encoding tag: " + JSON.stringify(tag)
    + " — this page writes: " + Object.keys(CODECS).join(", ") + ".");
  return tag + codec.enc(u8);
}
function decodeEnv(str){
  const s = str.replace(/\s+/g, "");
  const codec = CODECS[s[0]];
  if (!codec){
    throw new Error(s
      ? "Unknown envelope encoding tag: " + JSON.stringify(s[0])
        + " — this page reads: " + Object.keys(CODECS).join(", ") + "."
      : "Envelope is empty (no encoding tag).");
  }
  try { return codec.dec(s.slice(1)); }
  catch { throw new Error("Envelope is not valid " + codec.name + "."); }
}
async function encryptTo(recipPubRaw, plaintext){
  if (!(plaintext instanceof Uint8Array))
    throw new Error("Plaintext must be raw bytes (Uint8Array) — encode text with TE.encode().");
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
    { name: "AES-GCM", iv, tagLength: 128 }, aes, plaintext));
  return cat(new Uint8Array([VER]), ephPub, iv, ct);
}
async function decryptWith(privScalar, ownPubRaw, envStr){
  const u = decodeEnv(envStr);
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
  return new Uint8Array(pt);   // raw bytes; the caller decodes the text
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
  const recPub = pubDec(rec.pub);   // hex; throws on anything else
  const derivedPub = await pubFromPriv(scalar);
  if (hex(recPub) !== hex(derivedPub))
    throw new Error("Record is internally inconsistent (pub does not match private key).");
  return {
    v: 1, type: "x25519-private", pub: pubEnc(derivedPub),
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
  module.exports = { b64enc, b64dec, hex, pubEnc, pubDec, cat, isZero, TE, TD,
    CODECS, encodeEnv, decodeEnv,
    INFO, VER, PBKDF2_ITER,
    PKCS8_X25519, X25519_BASE, EMOJI, genKeyPair, importPriv, importPub, x25519, pubFromPriv,
    hkdf32, sha256, x25519Supported, encryptTo, decryptWith, aesKeyFromPass, wrapScalar,
    unwrapScalar, recordFromImport, fpOf };
}
