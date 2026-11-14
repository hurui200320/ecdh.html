#!/usr/bin/env node
/*
 * Crypto-core cross-check for ecdh.html — no browser required.
 * Needs Node >= 18.4 (global WebCrypto with X25519).
 *
 * Requires crypto.js — the DOM-free crypto core loaded by index.html —
 * and verifies it against Node's independent OpenSSL implementation — the
 * same operations as the BouncyCastle interop recipe in README.md:
 *
 *   - raw scalar <-> key objects via the pinned DER prefixes
 *   - X25519 ECDH, HKDF-SHA-256 (salt = ephPub || recipientPub), AES-256-GCM
 *   - PBKDF2-HMAC-SHA256 passphrase wrapper (incl. the production 800k cost)
 *   - SHA-256 fingerprint and the 12-emoji (72-bit, LSB-first) mapping
 *   - import validation: pub required, verified, record canonicalized
 *   - documented failure paths: zero shared secret, tampering, wrong
 *     version, truncated/garbage input, wrong passphrase, corrupt records
 *
 * Run:  node tests/crypto.test.js
 */
"use strict";

const assert = require("assert");
const nc = require("node:crypto");

/* ---- the core, required directly (the same bytes the browser loads) ---- */
const core = require("../crypto.js");

const { b64enc, b64dec, pubEnc, pubDec, INFO, VER, PBKDF2_ITER, PKCS8_X25519, EMOJI,
        genKeyPair, importPriv, pubFromPriv, x25519Supported, encryptTo, decryptWith,
        wrapScalar, unwrapScalar, recordFromImport, fpOf } = core;

/* helper: build a wrapper record the way the app does */
async function makeRecord(priv, pub, pass, iter){
  const w = await wrapScalar(pass, priv, iter);
  return { v: 1, type: "x25519-private", pub: pubEnc(pub), kdf: "PBKDF2-HMAC-SHA256",
           iter, salt: b64enc(w.salt), cipher: "AES-256-GCM", iv: b64enc(w.iv), ct: b64enc(w.ct) };
}

(async () => {
  /* 1. key generation and the DER round-trip */
  const { priv, pub } = await genKeyPair();
  assert.strictEqual(priv.length, 32);
  assert.strictEqual(pub.length, 32);
  assert.ok(Buffer.from(await pubFromPriv(priv)).equals(Buffer.from(pub)),
    "pubFromPriv(priv) must equal the generated public key");

  const nPriv = nc.createPrivateKey({
    key: Buffer.concat([Buffer.from(PKCS8_X25519), Buffer.from(priv)]),
    format: "der", type: "pkcs8" });
  const nPubRaw = nc.createPublicKey(nPriv).export({ format: "der", type: "spki" }).slice(-32);
  assert.ok(nPubRaw.equals(Buffer.from(pub)), "OpenSSL public key must match the WebCrypto one");

  await assert.rejects(importPriv(new Uint8Array(16)), /32 bytes/, "short scalar must be rejected");

  /* 1b. public key string form: canonical lowercase hex, lenient whitespace */
  assert.ok(/^[0-9a-f]{64}$/.test(pubEnc(pub)), "pubEnc is 64 lowercase hex chars");
  assert.strictEqual(pubEnc(pub), Buffer.from(pub).toString("hex"));
  assert.ok(Buffer.from(pubDec(pubEnc(pub))).equals(Buffer.from(pub)), "hex round-trip");
  assert.ok(Buffer.from(pubDec(pubEnc(pub).toUpperCase())).equals(Buffer.from(pub)),
    "uppercase hex tolerated on input");
  assert.ok(Buffer.from(pubDec(pubEnc(pub).replace(/(.{8})/g, "$1\n"))).equals(Buffer.from(pub)),
    "IM-style line-wrapped hex tolerated on input");
  assert.throws(() => pubDec(b64enc(pub)), /hex/i, "base64 public keys are rejected");
  assert.throws(() => pubDec("zzzz"), /hex/i, "non-hex garbage is rejected");
  assert.throws(() => pubDec(pubEnc(pub).slice(0, 62)), /64 hex chars/, "wrong length is rejected");

  /* 2. envelope round-trip + byte-exact layout (0x01 | ephPub[32] | iv[12] | ct+tag) */
  const msg = "hello 你好 😀 ∑≤√ x+1=2 \n\tquotes'\"<&>";
  const env = await encryptTo(pub, msg);
  const u = b64dec(env);
  assert.strictEqual(u[0], VER, "version byte");
  assert.strictEqual(u.length, 1 + 32 + 12 + Buffer.byteLength(msg) + 16, "envelope length");
  assert.strictEqual(await decryptWith(priv, pub, env), msg, "round-trip");
  assert.strictEqual(await decryptWith(priv, pub, env.replace(/(.{20})/g, "$1\n")), msg,
    "IM-style line-wrapped envelope");
  assert.strictEqual(await decryptWith(priv, pub, await encryptTo(pub, "")), "", "empty plaintext");

  /* 3. independent OpenSSL decrypt of the envelope (spec recipe) */
  {
    const ephPub = u.slice(1, 33), iv = u.slice(33, 45), ct = u.slice(45);
    const SPKI = Buffer.from([0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x03,0x21,0x00]);
    const ephPublic = nc.createPublicKey({
      key: Buffer.concat([SPKI, Buffer.from(ephPub)]), format: "der", type: "spki" });
    const ss = nc.diffieHellman({ privateKey: nPriv, publicKey: ephPublic });
    assert.ok(!ss.every((b) => b === 0), "shared secret must not be all-zero");
    const salt = Buffer.concat([Buffer.from(ephPub), Buffer.from(pub)]);
    const key = Buffer.from(nc.hkdfSync("sha256", ss, salt, Buffer.from(INFO), 32));
    const d = nc.createDecipheriv("aes-256-gcm", key, Buffer.from(iv));
    d.setAuthTag(Buffer.from(ct.slice(-16)));
    const out = Buffer.concat([d.update(Buffer.from(ct.slice(0, -16))), d.final()]);
    assert.strictEqual(out.toString("utf8"), msg, "OpenSSL cross-decrypt must match");
  }

  /* 4. failure paths */
  await assert.rejects(encryptTo(new Uint8Array(32), "x"), /invalid|zero|agreement/i,
    "all-zero recipient key must be rejected");
  const tam = u.slice(); tam[47] ^= 0xff;
  await assert.rejects(decryptWith(priv, pub, b64enc(tam)), /Decryption failed/i);
  const wv = u.slice(); wv[0] = 2;
  await assert.rejects(decryptWith(priv, pub, b64enc(wv)), /version/i);
  await assert.rejects(decryptWith(priv, pub, "AQID"), /truncated/i);
  await assert.rejects(decryptWith(priv, pub, "!!!"), /base64/i);
  const other = await genKeyPair();
  await assert.rejects(decryptWith(other.priv, other.pub, env), /Decryption failed/i,
    "wrong recipient key must fail");

  /* 5. fingerprint = sha256 -> 72 bits -> 12 emoji, LSB-first */
  const fp = await fpOf(pub);
  const h = nc.createHash("sha256").update(Buffer.from(pub)).digest();
  assert.strictEqual(fp.hexs, h.toString("hex"), "hex fingerprint = lowercase sha256(pub)");
  let v = 0n;
  for (let i = 0; i < 9; i++) v = (v << 8n) | BigInt(h[i]);
  const exp = [];
  for (let i = 0; i < 12; i++) { exp.push(EMOJI[Number(v & 63n)]); v >>= 6n; }
  assert.strictEqual(fp.emoji, exp.join(" "), "emoji mapping matches the README formula");
  assert.strictEqual(new Set(EMOJI).size, 64, "EMOJI alphabet must have 64 distinct entries");
  assert.ok(await x25519Supported(), "X25519 must be available under test");

  /* 6. passphrase wrapper: round-trip, rejection, production KDF cost */
  const rec = await makeRecord(priv, pub, "correct horse battery staple", 1500);
  assert.ok(Buffer.from(await unwrapScalar("correct horse battery staple", rec)).equals(Buffer.from(priv)));
  await assert.rejects(unwrapScalar("wrong pass", rec), /Wrong passphrase/i);
  await assert.rejects(unwrapScalar("x", { ...rec, v: 2 }), /Not an ecdh/i);
  await assert.rejects(unwrapScalar("x", { ...rec, salt: b64enc(new Uint8Array(8)) }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, ct: b64enc(new Uint8Array(30)) }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: 0 }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, kdf: "PBKDF2-HMAC-SHA512" }), /unsupported KDF/i);
  assert.strictEqual(PBKDF2_ITER, 800000, "production iteration count is pinned");
  const big = await makeRecord(priv, pub, "another pass", PBKDF2_ITER);
  assert.ok(Buffer.from(await unwrapScalar("another pass", big)).equals(Buffer.from(priv)),
    "full-cost (800k) wrapper round-trip");

  /* OpenSSL cross-check of the wrapper: PBKDF2 + AES-GCM unwrap */
  {
    const w = await wrapScalar("cross check", priv, 1500);
    const k = nc.pbkdf2Sync("cross check", Buffer.from(w.salt), 1500, 32, "sha256");
    const d = nc.createDecipheriv("aes-256-gcm", k, Buffer.from(w.iv));
    d.setAuthTag(Buffer.from(w.ct.slice(-16)));
    const pt = Buffer.concat([d.update(Buffer.from(w.ct.slice(0, -16))), d.final()]);
    assert.ok(pt.equals(Buffer.from(priv)), "OpenSSL PBKDF2+GCM unwrap must match");
  }

  /* 7. import validation: pub required, verified, record canonicalized (hex) */
  const scalar = await unwrapScalar("correct horse battery staple", rec);
  const canon = await recordFromImport(rec, scalar);
  assert.deepStrictEqual(Object.keys(canon).sort(),
    ["cipher", "ct", "iter", "iv", "kdf", "pub", "salt", "type", "v"],
    "canonical record has exactly the spec fields");
  assert.strictEqual(canon.pub, pubEnc(pub), "canonical pub is lowercase hex");
  assert.ok(Buffer.from(pubDec(canon.pub)).equals(Buffer.from(pub)));
  await assert.rejects(recordFromImport({ ...rec, pub: undefined }, scalar), /missing the required 'pub'/i);
  await assert.rejects(recordFromImport({ ...rec, pub: pubEnc(other.pub) }, scalar), /inconsistent/i);
  await assert.rejects(recordFromImport({ ...rec, pub: b64enc(pub) }, scalar), /hex/i,
    "base64 pub fields are rejected");
  await assert.rejects(recordFromImport({ ...rec, pub: pubEnc(new Uint8Array(16)) }, scalar), /64 hex chars/);
  await assert.rejects(recordFromImport({ ...rec, pub: "!!!" }, scalar), /hex/i);
  await assert.rejects(recordFromImport(null, scalar), /Not an ecdh/i);
  const oddIter = await makeRecord(priv, pub, "odd", 1500);
  oddIter.iter = 1500.7;   // hand-edited record: importer must use/store the integer actually used
  const canonOdd = await recordFromImport(oddIter, await unwrapScalar("odd", oddIter));
  assert.strictEqual(canonOdd.iter, 1500, "iter normalized to the integer actually used");

  console.log("ALL CRYPTO-CORE CROSS-CHECKS PASSED");
})().catch((err) => { console.error("FAIL:", err && err.message ? err.message : err); process.exit(1); });
