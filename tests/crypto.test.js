#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/*
 * Crypto-core cross-check for ecdh.html — no browser required.
 * Needs Node >= 20 (global WebCrypto with X25519).
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
 *   - envelope text layer: tag dispatch (A = Z85, 賒 = base4096), IM
 *     whitespace tolerance, unknown/missing tags rejected
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

const { b64enc, b64dec, z85enc, z85dec, pubEnc, pubDec, INFO, VER, PBKDF2_ITER, PKCS8_X25519, EMOJI, EMOJI_NAMES,
        B4096_TABLE, B4096_PAD1, B4096_PAD2, B4096_TAG, b4096enc, b4096dec,
        TE, TD, encodeEnv, decodeEnv, parseEnv,
        genKeyPair, importPriv, importPub, x25519, pubFromPriv, x25519Supported, encryptTo, decryptWith,
        wrapScalar, parseRecord, unwrapScalar, recordFromImport, contactsFromImport, fpOf, checkRuntime } = core;

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
  await assert.rejects(importPub(new Uint8Array(16)), /32 bytes/, "short public key must be rejected");
  await assert.rejects(x25519(new Uint8Array(16), pub), /32 bytes/, "x25519 rejects short scalar before deriveBits");
  await assert.rejects(x25519(priv, new Uint8Array(16)), /32 bytes/, "x25519 rejects short public key before deriveBits");
  await assert.rejects(encryptTo(new Uint8Array(16), new Uint8Array(4)), /32 bytes/, "encryptTo rejects short recipient key before deriveBits");

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
  const env = await encryptTo(pub, TE.encode(msg));   // raw bytes in, raw bytes out
  const u = env;
  assert.strictEqual(u[0], VER, "version byte");
  assert.strictEqual(u.length, 1 + 32 + 12 + Buffer.byteLength(msg) + 16, "envelope length");
  assert.strictEqual(TD.decode(await decryptWith(priv, pub, encodeEnv(env))), msg, "round-trip");
  assert.strictEqual(
    TD.decode(await decryptWith(priv, pub, encodeEnv(env).replace(/(.{20})/g, "$1\n"))), msg,
    "IM-style line-wrapped envelope");
  assert.strictEqual(
    TD.decode(await decryptWith(priv, pub, encodeEnv(await encryptTo(pub, new Uint8Array(0))))),
    "", "empty plaintext");
  assert.strictEqual(
    TD.decode(await decryptWith(priv, pub, encodeEnv(await encryptTo(pub, TE.encode("\uFEFFhello"))))),
    "\uFEFFhello", "leading UTF-8 BOM is preserved");

  /* 2b. envelope text layer: TAG || codec(envelope bytes) */
  const envStr = encodeEnv(env);
  assert.ok(envStr.startsWith("A") && envStr.slice(1) === z85enc(env),
    "envelopes are tagged 'A' + canonical Z85");
  assert.ok(Buffer.from(decodeEnv(envStr)).equals(Buffer.from(env)), "tag round-trip");
  assert.ok(Buffer.from(decodeEnv("A\n" + z85enc(env))).equals(Buffer.from(env)),
    "tag may be split from its payload by an IM line-wrap");
  assert.ok(Buffer.from(decodeEnv(" " + envStr.replace(/(.{20})/g, "$1\n"))).equals(Buffer.from(env)),
    "leading whitespace + wrapped payload tolerated");
  assert.throws(() => decodeEnv("a" + z85enc(env)), /tag/i, "tags are case-sensitive");
  assert.throws(() => decodeEnv("Z" + z85enc(env)), /tag/i, "unknown tag is rejected");
  assert.throws(() => decodeEnv("😀" + z85enc(env)), /"😀"/, "non-BMP unknown tag formats full codepoint");
  assert.throws(() => decodeEnv(""), /empty/i, "empty input is rejected");
  assert.throws(() => decodeEnv('A""'), /not valid Z85.*alphabet/i, "bad payload under a valid tag includes codec reason");
  assert.throws(() => decodeEnv("A#####"), /not valid Z85.*32 bits/i, "5-char group decoding above 32 bits is rejected");
  assert.throws(() => decodeEnv("A0"), /not valid Z85.*1-char tail/i, "a lone tail char is never valid");
  assert.throws(() => encodeEnv(env, "Z"), /tag/i, "unknown tag on encode");
  const parsedEnv = parseEnv(envStr);
  assert.strictEqual(parsedEnv.ephPub.length, 32, "parseEnv extracts 32-byte ephPub");
  assert.strictEqual(parsedEnv.iv.length, 12, "parseEnv extracts 12-byte iv");
  assert.throws(() => parseEnv(encodeEnv(env.slice(0, 40))), /truncated/i, "parseEnv rejects truncated envelope");

  /* 2c. Z85 codec: spec vector, tails, strictness, independent cross-check */
  // Vector from the ZeroMQ Z85 spec: 0x864FD26FB559F75B <-> "HelloWorld".
  const spec = new Uint8Array([0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b]);
  assert.strictEqual(z85enc(spec), "HelloWorld", "Z85 spec vector (encode)");
  assert.ok(Buffer.from(z85dec("HelloWorld")).equals(Buffer.from(spec)), "Z85 spec vector (decode)");
  // Tails (hand-checked): r trailing bytes -> r+1 chars.
  assert.strictEqual(z85enc(new Uint8Array([1])), "0r", "1-byte tail");
  assert.strictEqual(z85enc(new Uint8Array([1, 2])), "0rJ", "2-byte tail");
  assert.strictEqual(z85enc(new Uint8Array([1, 2, 3])), "0rJu", "3-byte tail");
  assert.throws(() => z85dec("0s"), /canonical/i, "1-byte Z85 tail with padding bits set is rejected");
  assert.throws(() => z85dec("0rK"), /canonical/i, "2-byte Z85 tail with padding bits set is rejected");
  assert.throws(() => z85dec("0rJv"), /canonical/i, "3-byte Z85 tail with padding bits set is rejected");
  assert.throws(() => z85dec("~~"), /alphabet/i, "chars outside the alphabet are rejected");
  // Cross-check against an independent BigInt implementation, every tail
  // shape plus random bulk data, and round-trip each.
  const refZ85enc = (u8) => {
    const A = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    let out = "";
    for (let i = 0; i < u8.length; i += 4){
      const take = Math.min(4, u8.length - i);
      let v = 0n;
      for (let j = 0; j < 4; j++) v = (v << 8n) | BigInt(j < take ? u8[i + j] : 0);
      const ds = [];
      for (let d = 0; d < 5; d++){ ds.unshift(A[Number(v % 85n)]); v /= 85n; }
      out += ds.slice(0, take + 1).join("");
    }
    return out;
  };
  for (let len = 0; len <= 64; len++){
    const raw = new Uint8Array(nc.randomBytes(len));
    const s = z85enc(raw);
    assert.strictEqual(s, refZ85enc(raw), "matches the BigInt reference at length " + len);
    assert.ok(Buffer.from(z85dec(s)).equals(Buffer.from(raw)), "round-trip at length " + len);
  }
  for (const fill of [0x00, 0xff]){
    for (let len = 1; len <= 8; len++){
      const raw = new Uint8Array(len).fill(fill);
      const s = z85enc(raw);
      assert.strictEqual(s, refZ85enc(raw), "boundary fill " + fill + " matches reference at length " + len);
      assert.ok(Buffer.from(z85dec(s)).equals(Buffer.from(raw)), "boundary fill " + fill + " round-trip at length " + len);
    }
  }
  const bulk = new Uint8Array(nc.randomBytes(4096));
  assert.ok(Buffer.from(z85dec(z85enc(bulk))).equals(Buffer.from(bulk)), "4 KiB round-trip");
  assert.ok(Buffer.from(decodeEnv("A" + z85enc(env).replace(/(.{20})/g, "$1 "))).equals(Buffer.from(env)),
    "Z85 tolerates stripped IM whitespace");

  /* 2d. base4096 codec (tag 賒): table invariants, spec vectors, tails,
   *     strictness, cross-codec equality */
  assert.strictEqual(B4096_TABLE.length, 4096, "table has 4096 digits");
  assert.strictEqual(new Set(B4096_TABLE).size, 4096, "digits are unique");
  let bAsc = true;
  for (let i = 1; i < 4096; i++)
    if (B4096_TABLE.codePointAt(i) <= B4096_TABLE.codePointAt(i - 1)) bAsc = false;
  assert.ok(bAsc, "digits strictly ascending by codepoint");
  for (const ch of B4096_TABLE){
    const cp = ch.codePointAt(0);
    assert.ok(cp >= 0x4e00 && cp <= 0x9fa6, "digit inside the CJK BMP block");
  }
  const bCtrl = [B4096_PAD1, B4096_PAD2, B4096_TAG];
  assert.strictEqual(new Set(bCtrl).size, 3, "PAD/TAG chars are distinct");
  for (const ch of bCtrl)
    assert.ok(!B4096_TABLE.includes(ch), "control char is not a digit: " + ch);
  // Spec vectors (README documents the same): [01 02 03] -> 圼嶖; tails carry
  // an explicit PAD marker: [01] -> 圼賐, [01 02] -> 圼嶒賑.
  assert.strictEqual(b4096enc(new Uint8Array([0x01, 0x02, 0x03])), "圼嶖", "base4096 spec vector");
  assert.strictEqual(b4096enc(new Uint8Array([0x01])), "圼賐", "1-byte tail = digit + PAD1");
  assert.strictEqual(b4096enc(new Uint8Array([0x01, 0x02])), "圼嶒賑", "2-byte tail = 2 digits + PAD2");
  assert.ok(Buffer.from(b4096dec("圼嶖")).equals(Buffer.from([1, 2, 3])), "vector decodes");
  assert.strictEqual(b4096dec("").length, 0, "empty payload decodes empty");
  // Round-trips across every tail shape plus bulk data.
  for (const len of [0, 1, 2, 3, 4, 5, 44, 45, 46, 47, 160, 161, 162, 255, 4096]){
    const raw = new Uint8Array(nc.randomBytes(len));
    assert.ok(Buffer.from(b4096dec(b4096enc(raw))).equals(Buffer.from(raw)),
      "base4096 round-trip at length " + len);
  }
  // Envelope-level: the 賒 tag dispatches to base4096 and whitespace survives.
  const env4096 = encodeEnv(env, B4096_TAG);
  assert.ok(env4096.startsWith(B4096_TAG), "envelope tagged 賒");
  assert.ok(Buffer.from(decodeEnv(env4096.replace(/(.{20})/g, "$1\n"))).equals(Buffer.from(env)),
    "base4096 tolerates stripped IM whitespace");
  // The same envelope bytes through either codec decrypt to the same text.
  assert.strictEqual(
    TD.decode(await decryptWith(priv, pub, encodeEnv(env, "A"))),
    TD.decode(await decryptWith(priv, pub, env4096)),
    "Z85 and base4096 carry identical bytes");
  // Strictness: bad lengths, stray PAD markers, non-canonical padding bits.
  assert.throws(() => b4096dec("圼"), /length/i,
    "odd digit count without a PAD marker is rejected");
  assert.throws(() => b4096dec(B4096_PAD1), /length/i,
    "lone PAD1 without a preceding digit is rejected");
  assert.throws(() => b4096dec("圼" + B4096_PAD2), /length/i,
    "1 digit before PAD2 (needs 2 digits) is rejected");
  assert.throws(() => b4096dec("圼賐圼嶖"), /alphabet/i,
    "a PAD marker inside the payload is not a digit");
  assert.throws(() => b4096dec(B4096_TABLE[17] + B4096_PAD1), /canonical/i,
    "1-byte tail with padding bits set is rejected");
  assert.throws(() => b4096dec(B4096_TABLE[16] + B4096_TABLE[255] + B4096_PAD2), /canonical/i,
    "2-byte tail with padding bits set is rejected");
  assert.throws(() => decodeEnv(B4096_TAG + "圼"), /not valid base4096.*length/i,
    "decodeEnv wraps codec failures under the 賒 tag with reason");
  // Charset property: none of these common simplified/traditional sensitive
  // words can be spelled with table digits (every char of each is excluded
  // from the table by construction).
  for (const w of ["共产党", "资本主义", "翻墙", "色情", "赌博", "毒品", "强奸", "炸弹",
                   "選舉", "獨立", "輿論", "顛覆"])
    for (const ch of w)
      assert.ok(!B4096_TABLE.includes(ch), "table excludes chars of " + w);

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
  await assert.rejects(x25519(priv, new Uint8Array(32)), /invalid|zero|agreement/i,
    "x25519 rejects all-zero public key directly");
  await assert.rejects(encryptTo(new Uint8Array(32), "x"), /raw bytes|Uint8Array/i,
    "plaintext must be raw bytes, not a string");
  await assert.rejects(encryptTo(new Uint8Array(32), new Uint8Array(4)), /invalid|zero|agreement/i,
    "all-zero recipient key must be rejected");
  await assert.rejects(decryptWith(priv, pubEnc(pub), encodeEnv(env)), /32 bytes/i,
    "decryptWith rejects string ownPubRaw");
  await assert.rejects(decryptWith(priv, new Uint8Array(16), encodeEnv(env)), /32 bytes/i,
    "decryptWith rejects short ownPubRaw");
  const zeroEphEnv = new Uint8Array(1 + 32 + 12 + 16);
  zeroEphEnv[0] = VER;
  await assert.rejects(decryptWith(priv, pub, encodeEnv(zeroEphEnv)), /invalid|zero|agreement/i,
    "all-zero ephemeral sender key must be rejected");
  const tam = u.slice(); tam[47] ^= 0xff;
  await assert.rejects(decryptWith(priv, pub, encodeEnv(tam)), /Decryption failed/i);
  const wv = u.slice(); wv[0] = 2;
  await assert.rejects(decryptWith(priv, pub, encodeEnv(wv)), /version/i);
  await assert.rejects(decryptWith(priv, pub, encodeEnv(u.slice(0, 40))), /truncated/i);
  await assert.rejects(decryptWith(priv, pub, "AQID"), /truncated|not valid Z85/i,
    "tagless old-style string parses as tag 'A' + short payload, then fails cleanly");
  const other = await genKeyPair();
  await assert.rejects(decryptWith(other.priv, other.pub, encodeEnv(env)), /Decryption failed/i,
    "wrong recipient key must fail");

  /* 5. fingerprint = sha256 -> 72 bits -> 12 emoji + English names, LSB-first */
  const fp = await fpOf(pub);
  const h = nc.createHash("sha256").update(Buffer.from(pub)).digest();
  assert.strictEqual(fp.hexs, h.toString("hex"), "hex fingerprint = lowercase sha256(pub)");
  let v = 0n;
  for (let i = 0; i < 9; i++) v = (v << 8n) | BigInt(h[i]);
  const exp = [], expNames = [], expItems = [];
  for (let i = 0; i < 12; i++) {
    const idx = Number(v & 63n);
    exp.push(EMOJI[idx]);
    expNames.push(EMOJI_NAMES[idx]);
    expItems.push({ emoji: EMOJI[idx], name: EMOJI_NAMES[idx] });
    v >>= 6n;
  }
  assert.strictEqual(fp.emoji, exp.join(" "), "emoji mapping matches the README formula");
  assert.deepStrictEqual(fp.names, expNames, "emoji names match the 12 indices");
  assert.deepStrictEqual(fp.items, expItems, "emoji items pair each emoji with its English name");
  assert.strictEqual(new Set(EMOJI).size, 64, "EMOJI alphabet must have 64 distinct entries");
  assert.strictEqual(EMOJI_NAMES.length, 64, "EMOJI_NAMES must have 64 entries");
  assert.strictEqual(new Set(EMOJI_NAMES.map(s => s.toLowerCase())).size, 64, "EMOJI_NAMES must have 64 distinct entries");
  assert.ok(EMOJI_NAMES.every(s => typeof s === "string" && /^[A-Z][a-z]+$/.test(s)), "every emoji name is a non-empty capitalized word");
  const zeroFp = await fpOf(new Uint8Array(32));
  assert.strictEqual(zeroFp.emoji, "🌲 🦁 🎩 🌋 🐙 🌊 🎵 🐯 🥑 🌊 🐰 🧊", "all-zero pub emoji vector");
  assert.deepStrictEqual(zeroFp.names,
    ["Pine", "Lion", "Hat", "Volcano", "Octopus", "Wave", "Music", "Tiger", "Avocado", "Wave", "Rabbit", "Ice"],
    "all-zero pub emoji names vector");
  assert.ok(await x25519Supported(), "X25519 must be available under test");

  /* 6. passphrase wrapper: round-trip, rejection, production KDF cost */
  const rec = await makeRecord(priv, pub, "correct horse battery staple", 1500);
  assert.ok(Buffer.from(await unwrapScalar("correct horse battery staple", rec)).equals(Buffer.from(priv)));
  await assert.rejects(unwrapScalar("wrong pass", rec), /Wrong passphrase/i);
  await assert.rejects(unwrapScalar("x", null), /Not an ecdh/i);
  await assert.rejects(unwrapScalar("x", "not-an-object"), /Not an ecdh/i);
  await assert.rejects(unwrapScalar("x", { ...rec, v: 2 }), /Not an ecdh/i);
  await assert.rejects(unwrapScalar("x", { ...rec, salt: b64enc(new Uint8Array(8)) }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, ct: b64enc(new Uint8Array(30)) }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: 0 }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: -100 }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: true }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: 100000001 }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, iter: 4294967297 }), /bad field sizes/i);
  await assert.rejects(unwrapScalar("x", { ...rec, salt: 123 }), /bad base64/i);
  await assert.rejects(wrapScalar("", priv, 1500), /non-empty string/i);
  await assert.rejects(wrapScalar(null, priv, 1500), /non-empty string/i);
  await assert.rejects(wrapScalar("pass", new Uint8Array(16), 1500), /32 bytes/i);
  await assert.rejects(wrapScalar("pass", priv, 0), /iteration/i);
  await assert.rejects(wrapScalar("pass", priv, 1500.5), /iteration/i);
  await assert.rejects(wrapScalar("pass", priv, 100000001), /iteration/i);
  await assert.rejects(unwrapScalar("x", { ...rec, kdf: "PBKDF2-HMAC-SHA512" }), /unsupported KDF/i);
  assert.strictEqual(PBKDF2_ITER, 800000, "production iteration count is pinned");
  const big = await makeRecord(priv, pub, "another pass", PBKDF2_ITER);
  assert.ok(Buffer.from(await unwrapScalar("another pass", big)).equals(Buffer.from(priv)),
    "full-cost (800k) wrapper round-trip");

  /* OpenSSL cross-check of the wrapper: PBKDF2 (UTF-8 passphrase) + AES-GCM unwrap */
  for (const pass of ["cross check", "口令 🔑 café"]){
    const w = await wrapScalar(pass, priv, 1500);
    const k = nc.pbkdf2Sync(Buffer.from(pass, "utf8"), Buffer.from(w.salt), 1500, 32, "sha256");
    const d = nc.createDecipheriv("aes-256-gcm", k, Buffer.from(w.iv));
    d.setAuthTag(Buffer.from(w.ct.slice(-16)));
    const pt = Buffer.concat([d.update(Buffer.from(w.ct.slice(0, -16))), d.final()]);
    assert.ok(pt.equals(Buffer.from(priv)), "OpenSSL PBKDF2+GCM unwrap must match for passphrase: " + pass);
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
  await assert.rejects(recordFromImport({ ...rec, v: 2 }, scalar), /Not an ecdh/i);
  await assert.rejects(recordFromImport({ ...rec, kdf: "scrypt" }, scalar), /unsupported KDF/i);
  const spacedRec = { ...rec, salt: " " + rec.salt + "\n", iv: " " + rec.iv };
  const canonSpaced = await recordFromImport(spacedRec, scalar);
  assert.strictEqual(canonSpaced.salt, rec.salt, "recordFromImport canonicalizes base64 salt");
  assert.strictEqual(canonSpaced.iv, rec.iv, "recordFromImport canonicalizes base64 iv");
  const oddIter = await makeRecord(priv, pub, "odd", 1500);
  oddIter.iter = 1500.7;   // hand-edited record: importer must use/store the integer actually used
  const canonOdd = await recordFromImport(oddIter, await unwrapScalar("odd", oddIter));
  assert.strictEqual(canonOdd.iter, 1500, "iter normalized to the integer actually used");

  /* 8. contact list import validation: {name, pub} / {name, publicKey} */
  const cList = contactsFromImport([
    { name: "  Alice ", pub: pubEnc(pub).toUpperCase() },
    { name: "", publicKey: pubEnc(other.pub) },
    { name: "Alice Renamed", pub: pubEnc(pub) },   // duplicate pub updates in place
  ]);
  assert.deepStrictEqual(cList, [
    { name: "Alice Renamed", pub: pubEnc(pub) },
    { name: "friend", pub: pubEnc(other.pub) },
  ], "contactsFromImport canonicalizes hex, trims names, defaults empty name, and deduplicates by pub");
  assert.throws(() => contactsFromImport([]), /non-empty/i);
  assert.throws(() => contactsFromImport({}), /non-empty/i);
  assert.throws(() => contactsFromImport([null]), /not an object/i);
  assert.throws(() => contactsFromImport([{ name: "Bob" }]), /missing a 'pub'/i);
  assert.throws(() => contactsFromImport([{ name: "Bob", pub: "not-hex" }]), /invalid hex/i);

  /* 9. runtime WebView / browser detection */
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
    null, "standard desktop Chrome passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0"),
    null, "standard desktop Edge passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"),
    null, "standard Firefox passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"),
    null, "standard macOS Safari passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"),
    null, "standard iOS Safari passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/133.0.0.0 Mobile/15E148 Safari/604.1"),
    null, "standard iOS Chrome passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", { navigator: { standalone: true } }),
    null, "installed iOS Home Screen PWA passes");
  assert.strictEqual(
    checkRuntime("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)", { navigator: { standalone: true } }),
    null, "installed iPadOS Home Screen PWA passes");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UQ1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.0.0 Mobile Safari/537.36 MicroMessenger/8.0.50"),
    { kind: "webview", label: "WeChat in-app WebView" }, "WeChat UA detected");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (X11; Linux x86_64) Chrome/133.0.0.0", { WeixinJSBridge: {} }),
    { kind: "webview", label: "WeChat in-app WebView" }, "WeChat global bridge detected even if UA is spoofed");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1", { TelegramWebviewProxy: {} }),
    { kind: "webview", label: "Telegram in-app WebView" }, "Telegram WebView global proxy detected");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UQ1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/133.0.0.0 Mobile Safari/537.36"),
    { kind: "webview", label: "Android in-app WebView" }, "generic Android WebView (; wv) detected");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148"),
    { kind: "webview", label: "iOS in-app WebView" }, "generic iOS WKWebView (missing Safari/) detected");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 UCBrowser/16.0.0"),
    { kind: "browser", label: "UC Browser" }, "iOS third-party browser detected specifically before generic WKWebView rule");
  assert.deepStrictEqual(
    checkRuntime("Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 QQBrowser/11.9.0"),
    { kind: "browser", label: "QQ Browser" }, "QQ Browser detected despite Chrome/Safari tokens");
  assert.deepStrictEqual(
    checkRuntime("CustomAgent/1.0"),
    { kind: "browser", label: "unrecognized browser" }, "unknown user agent flagged");

  console.log("ALL CRYPTO-CORE CROSS-CHECKS PASSED");
})().catch((err) => { console.error("FAIL:", err && err.message ? err.message : err); process.exit(1); });
