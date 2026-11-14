# ecdh.html

A simple and static web page for you and your average friend who not care
about security to share secrets safely (to some level) over a untrusted channel.

This is a tiny static site that you host yourself for exchanging encrypted text over
distrusted channels. No CDN, no libraries, no backend, no telemetry — every byte
served comes out of this repo.

> LLM usage: I use LLM to implement all the html, js and css.
> I have reviewed the outcome and decided to trust the artifacts.

**Cryptography:** per-message ephemeral X25519 (ECIES-style) → HKDF-SHA-256 →
AES-256-GCM. Browsers do all of it natively via Web Crypto.

**Designed use case:** the trusted channel dies (for example, server get blocked).
You and your friends still have *some* internet — an IM, an email, a pastebin —
but assume that channel is tapped, stored, and actively rewritable. This tool
turns that channel back into a confidential one by moving base64 blobs through
it. Nothing else.

> Special note: This system need another hard to tamper channel to setup.
> It's recommended to setup and share the keys over a trusted channel,
> or at least something like a voice call (which is hard to temper).

---

## Threat model

### The system in one sentence

Friends agree (out of band) to exchange ciphertext via whatever unsafe channel
still works; each side holds a passphrase-wrapped private key on their own
device. **Trust anchors are exactly two things:** (1) the code file you run, and
(2) public keys verified once out-of-band. Everything in between — the IM, the
mail provider, whoever taps the wire — is assumed able to read, store, replay,
and rewrite everything it carries.

> In another words, if your server/host get hacked and backdoor is planted,
> this system cannot protect you. And if you got MITM attack when you exchange
> public keys, this system cannot detect impersonated identities. You must verify
> the one who gives you public key is the actual person you're expecting.
> And if the user's device has been compromised, this system can't protect either.

### Actors

| Actor | Assumption |
|---|---|
| Passive eavesdropper on the unsafe channel | Present (that's the premise) |
| The unsafe channel itself (IM/email software, provider) | Hostile: may read, tamper with, or substitute anything, incl. the HTML file if sent through it |
| Endpoint malware on your device | Accepted risk (see below) |
| Nation-state with zero-days, active MITM, deepfaked voice | **Out of scope — see escalation** |

### Protected

| Asset | Protection |
|---|---|
| Message contents vs tapped/monitored channels | X25519 ECDH + AES-256-GCM, fresh key per message |
| Tampered or forged ciphertext | GCM tag — any modification = failed decryption |
| Key-substitution MITM (fake public keys) | Fingerprint voice-verification ceremony + all-zero shared-secret rejection |
| Private key at rest (device storage **and** backup file) | Mandatory passphrase wrap: PBKDF2-HMAC-SHA256 (800k iter) + AES-256-GCM |
| Availability during an emergency | Static files only; offline PWA cache; a saved copy works from `file://`; decryption needs zero server involvement |
| Interop with your own trusted tools | Byte-exact spec below, implementable in BouncyCastle in an afternoon |

### Consciously NOT protected

| Risk | Why accepted |
|---|---|
| **Sender impersonation** — anyone who has your public key can send you a message that decrypts | The operational protocol (voice-agreed usage windows + fingerprints) covers it. Real per-sender auth requires Ed25519 signatures, aka double key management per person. This is a simple tool for average people who doesn't care security. If both parties are psecurity focused, go use something like GPG and signal-based protocol. |
| Replay / reordering of genuinely old messages | Humans have conversational context; timestamps/CSPRNG nonces add trust in something unverifiable anyway |
| Traffic analysis (who, when, how much) — blobs are visibly blobs | Steganography is a different project |
| Endpoint compromise *while using the tool* | A keylogger beats any passphrase. The wrap protects at-rest artifacts only |
| Forward secrecy against later key theft (ECIES to a static recipient key) | Mitigated by wrap quality + wipe discipline. Ratchets (Signal-style) = 10× the complexity — that's what Signal is for, and is hard to implement as serverless static html website. Usual key management principles applies here. Rotate your keys periodically. |
| Automated sync / push / multi-device | Manual copy-paste is dumb, portable, and hard to break. Recovery = restore backup file |
| Forgotten passphrase = key and all its messages lost forever | By design; there is no escrow. Store the passphrase somewhere survivable (password manager, paper) |
| Offline brute-force of the passphrase wrap | No rate limiting exists offline — PBKDF2 slows it, **passphrase quality is the actual defense**. Use 4+ random words. Also reduce exposure of the backup file, and rotate your keys periodically. |

### The voice ceremony (the human half, ~10 seconds)

> This ceremony assumes you lost all trust channel and has to establish
> the key exchange over a untrusted channel. Usually, realtime voice chat
> let you verify your friend's identity and is hard to tamper (but might be
> recorded or monitored).

1. On a calm day, over a **hard-to-tamper channel** (voice call), agree to use
   the system, what for, and roughly when ("if the group dies, we coordinate
   here").
2. Each person opens the page **on their own device** and reads the
   **12-emoji fingerprint** shown under their own public key.
3. The other party checks it against the fingerprint displayed for that contact
   in their saved contacts. Verify in **both directions**.
4. Unexpected encrypted blobs outside an agreed window (or from unknown
   fingerprints after re-shares) are treated with suspicion — that's the soft
   sender-authentication.
5. Never delegate the comparison. If verification is impossible, treat
   confidentiality as intact but **sender/receiver identity as unknown**.

The fingerprint needs ~72 bits because brute-forcing a shorter one is offline
and unlimited: 4 emoji (24 bits) ≈ minutes on a laptop; 12 emoji (72 bits) is
beyond anything in this threat model. Never shrink it.

### Escalation line (decided in advance)

If the adversary budget grows — targeted nation-state, zero-days, deepfake
voice — **stop using this tool** and move to Signal-protocol implementations,
GPG over a verified web of trust, or in person. This tool's honest niche:
censorship-tolerant, dependency-free, human-ceremony emergency comms.

### Design decisions log

| Decision | Rationale |
|---|---|
| Per-message ephemeral X25519 (ECIES) | Fresh AES key per message → no IV-reuse hazard; sender retains nothing; receiver's public key is the only pre-shared material |
| HKDF-SHA-256 between ECDH and AES | Domain separation; ~3 lines; standard in BC |
| Envelope carries ephemeral pub + IV | Receiver needs zero sender state |
| Mandatory passphrase on stored key | Wrong passphrase is cleanly detectable via GCM auth failure |
| Export/import = the same wrapped record | One format, one code path; backup is ciphertext everywhere it rests; servers/apps that grab the file get noise |
| Fingerprint = SHA-256 → 72 bits → 12 emoji (+ full hex) | Readable aloud; 24-bit fingerprints are brute-forceable (see above) |
| No sender signatures | Operational convention instead (ceremony step 4) |
| No replay/timestamps, no AAD | See not-protected table; simplicity is a security feature in a rarely-used emergency tool |
| Offline PWA + `file://` capability | Emergencies + hosting-seizure tolerance; hosts only distribute the files |
| No test vectors embedded | The byte-exact spec below + DER constants are the interop contract |

---

## Protocol v1 (byte-exact)

All base64 is standard alphabet **with padding**. All "raw" X25519 keys are the
usual 32-byte little-endian u-coordinate strings — identical bytes in Web
Crypto, BouncyCastle, and libsodium.

### Envelope

```
envelope = base64( 0x01 | ephPub[32] | iv[12] | ciphertext )
```

- `0x01` — version byte
- `ephPub` — public key of a **per-message ephemeral** X25519 keypair,
  generated at encrypt time and immediately discarded (the private half never
  leaves that one click)
- `iv` — 12 uniform random bytes
- `ciphertext` — AES-256-GCM of the UTF-8 plaintext; 128-bit tag appended
  (Web Crypto and BC JCE both append the tag at the end)
- No AAD
- The receiver reconstructs: `ephPub` from the envelope, their own public key
  from their stored record

### Key derivation

```
ss  = X25519(ephPriv, recipientPub)          // 32 bytes
if ss == all zeros: REJECT (invalid/crafted public key)
key = HKDF-SHA256(ikm = ss,
                  salt = ephPub || recipientPub,   // 64 bytes
                  info = UTF-8("ecdh.html/v1"),
                  L = 32)
```

### Public key fingerprint

Canonical form: lowercase hex of **SHA-256(public key)**, all 32 digest bytes —
use this for cross-implementation comparison. The page additionally renders the
first 72 bits as 12 emoji (6 bits each, taken from the least-significant end,
fixed 64-emoji alphabet) for reading aloud.

Chunk order, spelled out for implementers: let `v` be the 72-bit big-endian
integer built from digest bytes 0–8; then twelve times: `emoji[i] =
ALPHABET[v mod 64]`, `v = floor(v / 64)`. The **leftmost** emoji carries the
*least*-significant 6 bits. `ALPHABET` is the `EMOJI` array in `crypto.js`,
in source order.

Test vector: the 32-byte all-zero public key hashes to
`66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`;
its 12-emoji fingerprint renders as
`🌲 🦁 🎩 🌋 🐙 🌊 🎵 🐯 🥑 🌊 🐰 🧊`.

### Private key wrapper (single format: localStorage *and* backup file)

```json
{
  "v": 1,
  "type": "x25519-private",
  "pub":   "<b64, raw 32-byte public key, plaintext field>",
  "kdf":   "PBKDF2-HMAC-SHA256",
  "iter":  800000,
  "salt":  "<b64, 16 bytes>",
  "cipher":"AES-256-GCM",
  "iv":    "<b64, 12 bytes>",
  "ct":    "<b64, AES-GCM of the raw 32-byte private scalar + 16-byte tag>"
}
```

- AES key = PBKDF2-HMAC-SHA256(passphrase, salt, iter) — importers honor the
  `iter` in the record rather than assuming
- `pub` is required and verified against the private scalar on import
- localStorage keys: `ecdh.key.v1` (this record), `ecdh.contacts.v1`
  (`[{"name","pub"}]`), `ecdh.lastcontact.v1`

### BouncyCastle interop — the constants you need

- Raw scalar ↔ key objects via fixed DER prefixes:
  - PKCS#8 X25519 private: `302e020100300506032b656e04220420 || raw32`
  - SPKI X25519 public: `302a300506032b656e032100 || raw32`
- DH: `new X25519PrivateKeyParameters(scalar, 0)` → `X25519Agreement`
  (agreement is 32 bytes, little-endian — identical to WebCrypto `deriveBits`)
- HKDF: `HKDFBytesGenerator(new SHA256Digest())` with
  `HKDFParameters(ikm, salt, info)`, `generateBytes(out, 0, 32)`
- PBKDF2: JCE `PBKDF2WithHmacSHA256` (`SecretKeyFactory`), 32 bytes of key
  material, or BC `PKCS5S2ParametersGenerator(new SHA256Digest())`
- AES-GCM: JCE `Cipher.getInstance("AES/GCM/NoPadding")` +
  `GCMParameterSpec(128, iv)` — BC appends the tag at the end, same as Web
  Crypto
- X25519 clamping is part of the scalar multiplication in every
  implementation — export/import of raw scalars needs no special handling

---

## Operational runbook

### Calm-day setup (once per person)

1. Deploy (below), and **save copies of `index.html` and `crypto.js` (same
   folder)** on your devices/drives — a saved pair is a full offline-capable
   instance. Optionally record the SHA-256 of `index.html` and `crypto.js`
   on paper next to your fingerprints.
2. Generate your identity with a **strong passphrase** (4+ random words).
3. **Export the backup JSON** and keep it somewhere survivable (email it to
   yourself, USB stick, password manager attachment — it's ciphertext; its
   safety = passphrase strength).
4. Voice ceremony with each contact (§ ceremony), add each other's public
   keys as named contacts.
5. Make sure your passphrase is recoverable somewhere. Losing it = losing every
   message ever sent to that key. There is no reset-without-loss.

### Emergency send

Open the page (offline/cached/saved copy all fine) → pick the contact →
type → Encrypt → copy the envelope → send it through *any* channel.

### Emergency receive

Paste envelope → passphrase → read. Plaintext is never stored; screenshot what
you must, then clear.

### Device loss / new device

Setup → Restore from backup: paste the exported JSON + passphrase → your
identity (and its fingerprint) are back, no re-verification ceremony needed.

If you have the spare time, rotate your keys and repeat the ceremony with your
friends.

### Compromise / rotation

Wipe key → generate → **re-run the voice ceremony** → peers delete the old
contact and add the new one.

---

## Deployment

| File | Purpose |
|---|---|
| `index.html` | The app — UI + inline CSS; loads `crypto.js` |
| `crypto.js` | DOM-free crypto core (X25519/HKDF/AES-GCM/PBKDF2/fingerprints), also used by the Node test |
| `sw.js` | Cache-first service worker (offline) |
| `manifest.json` | Minimal PWA manifest |
| `icon.svg` | Icon |
| `tests/` | Crypto-core cross-check harness (Node, no browser) |

- **HTTPS (or localhost) is mandatory.** Browsers expose Web Crypto
  (`crypto.subtle`) only in secure contexts. Serving over plain `http://` on a
  LAN IP silently disables everything — the page will tell you. Use a reverse
  proxy with TLS, or open locally.
- `file://` counts as a secure context: a USB-stick copy works fully offline
  (service worker simply doesn't apply there, and isn't needed).
- Browser support = everything evergreen since ~2024–2025 (X25519 in Web
  Crypto: Chrome/Edge 133+, Firefox 129+, Safari 17+). The page feature-detects
  and refuses politely.
- After editing any file, bump the `CACHE` version string in `sw.js` so
  returning clients update; the envelope/record version bytes keep old
  messages/keys valid across UI changes.
- iOS note: Safari may evict PWA storage after ~a week of non-use — another
  reason the export backup habit matters.

## Testing

Local smoke test:

```bash
python3 -m http.server 8000
# open http://localhost:8000  (localhost = secure context)
```

Crypto-core cross-check (no browser needed; Node >= 18.4 for X25519):

```bash
node tests/crypto.test.js
```

Loads `crypto.js` (the DOM-free crypto core the page loads) and verifies the DER
prefixes, envelope layout, HKDF derivation, PBKDF2 wrapper, and emoji
fingerprints against Node's independent OpenSSL implementation (the same
operations as the BouncyCastle recipe above), plus the documented failure
paths: zero shared secret, tampered ciphertext, wrong version byte,
truncated/garbage input, wrong passphrase, inconsistent records.

Validated in headless Chromium via Playwright:

- Page boots behind plain HTTP on a LAN IP → Web Crypto banner, buttons
  disabled (env: localhost works, `file://` works)
- Keypair generation; storage wrap (PBKDF2 800k + AES-GCM); 44-char pubkey;
  12-emoji + hex fingerprint rendered
- Contact add with live fingerprint preview; fingerprint deterministic across
  views; contact removal
- Encrypt → decrypt roundtrip with full unicode payload (emoji, CJK, math
  glyphs), envelope pasted with IM-style line wrapping
- Envelope layout asserted byte-exact: `0x01 | ephPub[32] | iv[12] | ct+tag`
- Wrong passphrase → clean error; tampered ciphertext → GCM auth failure;
  unknown version byte → rejected; garbage input → rejected
- Backup record → wipe (two-click confirm) → restore → same pubkey → the
  pre-backup envelope still decrypts
- Passphrase change: re-wrapped ct/salt, pub preserved, new pass works, old
  pass rejected
- Reload after any of the above: identity found, app functional

Two robustness fixes came out of testing and are already in the code:

1. **Boot never awaits service worker registration** — a hung/slow
   registration used to stall the default-tab selection. Registration is now
   fire-and-forget, so offline support can only ever *add* functionality.
2. **Invalid public-key errors are mapped** — Chromium rejects small-order
   points (e.g. all-zero public key) with an empty error message from
   `deriveBits`; Firefox instead returns an all-zero shared secret. Both paths
   now produce a clear "zero shared secret" error instead of a blank failure.

A later review pass hardened the implementation further (no wire-format or
record-format changes): import enforces the spec's mandatory `pub` field and
stores a canonical record; boot probes X25519 support separately from the
secure-context check; the ephemeral send key never leaves WebCrypto in raw
form; storage failures surface with explicit recovery guidance; the last-used
contact is tracked by public key instead of display name; compose and decrypt
hygiene controls are symmetric.

Caveat for the record: this headless environment's service-worker machinery
was wedged (the `register()` promise never resolves — happens *before* any of
our code installs; sw.js serves fine). So the SW itself is validated
structurally, not end-to-end here. **Post-deploy checklist:** load the page
once over HTTPS, go offline, reload — confirm the app shell comes from the SW
cache on your actual host. Everything else works regardless.

---

*Spec versions in play: envelope `0x01`, wrapper `v:1`, storage keys `.v1`,
SW cache `v1`. Change any byte-level behavior = bump everything under it and
document here.*
