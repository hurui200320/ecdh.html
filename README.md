# ecdh.html

A simple and static web page for you and your average friend (who doesn't care about security) to share secrets safely (to some level) over an untrusted channel.

Live at: https://ecdh-html.pages.dev (hosted by Cloudflare pages)

There is no CDN, no third-party library, no backend, and no telemetry. Every byte served comes directly from this repository, and all cryptographic operations run natively in the browser via the Web Crypto API:

- **Key exchange & encryption:** Per-message ephemeral X25519 (ECIES-style) → HKDF-SHA-256 → AES-256-GCM
- **At-rest key protection:** PBKDF2-HMAC-SHA256 (800,000 iterations) → AES-256-GCM

**Intended use case:** Your trusted communication channel goes down (for example, your private server gets blocked). You and your friends still have *some* way to exchange text — an instant messenger, email, or a pastebin — but you have to assume that channel is monitored, logged, and actively tampered with. This tool turns that untrusted channel back into a confidential one by passing only hex public keys and tagged ciphertext envelopes (encoded in CJK base4096 or Z85) through it.

> **Important:** Setting up this system requires an initial channel that is difficult to tamper with. You should exchange and verify public keys over a trusted channel beforehand, or at least verify key fingerprints over a real-time voice call, where active tampering is much harder to pull off.

---

## LLM Usage

All of the HTML, JavaScript, and CSS in this repository were written with the help of an LLM. I have personally reviewed the generated code and decided to trust the resulting files.

---

## Threat Model

This section explains what `ecdh.html` protects against and where its limits are, so you can decide **when to use it and when NOT to use it**.

### How the system works in one paragraph

Friends agree out of band to exchange encrypted text over whatever untrusted channel still works, while each person keeps a passphrase-wrapped private key on their own device. Everything in between — the messaging app, the email provider, or anyone tapping the network — is assumed to be able to read, store, replay, and modify every message it carries.

**Your security rests on three core assumptions:**

1. **The code you run is authentic.** If the server hosting this page is compromised and a backdoor is planted, this system cannot protect you. (Downloading a clean local copy of `index.html` and `crypto.js` from [this GitHub repository](https://github.com/hurui200320/ecdh.html) in advance avoids this risk.)
2. **Public keys are verified out of band.** If an attacker substitutes a fake public key during setup (a man-in-the-middle attack), the cryptography alone cannot tell you that you are talking to an impostor. You must verify that the public key actually belongs to your friend.
3. **Your device, browser runtime, and input path are not compromised.** If you open the page inside a chat app's built-in browser/WebView, run browser extensions or userscripts (such as Tampermonkey, translation plugins, or AI sidebars) that read page content, or have spyware, a cloud-connected third-party keyboard (IME), or a background clipboard monitor running, browser-side encryption cannot protect you.

### When to use this tool (and when NOT to)

**Use this tool when:**
- Your normal encrypted or private channels are blocked or unavailable, leaving only monitored or filtered text channels (domestic IMs, email, forums).
- The people you are communicating with want something simple that runs in a standard browser without installing command-line tools or managing complex keyrings.
- You can verify each other's 12-emoji key fingerprint over a real-time voice call (or in person) before relying on the channel.

**Do NOT use this tool when:**
- **Both parties are comfortable with dedicated security tools.** If everyone involved is willing to use **Signal-based protocol** or **GPG**, use those instead — they provide stronger guarantees like forward secrecy and cryptographic sender authentication.
- **You face a high-budget or nation-state adversary.** If your threat model includes device zero-days, active real-time MITM attacks accompanied by live voice deepfakes, or targeted endpoint compromise, **stop using this tool** and move to Signal-protocol apps, GPG with a verified web of trust, or in-person communication.

### Threat actors

| Actor | Assumption |
|---|---|
| Passive eavesdropper on the communication channel | Present (this is the baseline assumption). |
| The communication channel itself (IM/email app or provider) | Hostile: may log, censor, modify, or replace anything sent through it — including the HTML/JS files if distributed over that channel. |
| Malware on your device | Accepted risk (see below). |
| Targeted nation-state (zero-days, active MITM with voice deepfakes) | **Out of scope** (see *When NOT to use this tool* above). |

### What is protected

| Asset | How it is protected |
|---|---|
| Message confidentiality over monitored channels | Ephemeral X25519 ECDH + HKDF-SHA-256 + AES-256-GCM, using a fresh keypair for every message. |
| Tampered or forged ciphertext | AES-GCM authentication tag; any modification causes decryption to fail cleanly. |
| Key-substitution MITM (fake public keys) | Out-of-band 12-emoji fingerprint verification + automatic rejection of all-zero shared secrets. |
| Private key at rest (in `localStorage` and backup files) | Mandatory passphrase encryption using PBKDF2-HMAC-SHA256 (800,000 iterations) + AES-256-GCM. |
| Availability during an outage | Pure static files with an offline PWA service worker; saved copies also run directly from `file://` with zero server involvement. |
| Long-term interoperability | Byte-exact protocol specification below, easy to reimplement with standard libraries like BouncyCastle or OpenSSL. |

### What is consciously NOT protected

| Risk | Why it is accepted & how to mitigate it |
|---|---|
| **Sender impersonation** (anyone who knows your public key can send you a valid encrypted message) | Cryptographic sender authentication requires per-sender signing keys (e.g., Ed25519), which doubles the key-management burden. Since this is a lightweight tool for non-technical friends, sender authenticity relies on human context (agreed communication windows and verified contacts). If you need strict sender authentication, use GPG or Signal. |
| **Forward secrecy against later key compromise** | Messages are encrypted to a static recipient public key (ECIES). Stateful ratchets (like Signal's Double Ratchet) are far too complex and fragile for a stateless copy-paste web page. Protect your key with a strong passphrase, keep backups limited, and **rotate your keys periodically**. |
| **Offline brute-force of a stolen key backup** | Offline attackers have no rate limit. PBKDF2 (800,000 iterations) slows down guessing, but **passphrase strength is your real defense**. Use at least 4 random words, minimize where your backup file is stored, and **rotate keys periodically**. |
| **Replay or reordering of old messages** | An attacker on the channel can re-send a previously captured message. Humans already have conversational context, whereas unauthenticated timestamps or nonces add complexity without real security. |
| **Traffic analysis and exact plaintext length leakage** | Even when encoded as archaic CJK characters (base4096) to bypass keyword filters, ciphertexts are still recognizable as encoded blocks. In addition, **messages are not padded before encryption** (the binary envelope is always `61 + UTF-8 byte length of plaintext` bytes), so an observer can tell the exact byte length of the plaintext (for example, distinguishing `"no"` from `"yes"`). When sending short or predictable replies, manually add filler text or vary your phrasing. |
| **Plaintext metadata at rest (`localStorage` and contact exports) and `file://` storage sharing** | While your private scalar is passphrase-encrypted, **your own public key (`pub` inside `ecdh.key.v1`), your saved contacts' names and public keys (`ecdh.contacts.v1`), and the last selected contact (`ecdh.lastcontact.v1`) are stored in plaintext** so the UI can display identities and fingerprints without prompting for your passphrase on startup. Anyone inspecting your device's browser storage can see your contact list and link your device to public keys seen on the channel. In addition, **Chromium-based browsers (Chrome, Edge, Brave) share a single `localStorage` bucket across all `file://` pages on disk** — opening an untrusted downloaded `.html` file in the same browser profile could read your storage or silently replace a saved contact's public key. When running from `file://` in Chrome/Edge, use a dedicated browser profile and never open downloaded `.html` files in it (or use Firefox or a local `localhost` server). Use non-identifying nicknames if needed, and check **Also wipe all saved contacts** in the Danger zone when clearing a device. |
| **In-app browsers (WebViews), cloud browsers, and extensions/userscripts** | Tapping a link inside an instant messenger or social app (WeChat, QQ, DingTalk, Weibo, Telegram, etc.) usually opens it in the app's **built-in WebView**, where the host app has full control over the DOM, can inject JavaScript to steal your passphrase or plaintext, and may wipe `localStorage` at any time. Likewise, third-party "cloud-accelerated" browsers and browser extensions/userscripts with page access (such as **Tampermonkey**, auto-translate plugins, grammar checkers, or AI sidebars) can read or modify everything on the page. The page displays a warning banner if it detects an in-app WebView or non-standard browser, but **always open the page in standalone Firefox, Chrome, Edge, or Safari**, and **disable extensions on this site** (or use a clean browser profile). |
| **Cloud keyboards (IMEs) and clipboard managers** | Many mobile and desktop input methods (especially cloud-connected CJK IMEs) upload typed phrases to remote servers for predictive text. Likewise, copying decrypted plaintext or passphrases exposes them to OS clipboard history, cloud clipboard sync (such as Universal Clipboard or Windows Cloud Clipboard), and background apps that read the clipboard on focus. Browser crypto cannot protect data before it enters or after it leaves the page: **use your OS's built-in offline keyboard**, and **read decrypted messages on screen rather than copying plaintext to the clipboard**. |
| **Endpoint compromise while using the tool** | A keylogger or screen capture tool defeats any passphrase. Passphrase wrapping only protects keys while at rest. |
| **Forgotten passphrase** | By design, there is no key escrow or password reset. Losing your passphrase means permanently losing your key and all messages encrypted to it. Store your passphrase somewhere durable (such as a password manager or on paper). |
| **Automated multi-device sync or push notifications** | Manual copy-paste is simple, portable, and hard to break. To move to another device, export and import your encrypted key backup JSON (and optionally your contacts JSON). |

---

## Deployment and Usage

### Files in this repository

| File | Purpose |
|---|---|
| `index.html` | The application UI and inline CSS; loads `crypto.js`. |
| `crypto.js` | DOM-free cryptographic core (X25519, HKDF, AES-GCM, PBKDF2, codecs, fingerprints), shared with the Node test suite. |
| `sw.js` | Cache-first service worker for offline use. |
| `manifest.json` | Minimal PWA web app manifest. |
| `icon.svg` | Application icon. |
| `_headers` | HTTP security headers for Cloudflare Pages (`frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, etc.). |
| `tests/` | Automated Node.js test suite cross-checking `crypto.js` against OpenSSL and verifying static asset integrity. |

### Deployment notes

- **HTTPS or `localhost` is required when serving over a network.** Browsers only expose Web Crypto (`crypto.subtle`) in secure contexts. Opening the site over plain `http://` on a LAN IP will disable Web Crypto (the page will display a banner explaining why). Put it behind a TLS reverse proxy or open it on `localhost`.
- **Recommended HTTP headers when hosting:** `index.html` already includes a strict `<meta http-equiv="Content-Security-Policy">` (`default-src 'none'`, SHA-256 hash-pinned inline script, blocking network exfiltration and `eval()`), `<meta name="referrer" content="no-referrer">`, `translate="no"`, and a startup check that refuses to run inside an `<iframe>`. `_headers` configures Cloudflare Pages to send `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and a restrictive `Permissions-Policy`; configure the same headers on your own reverse proxy when self-hosting. *(Note: if you also set a full `Content-Security-Policy` via HTTP headers, do not apply `connect-src 'none'` to `sw.js`, since the service worker fetches same-origin assets during cache installation.)*
- **Local `file://` copies work offline (with a `localStorage` caveat in Chromium).** Browsers treat `file://` as a secure context, so downloading raw `index.html` and `crypto.js` from [this GitHub repository](https://github.com/hurui200320/ecdh.html) into the same folder on a USB drive or local disk gives you a fully functional offline copy without any web server. However, **Chromium-based browsers (Chrome, Edge, Brave) share one `localStorage` bucket across all `file://` pages on the filesystem** — opening any untrusted downloaded `.html` file in the same browser profile could read or overwrite your saved contacts and encrypted key record. The page displays a warning banner when opened via `file://`; if you use `file://` in Chrome/Edge, use a dedicated browser profile where you never open downloaded `.html` files, use Firefox (which partitions `file://` storage), or serve the folder over `http://localhost:8000` (see below). (Also, do **not** use the browser's *Save Page As* menu while using the app — see *Initial setup* below.)
- **Browser requirements:** Use a standard standalone browser with X25519 support in Web Crypto (**Chrome/Edge 133+, Firefox 130+, or Safari 18.4+ / iOS 18.4+**). On startup, the page checks for Web Crypto/X25519 support and also inspects the runtime environment—displaying a warning banner if opened inside an in-app WebView (such as WeChat, QQ, DingTalk, Weibo, Xiaohongshu, Bilibili, Zhihu, Taobao/Alibaba, or generic Android/iOS WebViews) or a non-standard/cloud browser.
- **Updating a hosted deployment:** If you edit any file, increment the `CACHE` version string in `sw.js` so returning browsers pick up the new assets (and if you edit the inline `<script>` in `index.html`, update its `'sha256-...'` CSP hash — `node tests/crypto.test.js` verifies this and prints the expected hash). After deploying over HTTPS, load the page once, switch to offline mode, and reload to confirm the service worker serves the cached app shell.
- **iOS Safari caveat:** Safari may clear PWA storage after roughly a week of inactivity — always export and keep a copy of your backup JSON.

To run locally for testing:

```bash
python3 -m http.server 8000 --bind 127.0.0.1
# Open http://localhost:8000 in your browser
```

To run the automated cryptographic test suite (requires Node.js >= 20):

```bash
node tests/crypto.test.js
```

### Usage guide

#### 1. Initial setup (do this on a calm day)

1. **Download a clean local copy:** Alongside using a hosted URL, download the raw `index.html` and `crypto.js` files from [this GitHub repository](https://github.com/hurui200320/ecdh.html) (or download the repository ZIP) and keep them in the same folder on your devices. Optionally write down their SHA-256 hashes on paper next to your contacts' fingerprints. When opening a local `file://` copy in Chrome or Edge, use a dedicated browser profile and never open untrusted downloaded `.html` files in that profile (or use Firefox or `http://localhost:8000`).
   > **Avoid "Save Page As" (`Ctrl+S` / `Cmd+S`) in your browser:** *Webpage, Complete* rewrites the `<script src="crypto.js">` path into a subfolder and serializes the **live DOM state** into the saved HTML file (which can accidentally bake your public key, saved contacts, or even currently displayed plaintext right into the file on disk), while *Webpage, HTML Only* omits `crypto.js` so the page will not work offline.
2. **Generate your keypair:** Open the page in standalone Firefox, Chrome, Edge, or Safari (never inside a chat app's built-in WebView, and with extensions like Tampermonkey or translation plugins disabled), and choose a **strong passphrase** (at least 4 random words) using your OS's built-in offline keyboard.
3. **Export your key backup JSON:** Save the exported JSON (`ecdh-backup-YYYYMMDD.json`) somewhere durable (email it to yourself, store it on a USB stick, or attach it to a password manager). Because the private key inside is encrypted, its safety matches the strength of your passphrase.
4. **Exchange, verify, and optionally export contacts:** Share public keys with your friends, complete the voice verification ceremony below, and save each friend as a named contact. You can also export your contact list (`ecdh-contacts-YYYYMMDD.json`) from the **Encrypt** tab under **Export / import contacts**. *(Note: unlike the key backup, the contacts JSON is unencrypted plaintext — store it somewhere trusted so an attacker cannot swap a public key inside the file.)*
5. **Keep your passphrase safe:** If you forget your passphrase, neither your key nor any messages sent to it can ever be recovered.

#### 2. The voice verification ceremony (~10 seconds)

> Ideally, exchange public keys while you still have a trusted channel. If all trusted channels are already gone and you have to pass public keys over an untrusted channel, verify them over a **real-time voice call**. A voice call may be monitored or recorded, but tampering with a live friend's voice in real time is much harder.

1. Over a voice call, agree on when and how you will use this system (for example: *"If our group chat gets shut down, we'll coordinate here"*).
2. Each person opens the page **on their own device** and reads aloud the **12-emoji fingerprint** (using the English label shown under each emoji) displayed beneath their own public key.
3. The other person checks those 12 emojis against the fingerprint shown for that contact on their screen. Verify in **both directions**.
4. Treat unexpected encrypted messages outside agreed times (or from unverified keys) with suspicion — this operational check is what substitutes for cryptographic sender signatures.
5. Never skip or delegate the fingerprint check. If you cannot verify a key's fingerprint, messages remain confidential against passive eavesdroppers, but **you have no guarantee of who sits on the other end**.

#### 3. Sending a message

Open the page (from the host, offline cache, or local `file://` copy) → select the recipient from your contacts → type your message → choose an output encoding → click **Encrypt** → copy the generated envelope and send it over *any* available channel.

**Choosing between the two encodings:**
- **CJK base4096 (default, tag `賒`) — best when the channel limits by *character count*:** Turns 100 bytes into ~67 Chinese characters. Although each CJK character takes 3 bytes in UTF-8 (~200 bytes total), many instant messengers enforce message limits by character count rather than byte size — counting each Chinese character as just 1 character. It also uses archaic characters that cannot form common words, avoiding naive keyword filters.
- **Z85 (tag `A`) — best when the channel limits by *byte size* (or is ASCII-only):** Turns 100 bytes into 125 ASCII characters (125 bytes in UTF-8), improving on standard Base64 (which produces ~133 characters per 100 bytes).

Pick whichever encoding fits your channel's rules; the receiver's page automatically detects the format from the first character.

#### 4. Receiving a message

Paste the received envelope into the decrypt box → enter your passphrase → click **Decrypt** → read the message.
- **Single-use passphrase entry:** Your private key is unwrapped on demand for that single message and immediately discarded from memory, and the passphrase input is cleared as soon as decryption succeeds. Leaving the browser tab open does not leave an "unlocked session" behind.
- **Keep plaintext out of the clipboard when possible:** Decrypted plaintext is never saved to storage; read it directly on screen and click **Clear** when done rather than copying it into your system clipboard if you do not need to.

#### 5. Restoring on a new or lost device

1. Open the **Setup** tab → under **Restore from backup**, paste your exported key backup JSON (`ecdh-backup-YYYYMMDD.json`) or select the file, enter your passphrase, and click **Restore key**. Your identity and fingerprint are restored immediately without needing to repeat the voice ceremony for your own key.
2. Open the **Encrypt** tab → expand **Export / import contacts** → paste or select your exported contacts JSON (`ecdh-contacts-YYYYMMDD.json`) and click **Import contacts**. (Because the contacts JSON is unencrypted, if it was stored somewhere untrusted, check that your contacts' 12-emoji fingerprints have not changed.)

However, if you suspect a lost device might be accessed by someone else, **rotate your key and repeat the ceremony with your contacts**.

#### 6. Key rotation, compromise recovery, or wiping a device

Open the **Setup** tab → expand **Danger zone** → optionally check **Also wipe all saved contacts** if you want to remove `ecdh.contacts.v1` and `ecdh.lastcontact.v1` alongside your key → click **Wipe** twice to confirm. To rotate your identity, generate a new keypair and **repeat the voice verification ceremony** with your friends so they delete your old contact entry and save the new public key.

---

## Design Details

### Key design decisions

| Decision | Rationale |
|---|---|
| Per-message ephemeral X25519 (ECIES) | Generates a fresh AES key for every message, avoiding IV-reuse hazards. The sender retains no state, and the recipient's public key is the only pre-shared material required. |
| HKDF-SHA-256 between ECDH and AES | Provides clean cryptographic domain separation using standard primitives available in Web Crypto and BouncyCastle. |
| Self-contained envelope (ephemeral public key + IV + ciphertext) | The recipient needs zero prior state from the sender to decrypt a message. |
| Mandatory passphrase on stored keys | Ensures private keys never sit in plaintext in `localStorage` or backup files; a wrong passphrase fails cleanly via AES-GCM authentication. |
| Single-use key unwrapping on decrypt | Unwraps the private scalar only for the duration of a single `Decrypt` click, never caches the unlocked key in memory, and immediately clears the passphrase field. |
| Identical format for `localStorage` and backup files | One data structure and one code path; exported key backups are safe to store on untrusted cloud drives assuming a strong passphrase, while contacts can be exported/imported separately as a `[{"name", "pub"}]` JSON array. |
| 12-emoji fingerprint (72 bits of SHA-256) | Easy to read aloud over a voice call. A short 4-emoji (24-bit) fingerprint can be brute-forced offline on a laptop in minutes; 72 bits is infeasible to brute-force within this threat model. |
| Dual envelope encodings: base4096 (CJK) and Z85 | Originally the tool used Base64 (100 bytes → 133 chars). Z85 reduces this to 125 ASCII chars (125 bytes), which is ideal for channels that limit by **byte size**. However, many IMs limit messages by **character count**, counting a 3-byte UTF-8 Chinese character as 1 character — so CJK base4096 packs 100 bytes into ~67 characters while also using archaic characters that avoid keyword filters. Users can choose whichever fits their channel. |
| No sender signatures, timestamps, or AAD | Keeps the protocol stateless, minimal, and easy to audit or reimplement in an afternoon. |

---

### Protocol v1 specification (byte-exact)

All raw X25519 keys are standard 32-byte little-endian u-coordinate byte strings—identical across Web Crypto, BouncyCastle, and libsodium. Binary fields inside the JSON key record use standard padded base64.

#### Public key encoding

Public keys are exchanged as **64-character lowercase hexadecimal strings** matching `^[0-9a-f]{64}$`. Using hex (`0-9a-f` only) prevents instant-messaging apps from mangling keys via autocorrect or turning character runs like base64's `+/=` into emojis. Decoders tolerate uppercase hex and embedded whitespace (such as line wraps inserted by chat apps), and reject everything else.

#### Message envelope layout

At the byte level, an envelope has a fixed binary layout. For copy-pasting over text channels, those bytes are wrapped in a tagged text encoding:

```
text form = TAG || codec( 0x01 | ephPub[32] | iv[12] | ciphertext )
```

- `TAG` — A single leading character identifying the text encoding so the decoder knows how to parse the payload:
  - `賒` (U+8CD2) = **base4096** (default in the UI)
  - `A` = **Z85**
  Tags are matched strictly (case-sensitive, no untagged fallback) and are **independent of the protocol version byte**: the tag specifies how the outer text is encoded, while `0x01` inside specifies the binary protocol version.
- Decoders strip all whitespace before inspecting the tag or payload, so line wraps inserted by chat or email clients do not break decryption. Encoders always output a single compact string.

Binary envelope fields:

- `0x01` — 1-byte protocol version.
- `ephPub` — 32-byte public key of a **per-message ephemeral** X25519 keypair, generated during encryption and immediately discarded.
- `iv` — 12 uniform random bytes.
- `ciphertext` — AES-256-GCM encryption of the UTF-8 plaintext, with the 128-bit authentication tag appended at the end (the standard layout in both Web Crypto and Java/BouncyCastle).
- No AAD (additional authenticated data) is used.
- To decrypt, the recipient reads `ephPub` from the envelope and combines it with their own keypair from storage.

#### Text encoding: base4096 (tag `賒`)

Tag `賒` encodes the binary envelope in **base4096**, packing 12 bits into each CJK character (3 bytes → 2 characters, or ~67 characters per 100 bytes). Even though each CJK character takes 3 bytes in UTF-8, many instant-messaging apps enforce length limits by **character count** rather than byte count—so 100 bytes of data uses only ~67 characters of your limit (nearly half the character count of Z85 or Base64). In addition, every digit is an archaic nature- or object-radical character, so the output looks like classical text while **incapable of spelling any common modern Chinese words (simplified or traditional)**, giving naive keyword filters nothing to trigger on.

- **Character table:** 4,096 characters defined in `B4096_TABLE` in `crypto.js` (the authoritative source), ordered strictly by codepoint from U+4E62 to U+8CCF. Every character lies in the Unicode BMP CJK Unified Ideographs block and predates Unicode 5.1, ensuring broad font support across devices.
- **Deterministic construction of the character set:**
  Starting from the Unicode 18.0 `kRSUnicode` metadata, filter for characters belonging to 47 nature/object radicals (`土山木水牛田石竹糸羊羽艸虫角谷豆豕豸貝車酉里金長門阜隹雨青非面革韋韭音頁風飛食首香馬魚鳥鹿龍龜`), remove every character encodable in GB2312 as well as every character in the *List of Frequently Used Characters in Modern Chinese* (《现代汉语常用字表》, 3,500 chars) and *List of Generally Used Characters in Modern Chinese* (《现代汉语通用字表》, 7,000 chars), and sort by codepoint. The first 4,096 characters form the digit table; the next three are reserved control characters:
  - `PAD1`: `賐` (U+8CD0)
  - `PAD2`: `賑` (U+8CD1)
  - `TAG`: `賒` (U+8CD2)
  *(Note: a tiny handful of rare traditional character combinations—such as `賄賂`—remain in the set and could appear by pure chance roughly once every 100,000 messages.)*
- **Full groups:** Each 3-byte group is read in **big-endian** order as a 24-bit integer and emitted as 2 base-4096 digits, **most significant digit first**.
- **Tails:**
  - A 1-byte remainder is encoded as one digit (`byte << 4`) followed by `PAD1` (`賐`).
  - A 2-byte remainder is encoded as two digits (`16 data bits << 8` across a 24-bit slot) followed by `PAD2` (`賑`).
  The explicit trailing `PAD` marker removes any length ambiguity between a 2-character tail and a full 2-character group.
- **Strict validation:** Decoders reject any character outside the table, any `PAD` marker not at the end of the string, any invalid character count, and any non-zero padding bits in a tail.

Test vectors:
- `01 02 03` → `圼嶖`
- `01` → `圼賐`
- `01 02` → `圼嶒賑`

#### Text encoding: Z85 (tag `A`)

Tag `A` encodes the binary envelope using **Z85** (ZeroMQ's base85 variant: 4 bytes → 5 ASCII characters, or 125 characters/bytes per 100 bytes of input, compared to ~133 in Base64). Because every character is single-byte ASCII, Z85 is the most efficient choice when a channel enforces message limits by **byte size** rather than character count. Its alphabet deliberately omits quotes and backslashes so strings survive JSON strings and single-quoted (`'...'`) shell literals unescaped (when sending over Markdown or chat apps with auto-emoji, wrap the Z85 string in backticks or a code block so characters like `*`, `<`, `[`, or `:)` are not reformatted):

```
0-9 a-z A-Z . - : + = ^ ! / * ? & < > ( ) [ ] { } @ % $ #
```

Digits are ordered 0–84 as listed above; the `Z85` constant in `crypto.js` is normative.

- **Full groups:** Each 4-byte group is read **big-endian** as an unsigned 32-bit integer and written as 5 base-85 digits, **most significant digit first** (`d4 = floor(value / 85⁴)`). Unlike Ascii85, there is no `z` shorthand for all-zero groups.
- **Tails:** Because envelope lengths (`61 + plaintext length`, or `45 + ciphertext length`) are not always multiples of 4, tail handling is defined explicitly:
  - **Encoding:** The final `r` bytes (`r` = 1..3) are zero-padded on the right to 4 bytes, encoded as 5 digits, and only the first `r + 1` characters are emitted.
  - **Decoding:** A trailing `k`-character group (`k` = 2..4) is padded to 5 characters using the highest digit `#` (value 84), decoded into 4 bytes, and the first `k − 1` bytes are kept. A 1-character tail is never valid.
- **Strict validation:** Decoders reject any character outside the alphabet, any length leaving a 1-character tail, any 5-character group whose decoded value exceeds `2³² − 1` (valid tails padded with `#` never overflow `2³² − 1`), and any non-canonical tail whose re-encoded `k − 1` bytes do not match the `k` tail characters (i.e., non-zero padding bits).

Test vectors:
- `86 4F D2 6F B5 59 F7 5B` → `HelloWorld`
- `01` → `0r`
- `01 02` → `0rJ`
- `01 02 03` → `0rJu`

#### Key derivation

```
ss  = X25519(ephPriv, recipientPub)          // 32 bytes
if ss == all zeros: REJECT (invalid or small-order public key)
key = HKDF-SHA256(ikm  = ss,
                  salt = ephPub || recipientPub,   // 64 bytes
                  info = UTF-8("ecdh.html/v1"),
                  L    = 32)
```

#### Public key fingerprint

The canonical fingerprint is the full 32-byte lowercase hex **SHA-256 digest of the raw 32-byte public key**. In addition, the UI renders the first 72 bits of that digest as **12 emojis paired with unambiguous English labels** (6 bits per entry from a fixed 64-entry table) in a 12-tile grid for easy voice comparison.

Exact emoji mapping for implementers:
Let `v` be the 72-bit big-endian integer formed by bytes `0..8` of `SHA-256(pub)`. Repeat 12 times for `i = 0..11`:
`idx = v mod 64`, `emoji[i] = EMOJI[idx]`, `name[i] = EMOJI_NAMES[idx]`, `v = floor(v / 64)`.
The **first** (top-left) entry represents the *least*-significant 6 bits of the 72-bit prefix. `EMOJI` and `EMOJI_NAMES` are the 64-entry arrays in `crypto.js`.

Test vector (32-byte all-zero public key):
- SHA-256 hex: `66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925`
- 12-emoji fingerprint: `🌲 Pine` · `🦁 Lion` · `🎩 Hat` · `🌋 Volcano` · `🐙 Octopus` · `🌊 Wave` · `🎵 Music` · `🐯 Tiger` · `🥑 Avocado` · `🌊 Wave` · `🐰 Rabbit` · `🧊 Ice`

#### Private key wrapper format (`localStorage` and backup JSON)

```json
{
  "v": 1,
  "type": "x25519-private",
  "pub": "<hex, raw 32-byte public key, plaintext>",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iter": 800000,
  "salt": "<base64, 16 bytes>",
  "cipher": "AES-256-GCM",
  "iv": "<base64, 12 bytes>",
  "ct": "<base64, AES-GCM of the raw 32-byte private scalar + 16-byte tag>"
}
```

- The wrapping key is derived via `PBKDF2-HMAC-SHA256(UTF-8(passphrase), salt, iter)` (using the raw UTF-8 bytes of the passphrase string without Unicode normalization). Importers honor the `iter` value stored in the JSON record when unwrapping rather than hardcoding 800,000 (and the UI re-wraps imported records at `800,000` before saving if `iter < 800000`).
- The `pub` field is mandatory; on import, the decrypted private scalar is multiplied by the base point to verify that it matches `pub`.
- `localStorage` keys used by the page:
  - `ecdh.key.v1` — the JSON record above (private scalar encrypted; `pub` in plaintext)
  - `ecdh.contacts.v1` — `[{"name": "...", "pub": "<64-char hex>"}]` (stored and exported/imported in plaintext; importers also accept `"publicKey"` as an alias for `"pub"`, canonicalizing to `"pub"`)
  - `ecdh.lastcontact.v1` — hex public key of the last selected contact (stored in plaintext)
  - `ecdh.theme.v1` — optional UI color-scheme preference (`"light"` or `"dark"`; when unset, follows the browser default)

#### BouncyCastle / JVM interoperability reference

If you want to build a compatible desktop or Android tool using BouncyCastle / JCE:

- **Wrapping raw 32-byte keys into ASN.1 DER:**
  - PKCS#8 X25519 private key prefix: `302e020100300506032b656e04220420 || raw32`
  - SPKI X25519 public key prefix: `302a300506032b656e032100 || raw32`
- **X25519 agreement:** `new X25519PrivateKeyParameters(scalar, 0)` with `X25519Agreement` produces the identical 32-byte little-endian shared secret as Web Crypto's `deriveBits`. (Standard X25519 clamping is handled internally during scalar multiplication in all implementations.)
- **HKDF:** `new HKDFBytesGenerator(new SHA256Digest())` initialized with `new HKDFParameters(ikm, salt, info)`, then `generateBytes(out, 0, 32)`.
- **PBKDF2:** JCE `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` (256-bit key) or BouncyCastle `PKCS5S2ParametersGenerator(new SHA256Digest())` initialized with `PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(passphrase)` (not `PKCS5PasswordToBytes`, which truncates characters to 8 bits).
- **AES-GCM:** JCE `Cipher.getInstance("AES/GCM/NoPadding")` with `new GCMParameterSpec(128, iv)` appends the 16-byte authentication tag to the end of the ciphertext, matching Web Crypto.

#### Implementation and testing notes

- **Cross-implementation test suite (`tests/crypto.test.js`):** Exercises `crypto.js` directly against Node's OpenSSL-backed `crypto` module. It verifies DER prefixes, envelope binary layout, tag dispatch, Z85 and base4096 encoding/decoding, HKDF key derivation, PBKDF2 key wrapping, emoji fingerprints, contact-list import validation, runtime WebView/browser detection, base4096 sensitive-word exclusion, and rejection of malformed inputs (all-zero shared secrets, tampered ciphertexts, unknown versions/tags, non-canonical tails, wrong passphrases, and mismatched public keys).
- **Browser end-to-end validation:** Tested in headless Chromium (Playwright) covering HTTP insecure-context warning banners, key generation, contact fingerprint previews, contact export/import, full Unicode encrypt/decrypt round-trips with line-wrapped envelopes, backup/wipe/restore flows (including optional contact wiping), and passphrase changes.
- **Browser quirks handled in code:**
  1. *Non-blocking service worker registration:* Startup does not `await` `navigator.serviceWorker.register()`, preventing a slow or stuck service worker registration from delaying UI initialization.
  2. *Consistent small-order public key errors:* Chromium throws a generic `OperationError` with an empty message when `deriveBits` encounters a low-order X25519 point (such as an all-zero public key), whereas Firefox returns 32 zero bytes. Both cases are caught and normalized into explicit invalid-key / zero-shared-secret error messages.

---

## License

Licensed under the [GNU Affero General Public License v3.0 (or later)](LICENSE) (`AGPL-3.0-or-later`).

---

*Current spec versions: envelope `0x01`, text-encoding tags `賒` (base4096) and `A` (Z85), key wrapper `v: 1`, `localStorage` keys `.v1`, service worker cache `v1`. Any byte-level format change must bump the corresponding version identifier and be documented here.*
