# Password Entropy Analyzer

A single-page, fully client-side web tool that analyzes password strength using **real cryptographic entropy math** and **pattern detection** — not arbitrary "weak/medium/strong" labels.

> **No password is ever sent over the network.** Everything computes in the browser.

## How to Run

```bash
# Just open the file in a browser:
open index.html

# Or serve it locally (any static server works):
npx serve .
python -m http.server 8000
```

No build step. No npm install. No backend.

---

## How It Works

### Two Types of Entropy

This tool shows you **two** entropy measurements side by side and explains the gap:

#### 1. Naive (Mathematical) Entropy

The theoretical maximum entropy assuming every character is chosen uniformly at random from the detected character pool.

```
E_naive = L × log₂(R)
```

Where:
- **L** = password length (number of characters)
- **R** = character pool size = sum of character sets used:
  - Lowercase a-z → 26
  - Uppercase A-Z → 26
  - Digits 0-9 → 10
  - Symbols/punctuation → 33
  - Total if all sets used: **95**

**Example:** `password123` has L=11, R=36 (lowercase + digits), so:
```
E_naive = 11 × log₂(36) ≈ 11 × 5.17 ≈ 56.9 bits
```

This number is **misleading** — it assumes the password is random, which it isn't.

#### 2. Effective Entropy (via zxcvbn)

The real-world guessability, derived from the [zxcvbn-ts](https://zxcvbn-ts.github.io/zxcvbn/) library's `guesses` output:

```
E_effective = log₂(guesses)
```

zxcvbn estimates the number of guesses an attacker would need by:
- Checking against **common password dictionaries** (passwords, English words, names, surnames)
- Detecting **keyboard patterns** (qwerty, asdf, zxcvbn)
- Detecting **repeated characters** (aaa, abcabc)
- Detecting **sequential characters** (abc, 123, 987)
- Detecting **date patterns** (1990, 01/01/2000)
- Recognizing **l33t substitutions** (p@$$w0rd)
- Finding the **optimal decomposition** of the password into the fewest, easiest-to-guess segments

**Example:** `password123` → zxcvbn finds "password" (dictionary, rank ~2) + "123" (sequence), estimates ~4 guesses → `E_effective = log₂(4) ≈ 2 bits`. The gap from 56.9 to ~2 bits reveals the password is **catastrophically weaker** than its length suggests.

### The Gap

When naive entropy says 57 bits but effective entropy says 2 bits, that 55-bit gap means an attacker needs **2⁵⁵ fewer guesses** than brute force. The tool explains _why_ using the specific patterns zxcvbn detected.

---

## Attack Model Assumptions

The tool computes crack time as:

```
time = guesses / rate
```

Where `guesses` comes directly from zxcvbn and `rate` depends on the attack scenario:

| Attack Vector | Rate (guesses/sec) | Scenario |
|---|---|---|
| Online, rate-limited | 10 | Banking login with lockouts after N failures |
| Online, no rate limiting | 1,000 | Web app with no throttling |
| Offline, slow hash | 50,000 | bcrypt (cost 12) or argon2 on modern hardware |
| Offline, fast hash | 10,000,000,000 | Unsalted MD5/SHA-1, GPU-accelerated |
| Dedicated cracking rig | 100,000,000,000 | Nation-state actor, GPU farm, ASICs |

### Why these numbers?

- **Online rates** are conservative estimates of real-world web servers. Rate-limited assumes account lockout after ~10 attempts per interval.
- **Offline slow hash (50K/sec)**: Reflects bcrypt with cost factor 12 on a modern multi-core CPU. argon2id would be similar or slower. This is the **recommended real-world baseline** — any properly-designed system should be using these.
- **Offline fast hash (10B/sec)**: A single modern GPU (RTX 4090) can compute ~10 billion MD5 hashes per second. This represents the danger of unsalted legacy hashes.
- **Dedicated rig (100B/sec)**: Multiple GPUs or purpose-built hardware. Represents the upper end of what a well-funded attacker might deploy.

### Time Display

Times are formatted on a human-readable log scale:
- Seconds → minutes → hours → days → months → years
- Large numbers use "thousand", "million", "billion", "trillion"
- Anything exceeding 13.8 billion years displays as **"longer than the age of the universe"**
- Raw scientific notation is available in tooltips

---

## Stretch Features

### Copy Strength Report
Copies a text summary to clipboard. **The actual password is never included** in the report — only the analysis results.

### Improvement Suggestion
Calculates how many additional random characters (from the full 95-char ASCII pool at ~6.57 bits each) would push the offline bcrypt/argon2 crack time past 100 years.

### Breach Check (HaveIBeenPwned)
Uses the [HIBP k-anonymity API](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange):
1. SHA-1 hashes the password locally
2. Sends only the **first 5 characters** of the hash (the "prefix")
3. Receives all matching suffixes and checks locally
4. **The full password hash is never transmitted**

This is opt-in only — triggered by clicking the button, never automatic.

---

## Privacy Guarantees

- No password is ever sent over the network (except HIBP prefix, opt-in only)
- No password is logged to `console`
- No password is stored in `localStorage` or `sessionStorage`
- No analytics or tracking scripts
- No external API calls during typing
- All entropy/crack-time computation happens in the browser via JavaScript

---

## Technology

- **HTML/CSS/JavaScript** — no framework, no build step
- **[zxcvbn-ts v3.0.4](https://github.com/zxcvbn-ts/zxcvbn)** — loaded via jsDelivr CDN (ES modules)
- **[Inter](https://fonts.google.com/specimen/Inter)** + **[JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono)** — via Google Fonts
- Dark mode by default, light mode toggle

## License

MIT
