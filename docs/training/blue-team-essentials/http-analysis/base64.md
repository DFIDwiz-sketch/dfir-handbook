---
title: "Base64 — How It Works, Recognising It, Suspicious Base64"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Base64 — How It Works, Recognising It, Suspicious Base64 { #base64 }

!!! abstract "What this page covers"
    Why Base64 exists (email couldn't carry arbitrary bytes), how it transforms data bit by bit — calculated by hand — what `=` padding means, how to recognise it and **guess the original file type from the first characters**, decoding commands, legitimate uses (JWT, Basic auth, data URIs, ViewState) versus suspicious ones, and how to tell them apart. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. Earlier Base64 cases appear in [POST abuse](../http/post-methods-headers.md#post-abuse) and [C2 hidden in cookies](user-agents-cookies.md#cookies).

## Eight key points { #key-points }

1. Base64 is **a wrapping that turns any bytes into printable characters**. **It is not encryption** — anyone can undo it instantly.
2. Its alphabet: the 64 characters `A-Z a-z 0-9 + /` plus `=` padding (the URL-safe variant uses `- _` instead of `+ /`).
3. How: concatenate the bits of 8-bit bytes, re-cut them **6 bits at a time**, and map each to the 64-character table. 3 bytes → 4 characters.
4. One or two trailing `=` are length padding; seeing them makes Base64 very likely (they can also be absent).
5. **The first characters reveal the original.** `TVqQ` = executable, `H4sI` = gzip, `UEsDB` = ZIP/Office document, `JVBERi0` = PDF, `eyJ` = JSON (JWT), `SQBFAFgA` = PowerShell `IEX`.
6. Legitimate web traffic uses Base64 a lot. The question is **"why encode it here?"**
7. Don't judge on Base64 alone. Suspect it when **Base64 where none is needed + a questionable host + an odd User-Agent** stack up.
8. Decoding to unreadable bytes doesn't mean benign — the data may have been **encrypted, then Base64-wrapped**.

## Why it exists { #why-base64 }

Early email (SMTP) standards could only carry **byte values 0–127**, but images and programs use every value from 0–255 and would break in transit. Using all of 0–127 wasn't safe either: it includes **invisible control characters** such as line feeds and the bell, which different equipment along the way could interpret differently.

So 64 **characters no equipment would misinterpret** were chosen, and all data is rewritten using only them. That's Base64 — like **rewriting a letter in 64 symbols every post office understands**. The content is unchanged; only the lettering changes. **Wrapping, not encryption.**

Today it's everywhere: email attachments, web cookies, POSTed values, authentication tokens. Legitimate web apps use it heavily, and so does malware for file transfer and C2. Analysts need to **recognise it on sight and question it when it's out of place**.

## How it works: converting bits by hand { #how-it-works }

Three steps:

1. Concatenate the original data 8 bits (one byte) at a time
2. Re-cut that bit string **6 bits at a time** (6 bits = 0–63, exactly 64 values)
3. Map each 6-bit value to a character from the table below, padding with `=` if short

| 6-bit value | Character |
| --- | --- |
| 0 – 25 | `A` – `Z` |
| 26 – 51 | `a` – `z` |
| 52 – 61 | `0` – `9` |
| 62 | `+` |
| 63 | `/` |
| (padding) | `=` |

**Example 1: `AZ` → `QVo=`**

```
Text:        A          Z
ASCII hex:   0x41       0x5A
8-bit:       01000001   01011010
Joined:      0100000101011010 + 00 (pad bits)
6-bit:       010000  010101  101000
Decimal:     16      21      40
Base64:      Q       V       o       =
```

- `A` is 0x41 = `01000001`, `Z` is 0x5A = `01011010`
- Joined they're 16 bits — not a multiple of 6 — so two `0` bits are added to make 18
- Cut into 6-bit groups: 16, 21, 40 → `Q`, `V`, `o` from the table
- A full 3-byte (24-bit) group would give 4 characters; with only 2 bytes one is missing → one `=` fills it

**Example 2: the padding rule**

```
"Man" (3 bytes)  →  TWFu      (no padding)
"Ma"  (2 bytes)  →  TWE=      (one =)
"M"   (1 byte)   →  TQ==      (two =)
```

- 3 bytes = 24 bits = exactly four 6-bit groups → no padding
- One byte short → one `=`; two bytes short → `==`
- So Base64 length is **always a multiple of 4** (with padding), and output is **about 1.33×** the original (3 bytes → 4 characters)

## Recognising it { #recognising }

Base64 is likely when these overlap:

- Every character is in `A-Z a-z 0-9 + /` (or URL-safe `- _`)
- It ends in `=` or `==` (often absent — no padding when the original length is a multiple of 3)
- The length is a multiple of 4
- No human words, just an even mix of upper case, lower case and digits

**[Added] Guessing the original from the first characters.** Files start with fixed [magic bytes](../http/responses.md#content-type), so their Base64 always **starts with the same few characters**. Memorise these to identify content before decoding:

| Base64 starts with | Original starts with | It is |
| --- | --- | --- |
| `TVqQ` | `MZ` + `90 00` | Windows executable (EXE, DLL) |
| `H4sI` | `1F 8B 08` | gzip compressed |
| `UEsDB` | `PK 03 04` | ZIP (`.docx`, `.xlsx`, `.jar` are ZIP inside) |
| `JVBERi0` | `%PDF-` | PDF |
| `iVBORw0KGgo` | `89 PNG` | PNG image |
| `eyJ` | `{"` | JSON — often a JWT |
| `SQBFAFgA` | `I E X` (UTF-16LE) | PowerShell `IEX` (run what was fetched) |

So a POST body beginning `TVqQAAMAAAAEAAAA//8AAA...` means **a whole executable is being sent**, before you even decode it.

## Decoding { #decoding }

```
$ echo 'aG9zdD1XUy0wMjMxO3VzZXI9YS5uZ3V5ZW47YXY9RGVmZW5kZXI=' | base64 -d
host=WS-0231;user=a.nguyen;av=Defender
```

- `echo '...'` — print the Base64 string
- `| base64 -d` — pipe (`|`) it into the `base64` command's decode (`-d`) mode
- Result: PC name, user and installed antivirus — a classic infected-host check-in

In Windows PowerShell:

```
PS> [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('Y21kPW9rO3NsZWVwPTYwMA=='))
cmd=ok;sleep=600
```

- `[Convert]::FromBase64String('...')` — decode Base64 to bytes
- `[Text.Encoding]::UTF8.GetString(...)` — turn bytes into text
- Result: "no command, call back in 600 seconds" — the shape of a C2 reply

CyberChef's "From Base64" is handy, especially for peeling layered encodings (Base64 inside gzip inside Base64). **If the result is an executable, don't run it** — hash it and look it up, or analyse it in an isolated environment.

**[Added] PowerShell encoded commands are UTF-16LE.** Base64 passed to PowerShell's `-EncodedCommand` (`-enc`) encodes **UTF-16LE** text (two bytes per character), so decoding yields `00` bytes between characters (`I.E.X.`). Convert with UTF-16LE (`[Text.Encoding]::Unicode`), not UTF-8, to read it. The tell is an `A` in every other position, as in `SQBFAFgA` (= `IEX`) or `JABzAD0A` (= `$s=`).

## Legitimate vs suspicious Base64 { #legit-vs-suspicious }

### Legitimate uses { #legit-uses }

| Where | Example | Note |
| --- | --- | --- |
| Email attachments (MIME) | `Content-Transfer-Encoding: base64` | The original purpose |
| Auth tokens (JWT) | `Authorization: Bearer eyJhbGciOi...` | Three dot-separated parts; **the first two are readable by anyone** |
| HTTP Basic auth | `Authorization: Basic YWRtaW46...` | Decodes to `user:password` **verbatim** — not encryption |
| Images in pages | `src="data:image/png;base64,iVBORw0KGgo..."` | Small images embedded directly |
| ASP.NET form state | `__VIEWSTATE=/wEPDwUK...` | Server-signed; whoever steals the signing key can forge it |
| Cookies and session values | Many web frameworks | Common |

**[Caution] Basic auth is effectively plaintext.** The value after `Authorization: Basic` is just `user:password` Base64-encoded. If that header crosses `http` (unencrypted) or lands in a log, **the password is exposed**.

### Questions that separate suspicious Base64 { #suspicious-base64 }

Base64 is common in legitimate traffic, so **"there's Base64 here" settles nothing**. Ask instead:

1. **"Why encode this here?"** — most ordinary POST data can be sent unencoded. Deliberate wrapping may mean something is being hidden.
2. **Is the destination trustworthy?** — never-seen or newly registered domains, bare IPs
3. **Is the User-Agent normal?** — non-browser, outdated, or odd values
4. **Does it repeat?** — the same-shaped Base64 going back and forth at regular intervals (a beacon)

Two requests for example:

```
GET /news/list.asp HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Host: info.weekly-digest-mail.example
Cookie: sid=aG9zdD1XUy0wMjMxO3VzZXI9YS5uZ3V5ZW47YXY9RGVmZW5kZXI=
```

```
POST /cgi/stat.php HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Win32)
Host: two-rabbits-cdn.example
Content-Length: 1484

TVqQAAMAAAAEAAAA//8AAAC4AAAAAAAAAEAAAAAA...
```

Request 1:

- Base64 in a cookie — "could be" on its own
- Decodes to `host=WS-0231;user=a.nguyen;av=Defender` → not a session ID but **PC, user and antivirus details**
- User-Agent is IE6 on Windows XP (`NT 5.1`) — impossible in 2026
- An unfamiliar host → three signals stack: strong suspicion

Request 2:

- A Base64 POST body — "why?"
- Starts with `TVqQ` → an **executable** is being moved (sending back a tool, or a next-stage payload)
- User-Agent `Mozilla/5.0 (compatible; Win32)` — a short fake no real browser sends
- An unfamiliar host

Attackers like Base64 for two reasons: it carries binary data over text channels (HTTP, SMTP), and it defeats **signatures that look for literal content** (e.g. alerting on `MZ` or `cmd.exe` in a body). MITRE ATT&CK lists it as **T1132.001 (Data Encoding: Standard Encoding)**, used by a long list of groups and tools. It's common beyond HTTP too — you'll meet it again in suspicious endpoint command lines (PowerShell `-enc`).

**Decoded but unreadable?** Attackers often **encrypt first, then Base64-wrap**, so decoding yields random bytes. You've still confirmed **it was valid Base64**, and random-looking content (high entropy) is itself a clue that something encrypted is leaving.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    How Base64 works, how to recognise it, "encoding is not encryption" and "ask why it's encoded here and combine with other signals" all hold. It's still the most common encoding in C2, exfiltration and PowerShell obfuscation.

!!! info "[Changed]"
    - **Layering is the default.** Modern malware rarely uses Base64 alone: it adds XOR or AES before Base64, uses **custom Base64** with a reshuffled alphabet, or mixes Base32, Base85 and hex. If standard decoding fails or yields garbage, don't conclude "not encoded" (ATT&CK T1132.002 Non-Standard Encoding).
    - **JWTs are everywhere.** Cloud, SaaS and API authentication runs on JWTs, so `eyJ...` is common in logs. The first two parts (header, payload) are **readable by anyone**, and since the token is itself an access pass, JWTs left in logs are theft targets.
    - **Tools decode automatically.** Many NDR, SIEM and EDR products decode Base64 and re-inspect the content, and PowerShell Script Block Logging (Event 4104) records the decoded command at execution time.
    - **ViewState forgery is back in the spotlight.** ASP.NET's Base64 `__VIEWSTATE` is protected by the server's signing key (MachineKey); as in 2025's SharePoint "ToolShell" attacks, stealing the key allows forging malicious ViewState for remote code execution ([web servers, 2026 perspective](../http/web-servers-urls-get.md#trends)).

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't call something malicious just because Base64 appears.** Legitimate uses abound.
    - **Conversely, don't dismiss "decoded to weird bytes, so nothing".** It may be encryption plus Base64.
    - **Don't share logs containing Basic auth or JWTs carelessly.** Decoding them yields passwords or valid access passes; redact values in reports.
    - **Never run a decoded executable or script.** Hash lookups or isolated analysis only.

## Practice questions { #quiz }

### Question 1

What is each of these most likely to be originally? Answer from the first characters only, without decoding.

```
A: TVqQAAMAAAAEAAAA//8AAAC4AAAA...
B: H4sIAAAAAAAA/+y9B2AcSZYlJi9t...
C: JVBERi0xLjcKJeLjz9MKMSAwIG9i...
D: eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

??? success "Answer and explanation"
    - **A — a Windows executable (EXE/DLL).** `TVqQ` is the Base64 of `MZ` + `90 00`; a whole executable is being carried
    - **B — gzip data.** `H4sI` is gzip's `1F 8B 08`; decode, then decompress, to see the content
    - **C — a PDF.** `JVBERi0` is `%PDF-`
    - **D — JSON, often a JWT.** `eyJ` is `{"`; `alg` and `typ` mean a JWT header

    With the prefix table memorised, you can spot "an executable just went past" while skimming logs.

### Question 2

A request log for an internal web application shows this header, over `http://` (unencrypted). What's the problem?

```
Authorization: Basic YWRtaW46U3VtbWVyMjAyNiE=
```

??? success "Answer and explanation"
    A Basic auth value is just `user:password` in Base64. It decodes to **`admin:Summer2026!`** — an admin account's username and password in plain sight.

    Three problems:

    1. Over `http`, **anyone on the path could read it** (like a postcard).
    2. If the header **is in logs**, the password is exposed to every person and system that can read them.
    3. A season-plus-year password like `Summer2026!` is weak and falls to password spraying.

    Response: change the password immediately, move the app to HTTPS, replace Basic auth with something safer such as company SSO if possible, and mask the header in logs. Also check where else this account has signed in.

### Question 3

A large POST went to a suspicious host with an entirely Base64 body. Decoding gives random bytes — no readable text, no known magic bytes. A colleague says "it wasn't Base64, or it's just junk". Are they right?

??? success "Answer and explanation"
    **No.** If it decoded cleanly, it was Base64. Random bytes after decoding most likely mean the data was **encrypted (or compressed/XORed) first, then Base64-wrapped** — a common attacker pattern. High-entropy, random-looking content is itself a clue that something encrypted is leaving.

    Next:

    1. **Combine with other signals** — destination reputation and age, User-Agent, repetition, total volume to that destination
    2. **Look at size** — Base64 is about 1.33× the original, so estimate the original data volume to gauge the scale of exfiltration
    3. **Check the host** — which process connected at that time (Sysmon Event ID 3), and whether large archiving (7-Zip, `rar.exe`) or mass file reads happened just before
    4. If it looks like exfiltration, move to the data-exfiltration response procedure
