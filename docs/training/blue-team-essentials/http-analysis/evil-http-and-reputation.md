---
title: "Attack Stages over HTTP, Choosing an Analysis Method, URL Reputation"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Attack Stages over HTTP, Choosing an Analysis Method, URL Reputation { #evil-http-and-reputation }

!!! abstract "What this page covers"
    How attackers use HTTP in almost every stage of an attack (delivery, exploitation, installation, C2, exfiltration) and what each stage looks like in logs, whether to reach for automated or manual analysis first, the easiest first step — URL reputation — and its traps (bad URLs on good domains, "no result" ≠ safe), and how to investigate without leaking information (OPSEC, defanging). Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. HTTP fundamentals are in the [HTTP section](../http/index.md).

## Eight key points { #key-points }

1. HTTP is used in almost every attack stage, and each stage looks different in the logs.
2. Go for **fast answers first**: automated (reputation, screenshots, sandboxes) → if that fails, manual (header and content analysis, file extraction, anomaly hunting).
3. Each method suits different stages. Screenshots are great for phishing, useless for C2 addresses.
4. URL reputation is the fastest way to confirm "this is malicious".
5. **No result ≠ clean.** Brand-new addresses have no history anywhere.
6. **Good domain ≠ safe URL.** Hacked blogs, cloud-shared files, watering holes.
7. Looking up is not submitting. Submitting to public scanners exposes data and can tip off the attacker (OPSEC).
8. Defang URLs in reports and tickets so they can't be clicked (`hxxps://evil[.]example`).

## HTTP is used in almost every attack stage { #kill-chain }

**Why it matters.** Nearly every organisation allows HTTP, so attacker traffic blends in. It delivers malicious files, steals passwords through phishing sites, and carries C2 and exfiltration. Analysts need to know **what HTTP looks like at each stage of an attack**.

A common frame for attack stages is Lockheed Martin's **Cyber Kill Chain**, which splits an attack into seven stages (it comes up again in other study pages on this site).

| Stage | Meaning | How HTTP is used |
| --- | --- | --- |
| 1 Recon | Research the target | Attackers browse the company website and job ads (visible in our web server logs) |
| 2 Weaponize | Build the attack | Happens on the attacker's side; usually invisible to us |
| 3 Deliver | Send the attack to the target | Phishing links, malvertising, redirects from compromised sites, fake updates |
| 4 Exploit | Trigger execution | Exploit kits, browser/plugin exploits, tricking the user into running something |
| 5 Install | Establish malware | Executable and script downloads |
| 6 C2 (Command & Control) | Remote control | **Periodic GETs and POSTs** |
| 7 Actions on objectives | Steal data, etc. | **Encoded or encrypted uploads** |

Here is how the stages might look in a proxy log (all domains are examples):

```
09:01:14  GET  https://parcel-redelivery.example/track?id=8812           200  text/html
09:01:20  GET  https://parcel-redelivery.example/dl/label.zip            200  application/zip
09:02:03  GET  http://203.0.113.71/u/update.ps1                          200  text/plain
09:05:00  POST https://api-telemetry-sync.example/gate                   200  text/html  (312 B)
09:10:00  POST https://api-telemetry-sync.example/gate                   200  text/html  (312 B)
13:47:31  POST https://api-telemetry-sync.example/upload                 200  text/html  (148 MB sent)
```

- Line 1 **Deliver:** the user clicks a phishing link posing as a parcel redelivery
- Line 2 **Deliver/Exploit:** a ZIP from that site (possibly containing an executable or script)
- Line 3 **Install:** a PowerShell script fetched **directly from an IP address**, no domain
- Lines 4–5 **C2:** small POSTs of identical size (312 bytes) to the same address exactly five minutes apart — a beacon
- Line 6 **Actions:** 148 MB uploaded to the same C2 — exfiltration

Each line on its own looks ordinary; strung together in time order, the whole attack ran over HTTP.

**[Added]** Many SOCs now use the finer-grained **MITRE ATT&CK** more than the kill chain. In ATT&CK terms, the phishing link is T1566.002 (Spearphishing Link), web-protocol C2 is T1071.001 (Web Protocols) and exfiltration over the C2 channel is T1041 (Exfiltration Over C2 Channel). The kill chain describes the big flow; ATT&CK names specific techniques.

## Choosing an analysis method: fast answers first { #methods }

**Why it matters.** Analyst time is limited; hours on one alert means others pile up. The skill is choosing **the method that reaches the right answer fastest** — without trading accuracy for speed.

| Kind | Method | Strength | Limit |
| --- | --- | --- | --- |
| Automated | URL/site reputation | An answer in seconds | New addresses have no history |
| Automated | Screenshot services | See a phishing page at a glance | Useless for C2 addresses (blank page) |
| Automated | Sandboxes (HTML analysis, full VM detonation) | See real behaviour | Takes time; some malware detects sandboxes |
| Manual | Header analysis (request/response) | Exactly what was exchanged | Costs analyst time |
| Manual | Content analysis, file extraction, anomaly hunting | Finds what tools missed | Slowest, needs skill |

The usual order is **quick automated checks → if there's no clear answer, go manual and deep**. And match the method to the stage:

- **Phishing page (Deliver)** → a screenshot is fastest; you can see a fake Microsoft login at a glance
- **Malicious download (Install)** → file-hash reputation, sandbox
- **C2 address** → a screenshot shows a blank page or a fake 404; you need header analysis and manual work on interval and size patterns

## The easiest first step: URL reputation { #url-reputation }

**What it is.** Looking up the "confirmed malicious URL" records collected by security vendors and communities worldwide. If someone has already confirmed the address as malicious, you can **settle it in seconds** — the fastest first step.

Well-known services (each with its own purpose and level of detail):

| Service | What it offers |
| --- | --- |
| VirusTotal | Verdicts on URLs, domains and file hashes from many engines at once |
| urlscan.io | Actually loads the page: screenshot, loaded resources, redirects |
| URLhaus (abuse.ch) | A list of malware-distribution URLs |
| Google Safe Browsing transparency report | Whether Chrome warns about the site |
| Cisco Talos Intelligence | IP and domain reputation |

### Trap 1: no result ≠ clean { #no-result }

Reputation only tells you **what someone has already found and recorded**. Attackers often register phishing domains, use them for a few hours and discard them; those show "0 engines detected" because nobody has seen them yet. **"No bad record" is not "safe".** A clean result means moving on to the next step (domain age, content analysis).

### Trap 2: good domain ≠ safe URL { #domain-vs-url }

**The reputation of one URL is not the reputation of the whole domain.** Malicious URLs can live on reputable domains:

```
https://www.small-bakery.example/wp-content/uploads/2026/11/inv.php
https://www.dropbox.com/scl/fi/a8k2.../Remittance_Advice.zip?dl=1
https://www.industry-association.example/news/2026-conference
```

- Line 1 **A hacked WordPress blog:** the bakery's domain is old and clean, but an attacker planted a PHP file in its uploads folder
- Line 2 **A cloud-shared file:** Dropbox has an excellent reputation, but anyone can upload files to it
- Line 3 **A watering hole:** compromising an industry-association site the targets visit regularly and planting attack code on it — named after a predator waiting at the waterhole

So look up **the full URL** and **the domain** separately: search the domain to judge the whole domain, search the URL to judge this address. A good domain reputation doesn't vouch for everything on it.

### Reading a result { #reading-results }

```
URL:        https://login-m365-secure.example/auth?client=office
Detections: 7 / 94 engines flagged as phishing
First seen: 2026-11-04 08:12 UTC (5 hours ago)
Domain age: 2 days
Final URL:  https://login-m365-secure.example/auth/index.php
Page title: "Sign in to your account"
```

- **7/94** — 7 of 94 engines say phishing. It looks small, but engines take time to catch up on new addresses, so even a few detections matter
- **First seen 5 hours ago, domain 2 days old** — freshly made
- **Page title "Sign in to your account"** — mimics the Microsoft sign-in title
- Taken together, effectively confirmed. Next: [who visited and what did they enter](#quiz)

### [Added] Investigating without leaking information (OPSEC) { #opsec }

Also consider whether using reputation services fits your **OPSEC (operational security) standards**. Lookups come in levels:

| Level | What happens | Risk |
| --- | --- | --- |
| Passive lookup | Search existing results only | Minimal |
| Public submission | The service visits and analyses the address; **results are public** | Others can see it; the attacker may notice |
| Private submission | Only you see results (paid/configured) | The service's visit still shows up in the attacker's server logs |
| Our own isolated environment | In-house sandbox or analysis VM | Must be set up so the organisation's IP isn't exposed |

Why care:

- **Public scan results are visible to anyone.** Phishing URLs often embed the victim's email (Base64 after `?u=`, etc.). Submitting publicly publishes your employee's address and the fact they were targeted. Wrongly submitting a **legitimate URL with a token** (password-reset or document-sharing links) can expose that document or account.
- **Attackers watch these services too.** When their URL shows up, they know they're spotted and change addresses or clean up.
- **Never open a suspicious URL directly from a company PC or company IP.** It tells the attacker's server logs that your organisation is investigating, and the PC could get infected.

**[Added] Defanging.** When writing suspicious URLs in reports, tickets or chat, change their shape so they can't be clicked or auto-linked:

```
https://login-m365-secure.example/auth   →   hxxps://login-m365-secure[.]example/auth
203.0.113.71                             →   203.0.113[.]71
```

- `http` → `hxxp`, `https` → `hxxps`
- dot `.` → `[.]`
- The recipient reverses it (refangs) before feeding it to tools

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    "HTTP is used in almost every stage", "quick automated checks → manual when needed", "no result ≠ safe" and "good domain ≠ safe URL" all hold — the last more than ever as abuse of cloud services grows.

!!! info "[Changed]"
    - **More ways to dodge reputation checks.** Phishing domains live for hours, cloaking shows clean pages to security scanners, and phishing pages hide behind CAPTCHA or Cloudflare Turnstile challenges that automated scanners can't pass. What the scanner saw and what the victim saw can differ.
    - **QR-code phishing (quishing) is common.** A QR image in the email instead of a URL dodges email URL scanning and pushes the victim to an unmanaged personal phone. Decode the QR to extract the URL, then check its reputation.
    - **Reputation checks are automated by default.** SIEM/SOAR enrichment now queries URLs, domains and hashes from alerts against several services automatically; analysts spend their time interpreting results and going beyond them.
    - **AI-generated phishing pages** weaken old clues like awkward wording, while technical signals — domain age, certificate issuance time, hosting location — still work.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't close a case because reputation is clean.** New domains, cloud hosting and challenge-gated pages may be unknown to reputation services.
    - **Don't submit just any URL to public scanners.** For URLs carrying victim data or tokens, strip parameters or use private options or an in-house isolated environment.
    - **Don't open suspicious URLs from a company PC.**

## Practice questions { #quiz }

### Question 1

Which kill-chain stage does each proxy log line most likely represent?

```
A: POST https://cdn-metrics-api.example/beacon   (every 60 s, 256 B)
B: GET  https://hr-portal-update.example/review.html   (link from email)
C: GET  http://198.51.100.9/s/a.exe
D: POST https://cdn-metrics-api.example/up   (2.3 GB sent, 02:10)
```

??? success "Answer and explanation"
    - **A — C2 (stage 6).** Small POSTs of identical size to the same address exactly every 60 seconds = a beacon.
    - **B — Deliver (stage 3).** A suspicious page opened from an email link = phishing delivery.
    - **C — Install (stage 5).** An executable fetched **directly from an IP address**, no domain; legitimate software normally uses domains and HTTPS.
    - **D — Actions on objectives (stage 7), exfiltration.** 2.3 GB uploaded to the C2 domain at 2 a.m.

    Note A and D share a domain: data was **exfiltrated over the C2 channel** (ATT&CK T1041). Chaining stage traces in time order gives you the whole incident.

### Question 2

A staff member clicked a link from an email. VirusTotal shows **0/94** for the URL and urlscan.io has no record. Is "it's safe, closing the case" right? What else should you check?

??? success "Answer and explanation"
    **No.** No result only means nobody has recorded it yet. Phishing domains are often brand-new and short-lived, and cloaking or challenge pages dodge scanners.

    Check further:

    1. **Domain age and registration** — a few days old is a strong signal
    2. **Certificate issuance time** — when the domain's first certificate appeared in Certificate Transparency (CT) logs
    3. **Content, safely** — load the page in an isolated analysis environment or via a private scan: does it imitate a login page?
    4. **Our logs** — did the staff member POST (enter credentials) to the site, and what did they receive afterwards?
    5. **Other recipients** — search the mail gateway for the same sender, subject or URL

### Question 3

A phishing email contains this URL:

```
https://login-verify.example/start?u=ai5zbWl0aEBjb3JwLmV4YW1wbGU=
```

Can you submit it as-is to a public scanner? What's the risk, and what should you do?

??? success "Answer and explanation"
    **Not as-is.** The value after `u=` is Base64 that decodes to **`j.smith@corp.example`** — your employee's email address.

    Risks:

    1. **The employee's email becomes public** in the scan results, along with the fact that this person in your organisation was targeted.
    2. Phishing pages use such values to pre-fill the email field (looking more genuine) or to **track who clicked**. A scanner visiting the URL may look to the attacker like "j.smith opened the link", or signal that someone is investigating.

    Instead:

    - Start with a **passive lookup** (existing results) on the domain
    - If you need the content, analyse a version with the **parameter removed or replaced by a dummy value**, using a **private option** or an **in-house isolated environment**
    - Record it defanged in reports: `hxxps://login-verify[.]example/start?u=<redacted>`
    - Then check your logs: did j.smith actually click, and enter credentials?
