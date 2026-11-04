---
title: "Screenshots, Sandboxes, and When to Go Manual"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Screenshots, Sandboxes, and When to Go Manual { #screenshots-sandboxes }

!!! abstract "What this page covers"
    Screenshot services — the easiest way to confirm credential phishing — and how to read their results, how tools differ in whether they share results, sandboxes for when reputation isn't enough (HTML/network-centric vs VM-based) and matching the tool to the question, how malware fools sandboxes, and a map of manual analysis for when automated methods don't answer. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The previous step is [Attack Stages over HTTP, Analysis Methods, URL Reputation](evil-http-and-reputation.md).

## Eight key points { #key-points }

1. Credential phishing is fastest to confirm by **looking at the page**; screenshot services open it for you.
2. Tools differ in **whether they publish results**. If the link mustn't be seen by others, pick one that doesn't share.
3. Don't relax because the screenshot matches the real thing. Check **the host in the address bar**, the certificate's age, and where form input goes.
4. Two kinds of sandbox: ones that **load the page and record HTML and HTTP transactions** (network-centric), and ones that **open it in a VM and record changes on the host** (malware-centric).
5. Choose by "what do I need to know?": individual requests → network-centric; processes and file changes → VM-based.
6. Sandboxes get fooled — VM detection, delays, required human clicks, country/device checks.
7. **Company documents uploaded to public sandboxes can be downloaded by others.**
8. When automation doesn't answer, go manual: headers (URL, User-Agent, Host), GET/POST content, files, and anomalies (Base64, bare-IP connections, repetitive beaconing).

## Confirming credential phishing with screenshots { #screenshots }

**Why it matters.** **Credential-phishing** sites must imitate Microsoft, Google or bank login screens, so you can often tell **at a glance**. But user-reported emails don't come with screenshots, and you can't open them on a company PC. So you use services where **someone else's computer opens the page and takes a picture**.

| Tool | What it does | Result sharing |
| --- | --- | --- |
| urlscan.io | Screenshot plus every HTTP transaction, resource and redirect; great for history of sites since taken down | Choose public, unlisted or private |
| URLQuery | Screenshot, IDS rule checks, list of loaded resources | Public |
| PhishTank | Community votes on whether a site is phishing | Public (sharing is the point) |
| Hybrid Analysis | Screenshot plus a very thorough sandbox analysis | Submissions public |
| Simple screenshot services | Just take a picture | Varies by service |
| Cloudflare URL Scanner | Screenshot, network requests, technology stack | Choose public or private |

**Why sharing matters.** As covered under [OPSEC](evil-http-and-reputation.md#opsec), leaving a link in a public database can expose victim data or tip off the attacker. Decide **"may others see this link?"** first, then pick the tool.

### Reading a scan result { #reading-scan }

A scan summary typically looks like this (example):

```
Submitted URL:  https://secure-docs-share.example/view?id=7731
Effective URL:  https://secure-docs-share.example/m365/login.php
Screenshot:     "Sign in" page with Microsoft logo, email + password form
Page title:     Sign in to your account
Main IP:        198.51.100.38  (AS64500 Example Hosting, NL)
TLS cert:       issued 2026-11-03 by Let's Encrypt (1 day old)
Domains:        secure-docs-share.example, aadcdn.msftauth.net, code.jquery.com
Form action:    POST https://secure-docs-share.example/m365/next.php
```

- **Submitted → Effective URL:** where the redirects actually landed; the path `m365/login.php` is already imitation
- **Screenshot / Page title:** copies the Microsoft sign-in screen and title
- **Main IP / AS:** a generic hosting company, not Microsoft
- **Certificate issued a day ago:** a freshly built site; real login pages don't look like this
- **Domains:** images such as the logo come from **Microsoft's real CDN** (`aadcdn.msftauth.net`) — a common phishing-kit trick to look genuine
- **Form action:** the email and password are POSTed to `next.php` **not at Microsoft** → the decisive evidence

**Judge the address, not the picture.** The question isn't whether the page looks real, but **whether it came from Microsoft's real address (`login.microsoftonline.com`)**.

## Going deeper: sandboxes { #sandboxing }

**What it is.** When reputation and screenshots aren't enough, use a **sandbox** — an isolated space where links or files are actually opened and everything that happens is recorded. It follows links, downloads HTML, opens pages in a virtual machine, and watches the host for suspicious changes (new processes, files, registry edits).

| Kind | What it does | Examples | Suits |
| --- | --- | --- | --- |
| HTML/network-centric | Loads the page, records HTML and **every HTTP request/response**, each downloadable | urlscan.io | Easy for newer analysts |
| VM-based | Opens it in a real Windows VM and records **process, file and registry changes** | Hybrid Analysis, ANY.RUN, Joe Sandbox | Complex output; suits experienced analysts |

**Pick the tool by what you need to know:**

| You want | Output to look for |
| --- | --- |
| The names of JavaScript files a page loads | The request list of a network-centric sandbox |
| What the desktop looked like opening the site | A VM sandbox's screen recording or screenshots |
| A packet capture (PCAP) of the interaction and downloaded files | Sandboxes offering PCAP and file downloads |
| Which IDS rules fire, which ATT&CK techniques apply | Sandboxes with IDS alerts and ATT&CK mapping |
| What a file runs on Windows (process tree) | A VM sandbox |

VM-based sandboxes are strong on malicious files and detailed host verdicts, but their interface isn't centred on network connections. urlscan.io, by contrast, shows actual HTTP transactions request by request, which suits network analysis. Try several tools yourself to learn their strengths.

### [Added] Sandboxes get fooled { #sandbox-evasion }

Attackers know about sandboxes and build in **"behave if I'm being analysed"** features:

| Technique | What it does |
| --- | --- |
| VM detection | Stops on seeing VM drivers, few CPUs or little memory, or analysis-tool processes |
| Delays | Waits minutes to hours (sandboxes usually watch for only a few minutes) |
| Human-activity checks | Needs mouse movement, clicks or document scrolling before running |
| Country/device checks (geofencing) | Shows the malicious page only to target-country IPs, certain languages or phones |
| Challenge pages | Hides phishing behind CAPTCHA or Turnstile |

So **a clean sandbox result isn't proof.** **Interactive sandboxes** such as ANY.RUN let analysts click and wait, getting past some of these; some services let you pick an exit IP in the target country.

## When automation fails: manual header and content analysis { #manual-analysis }

When reputation, screenshots and sandboxes don't answer, look yourself. It's slow at first, but after enough good and bad samples you develop a feel for "something's off here". **A single signal rarely settles it**; conclusions come when several signals point the same way.

| Look at | What | More detail |
| --- | --- | --- |
| Headers | URL, Host (virtual host), User-Agent, … | [Judging Requests](../http/reading-requests.md) |
| GET/POST content | Are parameters or bodies needlessly encoded? | [POST abuse](../http/post-methods-headers.md#post-abuse) |
| Files | Real type and hash of what was received | [Response headers](../http/responses.md#content-type) |
| Anomalies | Base64 content, **bare-IP connections with no domain**, **repetitive beaconing**, other oddities | The next pages in this section |

For example, each signal in this request is weak on its own but strong together:

```
POST http://198.51.100.77/api/v2/sync        ← naked IP, no domain, plain http
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/112.0.0.0
Content-Type: application/octet-stream
body: dXNlcj1qc21pdGgmaG9zdD1GSU4tUEMwNw==   ← Base64
(repeats every 300 s)                         ← beacon
```

- **Bare IP + http:** legitimate services normally use a domain and HTTPS
- **Chrome 112:** a 2023 version. Company Chrome auto-updates; if only this value stays frozen for years, it's hard-coded into a program
- **Base64 body:** decodes to `user=jsmith&host=FIN-PC07` — reporting user and PC name
- **Repeats every 300 s:** a beacon

Each is "could be innocent" alone; four together justify calling it C2. User-Agents, cookies, Base64, file extraction, high-frequency requests and bare-IP connections each get their own page next in this section.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    "Look at phishing pages first", "pick tools by whether they share", "match the sandbox to the question" and "when automation fails, combine weak signals manually" all hold.

!!! info "[Changed]"
    - **PhishTank has not accepted new registrations since 2020.** Lookups and data downloads remain, but its role as a community voting service has shrunk; scanners with public/private choices such as urlscan.io and Cloudflare URL Scanner are now the usual picks.
    - **AiTM phishing kits make screenshots look "real".** Adversary-in-the-middle kits such as Evilginx and Tycoon 2FA **relay the genuine Microsoft sign-in page**, so the screen and wording are perfect. Judge by **the host in the address bar, certificate age and hosting**, not the picture. These kits capture session cookies even after MFA ([Cookie](../http/post-methods-headers.md#cookie)).
    - **Phishing pages hide behind challenges.** A CAPTCHA or Turnstile must be passed first, so automated scanner screenshots often show only the challenge.
    - **Sandboxes have diversified.** Interactive (ANY.RUN), large-scale automated (Joe Sandbox, Recorded Future Triage, …) and sandboxes built into cloud security products are common, increasingly with AI summaries. Treat summaries as a starting point and check the raw records (request lists, process trees).

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't upload company documents to public sandboxes.** Public submissions can be **downloaded by other users** (especially paid accounts), leaking internal documents wholesale. Use private options or an in-house sandbox.
    - **Don't close a case on a clean sandbox or scan result.** Evasion and challenge pages can produce "nothing happened".
    - **Don't call a page legitimate because it looks real.** The address and where input goes are what count.

## Practice questions { #quiz }

### Question 1

You scan a user-reported link and the screenshot is **pixel-for-pixel identical to the real Microsoft sign-in page**. A colleague says "it's the real page — a legitimate link." The result summary:

```
Effective URL:  https://login.microsoftonline.com.sso-verify.example/common/oauth2
TLS cert:       issued 2026-11-04 (today)
Main IP:        203.0.113.140  (AS64511 Budget VPS)
```

Why is the colleague wrong, and what is this site most likely to be?

??? success "Answer and explanation"
    **Why they're wrong:** look at **the address**, not the screen. Reading right to left, the real owner is `sso-verify.example`; `login.microsoftonline.com` is just a subdomain in front. The certificate was issued today, and the IP belongs to a budget VPS provider, not Microsoft.

    **What it is:** a perfectly genuine-looking screen actually points to an **AiTM (adversary-in-the-middle) phishing kit**, which relays the real Microsoft page while capturing the email, password and the **session cookie** issued after MFA.

    **Next:** check whether the user sent credentials to the site (a POST in the proxy log). If so, a password reset isn't enough — **revoke all sessions**. Then look for sign-ins from unfamiliar IPs or devices, block the domain, and find other recipients of the same email.

### Question 2

Which kind of tool fits each question best?

(a) You want to see exactly which JavaScript files this phishing page loads from where, and what the server answered for each request.
(b) You want to know which processes run and which files appear on Windows when an emailed document is opened.
(c) The link contains a customer's name, so no result may be published in any form.

??? success "Answer and explanation"
    **(a) A network-centric sandbox** — such as urlscan.io, which records each HTTP request/response and lets you download them.

    **(b) A VM-based sandbox** — such as Hybrid Analysis, ANY.RUN or Joe Sandbox, which opens it in a real Windows VM and records **the process tree and file/registry changes**. For documents that need a human click, an interactive one (ANY.RUN) helps.

    **(c) A private option or an in-house isolated environment** — avoid services that publish by default (Hybrid Analysis public submissions, URLQuery, PhishTank, …). Where possible, strip the parameter containing the customer's name or replace it with a dummy value before analysing.

### Question 3

A colleague wants to upload "Board_Minutes_Q3.docx" — an attachment a staff member received that looks like board minutes and contains macros — **as-is to a public sandbox**. What's the risk, and what should they do?

??? success "Answer and explanation"
    **Risk:** files uploaded to public sandboxes can be searched and **downloaded by other users**. If it's genuine board minutes (an insider sending a legitimate macro document), **a confidential document leaks wholesale**. If it's an attacker's malicious document, the attacker can see it was submitted and **know they've been spotted**.

    **Do instead:**

    1. Look up **only the file hash (SHA-256)** in reputation services first — if it's already analysed as malicious, no upload is needed
    2. If content analysis is needed, use an **in-house sandbox** or a **private submission option**
    3. Check the sender and email headers to tell a genuine internal document from an attack
    4. Find other staff who received the same attachment via the mail gateway
