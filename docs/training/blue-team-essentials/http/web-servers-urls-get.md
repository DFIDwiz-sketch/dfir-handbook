---
title: "Web Servers, URLs and GET"
tags:
  - training
  - blue-team
  - http
  - concept
---

# Web Servers, URLs and GET { #web-servers-urls-get }

!!! abstract "What this page covers"
    What HTTP is (ordering and delivery), what a web server actually does (hand out files) and why that design leads to web shells, how to catch web shells in Windows logs (4688, Sysmon 1), how to read a URL piece by piece and the phishing tricks hidden in URLs (`@`, `#`, `%`, `file://`), reading Zeek `http.log`, and what GET requests look like, how they are logged and how attackers abuse them (SQL injection, path traversal, C2 beacons). Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Correction]** = fixes a commonly stated mistake, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The overall flow is on the [HTTP overview](index.md).

## Ten key points { #key-points }

1. HTTP is a text order form exchanged between a browser (customer) and a web server (kitchen), which is why logs alone can tell you what happened.
2. A web server is file sharing: the URL path is appended to a disk path (the document root).
3. `.php`, `.aspx` and `.jsp` files are *executed* by the server. Drop one malicious file there and you have a web shell.
4. Classic web-shell signal: a web server process (`w3wp.exe`, `java.exe`, …) spawns `cmd.exe` / `powershell.exe` → Event 4688 / Sysmon 1.
5. Split a URL into protocol → host → port → folder → file → parameters. Read the domain **right to left** to find the real owner.
6. If a URL contains `@`, the part after `@` is the real destination. Anything after `#` is never sent to the server and never logged.
7. Decode URL encoding such as `%27` and `%2F`; attackers use it to hide dangerous characters.
8. GET puts everything in the address (URL), so it lands verbatim in web server, proxy and SIEM logs and in browser history. Never send passwords with GET.
9. Attacks show up in GET parameters: quotes and `OR` (SQL injection), `../` (path traversal), Base64 blobs on a fixed interval (C2 beacon).
10. Thousands of sites can sit behind one IP (CDN). Judge and block by domain and URL, not IP.

## Warm-up: HTTP is "ordering and delivery" { #basics }

Think of a restaurant. A customer says "one kimchi stew, please" and the kitchen serves it. The web works the same way.

| Restaurant | Web | Proper term |
| --- | --- | --- |
| Customer | Browser (Chrome, Edge, …) | Client |
| Kitchen | Web server | Server |
| Order | "Please give me this file" | Request |
| Meal | File, web page | Response |
| Ordering rules | The agreed format | HTTP (HyperText Transfer Protocol) |

A real request really is just a short piece of text:

```
GET /menu.html HTTP/1.1
Host: www.restaurant.com
```

Line 1 means "please give me `/menu.html` (GET), I'm speaking HTTP 1.1". Line 2 means "the shop I'm ordering from is `www.restaurant.com`".

The server answers like this:

```
HTTP/1.1 200 OK
Content-Type: text/html

<html> ... menu page ... </html>
```

`200 OK` means "order received, here you go", and `Content-Type: text/html` says "what I'm sending is a web page". Everything below the blank line is the actual content.

**Why a SOC cares.** HTTP is a human-readable conversation, so incidents can be reconstructed from logs alone. Most of what a company PC does on the internet is this ordering and delivery — and malware downloads and C2 traffic use exactly the same order form. You need to know what a normal order form looks like before an odd one stands out.

## A web server is a program that hands out files { #web-servers }

In one sentence, a web server is **"fancy file sharing over HTTP"**. The best-known web server programs are Apache, NGINX and Microsoft IIS.

### Document root: the URL path is a disk path

A web server has one folder that it is allowed to show to the internet. This is the **document root** — think of it as the shop's display shelf.

```
Browser asks for:   /main/index.htm
Linux server:       /var/www/html/main/index.htm
Windows IIS:        C:\inetpub\wwwroot\main\index.htm
```

- Line 1: the path the browser asked for
- Line 2: on a Linux web server (Apache, NGINX) the path is appended to the default document root `/var/www/html`
- Line 3: on Windows IIS it is appended to `C:\inetpub\wwwroot`

The URL path continues straight into the server's disk path. This idea comes back in [path traversal](#get-attacks).

### Files served as-is vs files executed first

| Type | Examples | What the server does | Analogy |
| --- | --- | --- | --- |
| Static | `.html`, `.jpg`, `.css` | Sends it as-is | Pre-made side dish |
| Dynamic | `.php`, `.aspx`, `.jsp` | **Runs it first**, sends only the output | A recipe cooked to order |

Pages that can't be prepared in advance, such as search results, are built on the fly by a script using the user's input.

### Web shell: a recipe slipped in by an attacker

The server follows one rule: "anything in the recipe folder gets executed". If an attacker abuses, say, a flawed upload feature to drop **their own recipe** into that folder, the server runs the attacker's instructions every time the file is requested. That malicious file is a **web shell**.

```
GET /uploads/img.aspx?c=whoami HTTP/1.1
Host: intranet.corp.local
```

- "Run `/uploads/img.aspx` and pass it a value `c` = `whoami`"
- The server runs `img.aspx` → the malicious code runs `whoami` (the Windows command that asks "which account am I?") → the output comes back to the attacker as a web page
- The attacker is remote-controlling the server with nothing but a browser

### Catching web shells in Windows logs: parent and child processes

Each running program is a **process**. When one program launches another, the launcher is the **parent** and the launched program is the **child**. Open Notepad from the desktop and the parent is `explorer.exe`, the child `notepad.exe`.

In IIS the process that handles web requests is `w3wp.exe` — think of it as the head chef. A normal chef cooks; they almost never open the safe (`cmd.exe`, `powershell.exe`). When a web shell runs a command, `w3wp.exe` spawns `cmd.exe` as a child. **"The chef opened the safe" is the most classic web-shell signal.**

**Event 4688 — "A new process has been created".** Logged to the Security log every time any program starts, with the account, the new process and the parent process.

- **It is off by default.** Enable the "Audit Process Creation" audit policy, and to capture the command itself also enable the Group Policy setting "Include command line in process creation events".
- Why attackers dread it: whatever they do on a server ends up launching programs, and every launch leaves this record.

```
EventCode=4688
Account Name:          DefaultAppPool
New Process Name:      C:\Windows\System32\cmd.exe
Process Command Line:  cmd.exe /c whoami
Creator Process Name:  C:\Windows\System32\inetsrv\w3wp.exe
```

| Field | Meaning |
| --- | --- |
| `EventCode=4688` | A new process was created |
| `Account Name: DefaultAppPool` | The IIS site's own service account (not a person) |
| `New Process Name` | The program that started — a command prompt |
| `Process Command Line` | The actual command `whoami` — same as `c=whoami` in the URL |
| `Creator Process Name` | The parent — IIS worker `w3wp.exe` |

A GET line in the web server log paired with a 4688 at the same moment is close to certain proof of a web shell.

**[Added] Sysmon Event ID 1 (Process Create).** Microsoft's free Sysmon tool records the same thing in more detail (file hashes, the parent's command line). Many SOCs use 4688 and Sysmon 1 together.

### Module (plugin) backdoors: a spy hired as staff

Web servers accept add-on components (Apache `mod_*` modules, IIS modules) — like hiring new kitchen staff.

**[Added]** Attackers sometimes **register a malicious module** as part of the server. Instead of slipping a recipe in as a customer, they get hired as staff. IIS module backdoors have been reported in real incidents. In this case there is no suspicious `.aspx` file in the web folder, so "look for odd files in the web root" misses it. IIS keeps its registered modules in `applicationHost.config`; compare it with a known-good baseline to spot "staff you've never seen".

## Reading a URL piece by piece { #url }

Analysts see hundreds of URLs a day. Read them in a fixed order, the way you read a postal address from country to flat number.

```
http://this.is.a.site.com:8000/mysite/index.html?key1=val&key2=val
```

```
http://              ← 1. Protocol (how to talk)
this.is.a.site.com   ← 2. Hostname (which computer)
:8000                ← 3. Port (which door)
/mysite/             ← 4. Folder
index.html           ← 5. File
?key1=val&key2=val   ← 6. Parameters (extra info)
```

### 1. Protocol { #protocol }

"Which rules to talk by". `http` is a postcard (anyone can read it); `https` is a sealed letter (encrypted). Other protocols include ftp, ssh and file.

**[Added] The danger of `file://`.** If a phishing document contains a link like `file://203.0.113.5/share/doc.docx`, Windows tries to open a file share (SMB) on that machine — and to prove it is allowed in, it may **automatically send the user's login credentials (NTLM authentication data)**. It's like flashing your staff ID to a guard who never asked — at a building the attacker owns. The attacker can try to crack the password from it or relay it to another server to impersonate the user (depending on environment and hardening this may be blocked). Treat `file://` or `\\IP\` links pointing to external IPs as suspicious.

### 2. Hostname — read right to left { #hostname }

"Which computer to go to"; DNS turns it into an IP.

- `site.com` = **parent (registered) domain** — the **real owner** who paid to register it
- `this.is.a` = **subdomain** — whatever the owner chooses to put in front

```
microsoft.com.login-check.site.com
```

It starts with `microsoft.com`, but the real owner at the right-hand end is `site.com`. Everything before it is just a label `site.com`'s owner added. This trick is everywhere in phishing.

**[Correction] Subdomains are not "one per IP address".** One apartment block (one IP) can house hundreds of households (sites). The server tells customers apart by the request's `Host:` line (virtual hosting — see [request headers](post-methods-headers.md#host)). Conversely, one domain can have several IPs.

### 3. Port { #port }

"Which door on that computer". If omitted, `http` uses 80 and `https` 443. Ports like 8000, 8080 and 800 are used by legitimate sites too, so a port alone proves nothing; it matters when it overlaps with other signals, such as "a port we never see + a domain we've never seen".

### 4–5. Folder and file { #path }

`/mysite/index.html` is a location inside the [document root](#web-servers) — a folder and file on the server's disk.

### 6. Parameters (query string) { #parameters }

Extra information sent to the server. It starts at `?`, is written as `name=value`, and multiple pairs are joined with `&`.

```
https://www.google.com/search?q=weather+sydney&hl=en
```

- `q=weather+sydney` → search term "weather sydney" (`+` is a space)
- `hl=en` → interface language English

Parameters often tell you what the user was doing.

### Two hidden parts of a URL: `@` and `#` { #userinfo-fragment }

**[Added]** The full URL shape (RFC 3986) is:

```
scheme://userinfo@host:port/path?query#fragment
```

**`userinfo@` — a phishing trick.**

```
http://login.microsoftonline.com@198.51.100.7/common/login
```

By the rules, **everything before `@` is a "username" and the real destination is `198.51.100.7` after the `@`**. It's an envelope addressed "To Microsoft" in big letters with the attacker's home address as the actual delivery address. Some browsers warn about it, but it still appears in email and document links. **Whenever you see `@` in a URL, look after it.**

**`#fragment` — never sent to the server.** The part after `#` is used only inside the browser, like a note to yourself about which page to bookmark that you don't send to the bookshop. If a user opens `https://site.com/page#token=abc`, proxy and web server logs only show `/page`. **Not in the log ≠ not in the request.**

### Characters in disguise: URL encoding { #url-encoding }

Characters that can't appear in a URL are written as `%` + two hex digits (URL encoding, percent-encoding).

```
%20  →  (space)
%21  →  !
%27  →  '
%2F  →  /
%3D  →  =
```

Attackers use it as **disguise** — writing `%27` and `%2F` to slip past naive checks for `'` or `/`. When a URL is full of `%`, decode it before judging it.

### Real log: Zeek http.log { #zeek-http-log }

Zeek writes one line per HTTP request to `http.log` (JSON, key fields only):

```json
{
  "ts": "2026-10-24T07:15:02.113Z",
  "uid": "CHhAvVGS1DHFjwGM9",
  "id.orig_h": "10.1.5.23",
  "id.resp_h": "203.0.113.80",
  "id.resp_p": 8000,
  "method": "GET",
  "host": "this.is.a.site.com:8000",
  "uri": "/mysite/index.html?key1=val&key2=val",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "status_code": 200,
  "resp_mime_types": ["text/html"]
}
```

| Field | Meaning |
| --- | --- |
| `ts` | Request time. Trailing `Z` = UTC (Sydney daylight time is +11 h) |
| `uid` | The connection's case number; the same uid ties it to `conn.log`, `files.log` |
| `id.orig_h` | Originator — our PC |
| `id.resp_h` / `id.resp_p` | Responder's IP / port (the door) |
| `method` | Request method (GET) |
| `host` | Host header value; non-default port, so `:8000` is included |
| `uri` | Folder, file and parameters |
| `user_agent` | The client's self-introduction |
| `status_code` | Response code (200 = success) |
| `resp_mime_types` | File type Zeek determined by inspecting the response itself |

Zeek stores the URL **split into `host` and `uri`**; rebuild the full address as `http://` + `host` + `uri`. All fields are explained on [Zeek http.log](../../../network/zeek/http-log.md).

## GET = "please give me this" { #get }

If HTTP methods were a band, GET would be the lead singer. Opening one page fetches HTML, images, CSS and JavaScript as separate GETs, so dozens or hundreds of GETs per site are normal.

### What it looks like { #get-request }

```
GET /search?q=weather+sydney&hl=en HTTP/1.1
Host: www.google.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

```

1. `GET /search?q=weather+sydney&hl=en HTTP/1.1` — the **request line**: method (`GET`) / target (search page + parameters) / version (`HTTP/1.1`)
2. `Host` — which site (which household in the block)
3. `User-Agent` — "I'm Chrome on Windows 10"
4. `Accept` — "web page format, please"
5. `Accept-Encoding` — "you may compress with gzip, deflate or br"
6. `Connection: keep-alive` — "keep this connection open for the next file"
7. Blank line — "end of order"

Lines 2–6 (`name: value`) are **headers** (detailed in [request headers](post-methods-headers.md#headers)). The key point: **GET puts all its data in the address on the first line; the body is normally empty.**

```
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Content-Length: 18342

<!DOCTYPE html><html> ... (search results page) ...
```

`200 OK` = success, `Server: nginx` = the server software introducing itself, `Content-Type` = what's in the box, `Content-Length: 18342` = size in bytes. Response codes are listed on [HTTP status codes](../../../basics/http-status-codes.md).

### Why passwords must never go in a GET { #get-logging }

Whatever is in the address is **written to the logs verbatim** — web servers and proxies normally record the full URL. If a company app wrongly implemented login as GET, the Apache access log (Combined format) would contain:

```
10.1.5.23 - - [24/Oct/2026:18:15:02 +1100] "GET /login.php?user=jsmith&pass=Winter2026! HTTP/1.1" 302 215 "https://app.corp.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

| # | Value | Meaning |
| --- | --- | --- |
| 1 | `10.1.5.23` | Client IP |
| 2 | `-` | ident (legacy, always empty today) |
| 3 | `-` | HTTP-auth username (none) |
| 4 | `[24/Oct/2026:18:15:02 +1100]` | Time (`+1100` = Sydney daylight time) |
| 5 | `"GET /login.php?user=jsmith&pass=Winter2026! HTTP/1.1"` | Full request line — **password in clear text** |
| 6 | `302` | Status ("go to another page") |
| 7 | `215` | Response size (bytes) |
| 8 | `"https://app.corp.local/"` | Referer (previous page) |
| 9 | `"Mozilla/5.0 ..."` | User-Agent |

That one line is copied to the web server, the proxy and the SIEM.

**[Added] Two more leak paths.**

- **Browser history** — the address is saved as-is
- **Referer** — the "I just came from this page" note attached to new requests. If a page with the password in its URL loads an external image or link, that URL can travel to a third party. Modern browsers send only the domain to other sites by default, but site settings can change that

So logins, uploads and large data go in the body with [POST](post-methods-headers.md#post).

### Spotting attacks in GET { #get-attacks }

Whatever an attacker sends with GET is logged too.

**Attack 1: SQL injection.** The server slots parameter values into a database question (`id=1` → "show product 1"). The attacker puts in **characters that rewrite the question itself**.

```
GET /product.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1
```

Decoded: `id=1' OR '1'='1` → "show product 1, **or anything where 1 equals 1**". 1=1 is always true, so every row comes back. **Quotes, `OR`, `UNION` or `--` where a number belongs = suspicious.**

**Attack 2: Path traversal.**

```
GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
```

Decoded: `../../../etc/passwd`. `../` means "one folder up". Using [URL path = disk path](#web-servers) in reverse, the attacker climbs three levels out of the shelf to read Linux's account list. On Windows it looks like `..\..\windows\win.ini`.

**Attack 3: A C2 beacon disguised as GET.** C2 (Command and Control) is the attacker's server that remote-controls infected PCs; a beacon is the infected PC's regular "still alive — any orders?" call.

```
GET /images/logo.gif?id=YWRtaW4tUEMx HTTP/1.1
Host: cdn-static-assets.example.net
```

It looks like an image request, but `id` is **Base64** — a way of rewriting any data as letters, digits, `+`, `/` and `=`. It is gift wrapping, **not encryption**. Decoded it reads `admin-PC1`, the infected PC's name. The decisive clue is the **repetition**: the same PC hitting the same URL exactly every 60 seconds, day and night, is a program, not a person. See [Beaconing & C2 detection](../../../network/beaconing-c2.md).

### What "GET is for small data" really means { #get-size }

Servers cap address length (roughly 8 KB for the request line in default Apache and NGINX configs). That does **not** mean GET can't exfiltrate much: attackers chop data into thousands of GETs or hide it in cookies — moving a sack of rice one spoonful at a time. Watch **how many requests go to the same destination, and how regularly**, not the size of one request.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    Web server structure, URL anatomy, the shape of GET, and "whatever goes in the address gets logged" all still hold. In HTTP/2 and HTTP/3, GET and paths mean the same thing; only the wire format became binary. Web shells remain the most common artefact after a web server compromise, and "web server process → shell" parent-child detection is still a basic skill.

!!! info "[Changed]"
    - **Almost the whole web is HTTPS.** On the wire, paths, parameters and headers are encrypted; you mostly see the **SNI** (the site name announced at the start of the encrypted conversation — the name on the outside of the envelope). Paths and parameters now come from TLS-inspecting proxies, web server logs, WAFs and EDR. ECH (Encrypted Client Hello) is starting to hide even the SNI.
    - **Web server rankings.** W3Techs, October 2026: Cloudflare 32.5%, NGINX 30.3%, Apache 21.4%, LiteSpeed 14.0%, IIS 2.9%. Cloudflare is a **CDN** (a delivery-agent chain), so `Server: cloudflare` is the agent answering; the real (origin) server is hidden.
    - **IIS is still a key target inside companies.** Exchange and SharePoint run on IIS. In the July 2025 "ToolShell" attacks (CVE-2025-53770), attackers planted a `spinstall0.aspx` web shell on on-premises SharePoint and stole the **MachineKey** — the server's official seal for "data I genuinely produced". With the seal they could forge trusted data and get back in even after patching, so the key had to be rotated as well.
    - **Limits of "web server = file sharing".** With APIs and SPAs, a path like `/api/v2/users/1234/orders` is a **route** defined in code, not a file. Normal paths are long and complex, so eyeballing them without a baseline is harder.
    - **"No secrets in GET" is now a standard.** OAuth's old Implicit Grant (behind "Sign in with Google" style flows) put the access token after `#` in the URL. RFC 9700 (OAuth 2.0 Security Best Current Practice, January 2025) says not to use it.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **"One IP = one site" causes outages.** One CDN IP fronts thousands of sites; blocking a "malicious IP" blocks legitimate sites too. Judge and block by domain and URL.
    - **Don't assume GET is too small for exfiltration.** It gets chunked and repeated. Watch count and interval.
    - **Your SIEM can become a password store.** If any app sends passwords or tokens via GET, they pile up in the SIEM. Review SIEM access, mask at ingestion and tell the app team.

## Practice questions { #quiz }

Answer first, then expand the explanation.

### Question 1

This link was found in a phishing email:

```
http://portal.office.com@198.51.100.7:8080/login?next=%2Fmail%2Finbox#step2
```

(a) Which computer and port does a click actually connect to? (b) Which part is never sent to the server and so never appears in proxy logs? (c) What does the `next` value decode to?

??? success "Answer and explanation"
    **(a)** Port **8080 on `198.51.100.7`**. `portal.office.com` before the `@` is just text in the "username" slot.

    **(b)** `#step2`. The fragment after `#` stays in the browser.

    **(c)** `%2F` = `/`, so `/mail/inbox`.

    The link combines three phishing tricks: ① a famous domain placed before `@` to fool the eye ② `next=/mail/inbox` to make it feel like a real "log in and we'll take you to your inbox" flow ③ `http`, not `https` — a genuine Microsoft login never uses unencrypted `http` or an IP with port 8080, and with `http` the typed password crosses the network like a postcard.

### Question 2

A company IIS web server log contains this line. What is most likely going on, and in the Windows Security log at the same moment, **which event ID** and **which parent-child relationship** should you look for?

```
2026-10-24 07:42:11 10.20.1.15 GET /uploads/avatar.aspx c=ipconfig+/all 443 - 185.220.101.4 Mozilla/5.0 200 0 0 312
```

(Hint: IIS field order = date, time, server IP, method, path, query, port, username, client IP, User-Agent, status, two sub-status codes, time taken)

??? success "Answer and explanation"
    **Most likely a web shell.** Four reasons:

    1. An executable `.aspx` file in `uploads`, a folder meant for pictures
    2. The parameter is `ipconfig /all` (`+` = space) — a command that dumps network settings, typical post-intrusion reconnaissance
    3. Status `200` — the server processed it, so the command probably ran
    4. The request came from an external IP — check its reputation

    **Look for Event 4688** with parent (`Creator Process Name`) **`w3wp.exe`**, child (`New Process Name`) **`cmd.exe`** or **`ipconfig.exe`**, and command line `ipconfig /all`.

    **Time trap:** IIS logs default to **UTC**, while Event Viewer shows the **server's local time**. On a Sydney server, IIS `07:42:11` appears around **18:42:11** in Event Viewer. Search for 07:42 and you'll wrongly conclude "no trace".

    **Next steps:** find when `avatar.aspx` was created → look around that time for the same IP uploading it (usually a POST) → pull every other command from that IP → decide on isolating the server. See the [Web shell / server playbook](../../../playbooks/webshell-server.md).

### Question 3

Threat intel says "IP `104.21.48.10` is hosting a phishing site", and a lookup shows it's a Cloudflare IP. Is blocking it at the firewall straight away a good response?

??? success "Answer and explanation"
    **No.** One Cloudflare IP can front thousands of sites, so it's like locking the whole apartment block. Legitimate business sites may break, and the phisher can easily move to another IP, so the block won't last.

    **Better:**

    1. Get the **phishing domain / URL** from the intel and block that (proxy URL/domain blocking, DNS blocking / RPZ)
    2. Search proxy and DNS logs for **staff who already visited** it to scope the impact
    3. Report it to Cloudflare's abuse channel if appropriate
