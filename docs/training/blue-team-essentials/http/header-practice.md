---
title: "Header Reading Practice — One Request, One Response"
tags:
  - training
  - blue-team
  - http
  - practice
---

# Header Reading Practice — One Request, One Response { #header-practice }

!!! abstract "What this page covers"
    Putting request- and response-header knowledge to work on one realistic request and one realistic response. For the request: site, port and file, where the user came from, what they were looking at, browser and OS, and the user's language. For the response: success, file type, server software, size, time, and "it says HTML, so why does it look like garbage?" Includes decompressing gzip by hand. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. What each header means is on [POST, Other Methods and Request Headers](post-methods-headers.md#headers) and [Response Headers and Status Codes](responses.md). All domains in the examples are invented.

## Eight key points { #key-points }

1. Read with a question list: where to (Host, port, path) → where from (Referer) → what about (Referer and path content) → with what (User-Agent) → who (Accept-Language).
2. A non-default port appears in Host (`:85`). Non-standard port + random path + unfamiliar domain = stacked signals.
3. If the Referer is an ordinary site (a forum, say) and the next destination is suspicious, first suspect **the ordinary site was compromised and injected a redirect**.
4. `Trident/4.0` is IE8; `Trident/7.0` is IE11 (and Edge's IE mode).
5. Accept-Language hints at the user's language; it isn't evidence of nationality or location.
6. `Content-Encoding: gzip` in a response means the body is compressed. Looking like garbage is normal; decompress to get the original.
7. gzip data starts with `1F 8B`. See those magic bytes, decompress first.
8. A very old server version (e.g. a decade-old nginx) signals an unmaintained server — possibly compromised, or attacker infrastructure.

## Exercise 1: reading request headers { #request-practice }

A request sent by a staff PC:

```
GET /Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq HTTP/1.1
Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, */*
Referer: http://www.fitness-forum-training.example/showthread.php?95-Lumbar-Flexion-when-squatting
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)
Accept-Encoding: gzip, deflate
Host: quietmeadow-ledger.example:85
Connection: Keep-Alive
```

Answer these five:

1. Which site, port and file is the user accessing?
2. Which site sent the user to this new site?
3. What content was the user looking at?
4. What browser and OS is the client using?
5. What language does the user probably speak?

??? success "Answer and explanation"
    **1. Site, port, file.** Host shows `quietmeadow-ledger.example` on **port 85** — not HTTP's default 80, so `:85` is included in Host. The file is the long random string after `GET`: `/Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq`. Joining Host and path gives `http://quietmeadow-ledger.example:85/Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq`. Non-standard port, random path and unfamiliar domain all stack up.

    **2. Referring site.** Per the Referer, the user was just on `www.fitness-forum-training.example`.

    **3. What they were viewing.** The Referer path `showthread.php?95-Lumbar-Flexion-when-squatting` is a **workout-forum thread** about lumbar flexion when squatting. Jumping from an ordinary forum post to a randomly named site on a non-standard port is odd. Two interpretations:

    - **The forum was compromised** and an automatic redirect (hidden iframe, injected script) was planted → the user was dragged along without clicking anything; the classic first step of the exploit-kit era
    - The user **clicked a link** in the post → someone planted a malicious link in a post or comment

    Either way, suspect the forum itself.

    **4. Browser and OS.** `MSIE 8.0` and `Trident/4.0` = **Internet Explorer 8**; `Windows NT 6.1` = **Windows 7**. Browsers of that era were prime drive-by targets because of plugin vulnerabilities. The `Accept` values `application/x-ms-application` and `application/xaml+xml` are also typical of IE then, consistent with the User-Agent — this looks like **the victim's real browser**, not a fake.

    **5. Language.** `Accept-Language: en-US` → most likely an English (US) speaker. It's only a browser language setting, not evidence of nationality or location.

    **Overall:** "ordinary forum → random domain, non-standard port, random path" is the shape of a malicious redirect via a compromised site. Next, check this request's **response** (what was received), the following requests (any further downloads), and other staff who visited the same forum.

### [Added] Seeing an IE-style User-Agent in 2026 { #ie-mode }

IE8 on Windows 7 can't appear on a 2026 corporate PC, but the word `Trident` still can. Microsoft Edge has an **IE mode** for legacy internal systems, and pages opened in it send an IE11-style User-Agent:

```
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; rv:11.0) like Gecko
```

`Trident/7.0` and `rv:11.0` mark IE11. So `Trident` isn't automatically suspicious: first check **whether the destination is a legacy internal system registered for IE mode, or an external site**. An IE-mode User-Agent heading to an unfamiliar external site is either a faked value or out-of-policy use.

## Exercise 2: reading response headers { #response-practice }

A response returned by a server:

```
HTTP/1.1 200 OK
Server: nginx/0.7.67
Date: Tue, 29 Oct 2013 04:05:56 GMT
Content-Type: text/html
Content-Length: 2182
Connection: keep-alive
Content-Encoding: gzip

<binary-looking bytes: 1f 8b 08 00 00 00 00 00 00 03 ...>
```

Answer these six:

1. Was the page returned successfully?
2. What type of file was returned?
3. What software is the server running?
4. How big is the file?
5. When was the response sent?
6. It says HTML — why doesn't the content look like HTML?

??? success "Answer and explanation"
    **1. Success.** `200 OK` on the first line.

    **2. File type.** `Content-Type: text/html` → the server **claims** an HTML page.

    **3. Server software.** `Server: nginx/0.7.67` → nginx **0.7.67**, a very old version from around 2010. Two implications:

    - The version isn't hidden and hasn't been updated in over a decade — likely an **unmaintained server**, possibly already compromised and serving malicious content
    - Or attacker infrastructure hastily stood up from old images or tooling

    **4. Size.** `Content-Length: 2182` → 2,182 bytes — but that's **the compressed size**; it's larger once decompressed.

    **5. Time sent.** `Date: Tue, 29 Oct 2013 04:05:56 GMT` → 29 October 2013, 04:05:56 UTC (15:05:56 Sydney daylight time). Plausible for an old packet capture. If traffic captured today showed a server date years off, the server's clock is broken (an abandoned server) or the value is deliberately faked.

    **6. Why it doesn't look like HTML — `Content-Encoding: gzip`.** The server **gzip-compressed** the HTML. Content-Type describes the original content once unpacked; Content-Encoding describes how it's currently packed. Raw on the wire it looks like binary garbage, which is normal. The first bytes `1f 8b` are **gzip's magic bytes**. To extract and analyse the file you must decompress it first (see [Decompressing gzip](#gunzip)).

### [Added] Content-Type vs Content-Encoding { #type-vs-encoding }

As a parcel:

| Header | Analogy | Example |
| --- | --- | --- |
| `Content-Type` | What **item** is in the box | `text/html` = a web page |
| `Content-Encoding` | How the item was **packed** | `gzip` = vacuum-packed |

The request's `Accept-Encoding: gzip, deflate` is the customer saying "you can vacuum-pack it, I can open that"; the response's `Content-Encoding: gzip` is the kitchen replying "so I did". Brotli (`br`) and Zstandard (`zstd`), which compress better than gzip, are now common too.

### [Added] Decompressing gzip by hand { #gunzip }

Most analysis tools (Wireshark's "Export Objects → HTTP", Zeek, …) decompress gzip automatically, but if you carved bytes out of a capture yourself, you'll have to do it by hand.

First confirm it's gzip from the first bytes:

```
$ od -An -tx1 -N16 body.bin
 1f 8b 08 00 00 00 00 00 00 03 b3 c9 28 c9 cd b1
```

- `od` — Linux command that dumps a file byte by byte
- `-An` — omit the offset column on the left
- `-tx1` — print one byte at a time in hex
- `-N16` — only the first 16 bytes
- `1f 8b` is the gzip magic; the following `08` is the compression method (deflate)

Then decompress:

```
$ python3 -c "import gzip; print(gzip.decompress(open('body.bin','rb').read()).decode())"
<html><body>hello analyst</body></html>
```

- `python3 -c "..."` — run the quoted Python as a one-liner
- `open('body.bin','rb').read()` — read the file as raw bytes
- `gzip.decompress(...)` — undo the gzip compression
- `.decode()` — turn bytes into text for display
- Result: the original HTML

On Linux `gunzip -c body.bin` works too, as does CyberChef's "Gunzip". **Handle suspicious files only in an isolated analysis environment.**

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    Reading requests and responses with a question list, tracing "where from" via Referer, and checking Content-Encoding first and decompressing before analysis all still hold.

!!! info "[Changed]"
    - **More compression schemes.** Besides gzip and deflate, Brotli (`br`) is very common on the web, and Zstandard (`zstd`) has started appearing in major browsers and CDNs. If your tool can't decode the scheme the content looks garbled, so check Content-Encoding first.
    - **In HTTP/2 and HTTP/3 the headers themselves are compressed** (HPACK, QPACK). That's separate from body compression (Content-Encoding); reading the headers needs a tool that understands the version.
    - **IE-family User-Agents have nearly vanished**, but Edge IE mode's `Trident/7.0` still shows up on access to legacy internal systems.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Content-Length is the compressed size.** The decompressed size and file hash differ from the compressed form. When comparing with threat-intel hashes, hash **the decompressed file**.
    - **Don't infer an attacker's nationality from Accept-Language.** It's a browser setting, and attack tools can send anything.
    - **Don't wave through an ordinary-looking Referer such as a forum.** Compromised legitimate sites are a frequent starting point for malicious redirects.

## Practice questions { #quiz }

### Question 1

This User-Agent appears from a company PC. Should it be treated as malicious automatically? What would you check?

```
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; rv:11.0) like Gecko
```

??? success "Answer and explanation"
    **Not automatically.** `Trident/7.0` and `rv:11.0` are IE11-shaped, and in 2026 that mostly means **Edge's IE mode**. Many organisations register legacy internal systems (old HR or approval systems) to open in IE mode.

    Check:

    1. **The destination** — an **internal system** registered for IE mode, or an external site?
    2. If it's an unfamiliar external site → out-of-policy use or a **faked User-Agent** (malware or a tool)
    3. The process that made the connection (Sysmon Event ID 3) — `msedge.exe`, or something else?

### Question 2

A response has only `Content-Type: text/html` and **no `Content-Encoding` header**, yet the body starts with `1F 8B`. What's odd, and what should you do?

??? success "Answer and explanation"
    `1F 8B` is **gzip's magic**. Normally the server would add `Content-Encoding: gzip` so the browser knows to decompress it and show HTML. Without it, a browser sees "broken HTML" — so this response is probably **not a page meant for a person in a browser**.

    Two possibilities:

    - A server misconfiguration (rare, but it happens)
    - **Compressed data disguised as HTML** for a malicious program to unpack itself → extra malware or configuration fetched by a downloader

    Do: carve out the body, **decompress it**, check the magic bytes of the result again (e.g. `MZ`) → hash it and check reputation → identify the requesting process (Sysmon Event ID 3) and User-Agent on that PC. It's the same "declared type ≠ real content" signal as in [response headers](responses.md#content-type).

### Question 3

Like Exercise 1, several staff PCs show requests from an ordinary workout forum (Referer) to a random domain. What should you do about the forum?

??? success "Answer and explanation"
    Several staff following the same pattern from the same forum points to **a compromised forum with an injected redirect** (more likely than everyone clicking the same link).

    1. **Scope:** use proxy and DNS logs to find every staff member who visited the forum and the PCs that went on to the suspicious domain
    2. **Next stage:** what those PCs received (response Content-Type, `resp_mime_types`, size) and whether new processes or files appeared afterwards
    3. **Analyse the forum page:** fetch the page source **only in an isolated analysis environment** and look for injected scripts or hidden iframes (never open it on a company PC)
    4. **Block:** the redirect destination domain; decide on temporarily blocking the forum itself by weighing business impact and risk
    5. **Notify:** tell the forum operator it has been compromised
