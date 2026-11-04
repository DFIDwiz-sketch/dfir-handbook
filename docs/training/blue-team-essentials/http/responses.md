---
title: "Response Headers and Status Codes"
tags:
  - training
  - blue-team
  - http
  - concept
---

# Response Headers and Status Codes { #responses }

!!! abstract "What this page covers"
    The headers a server sends back (Server, Date, Content-Type, Content-Length, Last-Modified, Set-Cookie, plus the must-know Location and Content-Disposition), catching a server's lies with magic bytes, reading status codes (1xx–5xx) from a SOC point of view, "what if nothing follows a 407?", and dissecting an 8-byte response. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Correction]** = fixes a commonly stated mistake, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The request side is on [POST, Other Methods and Request Headers](post-methods-headers.md) and [Judging Requests](reading-requests.md).

## Ten key points { #key-points }

1. The request tells you what was asked for; the response tells you what was actually received. Look at both.
2. Content-Type is the server's **claim**. Verify the real content with magic bytes (e.g. `MZ` for executables) and Zeek's `resp_mime_types`.
3. A mismatch between Content-Type and `resp_mime_types` is a strong signal.
4. For size, trust bytes your sensor counted (Zeek `response_body_len`) over the Content-Length header.
5. `Location` is where the client goes next; `Content-Disposition` is the file name actually saved on the user's PC.
6. First digit of the status: 1 = hold on, 2 = success, 3 = go elsewhere, 4 = client's fault, 5 = server's fault.
7. The key question: did a malicious request get a 200 (or 201/206)?
8. Look for a 200 inside a 404 storm, 401 storms (password guessing), and a 500 right after odd input (a vulnerability signal).
9. A program that gets a 407 and never authenticates, retrying on a fixed interval, doesn't know the proxy — often malware.
10. Status codes are chosen by the server too. "It's a 404, so nothing happened" is a dangerous conclusion.

## Response headers { #response-headers }

**Why it matters.** If request headers are the customer's notes on the order, response headers are **the delivery slip the kitchen sticks on the box**: who made it, when it was sent, what's inside, how big it is. Requests only show what was asked for; responses show what was actually received.

Headers either describe the response itself (`Server`, …) or the content in the box (`Content-Type`, `Content-Length`, `Content-Encoding`, …). The latter used to be called "entity headers"; since RFC 9110 (June 2022) the official terms are "representation" / "content" headers.

```
HTTP/1.1 200 OK
Server: Apache/2.4.62 (Ubuntu)
Date: Sun, 01 Nov 2026 08:55:12 GMT
Content-Type: application/pdf
Content-Length: 482113
Last-Modified: Fri, 30 Oct 2026 23:10:04 GMT
Set-Cookie: sessionid=a91f3c7e2b; Path=/; Secure; HttpOnly; SameSite=Lax

%PDF-1.7 ... (file bytes) ...
```

The first line is the **status line**: version (`HTTP/1.1`), status code (`200`) and a human-readable reason (`OK`). Headers follow; the content sits below the blank line.

### Server — the kitchen's name { #server }

The web server software and version that produced the response (here Apache 2.4.62 on Ubuntu).

- **Checking our own servers:** a detailed version lets attackers pick matching vulnerabilities straight away, so operators usually hide it (`Server: nginx`).
- **Profiling external servers:** like a User-Agent it's only a self-introduction and can say anything. Attacker servers mostly claim nginx or Apache too.

**[Added] Habits over names.** The same software always has the same header order, default error pages and TLS behaviour. Server fingerprinting (JARM, JA4S, JA4X, …) uses this to find C2 servers hiding on the internet — the server-side version of [header-order fingerprints](post-methods-headers.md#header-order).

### Date — when it was sent { #date }

When the server sent the response, **always in GMT (= UTC)**. `08:55:12 GMT` is 19:55:12 Sydney daylight time (+11 h). Useful for lining up timelines with your own logs, but an attacker's server can write anything, so treat it as a reference value.

### Content-Type — what's inside (the most important) { #content-type }

The server's statement of what kind of file is in the box, written as a **MIME type** (a scheme originally for labelling email attachments): `type/subtype`.

```
text/html                         ← web page
image/png                         ← PNG image
application/pdf                   ← PDF document
application/zip                   ← ZIP archive
application/x-dosexec             ← Windows executable (EXE/DLL)
application/x-msdownload          ← Windows executable (another common label)
application/octet-stream          ← "just bytes" — unknown/generic binary
application/vnd.openxmlformats-officedocument.wordprocessingml.document  ← .docx
```

Its big advantage is **mass searching in a SIEM**: with Content-Type in your proxy logs you can pull "every executable a company PC downloaded from outside last week" in one search.

But Content-Type is **what the server claims**. An attacker's server can send an executable labelled `image/png`.

**[Added] Catching the lie: magic bytes.** Most files start with a few signature bytes. Labels (Content-Type, extension) can be swapped; change the signature and the file breaks.

```
4D 5A           "MZ"      ← Windows executable (EXE, DLL)
25 50 44 46     "%PDF"    ← PDF
50 4B 03 04     "PK.."    ← ZIP (also .docx, .xlsx, .jar, .apk — they are ZIP inside)
89 50 4E 47     ".PNG"    ← PNG image
FF D8 FF                  ← JPEG image
D0 CF 11 E0               ← old Office file (.doc, .xls) and .msi
```

`MZ` is the initials of Mark Zbikowski, who designed the MS-DOS executable format. `.docx`, `.xlsx` and `.jar` are ZIP inside, so they also start with `PK`.

Zeek's `resp_mime_types` in `http.log` is determined **from the content's magic bytes**, not the server header. So **a server Content-Type that disagrees with Zeek's `resp_mime_types` is a strong signal**.

**Content sniffing.** Without a Content-Type, some browsers guess the type from the content — which can be abused to run a script hidden in a fake image. Modern servers send `X-Content-Type-Options: nosniff`: "don't guess, use what I said".

### Content-Length — how big { #content-length }

The body size in bytes. Use the response's Content-Length to find **the largest downloads** and the request's to find **the largest uploads** (an exfiltration clue).

**[Added] Content-Length is often missing.** If the server doesn't know the size in advance it uses `Transfer-Encoding: chunked`, and HTTP/2 and HTTP/3 often omit it. Bytes **actually counted on the wire** (Zeek `response_body_len`, `request_body_len`) are more trustworthy.

### Last-Modified — when it last changed { #last-modified }

When the file on the server was last modified; its purpose is caching.

**[Correction] The main mechanism is a conditional GET, not HEAD.** The browser adds `If-Modified-Since: (previous Last-Modified)` to a GET, and if nothing changed the server replies **`304 Not Modified`** with no body. Comparing an `ETag` fingerprint (`If-None-Match`) instead of a date is also common.

**[Added]** On a malicious file's response, Last-Modified hints at **when the attacker uploaded or changed it**. It can be forged, so it's a reference value.

### Set-Cookie — putting on the wristband { #set-cookie }

The server says "store this cookie and show it with every request"; it comes back in later `Cookie:` headers ([Cookie](post-methods-headers.md#cookie)).

| Attribute | Meaning |
| --- | --- |
| `Secure` | Only send over HTTPS |
| `HttpOnly` | Page scripts can't read it → harder to steal via XSS |
| `SameSite=Lax` | Don't attach it freely to requests started from other sites |
| `Path=/` | Valid across the whole site |

For analysts, **the moment a server issues a fresh session cookie right after a successful login** matters — it's exactly the Set-Cookie that AiTM phishing intercepts.

### [Added] Location and Content-Disposition { #location-disposition }

```
HTTP/1.1 302 Found
Location: https://cdn.example.net/files/update.zip

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice_2026-10.pdf.exe"
```

- **`Location`** — "not here, go to this address". Sent with 3xx codes, it tells you **where the client went next**. Phishing and malvertising chain several redirects; follow the Locations to rebuild the path.
- **`Content-Disposition: attachment; filename="..."`** — "don't display this, **save it under this name**". Even if the URL is `/dl?id=8812`, the real saved name is here — in this example a double-extension `.pdf.exe`. Decisive when asking "where did this file in Downloads come from?"

## Status codes { #status-codes }

**Why it matters.** The status code is the kitchen's **one-line verdict** on the order. Analysts use it to tell whether something was actually retrieved, and if something went wrong, whether the client or the server caused it and what the issue was.

```
1xx  Informational   ← "hold on, keep going"
2xx  Success         ← "here you go"
3xx  Redirection     ← "not here, go over there"
4xx  Client error    ← "customer's fault"
5xx  Server error    ← "kitchen's fault"
```

| Code | Meaning | How a SOC reads it |
| --- | --- | --- |
| 100 Continue | "Keep sending the body" | Reply to `Expect: 100-continue` before a big POST; rarely security-relevant |
| 101 Switching Protocols | "Let's change how we talk" | Usually starts a **WebSocket**; what follows barely appears in normal HTTP logs — a possible C2 hiding place |
| 200 OK | Success | A 200 on a malicious request means execution or download probably happened |
| 201 Created | Created something new | External PUT + 201 = suspect web-shell upload |
| 204 No Content | Success, nothing to return | Also used as a beacon's "no tasks" reply |
| 206 Partial Content | Sent part of it | Resumed downloads; Windows BITS produces many, and attackers use BITS for quiet downloads → many 206s adding up to one executable |
| 301 / 308 | Moved permanently | Typically http → https |
| 302 / 307 | Temporarily elsewhere | **The travel path.** Phishing, malvertising and TDS chain them; follow Location |
| 304 Not Modified | Unchanged, use your copy | Caching; usually normal |
| 400 Bad Request | Malformed request | Real browsers don't make syntax errors → hand-crafted requests or attack tools |
| 401 Unauthorized | Log in first (not yet authenticated) | A 401 storm from one source = password guessing / spraying |
| 403 Forbidden | We know who you are, but no | Knocking on forbidden areas such as admin pages |
| 404 Not Found | Not here | A 404 storm = a scanner; **find the 200s** in between |
| 405 Method Not Allowed | Method not accepted | Traces of PUT/DELETE attempts |
| 407 Proxy Auth Required | Authenticate to the **proxy** first | See "reading between the lines" below |
| 421 Misdirected Request | Can't serve that site on this connection | SNI/Host mismatch (e.g. domain fronting attempts) |
| 429 Too Many Requests | Too many requests | Automated attacks hitting a rate limit |
| 500 Internal Server Error | Server-side error | A 500 straight after odd input (e.g. SQL injection) = the input broke server code = **a vulnerability signal** |
| 502 / 504 | Backend didn't answer | Failures behind a proxy or load balancer |
| 503 Service Unavailable | Can't cope | Overload/maintenance; suspect DoS |

If 401 vs 403 is confusing: 401 is not showing your staff badge at the front door; 403 is showing it but heading for a floor you're not cleared for.

### Reading between the lines: nothing after a 407? { #proxy-407 }

If the company proxy authenticates automatically with Windows credentials, a normal browser or any program using Windows' own networking stack (WinINet, WinHTTP) answers a 407 immediately and **silently** with Kerberos/NTLM and retries.

```
20:15:02.101  10.1.5.23  -        CONNECT login.microsoftonline.com:443  407
20:15:02.188  10.1.5.23  jsmith   CONNECT login.microsoftonline.com:443  200
```

The first request has no username and gets a 407; less than 0.1 s later the same request returns as `jsmith` and gets a 200. The user notices nothing.

```
20:15:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:16:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:17:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:18:00  10.1.5.40  -  CONNECT update-svc.example:443  407
```

It gets a 407, **never tries to authenticate**, and repeats exactly a minute later. This program doesn't know how to authenticate to the company proxy — typically **malware carrying its own HTTP code**. A one-minute interval makes it a beacon.

**The failed traffic is the clue.** The malware never reached its C2, yet it keeps announcing itself in the proxy log. And you can only see this is odd if you **know your normal flow first (407 → authenticate within 0.1 s → 200)**. The baseline is where detection starts.

!!! warning "[Caution] Not every silent 407 is malware"
    Legitimate software that isn't proxy-aware (some updaters, developer tools, old programs) produces the same pattern. Confirm **which program made the connection** on the host (Sysmon Event ID 3) before concluding.

## Reading practice: an 8-byte web page { #reading-response }

```
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 08 Feb 2021 14:21:07 GMT
Content-Type: text/html
Content-Length: 8
Connection: keep-alive

........
```

| Field | Explanation |
| --- | --- |
| `200 OK` | Success; the server returned something |
| `Date` | Sent on Monday 8 February 2021; line it up with your proxy log to confirm it's the same event |
| `Content-Type: text/html` | **Claims** to be a web page; between malware and a malicious server it could be deliberately misleading |
| `Server: nginx` | No version. nginx shows its version by default (`nginx/1.24.0`), so the operator hid it (`server_tokens off`) — also a common legitimate hardening step |
| `Content-Length: 8` | An **8-byte** body |

**[Added] What an 8-byte web page suggests.** The shortest HTML skeleton (`<html></html>`) is 13 bytes, so 8 bytes can't be a page meant for people. It's more likely a short signal for a program (`OK`, `0`, `noop`, a short token). It could be legitimate (health checks, ad-tracking replies), but if **the same PC gets it on a fixed interval, always the same size**, it's the classic shape of a C2 beacon's "no tasks" reply. When **one suddenly larger response** appears, that's the moment real commands or extra malware arrived. In beacon analysis, **response-size patterns** matter as much as intervals.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    Reading response headers (especially Content-Type, Content-Length, Set-Cookie), the meaning of status codes, and "silence after a 407 = a program that doesn't know the proxy" all still hold. In authenticated-proxy environments it remains a useful detection idea.

!!! info "[Changed]"
    - **HTTP/2 and HTTP/3 have no "OK".** The reason phrase is gone; only the number travels (`:status: 200`). A tool showing "200 OK" is adding the text itself.
    - **`421 Misdirected Request` shows up in practice** — what CDNs return when SNI and Host don't match, e.g. domain fronting attempts ([Domain fronting](post-methods-headers.md#domain-fronting)).
    - **Content-Length is less reliable.** Chunked transfer, HTTP/2/3 and compression mean it's often absent or different from the real size.
    - **Security response headers are now standard.** `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` and `Content-Security-Policy` are on most legitimate services, so a page imitating a big brand with none of them is a weak hint of a hastily built phishing page.
    - **Authenticated proxies are less common.** With cloud secure web gateways (SWG) or endpoint agents, the 407 trick doesn't apply; look instead for **connections that bypass the agent and go out directly**.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Content-Type is only a claim.** Extensions and Content-Type can both lie; judge by magic bytes, `resp_mime_types` and file hashes.
    - **"It's a 404, so nothing happened" is dangerous.** Some C2 frameworks return **fake 404s** so the server looks dead to scanners and researchers, delivering real commands inside the 404 body or only under certain conditions. A 404 that is large, varies in size or repeats on a schedule is suspicious.
    - **Date, Last-Modified and Server are server-written too.** Times and sizes recorded by your own devices are the primary evidence.

## Practice questions { #quiz }

Answer first, then expand the explanation.

### Question 1

The company proxy authenticates automatically with Windows credentials. Most PCs show "407 → a 200 with a username within 0.1 s", but one PC logs this all night:

```
01:00:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:05:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:10:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:15:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
```

(a) What does the pattern tell you? (b) Why shouldn't you call it malware straight away, and what would you check to decide? (c) Why is it a danger sign even though the C2 connection failed?

??? success "Answer and explanation"
    **(a)** Some program on this PC tries to reach `cdn-sync-api.example` **exactly every five minutes, all night with nobody there**, gets a 407 and **never attempts to authenticate**. It doesn't know the company proxy — it isn't using Windows' networking stack but its own HTTP code. With the mechanical interval, it's beacon-shaped.

    **(b)** **Legitimate software** that isn't proxy-aware (sync tools, updaters, developer tools, old programs) makes the same pattern, and `cdn-sync-api` could pass for a real sync service. To decide:

    1. **Which program** — EDR or **Sysmon Event ID 3** (network connection: which executable connected to which IP and port) for the process connecting to the proxy, and its executable path
    2. Where the file lives (odd places like `AppData`, `Temp`?), its digital signature and hash reputation
    3. How it starts automatically (scheduled task, service, Run key or other persistence)
    4. The domain's first-seen date, registration date and reputation
    5. Whether the same PC has connections that bypassed the proxy and went **straight out through the firewall**

    **(c)** Why it's dangerous despite failing:

    - It proves **an unknown program is persistently running** on the PC — infection and persistence already succeeded.
    - Once the attacker notices, they may push a proxy-aware version or try another channel (DNS tunnelling, direct connections).
    - Other variants may be succeeding on other PCs; hunt for the same domain and pattern across the organisation.
    - The failure buys you **time** to find and remove it before it succeeds.

### Question 2

Zeek `http.log` and the response header for the same request:

```
http.log:  method=GET  host=static-img-cdn.example  uri=/img/banner.png
           status_code=200  resp_mime_types=["application/x-dosexec"]
           response_body_len=1245184

Response header:  Content-Type: image/png
```

(a) What did the server say was inside, and what did Zeek see? Which do you trust, and why? (b) What are the first two bytes of the content most likely to be, in hex? (c) What next?

??? success "Answer and explanation"
    **(a)** The server **claims** `image/png`; Zeek inspected the content and saw `application/x-dosexec` (a Windows executable). **Trust Zeek**: Content-Type is a label the server writes freely, while `resp_mime_types` is based on the content's magic bytes. At about 1.2 MB the size is large for a banner and natural for an executable. Extension (`.png`), path (`/img/`) and Content-Type all disguise an executable as an image.

    **(b)** **`4D 5A` ("MZ")** — the Windows executable signature.

    **(c)**

    1. **Get the file** — the matching Zeek `files.log` record (the extracted copy, if file extraction is on) or an export from packet capture
    2. **Hash it (SHA-256) and check reputation**; analyse in an isolated sandbox if needed
    3. **Who fetched it** — the PC and User-Agent. A normal browser won't execute an executable fetched as an image, so a **downloader program** that deliberately fetches disguised payloads is probably already on the PC → Sysmon Event ID 3 for the process
    4. **Did it run** — Sysmon Event ID 11 (file create) to see if it hit disk, Sysmon 1 / 4688 (process create) for that hash executing
    5. Block the domain, find other PCs that fetched the same URL or hash, isolate the PC if needed

### Question 3

One PC requests the same external address exactly every five minutes:

```
02:00  GET /status  →  404 Not Found   Content-Length: 0
02:05  GET /status  →  404 Not Found   Content-Length: 0
02:10  GET /status  →  404 Not Found   Content-Length: 0
02:15  GET /status  →  404 Not Found   Content-Length: 18736
02:20  GET /status  →  404 Not Found   Content-Length: 0
```

A colleague says: "It's all 404s, so there's nothing there. Ignore it." What's wrong with that reasoning, and what might the 02:15 response mean?

??? success "Answer and explanation"
    **What's wrong:**

    1. **Status codes are chosen by the server.** A C2 server can return 404 on purpose to look dead to scanners and researchers.
    2. A PC has no reason to hit "an address with nothing there" **exactly every five minutes at 2 a.m.** The interval itself is a beacon signal.
    3. A normal web server's 404 usually carries an HTML error page of **consistent size**. A 404 with a **0-byte** body every time is unusual in itself.

    **What 02:15 may mean:** normally 0 bytes ("no tasks"), then a single **18,736-byte** response. Most likely **real commands or extra malware delivered while disguised as a 404**. The return to 0 bytes afterwards is the classic "deliver task → back to idle".

    **Next:**

    1. Get **the actual content** of the 02:15 response (proxy cache, packet capture)
    2. Check host activity right after 02:15 — new processes (Sysmon 1 / 4688), new files (Sysmon 11), new connections (Sysmon 3)
    3. Look for other PCs contacting the same address; consider isolating the PC
    4. Lesson: **watch interval and size patterns over status codes**
