---
title: "2.1 — Reading HTTP Requests: Methods, URIs and Request Headers"
tags:
  - training
  - network-forensics
  - http
---

# 2.1 — Reading HTTP Requests: Methods, URIs and Request Headers { #http-requests }

!!! abstract "Scope of this lesson"
    - Why HTTP: traces gone from the disk remain on the wire
    - HTTP's nature (text-based, stateless) and version history. [Changed] the current standards for HTTP/1.1, 2 and 3
    - The four parts of a request: request line, headers, blank line, body
    - Methods: [Correction] the methods a server must support are GET and **HEAD**, and the difference between "safe" and "idempotent"
    - The request target (URI), query strings and percent-encoding
    - Request headers one by one: Host, User-Agent, the Accept family, Cookie, Authorization, X-Forwarded-For, Referer
    - [Changed] What browsers send today: Referer policy, Client Hints, `Sec-Fetch-*` (checked with Chromium requests captured directly)

!!! note "Lab environment and notation"
    **(Actual output)** was produced in this environment. Browser requests were actually sent by the built-in Chromium (headless, version 153.0.8010.12), driven with Playwright, to a practice web server (Python `http.server`) on loopback; the server recorded the headers it received verbatim while tcpdump captured the traffic. Command-line requests were sent with `curl` 8.5.0. People and accounts in the scenarios are hypothetical, and external addresses use documentation ranges only.

## 1. Not on the disk, but on the wire { #why-http }

**(Hypothetical)** Another employee at lesson 1.4's research institute comes under investigation. This time the laptop is locked with full-disk encryption, and the employee reportedly used the browser only in **private mode**, possibly a portable browser carried on USB. Recovering web activity by disk forensics looks hard.

What remains in such cases is **the path the activity took** (lesson 1.1). Web activity almost all travels over HTTP, and its records end up in proxy logs (lesson 1.3), full packets (lesson 1.6), and the web server logs and Zeek logs covered in coming lessons. Reading HTTP is almost unavoidable in investigations.

- **People's web activity:** which pages were viewed and what was downloaded. A frequent question in employee misconduct and criminal cases.
- **Programs talking to each other (APIs):** HTTP today is as much the channel for **APIs**, through which programs exchange data with other services, as for web pages people look at. Knowing which software used which APIs can paint a fairly detailed picture of what happened on a system.
- **Malware command channels (C2):** much malware talks to its master over HTTP or HTTPS. Working with a malware analyst, you can learn what commands were exchanged and **what was taken**.
- **Web server compromise:** looking at the traffic itself, in addition to server logs and disk analysis, gives a more complete picture even if the attacker covered their tracks.

## 2. What kind of protocol is HTTP? { #what-is-http }

### 2.1 Letters written in text, letters that don't know each other { #text-stateless }

HTTP is a protocol of **requests and responses**. A letter analogy helps: the client writes "please send me this document" (the request), and the server writes back "here it is" (the response).

HTTP/1.x letters have two properties.

- **They're written in text.** The head of each request and response is readable letters and digits, exactly as seen when following a stream in lesson 1.9. So you can read a lot without tools.
- **Letters don't know about each other (stateless).** Each request and response stands on its own; the protocol itself doesn't remember earlier requests. When continuing state is needed, such as "logged-in user", a separate mechanism such as **cookies** is required (section 6.4).

Where the analogy differs: opening one web page actually involves not one letter but **tens to hundreds**. The page body, images, style sheets and scripts are each requested separately, from several servers. So behind the single sentence "they visited this site" lie hundreds of request lines, and sorting out which were **things the person actually did** is the investigator's job (section 6.7, lesson 2.4).

Traditionally HTTP uses TCP port 80 and HTTPS TCP port 443. But as lessons 1.9 and 1.12 showed, port numbers are just conventions; HTTP can travel on any port.

### 2.2 [Changed] Version history and today's standards { #versions }

| Version | First appeared | Characteristics | Current standard |
| --- | --- | --- | --- |
| HTTP/0.9 | 1991 | a single request line, no headers | should essentially never be seen |
| HTTP/1.0 | 1996 | headers and status codes appear | RFC 1945 (informational) |
| HTTP/1.1 | 1997 | `Host` required, connection reuse | **RFC 9110** (semantics), **RFC 9112** (message syntax), 2022 |
| HTTP/2 | 2015 | binary framing, multiplexing, header compression | **RFC 9113**, 2022 (replaces RFC 7540) |
| HTTP/3 | **2022** | runs over QUIC (UDP), TLS mandatory | **RFC 9114**, 2022 |

The source material cites RFC 2616 as the reference for HTTP/1.1; it was replaced by RFC 7230–7235 in 2014 and again by **RFC 9110–9112** in 2022. The source material also dates HTTP/3 to "2016" and describes it as "still in development", but HTTP/3 became a standard as **RFC 9114** in June 2022, and QUIC beneath it is RFC 9000 (2021). As lesson 1.2 showed, HTTP/3 (QUIC) uses UDP 443 and can therefore bypass proxies, which matters for investigations. HTTP/2 and HTTP/3 get their own treatment in lesson 2.3. This lesson and the next are based on **HTTP/1.1**. Methods, status codes and the **meaning** of headers stay the same across versions, so what you learn here carries over.

## 3. The four parts of a request { #request-anatomy }

Take a real request. This is what the server received when the built-in Chromium opened the practice server's `/start` page and clicked a link on it.

**(Actual output, exactly as the server received it)**

```http
GET /next?q=orchid+results HTTP/1.1
Host: 127.0.0.1:8201
Connection: keep-alive
sec-ch-ua: "HeadlessChrome";v="153", "Not_A Brand";v="8", "Chromium";v="153"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0.8010.12 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: http://127.0.0.1:8201/start
Accept-Encoding: gzip, deflate, br, zstd
```

```mermaid
flowchart TD
    A["Request line<br/>method · target · version"] --> B["Headers<br/>Name: value (one per line)"]
    B --> C["Blank line<br/>end of headers"]
    C --> D["Body<br/>only for POST etc."]
```

**How to read it:** top to bottom, in the order the request goes on the wire. Every line ends in `\r\n`, and **one blank line** marks the end of the headers. That's why lesson 1.13 looked for `\r\n\r\n` to cut off the body.

- **Request line (required):** `GET` (method), `/next?q=orchid+results` (request target), `HTTP/1.1` (version), separated by single spaces.
- **Headers:** one `Name: value` per line. In HTTP/1.1 only `Host` is required; the rest are **mostly optional**. That is, the sender can add, omit or fabricate them at will. Keep this in mind throughout the lesson.
- **Blank line:** the end of the headers.
- **Body:** usually absent on `GET` requests. Present on requests that send data, such as `POST` or `PUT` (the multipart body in lesson 1.13).

## 4. Methods: what is being requested? { #methods }

### 4.1 Common methods { #common-methods }

| Method | Meaning | What to note in investigations |
| --- | --- | --- |
| `GET` | give me the resource | The most common. Also sends values in the query string |
| `POST` | here's data, please process it | Form submissions, uploads, API calls. Content is in the body (usually not in logs, lesson 1.4) |
| `HEAD` | same as `GET`, headers only | Checks whether a file changed or how big it is. Also used by reconnaissance tools |
| `PUT` | create (replace) this location with this content | Can be used to upload files to a server. Notable if seen on a web server |
| `DELETE` | remove the resource at this location | Normal for APIs; odd on a static web server |
| `OPTIONS` | tell me what you support | Browser preflight (CORS) requests, scanners |
| `TRACE` | echo back the request you received | Diagnostic; mostly disabled. If seen, suspect a scan |
| `CONNECT` | open a tunnel | Used when a proxy relays HTTPS (lesson 1.2) |

Protocols that extend HTTP, such as WebDAV, use their own methods: `PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`. WebDAV, used like file sharing, can become an exfiltration channel, so when unfamiliar methods appear, first work out what protocol it is.

!!! warning "[Correction] The methods a server must support are GET and HEAD"
    The source material says "the only methods a server is required to support are GET and POST". The current standard, RFC 9110 section 9.1, states that "all general-purpose servers MUST support the methods **GET and HEAD**; all other methods are OPTIONAL" (RFC 7231 before it said the same). Many static web servers don't accept POST at all. This difference rarely matters in investigations, but a server responding oddly to `HEAD` can itself be a clue.

### 4.2 [Correction] "Safe" and "idempotent" are different { #safe-idempotent }

The source material describes GET as "idempotent", meaning the same request at a later time yields the same result without changing content on the server. The standard splits this into two concepts.

- **Safe:** the request **does not intend to change** server state. `GET`, `HEAD`, `OPTIONS`, `TRACE`.
- **Idempotent:** sending the same request **several times has the same effect as sending it once**. All safe methods plus `PUT` and `DELETE`, since `PUT`ting the same file twice or `DELETE`ing the same resource twice leaves the same result.
- `POST` is neither. `POST`ing the same order twice can create two orders.

**What this means for investigations:** these are **promises** only. As the source material notes, web apps that change state via GET, like `GET /delete.php?id=17`, are common, and attackers deliberately send commands by GET (most of the attack traces in web server logs in lesson 2.5 are GETs). So don't conclude "it was a GET, so nothing changed". The method is a **starting point** for guessing intent; confirm the actual effect from the response and server-side records.

## 5. The request target (URI) and query strings { #uri }

The middle of the request line is the **request target**, pointing to the resource the client wants. It's commonly called the URI, and logs also call it the "request string" or "URL".

```text
/next?q=orchid+results
└─┬─┘ └──────┬───────┘
 path    query string
```

- **Path:** once it pointed directly to folders and file names on the server's disk, but today a web app usually interprets the path and **generates** content. `/questions/34476646/forensic-...` looks like folders, but no such folders necessarily exist on the server.
- **Query string:** `name=value` pairs after `?`, joined with `&`. It's how a `GET` request passes values to the server: search terms, page numbers, tracking identifiers.
- **Percent-encoding:** characters not allowed in addresses become `%` plus two hex digits. Space is `%20`, `/` is `%2F`, and the Korean character "가" is three UTF-8 bytes, `%EA%B0%80`. In queries coming from forms, spaces may become `+`, as in `orchid+results` in the request above (lesson 1.13, question 2).

!!! info "[Supplement] The URI in logs may not be \"what a person read\""
    Logs and packets keep the encoded form (`%EA%B0%80`). Decode it to read search terms, and conversely, when searching by keyword, also search for **the encoded form**. Remember that the same character may appear with upper-case hex (`%2F`) or lower-case (`%2f`). Attackers also use double encoding (`%252F`) on purpose to evade filters.

## 6. Request headers one by one { #request-headers }

### 6.1 `Host` { #host }

**The only required header** in an HTTP/1.1 request. In **virtual hosting**, where one server (one IP address) runs many sites under different names, it says which site the request is for. So you can't say "they went to such-and-such site" from the IP address alone: one IP can host hundreds of sites (CDNs are the typical case), and `Host` (or SNI for HTTPS, lesson 1.2) tells you which. In HTTP/2 and HTTP/3, the `:authority` pseudo-header plays the same role (lesson 2.3).

### 6.2 `User-Agent`: a self-declared name { #user-agent }

The name the sending software **declares for itself**. It often contains the browser type and version and the operating system, which makes it good material for sketching a user's environment. But remember three things.

- **It can be changed at will.** It's an optional header by the standard, and a browser extension or a command-line option (`curl -A`) can put anything in it. The upload in lesson 1.13 claimed to be Firefox but was actually `curl`.
- **`Mozilla/5.0` means nothing.** It's a compatibility leftover from the days when old web sites chose features based on that string, so Chrome, Safari, Edge and Firefox all start with it.
- **Defaults are clues too.** In this lab, the request `curl` sent had only three headers.

**(Actual output)**

```http
GET /api/status HTTP/1.1
Host: 127.0.0.1:8201
User-Agent: curl/8.5.0
Accept: */*
```

The request Chromium sent to the same server (section 3) had fourteen headers. The **number, order and combination of headers** are more tedious to fake than the User-Agent string, so they're a supporting clue for judging whether a request came from a person's browser or an automated tool (lesson 2.4). Also, the headless Chromium in this lab put the word `HeadlessChrome` right into its User-Agent **(actual output)**: a trace that gives an automation tool away if it doesn't change it.

!!! info "[Changed] The User-Agent has shrunk, and Client Hints have appeared"
    In the source material's era, the User-Agent carried detailed OS versions and full browser versions. Since 2022 (Chrome 101), Chromium-based browsers have phased in **User-Agent reduction**, freezing the minor version numbers at `0.0.0` and sending a fixed OS version. More detail moved to **Client Hints** (`Sec-CH-UA-*` headers), sent only when the server asks; by default just three go out: `sec-ch-ua`, `sec-ch-ua-mobile` and `sec-ch-ua-platform`, as in the request above. So reading "the User-Agent says Windows 10, so it's Windows 10" can now be wrong (Windows 11 can send the same value). Note that this lab's headless Chromium sent its full version (`153.0.8010.12`). It may behave differently from ordinary desktop browsers, so in real cases test **that version of that browser** yourself before interpreting.

### 6.3 `Accept`, `Accept-Language`, `Accept-Encoding` { #accept }

These announce **what responses the client wants**: `Accept` for content types (MIME types), `Accept-Language` for languages, `Accept-Encoding` for compression. A trailing `q=0.9` is a preference weight (0–1).

In investigations, these too are **profile** material. For example, `Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8` suggests a user environment that prefers Korean. This lab's headless Chromium sent no `Accept-Language` at all, and its `Accept-Encoding` included `zstd`, which didn't exist in the source material's era **(actual output)**. If requests with a different combination suddenly appear from the same PC, that can signal a different program has started using HTTP.

### 6.4 `Cookie`: memory attached to a stateless protocol { #cookie }

As section 2.1 said, HTTP itself doesn't remember earlier requests. So the server leaves a small value with the client via the response's `Set-Cookie`, and the client returns it in a `Cookie` header on every later request. That's how logged-in state, shopping carts and user identification are maintained.

- **Session cookies:** have no expiry and disappear when the browser closes.
- **Persistent cookies:** stay on disk until a set expiry time.

In investigations, cookies are the thread linking **the same person (strictly, the same browser storage)** across requests and days. If the same cookie value keeps appearing as addresses change, it's probably the same browser. Advertising and analytics trackers' cookies even carry past information such as the time of the first visit, covered separately in lesson 2.3. Conversely, don't forget that **a session cookie is itself a login key**. Mishandling session cookies left in pcaps or logs is like walking into someone else's account.

### 6.5 `Authorization` and `Proxy-Authorization`: Base64 isn't encryption { #authorization }

Authentication through a login box the browser pops up (not a login form within the page) is called **HTTP authentication**, and its simplest scheme, `Basic`, puts `username:password` **converted to Base64** in a header. The request sent in this lab with `curl -u "jdoe:Spring2026!"` went out like this.

**(Actual output)**

```http
Authorization: Basic amRvZTpTcHJpbmcyMDI2IQ==
```

```bash
echo 'amRvZTpTcHJpbmcyMDI2IQ==' | base64 -d
```

**(Actual output)** `jdoe:Spring2026!`

Base64 is **a notation, not encryption**, so anyone can reverse it immediately (lesson 1.13). And Basic authentication sends this header **with every request**, so over plain HTTP the account is visible in any packet while the site is being used. In investigations it's a strong clue to the user's identity, and also very sensitive information, so mask it in reports.

- The **`Digest`** scheme doesn't send the password itself, but is rarely used today.
- **[Supplement] `Bearer` tokens:** today's APIs commonly send a token obtained at login, as in `Authorization: Bearer eyJ...`. If the token is a JWT, Base64-decoding the middle part reveals the issuer, user and expiry. Tokens, like session cookies, are **keys in themselves**.
- **`Proxy-Authorization`:** a header of the same form exchanged only between the client and the first proxy when a proxy requires authentication. This is how user names end up in the proxy logs of lesson 1.3.

### 6.6 `X-Forwarded-For`: an "original address" anyone can write { #xff }

A header that proxies and load balancers add when relaying a request, to convey the original client's address. Through several hops, addresses accumulate as `original client, first proxy, ...`.

The problem is that **the client can put it in from the start**. In this lab, sending `curl -H "X-Forwarded-For: 10.10.4.3"`, the server received the header as-is, even though the address that actually connected was `127.0.0.1` **(actual output)**.

```http
X-Forwarded-For: 10.10.4.3
```

`10.10.4.3` is the internal proxy address from lesson 1.1. If a web app trusts this header, as in "allow the admin screen for requests from the internal proxy", an attacker can get past that control with one header line, exactly as the source material warns.

**Investigative principle:** when you see `X-Forwarded-For` in logs, ask **who added it**. A value added by your own proxy or load balancer (the rightmost value, nearest your equipment) is trustworthy, but values already present to its left may have been written by the client. And whether that equipment **strips and rewrites** client-supplied values or **appends** to them depends on configuration, so check.

!!! info "[Supplement] Headers starting with `X-`, and the standard `Forwarded`"
    `X-` was a convention for non-standard extension headers, but RFC 6648 (2012) recommended against using the prefix for new headers. The already widespread `X-Forwarded-For` remained a de facto standard, and there's a formal standard header for the same purpose, `Forwarded` (RFC 7239, 2014). You may see both in logs. Other `X-` headers vary wildly by program, so an unusual `X-` header can become **a fingerprint of a particular program**.

### 6.7 `Referer`: where did they come from, and [Changed] how much does it say today? { #referer }

`Referer` (a spelling mistake in the original standard that stuck; the English word is referrer) is the address of **the previous page that led to this request**: the page holding the clicked link, or the page that loaded an image or script. Chaining requests by `Referer` lets you reconstruct **the path a user took between pages**. Of course, it's optional too and may be missing or faked.

The source material explains that "it shouldn't be sent when going from HTTPS to HTTP, but in practice a truncated value may go". Today's browsers additionally follow a **Referrer-Policy**, whose default when nothing is specified is `strict-origin-when-cross-origin` (in Chrome from 2020 and Firefox from around 2021, lesson 1.3). I tested three cases directly.

**(Actual output)**

| Navigation | `Referer` received by the server |
| --- | --- |
| Same origin: `http://127.0.0.1:8201/start` → `/next?q=...` | `http://127.0.0.1:8201/start` (full path) |
| Cross origin: `http://127.0.0.1:8201/start` → `http://localhost:8202/landing` | `http://127.0.0.1:8201/` (origin only, no path) |
| HTTPS → HTTP: `https://127.0.0.1:8443/secure` → `http://127.0.0.1:8202/plain` | **none** |

An "origin" is the combination of **scheme, host name and port**. `127.0.0.1` and `localhost` are the same computer but different names, so they were treated as different origins. In short, under today's default policy:

- **Within the same site**, the previous page's full address (including the query) is sent.
- **When going to another site**, only the origin is sent. If the visitor came from a search engine, as in the source material's example, you'll see only `Referer: https://search-engine/`, and **not what the search terms were**.
- **When going down from HTTPS to HTTP**, nothing is sent at all, matching the requirement in RFC 9110 section 10.1.3.

So don't conclude "they typed the address directly" just because `Referer` is missing. It may have been a link on an HTTPS page, or the page may have set its policy to `no-referrer`.

!!! info "[Supplement] `Sec-Fetch-*`: browsers telling you the circumstances of a request"
    Today's browsers use `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-User` and `Sec-Fetch-Dest` to say in what situation a request arose (W3C Fetch Metadata). In this lab, `Sec-Fetch-Site` was `none` when an address was opened directly, `same-origin` for a same-origin link and `cross-site` for a cross-origin link, and navigations made by **clicking** a link carried `Sec-Fetch-User: ?1` **(actual output)**. They also distinguish a page body (`Sec-Fetch-Dest: document`) from images and scripts. With `Referer` reduced, these headers are a good supporting clue for "was this navigation clicked by a person, or a resource the page loaded by itself?" But they're added by browsers, so non-browser tools may omit or fake them.

!!! info "[Supplement] The `DNT: 1` in the source material's example"
    The `DNT` ("do not track") header effectively died out because sites didn't honour it, and MDN marks it deprecated. If you see it in old logs, don't read much into it.

## 7. How to use this in real investigations { #in-practice }

1. **Start with the request line.** Method, request target, version. Note `PUT` or `DELETE` on a static site, diagnostic `TRACE`, or unfamiliar WebDAV methods.
2. **Decode query strings before reading them.** Search terms and identifiers live there. Search for keywords in their encoded form too.
3. **Name the site by `Host`, the server by IP.** Don't mix different sites on the same IP.
4. **Read optional headers as "self-declared".** User-Agent, `X-Forwarded-For` and `Referer` can be faked. Ask who added them and whether they agree with other evidence.
5. **Build profiles from header combinations.** Requests whose combination differs from a PC's usual one may come from a different program.
6. **Mask the keys.** `Authorization`, session cookies and tokens are the accounts themselves. Mask them in reports and shared material, and confirm legal authority before using them.

## 8. Summary { #summary }

- HTTP is text-based, stateless requests and responses. Web activity gone from the disk still remains on the wire and in logs.
- **[Changed]** The reference for HTTP/1.1 is RFC 9110 and 9112 (2022), not RFC 2616; HTTP/2 is RFC 9113, and HTTP/3 became a standard as RFC 9114 in 2022.
- A request consists of the request line, headers, a blank line and the body; the only required header is `Host`. Everything else is up to the sender.
- **[Correction]** The methods that must be supported are GET and HEAD. "Safe" (no intent to change state) and "idempotent" (same effect when repeated) differ, and both are only promises; confirm actual effects separately.
- Decode query strings and percent-encoding before reading them.
- The User-Agent is a self-declared name, and **[Changed]** has shrunk, with some detail moved to Client Hints. Header combinations (three from `curl`, fourteen from the browser) are a supporting clue.
- Basic authentication's Base64 decodes instantly. `X-Forwarded-For` can be written by anyone (confirmed directly).
- **[Changed]** Under today's default Referer policy: full address for the same origin, origin only for cross-origin, nothing for HTTPS→HTTP (confirmed directly). `Sec-Fetch-*` tells you the circumstances of a request.

## Review questions { #review }

**Question 1. (Structure)** Split the request line of the following request into its three parts, and pick out all headers that aren't required.

```http
POST /api/v2/sync?device=7f3a HTTP/1.1
Host: files.example.net
User-Agent: SyncAgent/4.2
Content-Type: application/json
Content-Length: 58
```

??? success "Answer and explanation"
    Method `POST`, request target `/api/v2/sync?device=7f3a` (path `/api/v2/sync` and query `device=7f3a`), version `HTTP/1.1`. Only `Host` is required, so `User-Agent`, `Content-Type` and `Content-Length` are all optional. But a request with a body needs `Content-Length` (or chunked transfer, lesson 1.13, question 6) for the server to read the body correctly. "Not a required header" and "not needed in this request" are different things. This request sent 58 bytes of JSON to an API; `SyncAgent/4.2` is a self-declared name, so confirm the actual program on the endpoint.

**Question 2. (Corrected content)** A colleague says, "This web server returned 405 (method not allowed) to a `HEAD` request. HEAD is optional, so nothing odd there." Right?

??? success "Answer and explanation"
    The standard (RFC 9110 section 9.1) says general-purpose servers **must** support **GET and HEAD**. So a general-purpose web server rejecting HEAD is **unusual** behaviour that doesn't match the standard. It might be a deliberate security setting, a characteristic of a particular web app or device, or a clumsy implementation in an attacker's fake server (C2). As lesson 2.2 shows, such "slight deviations from the standard" can become fingerprints identifying a server. So it's not "nothing odd" but "a characteristic worth recording".

**Question 3. (Common misconception)** "The log has only `GET /admin/user.php?action=remove&id=42` and no POST, so this user didn't change anything." Explain the problem with this conclusion.

??? success "Answer and explanation"
    GET being "safe" is only a **promise** set by the standard; whether the web app keeps it is another matter. This request's query is `action=remove`, and by its name alone it looks like a function deleting account 42. Whether it was actually deleted must be confirmed from ① the response status code and size (lesson 2.2), ② the web app's and database's records, and ③ whether that account had any later activity. The method lets you guess intent, but not conclude the effect.

**Question 4. (Decoding)** A proxy log has the request `GET /search?q=%EC%9C%A0%EC%B6%9C+%EB%B0%A9%EB%B2%95`. What's the search term, and what string should you search for to find this value in logs?

??? success "Answer and explanation"
    `%EC%9C%A0` is "유", `%EC%B6%9C` is "출", `+` is a space, `%EB%B0%A9` is "방" and `%EB%B2%95` is "법", so the search term is **"유출 방법"** ("how to leak"), in UTF-8 (decode with something like Python's `urllib.parse.unquote_plus`). Searching logs for the Korean text won't match; you must search for `%EC%9C%A0%EC%B6%9C`. Records may also be written with lower-case hex (`%ec%9c%a0...`), so a case-insensitive search is safer.

**Question 5. (Interpretation)** In section 6.2, `curl`'s request had 3 headers and Chromium's had 14. A PC sends a request every five minutes with `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/...` but only three headers: `Host`, `User-Agent` and `Accept: */*`. What can you suspect, and what can't you conclude?

??? success "Answer and explanation"
    **What you can suspect:** a real Chrome browser opening a page normally also sends headers like `Accept-Language`, `Accept-Encoding`, `sec-ch-ua` and `Sec-Fetch-*`, and this request isn't that combination. So it may be **a non-browser program borrowing Chrome's name**, and combined with the five-minute regularity (lesson 1.10), it looks like automated communication. **What you can't conclude:** that it's malware. Update tools, monitoring agents and in-house scripts can send requests like this too. Check the destination, the response content and the process that opened the connection on the endpoint. Also, requests a browser makes for images or APIs (where `Sec-Fetch-Dest` isn't `document`) can have different header combinations, so compare against the same kind of request from the same browser.

**Question 6. (Changed conditions)** An investigation procedure based on 2016 material says "for visitors arriving from search engines, find the search terms from the `q=` value in Referer". Does this still work? Explain with the results tested directly.

??? success "Answer and explanation"
    Hardly ever. Under today's default Referrer-Policy, `strict-origin-when-cross-origin`, only the origin is sent when navigating to **another origin**. In section 6.7's experiment, moving from `127.0.0.1:8201/start` to `localhost:8202` gave `Referer: http://127.0.0.1:8201/`, without path or query. Moreover, search engines are mostly HTTPS, and going from HTTPS to an HTTP site sent no `Referer` at all. Search engines often have their own policies not to pass search terms either. So find search terms in **the requests to the search engine itself** (`/search?q=` in proxy logs, the autocomplete requests of lesson 1.4).

**Question 7. (Application)** A web server log shows access to the admin page from an external address, recorded together with `X-Forwarded-For: 10.10.4.3, 192.0.2.10`. In front of the server is our organisation's load balancer, which appends the connecting address to whatever value it receives. Who most likely actually connected, and what is `10.10.4.3`?

??? success "Answer and explanation"
    If our load balancer **appends**, the rightmost `192.0.2.10` is the connection address the device actually saw: the trustworthy client address. `10.10.4.3` to its left was **already** in the header before the request reached the device. Another proxy in between may have added it, but the external client may also have **written it in directly**. That it happens to be the internal proxy address suggests a test of whether the web app uses this header to decide "request from inside" (section 6.6). So check ① which value the web app trusts, ② whether the response to that request was a success, and ③ other activity from `192.0.2.10`.

**Question 8. (Common misconception)** "The Authorization header's value is encrypted, so sharing the pcap won't expose the account." What's wrong?

??? success "Answer and explanation"
    The `Basic` value is **just Base64-converted**, so as in section 6.5, one `base64 -d` gives `username:password`. Over plain HTTP, anyone receiving the pcap can read the account. `Bearer` tokens and session cookies are keys in themselves too, reusable to get in while still valid. So when sharing pcaps or logs, make copies with these headers masked or removed, and restrict access to the originals. Logging in with accounts learned during an investigation must not be done without legal authority.

**Question 9. (Interpretation)** From a day of requests from one PC, you want only the pages the user actually opened by clicking a link. Which headers from this lesson can you use, and what are the limits?

??? success "Answer and explanation"
    With today's browsers, requests carrying both `Sec-Fetch-Dest: document` (a page-body request) and `Sec-Fetch-User: ?1` (navigation started by user activation) are good candidates; in section 6.7's experiment, both were attached to the navigations made by clicking links. `Sec-Fetch-Site` can also separate directly opened addresses (`none`) from those reached by link. The limits: ① these headers are visible only where **headers can be seen**, such as plain HTTP or a TLS-intercepting proxy (not if you only have HTTPS packets); ② the default proxy log format doesn't record headers (lesson 1.3); ③ older browsers and non-browser tools don't send them; ④ they can be faked. Without these headers, estimate human navigation from request timing and `Referer` chains, as in lesson 2.4.

## References { #references }

- Tools used in this environment: Chromium 153.0.8010.12 (headless, Playwright), curl 8.5.0, Python 3 `http.server`, tcpdump 4.99.4, tshark 4.2.2. Outputs were obtained on 2026-11-05.
- IETF, [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) (2022). Section 9.1 (GET and HEAD required), sections 9.2.1–9.2.2 (safe and idempotent methods), section 7.2 (Host), section 10.1.3 (Referer and less secure requests), section 11 (HTTP authentication).
- IETF, [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112), [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113), [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000).
- IETF, [RFC 3986: URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986), section 2.1 (percent-encoding); [RFC 7617: Basic authentication](https://www.rfc-editor.org/rfc/rfc7617); [RFC 7239: Forwarded](https://www.rfc-editor.org/rfc/rfc7239); [RFC 6648: deprecating the `X-` prefix](https://www.rfc-editor.org/rfc/rfc6648).
- W3C, [Referrer Policy](https://www.w3.org/TR/referrer-policy/) and [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/).
- Chromium, [User-Agent reduction](https://www.chromium.org/updates/ua-reduction/) (checked through search results on 2026-11-05: minor version frozen at `0.0.0` from Chrome 101, detail moved to Client Hints).

!!! note "About this page"
    A personal study note, rewritten in my own words from several learning resources. The experiment server and requests are my own, and the scenarios are hypothetical.
