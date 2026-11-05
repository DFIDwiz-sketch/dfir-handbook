---
title: "2.3 — Seeing the Past Through Tracking Cookies, and HTTP/2 and HTTP/3"
tags:
  - training
  - network-forensics
  - http
  - cookies
  - http2
---

# 2.3 — Seeing the Past Through Tracking Cookies, and HTTP/2 and HTTP/3 { #tracking-cookies-http2-http3 }

!!! abstract "Scope of this lesson"
    - Why advertising and analytics cookies are useful to investigators: they contain **times from a past you have no other evidence for**
    - The structure and reading of the classic analytics cookies (`__utma`, `__utmb`, `__utmz`). [Changed] today it's `_ga` and `_ga_<ID>`
    - A "user" is not a person but **a cookie store**: browsers, private mode, deletion
    - Marketing cookies (`__hstc`, `hubspotutk`, `hsfirstvisit`) and millisecond timestamps
    - [Changed] Browsers cap cookie lifetimes: Chrome 400 days, Safari 7 days
    - HTTP/2: binary framing, header compression, multiplexing (confirmed by decrypting HTTP/2 traffic captured directly, using session keys). [Changed] server push has been removed from browsers
    - HTTP/3: HTTP over QUIC, and what changes for investigations

!!! note "Lab environment and notation"
    **(Actual output)** was produced in this environment. HTTP/2 traffic came from nghttp2 1.59.0's `nghttpd` server on loopback, run both over TLS (with a self-signed certificate I created) and in cleartext (h2c), with requests sent by `curl` 8.5.0 (built with nghttp2) and captured with tcpdump. TLS session keys were written with `SSLKEYLOGFILE` and used to decrypt with tshark 4.2.2. All cookie values are **invented** for illustration, and time conversions were computed directly with `date`.

## 1. A window onto a past you have no evidence for { #why-cookies }

**(Hypothetical)** The pcap captured from the employee's PC under investigation covers only one week from 1 November 2026. But the question is "when did this employee **first** look at that competitor's recruitment site?" Even if the week's packets contain visits to the site, that only shows they visited that week, not when the first time was.

What unexpectedly helps here are **advertising and analytics cookies**. These companies make money by recording as precisely as possible when visitors first came, how often, and from where, so they often store that information **inside the cookie value**. The cookie travels in the `Cookie` header with every request (lesson 2.1, section 6.4), so a single line of today's packets can yield **a first-visit time months ago**.

As an analogy, it's a café **loyalty card**. Look at a customer's card today and you see the date it was issued, the date of the last visit and the number of stamps so far. The café's CCTV may hold only a week, but the card tells an older story. The analogy differs in two ways. First, the card belongs not to a **person** but to **a wallet** (the browser's cookie store). Second, the café (the company) designs the card format and **often doesn't publish it**, so interpretation always carries caveats.

## 2. The classic analytics cookies: `__utma`, `__utmb`, `__utmz` { #utm-cookies }

The source material covers in detail three old cookies of what was long the most widely used web analytics service. They're no longer used (section 3), but you can still meet them in **old evidence** (pcaps from years ago, old cookie files on disk), and they're a good example for learning "how to read the numbers inside a cookie", so here is their structure. The `utm` in the names comes from Urchin Tracking Module, on which the service was based.

All are dot-separated (`.`), and the first value is a **hash of the site (domain)**: it's the same across cookies of the same site.

| Cookie | Lifetime | Composition of the value |
| --- | --- | --- |
| `__utma` | 2 years | domain hash . visitor identifier . **first visit** . **previous visit** . **current visit** . visit count |
| `__utmb` | 30 minutes | domain hash . pages this session . outbound link countdown (from 10) . current visit time |
| `__utmz` | 6 months | domain hash . time . visit count . source count . source information (`utmcsr=source|utmccn=campaign|utmcmd=medium|utmctr=term`) |

**(Hypothetical)** Here's an `__utma` value invented for this lesson.

```text
__utma=111872281.1938459823.1767225600.1793000000.1793512345.14
```

The time values are Unix time (seconds since 1970, lesson 1.3), so convert with `date`.

```bash
date -u -d @1767225600
date -u -d @1793000000
date -u -d @1793512345
```

**(Actual output)**

```text
1767225600 → 2026-01-01 00:00:00 UTC   (first visit)
1793000000 → 2026-10-26 07:33:20 UTC   (previous visit)
1793512345 → 2026-11-01 05:52:25 UTC   (current visit)
```

The final `14` is the visit count. One line of packets from 1 November tells the story "**this browser first came to this site on 1 January 2026, this is its 14th visit, and the previous visit was 26 October**", a past a week of pcap could never show. This is exactly one of the objectives of the lab in lesson 2.4: using advertising cookies to see beyond the evidence you have.

`__utmz`'s source information tells you **how the visitor arrived** at the site. `utmcsr=search-engine|utmcmd=organic|utmctr=...` means via search, `utmcmd=referral` via a link on another site, and `utmcsr=(direct)` via a typed address or bookmark. As lesson 2.1 showed, `Referer` now often gives only the origin, so such source information, where it survives, is valuable (especially in old evidence).

## 3. [Changed] Today's analytics cookies: `_ga` and `_ga_<ID>` { #ga4 }

The old tracking code that set the `__utm*` cookies fell out of use long ago, and the generation that replaced it (Universal Analytics) **stopped processing data for standard properties on 1 July 2023** (per Google's help centre). The official cookie documentation for the generation widely used today (GA4) lists these two:

| Cookie | Default lifetime | Official description |
| --- | --- | --- |
| `_ga` | 2 years | used to distinguish users |
| `_ga_<container ID>` | 2 years | used to persist session state |

The official documentation **doesn't describe the internal structure** of the values. But a widely used interpretation is that `_ga` looks like `GA1.1.<random number>.<Unix time>`, with the last number being **the time the cookie was first created**. With the invented value placed in this lab's HTTP/2 requests:

```text
_ga=GA1.1.1234567890.1793500000
```

```bash
date -u -d @1793500000
```

**(Actual output)** `2026-11-01 02:26:40 UTC`. If the interpretation holds, that's "when this browser store first got that site's `_ga` cookie".

`_ga_<ID>` is known to hold values such as the session start time, session number and last activity time, and several sources reported around 2025 that its format changed from `GS1.1.…` to `$`-separated `GS2.1.…`. This change was confirmed from **third-party analyses, not the vendor's official documentation**, so when interpreting real evidence, look at the values as they were at the time, and open the same site in a test browser to see how the cookie changes before relying on it.

!!! warning "[Caution] Using undocumented values as evidence"
    Analytics vendors have no obligation to publish cookie formats, and change them without notice. So in the report, record ① on what basis you read a number as a time (official documentation, public analysis, or your own test), and ② whether it agrees with other evidence (as in the source material's example, compare with the browser history or the creation time in the cookie database). If there's only one interpretation, write "appears to be".

## 4. A "user" is a cookie store { #cookie-scope }

The "user" a cookie identifies is not a person but **one cookie store**. Confusing the two badly skews conclusions.

- **Each browser is different.** If one person uses Chrome and Firefox, there are two cookie stores and so two "users". The same goes for different profiles in the same browser.
- **Private mode is a new store each time.** Every private window starts from an empty store, so by cookies it's a "new user arriving for the first time" every time. In private mode, `__utma`'s first-visit time is just a time after that private window was opened.
- **Deleting starts over.** If the user deleted cookies, the first-visit time resets to after that.
- **Several people can share one store.** Shared PCs, shared accounts.

So read a cookie's first-visit time not as "when this person first visited" but as **"when this store first received that site's cookie, and it hasn't been deleted since"**. Still, the same cookie value appearing on several days and from several addresses is a strong thread linking **the same browser store**, which other evidence (logon records, the endpoint) can tie to a person.

## 5. Marketing cookies: `__hstc`, `hubspotutk`, `hsfirstvisit` { #marketing-cookies }

Analytics services aren't the only ones using such cookies. Seeing cookies from several different trackers in one case is common, and each vendor's format has to be looked up and interpreted. The source material's example is a marketing automation service's cookies.

- **`__hstc`:** the main visitor-tracking cookie. `domain hash . visitor identifier . first visit . previous visit . current visit . visit count`, almost the same structure as `__utma`, but with times in **milliseconds** (13 digits).
- **`hubspotutk`:** the visitor identifier. The same as `__hstc`'s second value, used to link the same person across **several sites** using that service.
- **`hsfirstvisit`:** a cookie present in the source material's era that held **the address through which the visitor first entered the domain** and a millisecond time.

Convert millisecond times by dropping the last three digits or dividing by 1000.

```bash
date -u -d @1793512345    # first 10 digits of 1793512345678
```

**(Actual output)** `2026-11-01 05:52:25 UTC` (the trailing `678` is 0.678 seconds).

!!! info "[Changed] Lifetimes have changed, and official values need checking"
    The source material gives `__hstc` two years and `hubspotutk` and `hsfirstvisit` ten years. Many sites' published cookie lists now give `__hstc` and `hubspotutk` **13 months**, but some say six months, so they disagree (search results, 2026-11-05). The vendor has changed lifetimes and its cookie list to meet privacy regulations. In real cases, check the vendor's current official documentation and the expiry of cookies actually received in a test browser.

## 6. [Changed] Browsers cap cookie lifetimes { #browser-limits }

Even if a vendor sets "two years" or "ten years", **the browser may cut it shorter**. GA4's official cookie documentation itself notes browser limits such as "a maximum of 400 days for Chrome and 7 days for Safari if a user doesn't return". Safari limits the lifetime of cookies set by script, and Chrome caps cookies at 400 days.

**What it means for investigations:** a first-visit time three weeks ago in a cookie doesn't mean "first came three weeks ago". A Safari user may have come earlier, with the cookie disappearing every seven days. Conversely, a first visit two years ago also means the browser didn't delete cookies in that time. You need the **browser type and version** (lesson 2.1's User-Agent and Client Hints) to know the upper bound of a cookie's times.

## 7. Where cookies are visible { #where-cookies }

- **Plain HTTP packets:** the `Cookie` header is visible as-is. Rare today.
- **HTTPS:** not visible from packets alone. You need records from a TLS-intercepting proxy (lesson 1.2) or session keys (lesson 1.12, section 8).
- **Proxy logs:** the default format doesn't record headers (lesson 1.3). They can be configured to record cookies, but session cookies are login keys in themselves, so store them with care.
- **The endpoint's cookie database:** the domain of disk forensics. Not kept in private mode.

And today's analytics cookies mostly attach to **the visited site's own domain** (first party). So the `_ga` cookie appears in the `Cookie` header of requests **to that site**, not to the analytics vendor. In this lab too, the `_ga` value travelled on both requests to the site (`127.0.0.1:8445`) **(actual output)**.

## 8. HTTP/2: a completely different shape, the same meaning { #http2 }

### 8.1 What changed { #http2-differences }

HTTP/2 (RFC 9113) keeps the **meaning** of methods, status codes and headers from HTTP/1.1, but its **shape** on the wire is completely different.

- **Binary framing:** traffic moves in binary units called **frames** instead of text. Following the stream as in lesson 1.9 shows almost nothing readable.
- **Header compression (HPACK, RFC 7541):** headers are compressed, and frequent ones are sent as index numbers. It's a **stateful** compression that remembers headers sent earlier in the same connection, so missing the beginning of a connection can make later headers undecodable.
- **Pseudo-headers:** `:method`, `:path`, `:authority` (HTTP/1.1's `Host`) and `:scheme` replace the request line, and `:status` replaces the status line (lesson 2.2: no reason phrase).
- **Multiplexing:** several **streams** (numbered request/response pairs) travel simultaneously in one TCP connection. Streams opened by the client have odd numbers (1, 3, 5, …).
- **TLS:** not mandatory by the standard, but browsers use HTTP/2 **only over TLS**. Cleartext HTTP/2 (h2c) appears only between servers or in tools.

### 8.2 Seeing it: zero lines without keys, a table with them { #http2-lab }

I requested two files from `nghttpd` over HTTPS. `curl` put both requests on **one TCP connection**.

```bash
SSLKEYLOGFILE=$PWD/keys.log curl -s -k --http2 -A "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0" \
  -H "Cookie: _ga=GA1.1.1234567890.1793500000" https://127.0.0.1:8445/index.html https://127.0.0.1:8445/report.txt
```

Applying `http2` in tshark without session keys gave **zero lines**: everything was encrypted with TLS. Given the keys written via `SSLKEYLOGFILE`:

```bash
tshark -n -r h2.pcap -o tls.keylog_file:keys.log -Y 'http2.type == 1' -T fields \
  -e tcp.stream -e http2.streamid -e http2.headers.method -e http2.headers.path \
  -e http2.headers.authority -e http2.headers.user_agent -e http2.headers.status
```

**(Actual output, User-Agent column partly trimmed)**

```text
0	1	GET	/index.html	127.0.0.1:8445	Mozilla/5.0 (X11; Linux x86_64; rv:140.0) ...
0	1,1					200
0	3	GET	/report.txt	127.0.0.1:8445	Mozilla/5.0 (X11; Linux x86_64; rv:140.0) ...
0	3,3					200
```

- `http2.type == 1` selects only HEADERS frames (frames carrying headers).
- The first column is `0` throughout: **one TCP stream**. Inside it, HTTP/2 streams `1` and `3` each carried one request. Lesson 1.9's "TCP stream" and HTTP/2's "stream" are **different concepts**; don't mix them.
- Wireshark shows decompressed headers **by name**, as in `http2.headers.user_agent` and `http2.headers.path`. Only the field names differ from HTTP/1.1's `http.user_agent`; the meaning is the same, so the filters and tables of lessons 1.9 and 1.10 carry over directly.

Following the stream of a request sent in cleartext HTTP/2 (h2c), only the very beginning was text and the rest was binary.

**(Actual output, beginning)**

```text
PRI * HTTP/2.0

SM

..............d.....................>...
```

`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` is the **fixed opening string** (connection preface) with which a client starts HTTP/2. If you see it, it's a cleartext HTTP/2 connection, and the headers after it are HPACK-compressed and unreadable. To have Wireshark dissect it, designate the port as HTTP/2 (`-d tcp.port==8446,http2`); doing so immediately showed `GET /index.html` and `200` **(actual output)**.

!!! info "[Supplement] HTTP/2 in browser developer tools"
    The source material also shows viewing HTTP/2 requests in a browser's developer tools (network tab). The browser is the TLS endpoint, so it shows headers such as `:authority` and `:path` regardless of encryption, and marks `h2` (HTTP/2) or `h3` (HTTP/3) in the protocol column. In investigations, use it to learn **by opening the same site in a test browser** what requests go out and in what shape. It's rarely possible to do this on the subject's own browser.

### 8.3 [Changed] Server push is gone from browsers { #server-push }

The source material warns about HTTP/2 **server push**, where a server pushes objects nobody requested into the browser cache. A file in the cache can't be told apart as user-requested or server-pushed, so endpoint cache analysis could be wrong. This feature was **disabled by default in Chrome 106 (2022)** for lack of real benefit, and Firefox announced in 2024 that it would disable it, then removed it. So in today's browser caches this concern has largely gone, but keep it in mind for **evidence from before 2022**. Its suggested replacement, the 103 Early Hints response, only sends a **hint** to preload a resource; the browser makes the actual request.

## 9. HTTP/3: HTTP over QUIC { #http3 }

HTTP/3 (RFC 9114, 2022) moves the ideas of HTTP/2 onto **QUIC** (RFC 9000). What changes for investigations:

- **It uses UDP 443.** Not TCP, so as lesson 1.2 showed, it can bypass proxies that handle only TCP. That's why you need to look separately at **UDP 443** in firewall records.
- **Almost everything is encrypted.** QUIC builds in TLS 1.3 and encrypts not only HTTP headers but most of the **transport-layer information** that would be visible with TCP (sequence numbers, acknowledgements). From packets alone you can see little more than addresses, ports, sizes, timing and connection identifiers, plus the SNI in the Client Hello of the first Initial packet (unless ECH is used, lesson 1.12).
- **Header compression is QPACK** (RFC 9204): a similar idea to HPACK, but a different mechanism.
- **Decrypting it still needs session keys.** Wireshark documents decrypting QUIC with keys in `SSLKEYLOGFILE` format. The `curl` in this environment was built without HTTP/3 support, so **I couldn't test HTTP/3 directly**.

In the end, for both HTTP/2 and HTTP/3, investigators need records from **one end of the connection** (the browser, a TLS-intercepting proxy, server logs) or session keys to see content. With packets alone, turn to lesson 1.12's flow analysis (size and timing patterns).

## 10. How to use this in real investigations { #in-practice }

1. **Identify the vendor from the cookie name.** Names like `_ga`, `__utma` and `__hstc` tell you the vendor and format. For unknown names, look for the vendor's public documentation and published cookie lists.
2. **Try converting numbers to times.** Ten digits are often seconds, thirteen milliseconds. Check that the converted time falls in a plausible range (the last few years).
3. **Read the "user" as a store.** Allow for browsers, profiles, private mode and deletion, and bound the times with the browser's cookie-lifetime caps.
4. **Record the level of documentation.** Note whether the basis is official documentation, public analysis or your own test.
5. **For HTTP/2 and 3, look for keys or endpoint records first.** Without them, use the TLS version, SNI, and size and timing patterns.
6. **Distinguish TCP streams from HTTP/2 streams.** One TCP connection carries several requests simultaneously.

## 11. Summary { #summary }

- Advertising and analytics cookies contain past information such as **first visit, previous visit, visit count and traffic source**, showing beyond the period of your evidence. From an invented `__utma` value we read the first visit (2026-01-01), the previous visit and the visit count (14).
- **[Changed]** `__utm*` is an old generation, and the next one stopped processing on 2023-07-01. Today it's `_ga` and `_ga_<ID>` (official default lifetime two years); their structure isn't in official documentation, and the format has changed before.
- A cookie's "user" is **a cookie store**, varying with browser, private mode and deletion.
- Marketing cookies use millisecond times. **[Changed]** Lifetimes differ from the source material, and published lists disagree, so check.
- **[Changed]** Browsers cap cookie lifetimes (Chrome 400 days, Safari 7 days). The upper bound on first-visit times depends on the browser.
- HTTP/2 is binary framing, HPACK, pseudo-headers and multiplexing. Without keys, zero lines; with session keys, HTTP/2 streams 1 and 3 appeared inside one TCP connection. Cleartext starts with `PRI * HTTP/2.0`.
- **[Changed]** Server push has been removed from Chrome 106 and Firefox.
- HTTP/3 encrypts almost everything over QUIC on UDP 443. Content is visible only through endpoint records or session keys.

## Review questions { #review }

**Question 1. (Calculation)** A pcap from 4 November 2026 shows `__utma=48210377.551902814.1735689600.1792800000.1793750400.37`. Find the dates of the first, previous and current visits, and the visit count.

??? success "Answer and explanation"
    `date -u -d @1735689600` is **2025-01-01 00:00:00 UTC**, `@1792800000` is **2026-10-24 00:00:00 UTC**, and `@1793750400` is **2026-11-04 00:00:00 UTC** (you can verify by dividing the seconds by 86,400 per day). The visit count is the last value, **37**. So this browser store first received this site's cookie on 1 January 2025, 4 November 2026 is the 37th visit, and the previous visit was 24 October. Note that the first visit means "this store first received it then and hasn't deleted it since" (section 4).

**Question 2. (Common misconception)** "The last number of the competitor site's `_ga` cookie on the employee's PC is three days ago, so the employee first visited that site three days ago." Give at least three cases where this conclusion could be wrong.

??? success "Answer and explanation"
    ① In **private mode**, each window is a new store, so it's just a cookie first received in a private window opened three days ago. ② If **cookies were deleted**, it resets from then. ③ The employee may have visited earlier with **another browser or profile**. ④ A **browser lifetime cap** (e.g. Safari's short limit) may have removed an older cookie and created a new one. ⑤ Reading that number as "first creation time" is itself **an interpretation not in official documentation**. So the sentence you can write is "this browser store's `_ga` cookie for that site appears to have been created three days ago", and the first visit is traced back through other evidence (proxy logs, browser history).

**Question 3. (Calculation)** A marketing cookie contains the value `1793598745123`. What time is it? What happens if you feed it as-is to `date -u -d @1793598745123`?

??? success "Answer and explanation"
    With 13 digits, treat it as **milliseconds** and convert the first 10 digits, `1793598745`: **2026-11-02 05:52:25 UTC**, with the trailing `123` being 0.123 seconds (1793512345 was 05:52:25 on 1 November; adding 86,400 seconds gives 1793598745, exactly one day later). Fed as-is, `date` takes the 13 digits as seconds and gives an absurd date **tens of thousands of years** in the future, or a range error. When an implausible year comes out, first suspect the unit (seconds, milliseconds, microseconds).

**Question 4. (Interpretation)** The same `hubspotutk` value appears in requests to three different companies' web sites. What can you tell, and what can't you?

??? success "Answer and explanation"
    **What you can tell:** **the same browser store** visited three sites that use that marketing service. The value is an identifier the service gave the visitor, so it links the same person (strictly, the same store) across different sites. **What you can't:** who the **person** using the store was (it may be a shared PC), and how the value was generated (the source material also says its composition is undocumented). How the value is shared across sites can also depend on the vendor and the browser's cookie policy (first-party, third-party restrictions), so confirm the behaviour at the time before writing it up.

**Question 5. (Changed conditions)** A procedure written in 2016 says "treat files in the endpoint's browser cache as requested by the user, but note the possibility of HTTP/2 server push". For a Chrome cache in a 2026 case, how should this caveat change?

??? success "Answer and explanation"
    Chrome disabled HTTP/2 server push by default **from 106 (2022)**, so a cache from later Chrome versions is very unlikely to contain server-pushed objects. For a 2026 case, write "server push disabled since Chrome 106" with its basis, and instead note that files may be in the cache **for other reasons the user didn't directly request**: images and scripts the page loaded itself, prefetching, resources the browser fetched early due to 103 Early Hints. The principle of not reading a single cache file as "something the user chose to open" stays.

**Question 6. (Structure)** In section 8.2's results, `tcp.stream` is always 0 but `http2.streamid` is 1 and 3. Explain the difference, and say how the same requests would have looked over HTTP/1.1.

??? success "Answer and explanation"
    `tcp.stream` is the number Wireshark assigns per **TCP connection**; `http2.streamid` is the number HTTP/2 assigns per request/response pair **within one connection**. The two requests were **multiplexed** as HTTP/2 streams 1 and 3 inside one TCP connection (client-opened streams are odd). Over HTTP/1.1, persistent connections (lesson 2.2, section 4.1) could also put them on one TCP connection, but requests would go **one after another** (the next only after the previous response finished), with no stream numbers. Sending two requests at the same time often means opening two TCP connections. So in HTTP/2 environments there are fewer connections, and counting "one connection = one request" in flow records is even more wrong.

**Question 7. (Application)** UDP 443 traffic on the packet sensors has grown sharply, but the number of web requests in the proxy logs is unchanged. What has most likely happened, and what do you check?

??? success "Answer and explanation"
    Browsers or apps are most likely going out directly over **HTTP/3 (QUIC)**, bypassing a proxy that handles only TCP (lesson 1.2). Check ① the sources and destinations of outbound UDP 443 at the firewall (which PCs, which services), ② browser policy (e.g. whether QUIC is allowed) and when it changed, ③ destination names from the SNI in QUIC Initial packets (unless ECH), ④ whether proxy-log requests from the same PCs to the same services decreased. Remedies include blocking UDP 443 so browsers fall back to TCP, or disabling QUIC by policy; record the decision and its basis.

**Question 8. (Common misconception)** "HTTP/2 headers are compressed, so with the session keys you can read all headers from any point in the pcap." What's missing?

??? success "Answer and explanation"
    HPACK is **stateful** compression: it remembers headers sent earlier in the same connection in a **dynamic table** and later refers to them by number. So if capture began **in the middle** of a connection, or early packets are missing, some later headers may point to entries you don't know and can't be fully decoded, even with session keys. The TLS session keys themselves also need to be matched with the handshake at the start of the connection. So analysing HTTP/2 needs a pcap captured **from the start** of the connection, and the capture notes should record the start time.

**Question 9. (Interpretation)** In an old pcap (2014), you find `__utmz=...utmcsr=search-engine|utmccn=(organic)|utmcmd=organic|utmctr=orchid%20alloy%20formula`. What can you tell?

??? success "Answer and explanation"
    `__utmz` records **how the visitor arrived** at the site. `utmcmd=organic` means they came by clicking a (non-advertising) search result, and decoding `utmctr` gives **"orchid alloy formula"**, the search term used at the time. Back then, search terms were sometimes passed along when going from a search engine to another site, which is why such values survived. Today `Referer` passes only the origin (lesson 2.1) and search engines often don't pass search terms, so such information is **especially valuable in old evidence**. But note that the cookie records the store's **most recent source** (as of when the cookie was updated), and which visit it belonged to must be read together with the other values.

## References { #references }

- Tools used in this environment: nghttp2 1.59.0 (`nghttpd`), curl 8.5.0 (built with nghttp2, `SSLKEYLOGFILE`), tcpdump 4.99.4, tshark 4.2.2, GNU `date`. Outputs were obtained on 2026-11-05.
- Google, [GA4 cookie usage](https://developers.google.com/analytics/devguides/collection/ga4/cookie-usage) (checked through search results on 2026-11-05). `_ga` and `_ga_<container-id>` default two years; browser lifetime caps (Chrome 400 days, Safari 7 days).
- Google, [Universal Analytics shutdown notice](https://support.google.com/analytics/answer/13467533) (checked through search results on 2026-11-05). Standard properties stopped processing on 2023-07-01.
- Chrome Developers blog, [Removing HTTP/2 Server Push from Chrome](https://developer.chrome.com/blog/removing-push) (checked through search results on 2026-11-05). Disabled by default in Chrome 106; 103 Early Hints recommended.
- IETF, [RFC 9113: HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) (section 3.4 connection preface, section 5 streams), [RFC 7541: HPACK](https://www.rfc-editor.org/rfc/rfc7541), [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114), [RFC 9204: QPACK](https://www.rfc-editor.org/rfc/rfc9204), [RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000), [RFC 8297: 103 Early Hints](https://www.rfc-editor.org/rfc/rfc8297).
- Marketing cookie lifetimes disagreed between published cookie lists on several sites (13 months versus 6 months, search on 2026-11-05). Check the vendor's current official documentation.

!!! note "About this page"
    A personal study note, rewritten in my own words from several learning resources. The cookie values and experiment traffic are my own, and the scenarios are hypothetical.
