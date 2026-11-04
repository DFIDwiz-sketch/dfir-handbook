---
title: "New HTTP Standards — HTTP/2, HTTP/3/QUIC, WebSocket, and HTTP Wrap-up"
tags:
  - training
  - blue-team
  - http
  - concept
---

# New HTTP Standards — HTTP/2, HTTP/3/QUIC, WebSocket, and HTTP Wrap-up { #new-standards }

!!! abstract "What this page covers"
    Why HTTP/2 exists and what changed (numbered streams in one connection, HEADERS and DATA frames, binary format, HPACK header compression, effectively mandatory encryption, server push), following one HTTP/2 transaction in Wireshark, HTTP/3 and QUIC (TCP+TLS rebuilt on UDP), reading Zeek `quic.log`, how organisations handle QUIC, the WebSocket handshake and detection, and a wrap-up of the whole HTTP section. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Correction]** = fixes a commonly stated mistake, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. The earlier pages are listed on the [HTTP overview](index.md).

## Ten key points { #key-points }

1. HTTP/2 and HTTP/3 keep **the meaning (methods, paths, headers, status codes)**; only **the delivery** changed.
2. HTTP/2 interleaves many numbered **streams** inside **one** TCP connection. One transaction = IP + TCP connection + **stream ID**.
3. Request/response headers travel in **HEADERS frames** and bodies in **DATA frames**. Headers are binary and HPACK-compressed, so "Follow TCP Stream" can't read them.
4. HTTP/2 header names are **lowercase**, and the request line and Host become pseudo-headers such as `:method`, `:path`, `:authority`, `:scheme`, `:status`.
5. Browsers only use HTTP/2 **over encrypted connections**. Seeing content needs TLS inspection or session keys.
6. Server push (sending files without a request) has effectively disappeared after browsers turned it off.
7. HTTP/3 runs on QUIC over **UDP 443**. Encryption is built into the protocol, so there's no separate TCP or TLS to look at.
8. You can still read the **SNI** from QUIC's first (Initial) packet, unless ECH is used — Zeek `quic.log`'s `server_name`.
9. Many organisations **block outbound UDP 443** so browsers fall back to TCP+TLS that existing inspection tools can see.
10. WebSocket turns into a **long-lived two-way channel** after `101 Switching Protocols`; what follows the handshake barely appears in HTTP logs.

## HTTP/2 { #http2 }

### Why it exists { #why-http2 }

HTTP/1.1 exchanges **one thing at a time** per connection: the next answer can't arrive until the previous one is done — one counter, one queue. Browsers coped by opening several connections per site (typically around six), and pages with dozens of images and scripts got slow.

Google's experimental fix was **SPDY** ("speedy"), refined into **HTTP/2** (standardised in 2015, revised as RFC 9113 in 2022). Two goals: **faster**, and **encrypted by default** — good for users, harder for analysts who used to read plain text.

### What changed { #what-changed }

If HTTP/1.1 is "one counter, one queue", HTTP/2 is **"one conveyor belt carrying numbered boxes, mixed together"**.

| Change | HTTP/1.1 | HTTP/2 |
| --- | --- | --- |
| Connections | Several TCP connections per site | Usually **one TCP connection** |
| Concurrency | One at a time per connection | Many numbered **streams** interleaved |
| Unit | Text requests/responses | **Frames**: HEADERS for headers, DATA for bodies |
| Format | Human-readable text | **Binary** |
| Headers | As-is | **HPACK**-compressed (repeated headers sent as index numbers) |
| Encryption | Optional | Optional in the standard, but **browsers use it only over TLS** |
| Server push | None | Server may send files unrequested (now effectively retired) |

**Streams and frames.** Each request in the connection gets a **stream ID** (client-initiated streams are odd: 1, 3, 5, …). The request headers go out in a HEADERS frame with that number; response headers and body come back in HEADERS and DATA frames with the same number. Frames from different streams are **interleaved**, so isolating one transaction takes **IP + TCP connection + stream ID**.

Common frame types:

| Frame | Purpose |
| --- | --- |
| `HEADERS` | Request/response headers |
| `DATA` | Body (file content) |
| `SETTINGS` | Exchange connection settings (at start) |
| `WINDOW_UPDATE` | Flow control: "you may send more" |
| `PING` | Check the connection is alive |
| `RST_STREAM` | Cancel one stream |
| `GOAWAY` | Announce connection shutdown |
| `PUSH_PROMISE` | Announce a server push |

### Special fields instead of text: pseudo-headers { #pseudo-headers }

HTTP/1.1's request line (`GET /path HTTP/1.1`) and Host become **colon-prefixed pseudo-headers** in HTTP/2.

```
HTTP/1.1                              HTTP/2 (decoded)
GET /images/logo.png HTTP/1.1         :method: GET
Host: www.example.com                 :path: /images/logo.png
                                      :authority: www.example.com
                                      :scheme: https
User-Agent: Mozilla/5.0 ...           user-agent: Mozilla/5.0 ...

HTTP/1.1 200 OK                       :status: 200
Content-Type: image/png               content-type: image/png
```

- `:method` = method, `:path` = path, `:authority` = the Host equivalent, `:scheme` = http/https
- The response's first line is just `:status` — **no reason phrase like "OK"**
- Regular header names are **all lowercase** (`user-agent`, `content-type`)

**[Added] Where detection rules break.** Rules or regexes looking for a literal capitalised "`User-Agent:`" can miss decoded HTTP/2 traffic. Compare header names **case-insensitively**.

### What it looks like: upgrading to cleartext HTTP/2 { #h2c-upgrade }

Browsers only use HTTP/2 inside TLS, but cleartext HTTP/2 (`h2c`) is in the standard too. Starting on HTTP/1.1 and upgrading is the classic example of status 101.

```
No.  Info
1    GET / HTTP/1.1   (Upgrade: h2c, HTTP2-Settings: ...)
2    HTTP/1.1 101 Switching Protocols
3    Magic, SETTINGS[0]
4    SETTINGS[0], WINDOW_UPDATE[0]
5    HEADERS[1]: 200 OK
6    DATA[1]
7    HEADERS[3]: GET /style.css
8    HEADERS[5]: GET /logo.png
9    HEADERS[3]: 200 OK, DATA[3]
10   HEADERS[5]: 200 OK, DATA[5]
```

1. The client requests the first page over HTTP/1.1 and asks "may we switch to HTTP/2?" with `Upgrade: h2c`
2. The server agrees with `101 Switching Protocols`
3. The client sends the HTTP/2 preface (Magic) and its SETTINGS (stream 0 = the whole connection)
4. The server sends its settings and a flow-control update
5–6. The first request's answer arrives on **stream 1** as HEADERS and DATA
7–8. Two more requests go out **together** on streams 3 and 5
9–10. Answers come back per stream number (order may interleave)

Instead of one tidy "200 OK", you follow frame names and stream numbers.

### Following one HTTP/2 transaction in Wireshark { #http2-wireshark }

With a decrypted (or cleartext) HTTP/2 capture:

```
http2
http2.type == 1
http2.streamid == 19
tcp.stream == 4 && http2.streamid == 19
```

- Line 1: HTTP/2 packets only
- Line 2: HEADERS frames only (frame type numbers: DATA = 0, HEADERS = 1) → the list of request/response headers
- Line 3: stream 19 only
- Line 4: **stream 19 of TCP connection 4 only** → one transaction (other connections can also have a stream 19, hence the connection number)

Expanding a HEADERS frame shows, in the packet details pane:

```
HyperText Transfer Protocol 2
  Stream: HEADERS, Stream ID: 19, Length 52, GET /images/logo.png
    Header: :method: GET
    Header: :path: /images/logo.png
    Header: :authority: www.example.com
    Header: :scheme: https
    Header: user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
```

Because of HPACK, "Follow TCP Stream" shows only garbled bytes. Use Wireshark's **Follow → HTTP/2 Stream** instead to read one stream's headers and body.

**[Added] Seeing encrypted HTTP/2 in a lab.** If the `SSLKEYLOGFILE` environment variable is set, browsers write TLS session keys to that file. Point Wireshark's Preferences → Protocols → TLS → "(Pre)-Master-Secret log filename" at it and the capture decrypts to show HTTP/2. That key file unlocks every encrypted session from that period, so use it **only in a lab** and delete it securely. At organisational scale, a TLS-inspecting proxy plays the same role.

### Server push { #server-push }

The server guesses "whoever views this page will need this CSS" and sends files **before being asked**. For analysts, that meant files arriving with no request record.

**[Changed]** It delivered less than hoped and caused problems; Chrome disabled it by default in 2022 and other browsers followed, so it has **effectively disappeared**. `103 Early Hints` (an interim response hinting "fetch these files early") replaced it — and since the browser still fetches the files with its own requests, request records remain.

## HTTP/3 and QUIC { #http3 }

### What it is { #what-is-quic }

HTTP/2 still carries everything over one TCP connection, so when one packet is lost, **every stream stalls** until TCP retransmits it. Google built a new transport **on UDP instead of TCP**: **QUIC** (originally "Quick UDP Internet Connections", now just a name). Google's design document describes it as very similar to TCP+TLS+HTTP/2, but implemented on top of UDP. It became a standard as RFC 9000 in 2021, and HTTP running on QUIC is **HTTP/3** (RFC 9114, 2022).

| Layer | HTTP/1.1 and HTTP/2 | HTTP/3 |
| --- | --- | --- |
| Application | HTTP | HTTP/3 |
| Security | TLS (separate layer) | **TLS 1.3 built into QUIC** |
| Transport | TCP | **QUIC** |
| Below | IP | **UDP** (usually port 443) → IP |

It doesn't change what HTTP says; it's closer to **rebuilding layer 4 (transport)**. So the familiar traces — TCP three-way handshake, TCP retransmissions, a plaintext TLS handshake — aren't there.

### How browsers know to use HTTP/3 { #h3-discovery }

Browsers don't start on UDP. They usually learn "this site also speaks HTTP/3" in one of two ways:

```
Alt-Svc: h3=":443"; ma=86400
```

- An `Alt-Svc` header on the first (TCP+TLS, HTTP/2) response: "HTTP/3 (`h3`) is also available on UDP 443 here; remember this for 86,400 seconds (a day)"
- Or the DNS [HTTPS record (type 65)](../dns/understanding-dns.md#records) announces `alpn="h3,h2"` up front

If UDP is blocked, browsers **quietly fall back to TCP+TLS** — which leads to the organisational approach below.

### What you can still see: QUIC's first packet and Zeek quic.log { #quic-visibility }

QUIC encrypts most of its packets, headers included. But the connection-opening **Initial packet** is protected only by keys anyone can derive (from the connection ID), so network sensors can read the TLS ClientHello inside — i.e. the **SNI (site name)**, unless ECH is used. Zeek's QUIC analyzer, added in Zeek 6.1, records it in `quic.log`:

```json
{
  "ts": "2026-11-04T13:40:12.502Z",
  "uid": "CQx9aW2Z7mL1kd3Fe",
  "id.orig_h": "10.1.5.23",
  "id.orig_p": 53727,
  "id.resp_h": "203.0.113.44",
  "id.resp_p": 443,
  "version": "1",
  "client_initial_dcid": "95412c47018cdfe8",
  "server_scid": "d5412c47018cdfe8",
  "server_name": "media.example.com",
  "client_protocol": "h3",
  "history": "ISisH"
}
```

| Field | Meaning |
| --- | --- |
| `id.orig_h` / `id.resp_h` / `id.resp_p` | Our PC / server IP / port (UDP 443) |
| `version` | QUIC version (`1` = RFC 9000, `quicv2` = version 2) |
| `client_initial_dcid` | Connection ID the client randomly generated to start |
| `server_scid` | Connection ID the server chose |
| `server_name` | **SNI — the site name.** The most useful field here |
| `client_protocol` | First ALPN value in the ClientHello; `h3` = HTTP/3 |
| `history` | Letters summarising the QUIC packet flow (like `conn.log`'s history) |

Paths, headers and status codes aren't visible. For HTTP/3 the network limit is **"which site, how much, how often"**; the rest comes from decryption devices or endpoints.

### How organisations handle QUIC { #quic-policy }

Many organisations:

1. **Block outbound UDP 443 at the firewall.** Browsers give up on HTTP/3 and fall back to TCP+TLS (HTTP/2), so existing TLS-inspection proxies and logs keep working. Users notice little more than a slight slowdown.
2. **Disable QUIC by browser policy** (e.g. the Chrome/Edge `QuicAllowed` policy).
3. Treat any remaining **attempts to send on UDP 443** as worth checking — something other than the browser (another QUIC app, a remote-access tool, malware) is sending them.

### QUIC carries more than HTTP { #smb-over-quic }

QUIC isn't web-only. Windows **SMB over QUIC** carries file sharing (SMB) across the internet on UDP 443 without a VPN. In 2022 it was limited to Windows 11 and Windows Server 2022 Azure Edition, but **from Windows Server 2025 it's available in the regular editions too**. So "UDP 443 = web" can be wrong, and outbound QUIC may contain file sharing.

**[Added]** On the attack-tool side, some open-source C2 frameworks (e.g. Merlin) support HTTP/2 and HTTP/3 transports. Where UDP 443 is open, it can become a C2 channel that sidesteps TCP-based inspection.

## [Added] WebSocket { #websocket }

**What it is.** HTTP is "customer asks, kitchen answers", so the server can't speak first. For services where **both sides talk whenever they like** — chat, live notifications, stock tickers — WebSocket starts as HTTP and then upgrades to "let's keep the line open like a phone call". URLs use `ws://` (unencrypted) and `wss://` (TLS).

```
GET /chat HTTP/1.1
Host: chat.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

- `Upgrade: websocket` + `Connection: Upgrade` — "let's switch to WebSocket"
- `Sec-WebSocket-Key` — a random value from the client (Base64); not a security secret but a greeting to confirm a real WebSocket server
- `Sec-WebSocket-Version: 13` — the current standard (RFC 6455)
- `101 Switching Protocols` — accepted
- `Sec-WebSocket-Accept` — the server's answer computed from the Key with a fixed value; if it matches, the connection is established

**SOC view.** After 101, traffic flows as **WebSocket frames**, not HTTP requests/responses, so proxy and web logs usually keep **only the initial handshake line**. The connection can stay open for hours with nothing more in the HTTP logs — attractive for C2. Detect with:

- **Very long-lived connections** (hours) in connection logs such as `conn.log`, and their destinations' reputation
- WebSocket handshakes to never-seen or newly registered domains
- Whether the process making the connection is a browser (Sysmon Event ID 3)

## HTTP section wrap-up { #summary }

HTTP carries web pages, email, messaging, social networks, calendars — and malware. Reading and interpreting requests and responses is everyday analyst work. The core of this section:

| You need to | Page |
| --- | --- |
| Break a URL into protocol, host, path and parameters | [Web Servers, URLs and GET](web-servers-urls-get.md#url) |
| Understand how server-side scripts change responses (incl. web shells) | [Web Servers, URLs and GET](web-servers-urls-get.md#web-servers) |
| Know GET, POST and the other methods | [POST, Other Methods and Request Headers](post-methods-headers.md) |
| Interpret status codes | [Response Headers and Status Codes](responses.md#status-codes) |
| Know the key request and response headers (Host, User-Agent, Referer, method, MIME type) | [Request headers](post-methods-headers.md#headers), [Response headers](responses.md#response-headers) |
| Spot what's odd in headers at a glance | [Judging Requests](reading-requests.md), [Header Reading Practice](header-practice.md) |
| Understand new standards (WebSocket, HTTP/2, HTTP/3/QUIC) | This page |

Plenty of malware hides as "well-behaved, protocol-compliant HTTP", so noticing what's off in headers is a core skill. At the same time, with encryption now the default, less and less is visible without decryption (TLS inspection) and endpoint records.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    "New standards keep the meaning and change the delivery", "one transaction = IP + connection + stream ID" and "without decryption you see less and less" all hold. As predicted, HTTP/2 and HTTP/3 are now the norm: per W3Techs, 41.2% of websites support HTTP/3 as of November 2026.

!!! info "[Changed]"
    - **Tools have caught up.** Wireshark decrypts and displays QUIC and HTTP/3 given session keys, and has **Follow → HTTP/2 Stream**. Zeek writes `quic.log` from version 6.1.
    - **Server push is effectively gone**, replaced by `103 Early Hints`.
    - **HTTP/2 itself became an attack vector.** 2023's "Rapid Reset" (CVE-2023-44487) opened and immediately cancelled (RST_STREAM) streams at enormous speed, producing record-breaking DDoS attacks; in 2024 an attack sending endless CONTINUATION frames was disclosed. Patching web servers' and proxies' HTTP/2 implementations matters.
    - **SMB over QUIC reached the regular editions in Windows Server 2025.** UDP 443 may carry non-web traffic.
    - **ECH is now a standard** (RFC 9849, March 2026). The SNI readable in QUIC's Initial packet disappears when ECH is used ([Domain fronting and ECH](post-methods-headers.md#domain-fronting)).

!!! warning "[Caution] / [Correction]"
    - **[Correction] "Methods differ significantly in HTTP/2 and HTTP/3" is a misconception.** Methods, paths and status codes mean the same; the request line and Host just became pseudo-headers.
    - **Watching TCP only misses QUIC entirely.** Set an outbound UDP 443 policy (block, or allow and log) and watch for attempts outside it.
    - **Rules matching capitalised header names can break on HTTP/2.** Compare case-insensitively.
    - **Don't leave `SSLKEYLOGFILE` enabled on production PCs.** That one file unlocks every encrypted session. An attacker who controls a PC could set it to harvest keys too, so the variable being set on a non-lab PC is worth checking.

## Practice questions { #quiz }

### Question 1

In a decrypted HTTP/2 capture, these frames appear in order on the same TCP connection:

```
HEADERS[7]: GET /report.pdf
HEADERS[9]: GET /update.bin
HEADERS[9]: 200 OK
DATA[9]
HEADERS[7]: 200 OK
DATA[7]
DATA[9]
```

(a) Which frames carry the contents of `update.bin`? (b) How do you narrow Wireshark to just this transaction?

??? success "Answer and explanation"
    **(a)** The DATA frames of **stream 9** — lines 4 and 7. In HTTP/2, frames from different streams **interleave**, so you pair them by **stream ID**, not order. `report.pdf` is stream 7 (the DATA on line 6).

    **(b)** Specify both the connection and the stream:

    ```
    tcp.stream == N && http2.streamid == 9
    ```

    `N` is Wireshark's number for this TCP connection. Other TCP connections may also have a stream 9, so narrow by **IP + TCP connection + stream ID**. Then use Follow → HTTP/2 Stream to read headers and body, or Export Objects to extract the file.

### Question 2

The organisation decides to block outbound UDP 443 at the firewall. (a) What happens to Chrome users, and why would the security team do this? (b) If a PC keeps trying to send to external UDP 443 afterwards, what should you suspect?

??? success "Answer and explanation"
    **(a)** Chrome notices HTTP/3 (QUIC) fails and **quietly falls back to TCP+TLS (HTTP/2)**; users barely notice (perhaps slightly slower). The reason: TCP+TLS traffic is handled by the existing **TLS-inspection proxy, proxy logs and web filters**, while QUIC easily bypasses them. The browser policy (`QuicAllowed` off) is usually applied too.

    **(b)** Browsers have already fallen back to TCP, so whatever keeps trying UDP 443 is **not the browser**:

    - Other legitimate QUIC apps (some video-conferencing or streaming apps)
    - **SMB over QUIC** (file sharing with an external file server)
    - **C2 malware** with QUIC/HTTP/3 transport

    Check the destination via the firewall's block records and Zeek `quic.log`'s `server_name`, and identify **which process** sent it via Sysmon Event ID 3.

### Question 3

One PC shows the records below. Interpret them and say what to do next.

```
http.log:  GET /ws  Host: live-feed.example.net  Upgrade: websocket  status=101
conn.log:  10.1.5.88 → 198.51.100.20:443  duration=9h12m  orig_bytes=184,320  resp_bytes=97,280
```

??? success "Answer and explanation"
    **Interpretation:** the PC opened a **WebSocket** to `live-feed.example.net` (`Upgrade: websocket` → `101`), and the connection stayed open **over nine hours**. Everything after 101 was WebSocket frames, so the HTTP log has only the first line while the connection log shows a long duration and modest byte counts. It could be a **legitimate service** (chat, live feed) or a long-lived **C2 channel**.

    **Next:**

    1. **Destination reputation** — `live-feed.example.net` and its IP: reputation, registration date, first seen in the organisation?
    2. **Which process** — Sysmon Event ID 3: a normal browser tab, or an unfamiliar program in `AppData` or similar?
    3. **Compare with human activity** — was the user actually working during those nine hours? (Open after hours or overnight is more suspicious.)
    4. **Data pattern** — WebSocket frame content if TLS inspection is available; otherwise whether it looks like small signals at regular intervals (a beacon)
    5. Other PCs opening WebSockets to the same destination
