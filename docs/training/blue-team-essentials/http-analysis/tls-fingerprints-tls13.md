---
title: "TLS Fingerprints (JA3, JA3S, JARM, JA4), TLS 1.3, and the HTTP(S) Analysis Wrap-up"
tags:
  - training
  - blue-team
  - http
  - tls
---

# TLS Fingerprints (JA3, JA3S, JARM, JA4), TLS 1.3, and the HTTP(S) Analysis Wrap-up { #tls-fingerprints-tls13 }

!!! abstract "What this page covers"
    TLS fingerprints, which tell you "which program made this connection" without decrypting anything: what JA3 and JA3S collect and how they are calculated, line by line; why JA3 started to break in 2023 and how JA4 replaced it; and JARM, which actively probes servers, along with its risks. Then what TLS 1.3 took away from the security team (certificates, passive decryption, downgrades, and soon the SNI), and a checklist that pulls the whole HTTP(S) analysis module together. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Continues from [HTTPS — TLS Decryption, Working Without It, Reading Certificates](https-certificates.md).

## The 8 key points { #key-points }

1. Every program's **opening handshake message (ClientHello) looks slightly different.** A short value summarising that shape is a **TLS fingerprint**.
2. **JA3** = client fingerprint (ClientHello), **JA3S** = server fingerprint (ServerHello). Both join a few fields together and take the **MD5**, giving a 32-character value.
3. Unlike the User-Agent, a fingerprint is **not something the program writes about itself**. It is fixed when the program is built, so it is harder to fake (though not impossible).
4. How to use it: the **common fingerprints in your organisation = the normal baseline**. Look for rare fingerprints and match against threat-intel **lists of known-bad fingerprints**.
5. [Changed] In 2023 Chrome started shuffling its extension order on every connection, which **badly broke JA3.** **JA4**, which sorts extensions before hashing, is today's standard.
6. **JARM** is not passive observation: it **actively connects to a server**. It can confirm whether a suspicious server is a C2 server, but it **reveals you to the attacker (OPSEC).**
7. **TLS 1.3**: certificates are encrypted, **passive decryption** with the server's private key **is impossible** (perfect forward secrecy is mandatory), and **downgrade** to older versions is blocked. The remaining SNI is being hidden by **ECH**.
8. HTTP(S) analysis wrap-up: **fields → content → source/destination/certificates → frequency and context → knowledge of attacker tools**, layering several methods together.

## Why TLS fingerprints matter { #why-fingerprints }

As the previous page showed, without TLS decryption you lose the path, headers and User-Agent. But **the very first message that starts a connection (ClientHello) is not encrypted.** No keys have been agreed yet, so it cannot be.

The ClientHello carries lists that say "I can use this TLS version, I support these cipher suites in this order, and I want these features (extensions)". Those lists are determined by **which TLS library the program was built with and how it is configured.** So Firefox, Chrome, Python `requests`, a Tor client and a given piece of malware each send a slightly different ClientHello.

Think of it as **the way someone shakes hands.** Anyone can write any name on a name tag (the User-Agent), but the angle of the hand, the grip and the number of shakes are ingrained habits that are harder to change. A TLS fingerprint condenses that "handshake habit" into a short value.

## JA3 and JA3S { #ja3 }

### The five things JA3 collects { #ja3-fields }

JA3 pulls five things from the ClientHello, **in this order**.

| Order | Field | Meaning |
| --- | --- | --- |
| 1 | TLS Version | The version number written in the ClientHello (decimal). 771 = 0x0303 = TLS 1.2 |
| 2 | Cipher Suites | The list of supported cipher suites, **in the order sent** |
| 3 | Extensions | The list of requested features (extensions), **in the order sent** |
| 4 | Elliptic Curves (Supported Groups) | The curves/groups available for key exchange |
| 5 | EC Point Formats | How elliptic-curve points are encoded |

The rules: values inside each list are **converted to decimal and joined with `-`**, and the five groups are **joined with `,`.** **GREASE values are dropped.** GREASE values are meaningless values (shaped like 0x0a0a, 0x1a1a) that Chrome and others deliberately mix in to test that servers don't break on unknown values. They change every time, so they must not go into a fingerprint.

### Calculating one yourself { #ja3-calc }

Suppose a client sent the following (a shortened, invented example for explanation).

```
TLS Version        : 0x0303                      -> 771
Cipher Suites      : 0x1301 0x1302 0x1303 0xc02b 0xc02f
                                                 -> 4865-4866-4867-49195-49199
Extensions         : 0 10 11 13 16 43 45 51      -> 0-10-11-13-16-43-45-51
Supported Groups   : 0x001d 0x0017 0x0018        -> 29-23-24
EC Point Formats   : 0                           -> 0
```

- `0x0303 -> 771` — for compatibility, even TLS 1.3 clients put TLS 1.2 (0x0303) in this field. Real TLS 1.3 support is signalled inside extension 43 (supported_versions). So the JA3 version field is almost always 771
- `4865-...-49199` — 0x1301 to 0x1303 are TLS 1.3 cipher suites; 0xc02b and 0xc02f are TLS 1.2 ECDHE-GCM suites
- `0-10-11-13-16-43-45-51` — 0 = SNI, 10 = supported_groups, 11 = ec_point_formats, 13 = signature_algorithms, 16 = ALPN, 43 = supported_versions, 45 = psk_key_exchange_modes, 51 = key_share
- `29-23-24` — 29 = X25519, 23 = P-256, 24 = P-384
- `0` — uncompressed

Joined together, that is the **JA3 string**.

```
771,4865-4866-4867-49195-49199,0-10-11-13-16-43-45-51,29-23-24,0
```

The MD5 of that string is the **JA3 hash**.

```
$ echo -n "771,4865-4866-4867-49195-49199,0-10-11-13-16-43-45-51,29-23-24,0" | md5sum
0c55049b7c3967e9b529134ee3c1bcc7  -
```

- `echo -n` — prints the string without a trailing newline (a newline would change the hash completely)
- `| md5sum` — computes the MD5 of that string
- The result `0c55049b...` — this 32-character value is the `ja3` value you see in logs

Change a single character (say, one extra curve) and the hash is completely different. That is both its strength and its weakness (see [Changed] below).

### JA3S — the server-side fingerprint { #ja3s }

This one is built from the server's ServerHello reply. The server doesn't send a list; it **picks one** option, so there are three fields.

```
JA3S string : 771,49199,65281-0-11-35
JA3S hash   : a2c05b7498f29a65608835b44035c0c5
```

- `771` — the version the server replied with
- `49199` — the single cipher suite the server chose (0xc02f)
- `65281-0-11-35` — the extensions the server included in its reply

The key point: **the server's reply depends on the client's question.** The same server can answer Firefox and a piece of malware differently. So JA3S is much stronger as a **JA3 + JA3S pair** than on its own: you can catch "the combination that only appears when this malware (JA3) talks to this C2 server software (JA3S)".

### Reading it in Zeek { #ja3-zeek }

With a JA3 package installed, Zeek adds fields to `ssl.log`.

```
ssl.log:
  ts=2026-11-04T09:12:40Z  id.orig_h=10.1.8.23  id.resp_h=198.51.100.44  id.resp_p=443
  version=TLSv12  server_name=cdn-assets-sync.example
  ja3=6f1a9e0c3b5d7e2a4c8b0d1e3f5a7b9c  ja3s=d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
```

- `ja3` — the fingerprint of the ClientHello sent by a program on this PC
- `ja3s` — the fingerprint of the ServerHello the server sent back
- (The hash values are invented for illustration)

### How a SOC uses it { #ja3-usage }

1. **Build a baseline:** count `ssl.log` entries per `ja3` value across the organisation. Your browsers, updaters and security agents will sit at the top. Reproduce them from a standard PC image and you can label them: "this is our Chrome", "this is our backup agent"
2. **Find rare fingerprints:** a fingerprint seen on only one or two PCs is worth a look (though it may be a developer tool or an unusual business app)
3. **Match against bad lists:** compare with malware and attack-tool fingerprints from threat intelligence
4. **Layer with other signals:** when **several signals converge on one connection** — a rare fingerprint, a newly registered domain, a regular interval, no SNI — raise its priority

**[Caution] A fingerprint identifies a "TLS library and configuration", not a "program".** A legitimate script and a piece of malware built on the same Python library can share a fingerprint, and many programs share the operating system's TLS library (Schannel on Windows, for example) and so produce the same one. Never call something malicious on the fingerprint alone. Attackers can also use **tools that mimic a browser's fingerprint** (making their TLS library look like Chrome).

**[Supplement] The old "JA3 → User-Agent lookup site" is gone.** There used to be a public site that calculated your browser's JA3 and matched it to a User-Agent, but it no longer operates. Today you use the JA4 database (ja4db), threat-intel platforms, or your own organisational baseline.

## [Changed] Why JA3 broke, and JA4 { #ja4 }

**What happened.** In early 2023, Chrome (and Chromium-based browsers) started **randomising the order of ClientHello extensions on every connection.** The aim was to stop servers and middleboxes from breaking by depending on a particular order. But because JA3 joins values "in the order sent", **Chrome alone now produced a different JA3 on every connection.** The baseline collapsed. The developer who created JA3 moved on and built a new method (JA4), and the original JA3 repository is no longer maintained.

**What JA4 does differently.** JA4 **sorts the lists before hashing**, so shuffled order gives the same value. It also adds a human-readable prefix, so you can tell roughly what something is just by looking at it. It has three parts, `a_b_c`. The same example as above, as JA4:

```
JA4 = t13d0508h2_e133e205ac38_2f59b3fc5483
```

| Part | Value | Meaning |
| --- | --- | --- |
| a (readable) | `t` | Transport: t = TCP, q = QUIC, d = DTLS |
| | `13` | Highest TLS version actually supported (from the supported_versions extension) → 1.3 |
| | `d` | SNI present (connecting to a domain). `i` means no SNI = **direct-to-IP connection** |
| | `05` | Number of cipher suites (excluding GREASE) |
| | `08` | Number of extensions (excluding GREASE) |
| | `h2` | First and last characters of the first ALPN value → h2 (HTTP/2). `00` if none |
| b | `e133e205ac38` | The cipher suite list **sorted**, SHA256-hashed, first 12 characters |
| c | `2f59b3fc5483` | The extension list (excluding SNI and ALPN) **sorted**, with the signature algorithm list appended, SHA256-hashed, first 12 characters |

Part a alone tells you a lot. For example `t12i...00` reads "TLS 1.2 at most, no SNI so straight to an IP, no ALPN" — a completely different shape from a modern browser, and it stands out immediately. Because the parts are separate, **you can hunt on parts alone.** If an attack tool changes just one cipher suite, only b changes while a and c stay the same, so you can keep tracking it on the `a_c` combination.

**The JA4+ family.** The same approach has been extended to other areas.

| Name | What it fingerprints |
| --- | --- |
| JA4 | TLS client (ClientHello) |
| JA4S | TLS server (ServerHello) — successor to JA3S |
| JA4H | HTTP client (header set, order, cookies, language) — on decrypted or plain HTTP |
| JA4X | **How** an X.509 certificate was built (field structure) — groups certificates minted by the same tool |
| JA4SSH | The packet shape of an SSH session (interactive shell vs file transfer, etc.) |
| JA4T / JA4TS | TCP client and server (window size, TCP options) — operating system / device character |
| JA4L | "Distance" measured by round-trip latency |

Licensing is worth knowing too. **JA4 (client) is BSD 3-Clause** and free to use; the rest of JA4+ is under the **FoxIO License 1.1**. You can use it for internal business and academic work, but products that sell it need a separate licence.

**Where you'll find it.** Wireshark, Zeek (JA4+ package), Arkime and Security Onion support JA4+; Suricata support is in progress. Cloudflare, AWS CloudFront and WAF, Akamai, Zscaler, VirusTotal and others provide JA4. With the package installed, Zeek logs it like this:

```
ssl.log:
  id.orig_h=10.1.8.23  id.resp_h=198.51.100.44  id.resp_p=443
  server_name=cdn-assets-sync.example  version=TLSv13
  ja4=t13d0508h2_e133e205ac38_2f59b3fc5483  ja4s=t130200_1301_a56c5b993250
```

- `ja4` — the client fingerprint (the value we built above)
- `ja4s` — the server fingerprint: `t13` (TCP, TLS 1.3), `02` (2 extensions), `00` (no ALPN), `_1301` (chosen cipher suite), `_...` (extension hash)
- (The `ja4s` hash is invented for illustration)

## JARM — fingerprinting a server by knocking on it { #jarm }

JA3 and JA4 are passive: they **observe traffic going past.** JARM is different. **The analyst connects to the server directly**, sends **10** deliberately different ClientHellos, collects how the server answers each one (which version and cipher suite it picks, which extensions it returns), and builds a **62-character fingerprint**.

```
$ python3 jarm.py c2-panel.example
Domain: c2-panel.example
Resolved IP: 203.0.113.91
JARM: 2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53
```

- `jarm.py <host>` — the JARM tool connects to that server 10 times
- First 30 characters — 3 characters per probe summarising the cipher suite and version the server chose
- Last 32 characters — a hash of the extensions the server returned
- (The fingerprint value is invented for illustration)

**Why use it.** How a server answers TLS is determined by **the server software and its configuration.** Attacker C2 server software left on default settings produces a characteristic JARM. So you can compare a suspicious server's JARM against known C2 fingerprints, or **search internet scan data (Censys, Shodan and the like) for other servers with the same JARM** to expand the attacker's infrastructure.

**[Caution] JARM reveals you (OPSEC).** The moment you connect, your IP lands in the attacker's server logs, and the attacker can tell "someone is investigating our server". **Never do this from a company IP or a company PC.** If it is really needed, use an isolated analysis environment and a line that hides your origin — or, more safely, look up JARM values internet scanning companies have already collected.

**[Caution] Don't decide on JARM alone.** Many C2 servers run on common TLS stacks such as Java, Go or nginx, so **thousands of legitimate servers can share the same JARM.** JARM is a tool for "narrowing down candidates", not standalone evidence.

## What TLS 1.3 changed { #tls13 }

TLS 1.3 greatly improved user security, but it broke several of the security team's existing methods. One at a time:

### 1. Certificates are encrypted { #tls13-cert }

In TLS 1.2 the server certificate travels in the clear, so you could read the Subject, Issuer and validity as on the previous page. In TLS 1.3 encryption starts right after the ServerHello, and **the certificate is delivered inside that encrypted part.** Reading certificates without decryption doesn't work on TLS 1.3 connections.

```
TLS 1.2                              TLS 1.3
ClientHello        (clear)           ClientHello        (clear: SNI, JA4)
ServerHello        (clear)           ServerHello        (clear: JA4S)
Certificate        (clear) ← visible {EncryptedExtensions}  (encrypted)
ServerKeyExchange  (clear)           {Certificate}          (encrypted) ← hidden
...                                  {Finished}             (encrypted)
```

### 2. No more "passive decryption" with the server's private key { #tls13-pfs }

TLS 1.2 and below had a method called **RSA key exchange.** The session key travelled locked with the server's private key, so a device (or Wireshark) holding that private key could **decrypt recorded traffic later.** This is how an IDS quietly decrypted traffic coming into the organisation's own web servers from the side.

TLS 1.3 removes that method entirely and makes **perfect forward secrecy (PFS)** mandatory. Each connection, both sides create a fresh one-time key (ECDHE), use it and discard it, so **even with the server's private key you cannot decrypt past traffic.** In the past, one master key opened every safe; now each safe uses a key that is melted down after a single use.

Two options remain:

- **Stand in the middle of the connection and terminate it yourself (an active proxy / TLS inspection device)** — the method from the previous page
- **Extract session keys from the endpoint** — in the lab or during incident analysis, the `SSLKEYLOGFILE` environment variable makes browsers write their session keys to a file, which you load into Wireshark. On the server side, log at the point where TLS terminates, such as a load balancer

```
# Lab/IR use only, on a machine you control
$ export SSLKEYLOGFILE=$HOME/tls-keys.log
$ firefox &
# Wireshark: Preferences > Protocols > TLS > (Pre)-Master-Secret log filename = ~/tls-keys.log
```

- `export SSLKEYLOGFILE=...` — when this variable is set, Firefox, Chrome and others write each connection's session keys to that file
- Point Wireshark at the file and TLS traffic captured in the same period is decrypted, revealing the HTTP content
- **[Caution]** This file is the key to every encrypted connection in that period. Delete it when the analysis is done and never leave it permanently enabled on a work PC. Attackers sometimes set this variable covertly to steal keys, so a user environment with `SSLKEYLOGFILE` set is itself something to investigate

### 3. Inspection devices can't easily "step out" { #tls13-proxy }

In the TLS 1.2 era, some inspection devices **looked at the plaintext server certificate**, decided "this is a bank, don't decrypt", and stepped out of the connection. In TLS 1.3 the certificate is encrypted, so that decision can't be made from it. About all the device has is the **SNI** in the ClientHello; to learn more, it must **stand in the middle from start to finish.** Once it has stepped in, it can't quietly step out (the keys on each side are already different).

### 4. Downgrades are blocked { #tls13-downgrade }

The trick of "TLS 1.3 is inconvenient, so force the connection down to TLS 1.2" is also blocked. When a server that supports TLS 1.3 answers with a lower version, it puts a **special marker (the bytes spelling `DOWNGRD`)** in the last 8 bytes of the ServerHello random value. A TLS 1.3 client that sees this concludes "someone in the middle forced the version down" and drops the connection.

### 5. ECH is hiding the remaining SNI { #tls13-ech }

Even in TLS 1.3, the ClientHello's **SNI is still plaintext**, so the destination domain is visible. But with **ECH (Encrypted Client Hello)** standardised as RFC 9849 in 2026, sites and browsers that support it encrypt the real SNI and show only the CDN's public name on the outside ([ECH](../http/post-methods-headers.md#domain-fronting)). What remains visible without decryption is then roughly **IP/ASN, port, volume/timing/interval, and fingerprints such as JA4.**

| Visible | TLS 1.2 | TLS 1.3 | TLS 1.3 + ECH |
| --- | --- | --- | --- |
| IP, port, volume, timing | Yes | Yes | Yes |
| SNI (domain) | Yes | Yes | Outer name only (CDN) |
| Client/server fingerprints (JA4, JA4S) | Yes | Yes | Partly (based on the outer ClientHello) |
| Server certificate | Yes | No | No |
| Passive decryption with server private key | Yes, if RSA key exchange | No | No |
| HTTP path, headers, body | No (without decryption) | No | No |

## HTTP(S) analysis wrap-up — a checklist { #summary }

There is no single rule that catches every HTTP or HTTPS attack. But a malicious request, examined carefully, **almost always has something odd about it**: an odd field value, an odd pattern (repeated requests for innocent-sounding files from a suspicious location), encoding where none is needed, a self-signed certificate, and so on. That is why the most important thing is **to know in your bones what normal HTTP looks like.** You only see the abnormal once you know the normal.

Pulling this whole module into a checklist:

1. **Request and response fields** — method, URL, Host, User-Agent, Referer, Cookie, status code, Content-Type, Server, X-Forwarded-For ([reading requests](../http/reading-requests.md), [responses](../http/responses.md))
2. **Request and response content** — file type of the body (magic bytes), Base64 and other encodings, what downloaded files really are ([Base64](base64.md), [files and frequency](files-frequency-naked-ip.md))
3. **Source, destination and identity** — domain age and reputation, IP/ASN, SNI, certificates, TLS fingerprints ([reputation](evil-http-and-reputation.md), [certificates](https-certificates.md), this page)
4. **Frequency and context** — how many hosts, how often, at what interval, and what the user was doing at the time ([beacon analysis](../../../network/beaconing-c2.md))
5. **Know attacker tools and methods** — exploit kits, web shells, Cobalt Strike profiles, recent techniques such as ClickFix and AiTM ([exploit kits](exploit-kits-practice.md))

The best attack tools (for example a well-crafted Cobalt Strike profile) can make all of this look normal. That is why you **layer several methods instead of relying on one**, and why **threat hunting** — going out to look rather than waiting for alerts — is necessary.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    "The ClientHello is plaintext, so you can fingerprint it", "use fingerprints as a baseline plus rare values plus bad lists", "active probing like JARM has an OPSEC cost", "TLS 1.3 hides certificates, prevents passive decryption and blocks downgrades" and "you must know normal to see abnormal, and layer several methods" all still hold.

!!! info "[Changed] What has changed"
    - **JA3 → JA4.** Since Chrome's extension-order randomisation (2023), JA3 is hard to use as a baseline for Chromium-based clients. The original JA3 repository is no longer maintained, and **JA4+**, built next by the same developer, is now in Wireshark, Zeek, Arkime and major CDN and cloud WAFs — effectively the standard. Old threat-intel JA3 lists still have some use (malware often doesn't shuffle), but build new detections on JA4.
    - **JARM has stalled too.** The original JARM tool isn't actively maintained, and active TLS server fingerprinting is moving to the JA4+ family (JA4Scan-TLS/QUIC) and to internet-scanning companies' data.
    - **Post-quantum key exchange is now the default.** Since 2024–2025, major browsers use a **hybrid key exchange (X25519MLKEM768)** that mixes the post-quantum algorithm ML-KEM with X25519 by default. The ClientHello grows and is split across several packets, and older IDS and proxies that can't reassemble it miss the SNI or fingerprint, or break the connection. Calculated as JA3, a new value (4588) appears in the curve list and the hash changes, so old JA3 baselines need rebuilding.
    - **ECH is a standard (RFC 9849, 2026).** SNI is being hidden first for sites behind CDNs. More organisations disable ECH by policy (managed browser policy, blocking DNS HTTPS records) or handle it on inspection devices.
    - **Fingerprints for QUIC (HTTP/3).** QUIC connections are fingerprinted too, as the leading `q` in JA4 shows. Many organisations still block UDP 443 to force a fallback to TCP.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't identify browsers from a JA3 hash, and don't read "Chrome with a different JA3 every time" as suspicious.** That's normal because of extension-order randomisation. Use JA4.
    - **Don't call something malicious on the fingerprint alone.** Shared TLS libraries and browser-mimicking tools cause both false positives and false negatives. Layer with other signals.
    - **Don't run JARM or scans against suspicious servers from a company IP.**
    - **Don't try "force TLS 1.2 and it becomes visible again".** TLS 1.3 detects the downgrade and drops the connection, and it weakens security.
    - **Don't leave `SSLKEYLOGFILE` permanently set on work PCs.** If it is set in a user's environment, check it — it may be an attacker's doing.

## Practice questions { #quiz }

### Question 1

Counting JA4 values across the organisation's `ssl.log` for the last 7 days gives the following. What do you investigate first, and why?

```
count   hosts  ja4                                   top server_name
412093  1830   t13d1516h2_8daaf6152771_02713d6af862  (many)
 98211  1822   t13d1517h2_8daaf6152771_b1ff8ab2d16f  (many)
  5120    44   t13d1715h2_5b57614c22b0_3d5424432f57  update.vendor-sync.example
  1440     1   t12i0806h2_9a4f0c1e7d22_6e0b8a2f1c3d  -
```

??? success "Answer and explanation"
    **Investigate the last line (1,440 connections, 1 PC) first.**

    - The top two lines appear on almost every PC (1,830 and 1,822 hosts) → the **baseline**, likely the standard company browser
    - The third line is used by 44 PCs against a single update domain → probably a specific business tool. Confirm and label it later
    - The fourth line has part a `t12i0806h2`:
        - `t12` — TLS 1.2 at most. Modern browsers use 1.3
        - `i` — **no SNI = direct-to-IP connection** (top server_name is also `-`)
        - `0806` — 8 cipher suites and 6 extensions, much simpler than a browser
        - On **one PC** only, 1,440 times in 7 days ≈ 206 a day, roughly once every 7 minutes, regularly

    A rare fingerprint, no SNI and regular repetition converge on one connection, so suspect C2. Next: identify that PC and the destination IP, analyse the connection interval, find the process that made the connection on the endpoint (Sysmon Event ID 3 — network connection, records which program connected where), and check the IP's reputation and the certificate (it's TLS 1.2, so it may still be in `x509.log`).

### Question 2

A colleague says "let's check right now with JARM whether suspicious IP 203.0.113.91 is a C2 server" and is about to run `jarm.py` from a work PC. What is wrong with that, and what is the right approach?

??? success "Answer and explanation"
    **The problem:** JARM is active probing that **connects to the server 10 times.** Done from a work PC and company IP, **your IP lands in the attacker's server logs**, and the attacker may realise they are being investigated and change infrastructure, wipe traces or speed up their operation (OPSEC exposure). An attacker's server may also return malicious responses to an investigator's connection.

    **The right approach:**

    1. Start with **passive data** — look up the JARM, certificate and JA4S already collected for that IP by internet-scanning companies (Censys, Shodan and the like) or threat-intel platforms
    2. If active probing is really needed, run it from an **isolated analysis environment** on a line not linked to the organisation, following the organisation's approval process
    3. Even if the resulting JARM matches a known C2 fingerprint, **don't use it as standalone evidence** — it may overlap with legitimate servers on common TLS stacks (Java, Go, nginx). Decide together with the certificate, domain age and internal connection patterns

### Question 3

Your team lead says: "TLS 1.3 traffic is growing, so let's load the web server's private key into the IDS and quietly decrypt incoming HTTPS from the side like before." Explain why this plan won't work and what you can do instead.

??? success "Answer and explanation"
    **Why it won't work:** the old method only worked with **RSA key exchange** in TLS 1.2 and below. Back then the session key travelled locked with the server's private key, so an IDS holding that key could decrypt a copy of the traffic. TLS 1.3 removes RSA key exchange and makes **perfect forward secrecy (PFS)** mandatory. Each connection creates, uses and discards a one-time key (ECDHE), so **even with the server's private key you cannot decrypt traffic seen from the side.** Even with TLS 1.2, most connections now use ECDHE, so the same applies. "Let's downgrade to TLS 1.2" doesn't work either because of downgrade protection, and it only weakens security.

    **What you can do instead:**

    1. **Look where TLS terminates** — load balancers, reverse proxies and WAFs decrypt TLS and pass traffic to the servers behind them, so send their logs (URL, headers, status codes) to the SIEM, or put a sensor on the plaintext segment behind them
    2. **The web server's own logs and the endpoint** — web server access logs, WAF logs, and EDR on the server (if the web server process spawns a shell, it shows up as Windows Event ID 4688 — new process created — or Sysmon Event ID 1)
    3. **What's visible without decryption** — client JA4, IP/ASN, request volume and interval
