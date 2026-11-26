---
title: "Analysing Network Events Layer by Layer — IP and Domain, Ports, TLS Certificates, Application Metadata and Content"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - investigation
  - network
---

# Analysing Network Events Layer by Layer — IP and Domain, Ports, TLS Certificates, Application Metadata and Content { #analysing-network-events }

!!! abstract "What this page covers"
    The fourth investigation question — **what does the data tell me?** — applied to network evidence. First, how to interpret evidence at all: with every hypothesis on the table, a fresh look at the whole picture, and an effort to disprove rather than confirm. Then the central idea of the page: network traffic is **encapsulated**, and an attacker can play games at any single layer while every other layer looks perfectly normal — an SSH upload whose only tell is its destination, a malware download from a trusted file-sharing site whose only tell is the file itself. Then a check-list for each layer: **Layer 3** (IP addresses and domains — intel lists, how many of your hosts go there, history, reputation, passive DNS, ASN, domain age, randomness, rank, length, subdomains), **Layer 4** (ports — what each implies, mismatched protocols, non-standard and "known bad" ports, random ports, and why the destination port is the interesting one), **Layer 5** (TLS — SNI, suspicious, self-signed or expired certificates, JA3/JA3S and their successor JA4+, never-seen certificates, and certificate data that doesn't match where the traffic goes, including domain fronting) and **Layer 7** (protocol metadata from Zeek and Suricata versus content that only full packet capture holds). Five invented network events from one morning are worked through with Zeek `conn.log`, `ssh.log`, `ssl.log`, `x509.log`, `http.log` and `files.log` lines read field by field, a `zeek-cut` prevalence check line by line, and a packet-capture extraction. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Bluegum Freight), hostnames, accounts, domains, IPs, certificates, hashes and log lines are invented for illustration (`.example`, documentation and private IPs). Tools, protocols and services are real and described in my own words.

## The 8 key points { #key-points }

1. **Interpreting data means testing every hypothesis against it.** Look at the evidence as a whole, with fresh eyes, and try to *disprove* explanations — especially your favourite.
2. **Traffic is encapsulated, and badness may show at only one layer.** IP, port, TLS and application content are separate layers; an attacker can make all but one look normal. Check them all.
3. **Layer 3 — the destination — is often the cheapest and best clue.** Attackers usually run their own infrastructure, so a bad IP or domain may be the only sign of an otherwise normal-looking connection. Ask: is it on an intel list, how many of our hosts go there, have we ever seen it before?
4. **Rare is suspicious; common is usually fine.** A destination visited by thousands of your hosts is unlikely to be malicious; one visited by a single host for the first time deserves a closer look.
5. **Layer 4 ports imply a service, and attackers know it.** Look for protocol/port mismatches, non-standard ports, "known bad" ports (4444, 6667) and random ports. A bad thing can run on a good port and a good thing on an odd port — but rarely on a known-bad port.
6. **Layer 5 TLS details leak a lot without decryption.** SNI, certificate subject and issuer, self-signed or expired certificates, never-seen certificates and client fingerprints (JA3, now JA4+) all help — and so does a mismatch between the certificate, the DNS name and the HTTP host.
7. **Layer 7 has two parts: metadata and content.** Metadata (methods, URLs, user agents, file names) is logged by Zeek and Suricata and is enough for most detections. Content — the actual bytes of a file — is only in full packet capture.
8. **Some attacks are visible only in the content.** Malware downloaded from a trusted cloud file-sharing site looks normal at every layer until you examine the file itself.

## Why this matters in a SOC { #why }

Think of a parcel arriving at a mailroom. The address label says where it is going (Layer 3). The size of the box says what sort of thing it ought to be — an envelope for a letter, a long tube for a poster (Layer 4). There is a courier's seal saying who packed it (Layer 5, TLS). And inside there is the contents (Layer 7). A smuggler only has to make *one* of these misleading: a correct label on a box of contraband, a letter-sized envelope with something else inside, a forged seal. A mailroom clerk who checks only the label misses everything else.

Back to the technical reality. Most network alerts point at one layer — a reputation hit on an IP, a signature matching a payload — and it is tempting to evaluate only that layer. But an alert is a starting point, and the question "is this malicious?" can only be answered by looking at all the layers your data covers. Equally, a connection that raised *no* alert at Layer 7 may be the most dangerous one of the day if its destination is wrong. The layered check-list on this page is how analysts avoid both mistakes.

## #4 — What does the data tell you? { #q4 }

The last of the four investigation questions is the analysis itself: you have the network traffic, the files or the host logs in hand, and now you have to decide what actually happened. A few habits make the difference:

- **Keep all the hypotheses on the table.** Before deciding, list every explanation consistent with the data — benign, malicious, test, misconfiguration, "the data is wrong" — as the structured-analysis section taught. Then ask which evidence distinguishes them.
- **Look with fresh eyes, at the whole picture.** Read the evidence again as if someone else had collected it. A single field you skipped the first time (a byte count, a time zone, a parent process) can change the story.
- **Try to disprove.** For each explanation ask "what would I see if this were *false*?" and look for that. A hypothesis that survives serious attempts to kill it is worth more than one with lots of supporting detail.

How you answer depends on the kind of evidence. This page covers network interactions; the next pages cover links and email (is a link malicious, did the user interact with it, targeted or opportunistic, business email compromise).

## Encapsulation: why you check every layer { #encapsulation }

The mental-models section described **encapsulation**: each layer wraps the one above it, and each can be inspected separately. For network analysis the layers that matter are:

| Layer | What you see | Typical sources |
| --- | --- | --- |
| 3 — Network | Source and destination IP addresses (and the domain names that map to them) | NetFlow, firewall, Zeek `conn.log`, DNS logs |
| 4 — Transport | TCP/UDP ports, byte counts, connection state | Firewall, NetFlow, Zeek `conn.log` |
| 5 — Session | TLS handshake and certificate details (where TLS is used) | Zeek `ssl.log`/`x509.log`, proxy, Suricata TLS logs |
| 7 — Application | Headers and metadata (methods, URLs, user agents, file names), and the payload itself | Zeek `http.log`/`files.log`/`dns.log`, proxy, Suricata, full PCAP |

**[Supplement]** Real protocol stacks don't map neatly onto the classic seven-layer OSI model — TLS is often described as sitting between Layer 4 and Layer 7 rather than "at Layer 5" — but the four-way split above is the practical one for analysts: *where is it going, on which port, inside which encrypted wrapper, carrying what?*

The point is that **badness may show up at only one layer**. Two contrasting examples:

**Only Layer 3 is wrong.** An attacker uses SSH to copy a stolen database out of the network. SSH is encrypted, so you can't see that the Layer 7 contents are your customer records. It runs on the standard port 22, so Layer 4 looks fine. If outbound SSH is allowed from that host, nothing in the protocol is unusual. The only network-level clue is **where it goes**: an IP address associated with the attacker, or one with bad reputation in a threat feed. (Plus the business question: is outbound SSH expected from this host at all?)

**Only Layer 7 content is wrong.** A user is phished with a link to malware hosted on a public cloud file-sharing site. Even with TLS decryption, everything looks normal: a good IP and domain, the expected port 443, a valid TLS session to a well-known certificate, valid HTTP with normal headers. The only thing wrong is **what was transferred** — and to know that, you have to examine the file itself.

You never know in advance which layer an attacker will play with. Encapsulation gives them many choices: good protocols with bad content, or good, standards-compliant transactions to bad destinations. So the rule is simple: **evaluate every layer your data covers.**

## The morning's network events { #worked-events }

Here are five network events from Bluegum Freight's sensors on one morning, each flagged by a different rule or hunt. We will use them throughout the page.

| # | What was flagged | Host | Destination |
| --- | --- | --- | --- |
| N1 | Threat-feed match on destination IP | BG-DB-03 (10.20.8.30) | 203.0.113.45:22 |
| N2 | Protocol/port mismatch | BG-WS-0219 (10.20.2.19) | 198.51.100.81:80 |
| N3 | Self-signed TLS certificate to rare destination | BG-WS-0612 (10.20.6.12) | 203.0.113.9:8443 |
| N4 | SNI / HTTP Host mismatch on the proxy | BG-WS-0533 (10.20.5.33) | 192.0.2.120:443 (CDN) |
| N5 | ISO file downloaded from cloud file sharing | BG-WS-0437 (10.20.4.37) | `files.cloudshare.example` (198.51.100.10:443) |

## Layer 3: IP and domain inspection { #layer3 }

Most of the time, attackers work from **their own infrastructure**: their own servers, their own domains, their own hosting. Using a victim's server or a legitimate service gives them less control — it can be cleaned up or taken down at any moment. That is why knowing that an IP or domain is bad is often enough to start treating traffic as malicious. Doing so depends on two things: the indicator being on a deny list or intel feed, or the enrichment techniques from the DNS and HTTP sections flagging it as anomalous.

**The quick checks** (seconds each):

- Is the IP or domain on **any intel list** you have?
- **How many** of your hosts or users go there?
- Do you have **historical data** — when was it first seen in your environment?

**Deeper checks for an IP address:** reputation services; your threat-intel platform; **reverse DNS** (what name the owner gives it) and **passive DNS** (which domains have pointed to it over time); OSINT searches; the **ASN** (which network owns it — a residential ISP, a cloud provider, a "bulletproof" host); and the history of what it has hosted.

**Deeper checks for a domain:** reputation and intel; current and **passive DNS**; **randomness** of the name (algorithmically generated names look like `xq7kd2plm.example`); **age** (registered last week?); OSINT; popularity **rank**; **length**; and **subdomains** (dozens of odd subdomains under one parent can mean tunnelling or a phishing kit).

### Worked example: N1, the SSH upload { #n1 }

The Zeek `conn.log` line (fields shown as name=value for readability):

```
ts=2026-11-25T18:02:41Z  uid=CsH81b  id.orig_h=10.20.8.30  id.orig_p=49812  id.resp_h=203.0.113.45  id.resp_p=22  proto=tcp  service=ssh  duration=2214.6  orig_bytes=4398046511  resp_bytes=3811402  conn_state=SF  local_orig=T  local_resp=F
```

- `id.orig_h=10.20.8.30` — BG-DB-03, a database server, started the connection.
- `id.resp_h=203.0.113.45`, `id.resp_p=22` — to an external address on the SSH port.
- `service=ssh` — Zeek's protocol detection confirmed it really is SSH, so Layer 4 and the protocol agree.
- `duration=2214.6` — 37 minutes.
- `orig_bytes=4398046511` — about **4.1 GiB sent out** by the database server; `resp_bytes=3811402` — under 4 MB back. A large upload.
- `conn_state=SF` — a normal, completed TCP session (SYN, then FIN): nothing broken.
- `local_orig=T`, `local_resp=F` — inside to outside.

Zeek's `ssh.log` for the same `uid`:

```
ts=2026-11-25T18:02:41Z  uid=CsH81b  version=2  auth_success=T  auth_attempts=1  direction=OUTBOUND  client=SSH-2.0-OpenSSH_9.6  server=SSH-2.0-OpenSSH_8.9p1  cipher_alg=chacha20-poly1305@openssh.com
```

- `auth_success=T`, `auth_attempts=1` — logged in first time. Zeek infers this from traffic patterns, so treat it as likely rather than certain.
- `direction=OUTBOUND` — the database server was the client.
- `client=SSH-2.0-OpenSSH_9.6` — an OpenSSH client, which on a Windows or Linux database server may be built in.
- `cipher_alg=chacha20-poly1305@…` — modern encryption: **no Layer 7 content is visible**.

Every layer from 4 upwards is ordinary. Now Layer 3:

- **Intel:** 203.0.113.45 is on a commercial feed as a server used for data theft in recent extortion cases — that's what raised the alert.
- **Prevalence:** has any other host ever talked to it? The analyst checks the last two months of Zeek connection logs on the sensor:

```
zcat /nsm/zeek/logs/2026-1*/conn.*.log.gz | zeek-cut id.orig_h id.resp_h | awk '$2 == "203.0.113.45"' | sort -u
```

- `zcat /nsm/zeek/logs/2026-1*/conn.*.log.gz` — decompress and print every archived `conn.log` for October and November.
- `zeek-cut id.orig_h id.resp_h` — keep only two columns: source and destination IP (`zeek-cut` reads Zeek's header to find them by name).
- `awk '$2 == "203.0.113.45"'` — keep only lines where the second column, the destination, is the suspicious address.
- `sort -u` — sort and remove duplicates, leaving one line per distinct source → destination pair.

The output:

```
10.20.8.30	203.0.113.45
```

One line: only BG-DB-03 has *ever* connected to it, and only this evening.

- **ASN and history:** the address belongs to a small virtual-server provider; passive DNS shows no domains pointing to it, which is common for infrastructure used only by IP.
- **Business check:** the database team confirm there is no reason for BG-DB-03 to make outbound SSH connections at all.

Verdict: a large, unexpected, first-ever upload from a database server to an address on a data-theft intel list. Treat as **exfiltration** (T1048.002 Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol) and escalate — the database's contents decide the business impact. The only layer that gave it away was Layer 3.

**[Supplement]** Two habits from this example are worth keeping. First, **prevalence** (how many of your hosts go somewhere) is one of the strongest, cheapest signals you have: "thousands of hosts visit it" makes malice unlikely; "one host, first time" says keep digging. Second, **outbound byte counts** are Layer 4 data that often matter more than the port.

## Layer 4: ports { #layer4 }

Every port implies a service — 22 means SSH, 80 HTTP, 443 HTTPS, 3389 RDP, 445 SMB — and this is how people and many security devices think. The port alone is only weakly linked to badness, but some situations are much stronger signals than others:

- **Mismatched port and protocol** — SSH on port 80, IRC on port 80. Attackers run protocols on well-known ports precisely because port 80 and 443 are almost always allowed outbound.
- **Non-standard ports for a protocol** — HTTP on 8080, 8000, 8443. Often legitimate (developer tools, appliances), but worth knowing.
- **Ports commonly used for malicious purposes** — **4444** is the default listener port of Metasploit's Meterpreter; **6667** is IRC, historically used for botnet command and control. Legitimate software authors avoid these because they know the reputation, so a hit almost always deserves investigation.
- **Random-looking destination ports with no known service** — could be software you don't know about, or malware using its own port (T1571 Non-Standard Port).
- **Any port you don't expect** — anything outside what your baseline says this host or segment normally uses.

| Port | Expected service | When it is a signal |
| --- | --- | --- |
| 22 | SSH | Outbound from servers or desktops that don't need it; large uploads |
| 23 | Telnet | Almost anywhere today |
| 80 / 443 | HTTP / HTTPS | When the protocol on it isn't HTTP/TLS |
| 445 | SMB | Outbound to the internet; workstation-to-workstation |
| 3389 | RDP | Inbound from the internet; workstation-to-workstation |
| 5900 | VNC | Inbound from the internet; anywhere it isn't approved |
| 4444 | Meterpreter default | Almost always investigate |
| 6667 | IRC | Almost always investigate in a business network |
| 8080 / 8000 / 8443 | Alternate HTTP(S) | To rare external destinations |
| 49152 – 65535 | Ephemeral (client side) | As a *destination* on an outbound connection to the internet |

**The destination port is the interesting one.** When an infected host connects out, its *source* port is almost always a random ephemeral port chosen by the operating system — that tells you nothing. The *destination* port is the one the server is listening on, and that's the port that implies a service. (The exception is when the infected host is itself acting as a server, for example a bind shell: then look at its listening port.)

In short: a bad thing can run on a "known good" port, and a good thing can run on an unusual port, but you rarely see a good thing on a "known bad" port. To tell which is which you usually need Layer 7, but port oddities and protocol mismatches are a good starting point — and IDSs and next-generation firewalls should flag non-conforming protocols on well-known ports for you.

### Worked example: N2, IRC on port 80 { #n2 }

```
ts=2026-11-26T00:14:03Z  uid=Ci9Uv2  id.orig_h=10.20.2.19  id.orig_p=52011  id.resp_h=198.51.100.81  id.resp_p=80  proto=tcp  service=irc  duration=18322.5  orig_bytes=41872  resp_bytes=96321  conn_state=S1  history=ShADad
```

- `id.resp_p=80` — the port says "web".
- `service=irc` — Zeek's dynamic protocol detection, which identifies protocols by their content rather than their port, says this is **IRC**. That is the mismatch.
- `duration=18322.5` — five hours: a long-lived session, not a web page load.
- `orig_bytes=41872`, `resp_bytes=96321` — small amounts both ways over hours: a chatty control channel, not a download.
- `conn_state=S1` — the connection was established and had not closed when Zeek wrote the log (Zeek writes long connections periodically); `history=ShADad` — handshake (`S`, `h`), then data in both directions (`A`, `D`, `a`, `d`).

Zeek's `irc.log` would show the commands: a `NICK` with a random-looking name and a `JOIN` to a channel — the classic shape of a bot waiting for orders. Old-school, but still seen: IRC command and control hidden on port 80 because outbound 6667 is blocked (T1071 Application Layer Protocol). The next step is the host: which process on BG-WS-0219 owns this connection?

## Layer 5: TLS certificates { #layer5 }

TLS is now the most common wrapper on the internet, and attackers use it for their malware traffic too. Even without decrypting it, the handshake leaves plenty to analyse:

- **The domain being visited** — present in the **SNI** (Server Name Indication) field of the client's hello, as well as in DNS.
- **Missing or suspicious certificate fields** — an empty organisation, a default subject such as `CN=localhost` or `O=Internet Widgits Pty Ltd` (the default in OpenSSL's sample configuration), a subject that doesn't match the domain.
- **Self-signed or expired certificates** — legitimate public services almost always use certificates from a trusted authority. Many attackers don't bother getting one.
- **Client and server fingerprints** — JA3 (client) and JA3S (server) hash the way each side offers or chooses TLS options; known-bad values identify specific malware families or tools. **[Changed]** see below: JA4+ is now the usual choice.
- **Certificates you've never seen before** — a certificate (by its fingerprint) seen on exactly one connection in your environment is worth a look.
- **Certificate data that doesn't match where the traffic goes** — when the certificate's names, the DNS lookup, the IP address and the HTTP host disagree, it may indicate domain masquerading or **domain fronting**.

### Worked example: N3, a self-signed certificate { #n3 }

Zeek's `ssl.log` (JA4 field from the JA4+ package):

```
ts=2026-11-26T01:30:12Z  uid=Ct7Ma3  id.orig_h=10.20.6.12  id.resp_h=203.0.113.9  id.resp_p=8443  version=TLSv12  cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  server_name=-  established=T  validation_status=self signed certificate  ja4=t12i190800_d83cc789557e_7af1ed941c26  cert_chain_fps=9a41c7…e05d
```

- `id.resp_p=8443` — an alternate HTTPS port, to an external address.
- `version=TLSv12` — TLS 1.2. Because the certificate is sent unencrypted in TLS 1.2, Zeek can see it; in TLS 1.3 it is encrypted (see the 2026 view).
- `server_name=-` — **no SNI**. A browser visiting a website always sends one; a program connecting straight to an IP address often doesn't.
- `validation_status=self signed certificate` — Zeek checked the chain against its trusted roots, and the certificate signed itself.
- `ja4=t12i190800_…` — the client's TLS fingerprint, readable in parts: `t` (over TCP), `12` (TLS 1.2), `i` (no SNI — connecting to an IP; a named site would give `d`), `19` cipher suites offered, `08` extensions, `00` no ALPN value; then two hashes of the sorted cipher and extension lists. Looked up in the team's fingerprint list, it matches no browser on Bluegum's standard build.
- `cert_chain_fps=9a41c7…e05d` — the certificate's fingerprint; searching the sensor history shows it on no other connection.

The matching `x509.log`:

```
fingerprint=9a41c7…e05d  certificate.subject=CN=localhost,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU  certificate.issuer=CN=localhost,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU  certificate.not_valid_before=2026-11-17T22:10:00Z  certificate.not_valid_after=2027-11-17T22:10:00Z  san.dns=-
```

- `certificate.subject` and `certificate.issuer` are **identical** — the mark of a self-signed certificate.
- `O=Internet Widgits Pty Ltd,ST=Some-State` — OpenSSL's placeholder values: someone ran the certificate generator and pressed Enter at every prompt.
- `not_valid_before=2026-11-17` — created nine days ago, the day before `vcupd.exe` first ran on this host (the previous page's Prefetch evidence).
- `san.dns=-` — no names at all.

Combined: no SNI, a default self-signed certificate created last week, a fingerprint seen nowhere else, a client fingerprint that matches no installed browser, on a non-standard port, to a rare destination. Each alone is weak; together they describe a malware command-and-control channel (T1573.002 Encrypted Channel: Asymmetric Cryptography, T1571 Non-Standard Port, and T1587.003 Develop Capabilities: Digital Certificates for the attacker's side).

### Worked example: N4, a name that doesn't match { #n4 }

Bluegum's proxy decrypts TLS for most categories. For one connection it logged:

```
2026-11-26T02:05:47Z  src=10.20.5.33  user=BLUEGUM\p.walsh  dst=192.0.2.120:443  sni=assets.trusted-cdn-customer.example  http_host=x7c2.unrelated-app.example  method=POST  url=/api/v2/sync  status=200  bytes_out=2210  bytes_in=418  ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

- `dst=192.0.2.120:443` — an IP address belonging to a large content-delivery network.
- `sni=assets.trusted-cdn-customer.example` — in the TLS handshake (visible to everyone on the path), the client asked for a well-known, reputable site hosted on that CDN.
- `http_host=x7c2.unrelated-app.example` — *inside* the encrypted HTTP request, the `Host` header asks for a completely different site on the same CDN.
- `method=POST`, `url=/api/v2/sync`, small byte counts — check-in-sized traffic.
- `ua=` — a generic browser-like user agent, but the EDR shows the process is not a browser.

This is the shape of **domain fronting** (T1090.004 Proxy: Domain Fronting): the outer, visible name is a trusted one, so filters and analysts who only see SNI or DNS let it through; the CDN routes the request by the inner `Host` header to the attacker's site. Without TLS inspection, the only Layer 5 evidence would be an innocent-looking SNI — which is exactly the point of the technique.

**[Changed]** Domain fronting has become much harder. Google and Amazon restricted it on their platforms in 2018, and Microsoft rolled out blocking on Azure Front Door and Azure CDN in stages from late 2022 into 2024 (mismatched requests are refused). Some CDNs and smaller providers still allow it, and related tricks remain, so the mismatch check is still worth running — but in 2026 a mismatch is as likely to be a misconfigured application as an attacker, and the host evidence decides.

## Layer 7: protocol metadata and content { #layer7 }

At the top of the stack is the application protocol itself: HTTP methods, FTP commands, DNS queries — whatever protocol is being spoken, regardless of port or IP. Layer 7 has two very different parts.

**1. Metadata** — for example HTTP headers.

- Logged by tools such as **Zeek** and **Suricata**: methods, URLs, host names, user agents, referrers, cookies, response codes, file names, MIME types, hashes of transferred files — whatever the parser can extract.
- Usually available in the SIEM.
- Good enough for many detections: a known-malicious user agent, an obvious C2 pattern in a URL, an executable served with an image MIME type.
- It's also the best place to start, because it doesn't drown you in raw bytes.

**2. Content** — for example the file transferred over HTTP.

- **Not** logged by Zeek and similar tools (Zeek can extract files, but that is a separate, optional feature and is limited to protocols it can see in clear text).
- Only retrievable from **full packet capture** (PCAP): a byte-for-byte copy of everything transferred.
- Needed when metadata looks normal and only the payload is bad.

Here's the difference in one sentence: the HTTP log tells you `GET /invoice_8841.iso`; only the packet capture gives you the ISO file.

### Worked example: N5, a "safe" site serving a bad file { #n5 }

Bluegum's proxy decrypts traffic to cloud file-sharing services and passes it to a Zeek sensor. The `http.log`:

```
ts=2026-11-26T03:11:28Z  uid=Cf2Lp8  id.orig_h=10.20.4.37  id.resp_h=198.51.100.10  id.resp_p=443  method=GET  host=files.cloudshare.example  uri=/s/k93hDq2/invoice_8841.iso?dl=1  referrer=-  user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36  status_code=200  resp_mime_types=application/x-iso9660-image  resp_fuids=FhX2ab1
```

- `host=files.cloudshare.example` — a large, reputable cloud file-sharing service that thousands of Bluegum users visit every day. Layer 3: fine.
- `id.resp_p=443` — normal port. Layer 4: fine.
- TLS — a valid certificate from a trusted authority for the service's own domain. Layer 5: fine.
- `method=GET`, `status_code=200`, a current Chrome user agent — normal HTTP. Layer 7 metadata: almost fine.
- `uri=/s/k93hDq2/invoice_8841.iso?dl=1` — a shared-link download of a file called `invoice_8841.iso`. The **file name** is the first odd thing: invoices are not disk images.
- `resp_mime_types=application/x-iso9660-image` — Zeek's content sniffing agrees it is an ISO image, a format attackers use to deliver malware inside a container (it gets around some download protections).
- `resp_fuids=FhX2ab1` — the ID of the transferred file in `files.log`:

```
ts=2026-11-26T03:11:29Z  fuid=FhX2ab1  source=HTTP  mime_type=application/x-iso9660-image  filename=invoice_8841.iso  total_bytes=1638400  sha256=4e0b…77c1  extracted=-
```

- `total_bytes=1638400` — 1.6 MB.
- `sha256=4e0b…77c1` — a hash you can look up (search, don't upload — see the OSINT notes on the previous page). Here it has no history anywhere: unknown.
- `extracted=-` — Zeek did not save the file itself. So the metadata has taken us as far as it can: *something suspicious-looking was downloaded*. To know what's inside, you need the bytes.

The analyst opens the packet-capture system (Arkime), finds the session by the connection's IPs and time, and exports the reassembled HTTP response body to an isolated analysis machine. Inspecting the ISO (as in the file-analysis section) shows two files: `invoice_8841.pdf.lnk` and a hidden `data.dll`. The `.lnk` runs `rundll32.exe` on the DLL. **The download is malicious** — and nothing in the network metadata alone could have proved it (T1566.002 for the link, T1608.001 Stage Capabilities: Upload Malware for the attacker hosting it on a trusted service, T1204.002 when it is opened).

This is where many SIEM investigations stop: the SIEM has the URL and file name, but not the file. A suspicious file name lets you *suspect*; only the decoded content from full packet capture (or the file collected from the host or by the EDR) lets you *know*.

## A layer-by-layer check-list { #checklist }

| Layer | Questions to ask | N1 | N2 | N3 | N4 | N5 |
| --- | --- | --- | --- | --- | --- | --- |
| 3 | On an intel list? How many of our hosts go there? Seen before? Age, ASN, passive DNS? | **Bad** (intel, first-ever) | Rare | Rare | CDN (shared) | Very common |
| 4 | Port matches protocol? Non-standard, known-bad, random? Byte counts and duration? | Normal port, **huge upload** | **Mismatch** (IRC on 80) | Non-standard 8443 | Normal | Normal |
| 5 | SNI present? Certificate trusted, current, sensible fields? Seen before? JA3/JA4? Names match? | — (SSH) | — | **Self-signed default**, no SNI, unknown JA4 | **SNI ≠ Host** | Normal |
| 7 | Metadata: methods, URLs, user agent, file name, MIME? Content: what was actually transferred? | Not visible (encrypted) | IRC `NICK`/`JOIN` | Not visible | `POST` beacon | **ISO with `.lnk` + DLL** |

Each event was given away by a *different* layer. An analyst who habitually checks only one layer would have caught one of the five.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Checking every layer is still the core of network analysis, and the examples on this page remain typical: data theft to attacker-controlled servers over encrypted protocols, abuse of trusted cloud services to host payloads, self-signed C2 certificates and odd ports. Destination prevalence and first-seen checks, intel matching, ASN and passive-DNS enrichment, and Zeek and Suricata metadata are standard in 2026 SOCs. The ports 4444 (Meterpreter default) and 6667 (IRC) still deserve investigation wherever they appear.

!!! info "[Changed] What has changed"
    - **JA3 has given way to JA4+.** Since 2023, Chrome and other browsers randomise the order of TLS extensions, which makes a browser's JA3 hash change from connection to connection. FoxIO's **JA4+** suite (JA4 for clients, JA4S for servers, plus fingerprints for HTTP, certificates, SSH and more) sorts what it hashes, so it stays stable; it is supported by many security tools and is available for Zeek as a package. Keep JA3 lookups for older tooling, but build new detections on JA4+ (check the licence terms of the parts you use).
    - **TLS 1.3 hides the certificate, and ECH hides the name.** In TLS 1.3 the server's certificate is encrypted, so passive sensors no longer see it; with **Encrypted Client Hello** (published as RFC 9849, supported by major browsers and some CDNs) even the SNI can be hidden. Without inspection, Layer 5 evidence shrinks to IPs, fingerprints and timing — and DNS logs, endpoint telemetry and proxies with TLS inspection become more important.
    - **Domain fronting is largely closed on the big CDNs** (Google and Amazon 2018, Microsoft Azure in stages through 2024). Attackers moved to other ways of hiding behind trusted services: legitimate cloud apps and APIs as C2, tunnelling services, and redirectors on reputable hosting.
    - **Free, valid certificates are everywhere.** Many malicious sites now present perfectly valid certificates from free automated authorities, so "trusted certificate" says nothing about intent; *how new* the certificate is and *who else* uses it matter more. Certificate lifetimes are also shrinking under CA/Browser Forum rules (stepping down towards 47 days by 2029), so short validity alone is becoming normal.
    - **Packet capture is now Arkime** (formerly Moloch), and many teams rely more on EDR file collection than on PCAP to get the bytes of a download.
    - **AI-assisted triage** in NDR and SIEM products now scores destinations, fingerprints and beacons automatically. Useful — but the analyst still has to ask the layer questions, because a model trained on "typical" traffic is weakest exactly where a trusted service carries bad content.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't clear a connection because one layer looks good.** A good reputation, a normal port or a valid certificate clears only that layer.
    - **Don't trust the port to tell you the protocol.** Use protocol detection (Zeek's `service`, Suricata's app-layer fields, firewall application IDs).
    - **Shared infrastructure breaks Layer 3 logic.** CDN, cloud and file-sharing IPs serve thousands of sites; reputation and blocking by IP there are close to meaningless — and blocking one can break a business service. Use names, URLs and content instead.
    - **Don't upload a suspicious file from a live case to public services.** Search the hash first; analyse the bytes on an isolated machine; follow the OPSEC rules in the next section.
    - **Self-signed doesn't always mean malicious** — internal appliances, printers and lab systems use them all the time. Self-signed *to a rare external destination from a non-browser process* is the signal.

## Practice questions { #quiz }

### Question 1

Why can an SSH upload to the internet be malicious even when every layer from 4 upwards looks completely normal? Using N1, list the evidence that made it suspicious, say which layer each piece belongs to, and name one non-network question you would ask.

??? success "Answer and explanation"
    SSH is encrypted, so Layer 7 content (the stolen data) is invisible; it ran on the standard port 22 and Zeek confirmed the protocol really was SSH, so Layer 4 and the protocol agree; the session completed normally. If outbound SSH is permitted, the protocol itself gives nothing away. What is left is **where it went** and **how much**.

    Evidence: the destination 203.0.113.45 was on a data-theft intel feed (**Layer 3**); no other host had ever connected to it, shown by the `zeek-cut` prevalence check (**Layer 3**, prevalence/history); about 4.1 GiB left a database server in 37 minutes (**Layer 4** byte counts and duration); the address sat with a small VPS provider and had no domains in passive DNS (**Layer 3** enrichment).

    Non-network question: *is there any business reason for BG-DB-03 to make outbound SSH connections?* — answered by the database team or change records. Also useful: which process and account on BG-DB-03 started the client (host logs/EDR).

### Question 2

A colleague says: "Port 443 traffic to a reputable cloud file-sharing site with a valid certificate — it's fine, close it." Explain, with N5, why that conclusion is premature, what Layer 7 metadata gave the first hint, and what was needed to prove the download malicious.

??? success "Answer and explanation"
    The colleague has checked Layers 3, 4 and 5 — all genuinely fine, because the attacker is using a trusted service precisely so that those layers look good. The badness was only in **Layer 7**.

    The first hint was in the **metadata**: an `http.log` showing a file named `invoice_8841.iso` (an "invoice" that is a disk image), with Zeek's MIME detection confirming `application/x-iso9660-image`, and a `files.log` hash with no history anywhere.

    Metadata only raised suspicion. Proof needed the **content**: the reassembled file from full packet capture (Arkime) — or a copy from the host or EDR — analysed on an isolated machine, which revealed a `.lnk` launching a hidden DLL with `rundll32.exe`. The general lesson: when every layer but the content looks normal, you need the bytes.

### Question 3

For N3, explain what each of these tells you and why the combination matters more than any single item: `server_name=-`; `validation_status=self signed certificate`; identical `certificate.subject` and `certificate.issuer` containing `Internet Widgits Pty Ltd`; a certificate fingerprint seen on no other connection; destination port 8443. Then say why JA3 alone would be a weaker check in 2026.

??? success "Answer and explanation"
    - `server_name=-` — no SNI: the client connected to an IP rather than a named website, which browsers don't do for normal browsing.
    - `self signed certificate` / identical subject and issuer — no trusted authority vouches for the server; the operator made the certificate themselves.
    - `Internet Widgits Pty Ltd` — OpenSSL's default placeholder: the certificate was generated quickly with default answers, typical of throwaway attacker infrastructure (and of lab equipment).
    - A fingerprint seen nowhere else — this server is unique in your environment, not a shared service.
    - Port 8443 — a non-standard HTTPS port to a rare external host.

    Each one has innocent explanations (internal appliances, developer tools, lab systems), so each alone is weak. Together, from a non-browser process on a workstation to a rare external IP, they fit a command-and-control channel and justify going to the host.

    **JA3** is weaker in 2026 because browsers randomise TLS extension order, so a single browser produces many JA3 hashes and allow-listing "normal" clients by JA3 breaks down; malware can also mimic common JA3 values. **JA4** sorts the values before hashing, so it is stable across those randomised hellos; it is still only one clue, but a better one.

## Related { #related }

- [Starting an investigation](questions-and-data.md) — previous page: the four questions and where the data lives
- [Investigation Questions](index.md) — section overview
- [Encapsulation and the OODA loop](../mental-models/encapsulation-ooda.md) — the layer model behind this page
- [Domain signals](../dns/domain-signals.md) · [DNS abuse](../dns/dns-abuse.md)
- [Evil HTTP and reputation](../http-analysis/evil-http-and-reputation.md) · [HTTPS and certificates](../http-analysis/https-certificates.md) · [TLS fingerprints and TLS 1.3](../http-analysis/tls-fingerprints-tls13.md)
- [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md) · [Spotting data exfiltration and destruction](../alert-triage/exfil-destruction-sensitive.md)
- [Handling suspect files safely](../file-analysis/safe-handling-file-types.md)
