---
title: RedLine Stealer — PowerShell Script to net.tcp C2 Data Theft (Arkime Walkthrough)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - redline
  - infostealer
  - c2
  - ticket
---

# RedLine Stealer — PowerShell Script to net.tcp C2 Data Theft { #redline-stealer }

!!! abstract "Case summary"
    On a Windows 10 PC in the `coolweathercoat.com` domain, the user ran a **PowerShell script** (`mystery_file.ps1`). The script reported "started, antivirus is Windows Defender" to an attacker server and downloaded a malicious executable disguised as `.jpg` over HTTPS. The **RedLine Stealer** it launched connected straight to an IP (no DNS) on **TCP port 12432**, collected data according to a "what to steal" list sent by the server, and uploaded **about 540 KB** in one go: a screenshot, system details, the process list, a password saved in Edge and a document. The whole capture is only **36 seconds** long.

| | |
|---|---|
| **Evidence** | Unit 42 Wireshark quiz PCAP, July 2023: 2023-07-10 22:39:22 – 22:39:58 UTC (36 s), about 120 sessions |
| **Environment** | Treated as closed network (no hash/reputation lookups). Steps and queries in Arkime terms, decoding with CyberChef |
| **Deliverable** | Answers to the 6 quiz questions and an incident ticket |
| **Related pages** | [Arkime-only walkthrough — Trickbot case](arkime-only-credential-theft-tls-c2.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Arkime offline PCAP guide](../../network/arkime/offline-pcap-guide.md) |

!!! warning "Want to solve it first?"
    Answers follow. To try it yourself, stop here and answer these six questions:

    1. Date and time (UTC) the infection started
    2. IP address of the infected Windows client
    3. MAC address
    4. Hostname
    5. User account name
    6. What type of information this RedLine Stealer tried to steal

!!! note "About the numbers on this page"
    The PCAP was parsed directly with Python to compute what Arkime would show (sessions, bytes, fields), and each value is paired with the Arkime query that finds it. Some numbers, such as the session count, may differ slightly in the Arkime UI — check as you follow along. Results were [compared with the official Unit 42 answers](#official-answers).

!!! tip "How to read this page"
    Same structure as the [Trickbot case](arkime-only-credential-theft-tls-c2.md): every step has **goal → query → query explained → actual result → reading the result → ticket entry**. Copy queries with the **copy button**. Basics such as time range, time zone and SPI View are covered in detail in [steps 0–1 of the Trickbot case](arkime-only-credential-theft-tls-c2.md#step-0).

## Answers at a glance { #answers }

| # | Question | Answer | Status |
|---|---|---|---|
| 1 | Infection start | **2023-07-10 22:39 UTC** (first malicious traffic: PowerShell HTTP request at 22:39:47) | Confirmed |
| 2 | IP | **10.7.10.47** | Confirmed |
| 3 | MAC | **80:86:5b:ab:1e:c4** | Confirmed |
| 4 | Hostname | **DESKTOP-9PEA63H** | Confirmed |
| 5 | User | **rwalters** | Confirmed |
| 6 | Targeted information | Desktop and Documents files (`*.txt`, `*.doc*`, `*key*`, `*wallet*`, `*seed*`), browser user data (Chromium- and Firefox-based), crypto wallets (programs and browser extensions), cloud/developer API keys and credentials. Actually uploaded: screenshot, system details, process list, one saved Edge password, `Top_secret_ducment.docx` | Confirmed |

| Item | Value |
|---|---|
| Network | 10.7.10.0/24, gateway 10.7.10.1, DC/DNS/DHCP **10.7.10.9 (WIN-S3WT6LGQFVX)**, domain `coolweathercoat.com` |
| Initial execution | `powershell.exe ... & 'C:\Users\rwalters\Documents\mystery_file.ps1'` |
| Check-ins | `hxxp://623start[.]site/?status=start&av=Windows%20Defender`, `/?status=install` (195.161.114.3) |
| Payload | `hxxp(s)://guiatelefonos[.]com/data/czx.jpg` (92.118.151.9), about 353 KB over HTTPS |
| C2 / exfil | **194.26.135.119:12432**, .NET net.tcp (SOAP), 542,386 bytes uploaded |

---

## Step 0 — Data range and the big picture { #step-0 }

**Goal:** find the start, end and size of the data and the internal hosts.

**Query:** time range **All**, empty search, Search. Start/end from Sessions sorted Start Time ascending / Stop Time descending (method in [Trickbot step 1](arkime-only-credential-theft-tls-c2.md#data-range)).

**Actual result:**

```text
Start  2023/07/10 22:39:22 UTC
End    2023/07/10 22:39:58 UTC   (duration 00:00:36)
Sessions about 120
Src IP 10.7.10.47 (118)   10.7.10.9 (1)   0.0.0.0 (1)
```

SPI View → General → Dst Port (session count, protocol/port):

```text
udp 53 (34)   tcp 88 (26)   tcp 443 (20)   tcp 389 (14)   udp 389 (7)   tcp 135 (4)   tcp 49669 (3)
tcp 80 (2)    udp 67 (1)    udp 68 (1)     udp 5353 (1)   udp 137 (1)   udp 138 (1)   udp 123 (1)
tcp 445 (1)   tcp 55390 (1) tcp 12432 (1)
```

**Reading the result:**

- The capture is only **36 seconds**, and the very first session is **DHCP** (`0.0.0.0:68 → 255.255.255.255:67`): it starts as the PC gets its IP — just booted or reconnected.
- **One internal client, 10.7.10.47**, starts almost every session (118). 10.7.10.9 starts only the DHCP reply and otherwise just receives — a **server**. 0.0.0.0 is the DHCP request before the PC has an address.
- Ports grouped by role:

| Ports | Protocols | Verdict |
|---|---|---|
| 53, 88, 389, 445, 135, 49669·55390 (dynamic RPC), 123 | DNS, Kerberos, LDAP, SMB, RPC, NTP | **Normal AD traffic** of a domain logon, all to 10.7.10.9 |
| 67/68, 137/138, 5353 | DHCP, NetBIOS, mDNS | Normal |
| 443 (20) | TLS | Mostly Microsoft/Bing services; checked in [step 5](#step-5) |
| **80 (2)** | HTTP | **Cleartext** — look first |
| **12432 (1)** | ??? | No standard service uses it — **most suspicious** |

In a 36-second PCAP, "one unknown port" jumps out. We still fill in the basics first, because the ticket needs IP, MAC, hostname and account.

**Ticket entry:**

```text
[251118 0010, Analyst] Establishing data time range and session count - Found
[251118 0012, Analyst] Reviewing protocols and internal hosts - Found

[251118 0010, Analyst] Data range 2023-07-10 22:39:22 - 22:39:58 UTC (36 seconds), about 120 sessions. Capture starts with a DHCP request.
[251118 0012, Analyst] Only one internal client: 10.7.10.47 (118 sessions as source). Server 10.7.10.9. Normal AD logon traffic + tls (20) + http (2) + one tcp session to port 12432.
```

---

## Step 1 — IP, MAC and hostname from DHCP (Q2–Q4) { #dhcp }

**Goal:** a DHCP request carries the **MAC address and hostname**. This PCAP starts with DHCP, so it is the most reliable source.

**Query:**

```text
protocols == dhcp
```

| Piece | Meaning |
|---|---|
| `protocols` | Protocol field detected by Arkime |
| `== dhcp` | DHCP sessions only |

SPI View → **dhcp** → **Load All**. The key fields are `dhcp.host` (hostname), `dhcp.mac` (client MAC) and `dhcp.classId` (vendor class). Open the sessions to see the request and reply.

**Actual result:**

```text
22:39:22.849  DHCP Request   0.0.0.0:68 → 255.255.255.255:67
              Client MAC        80:86:5b:ab:1e:c4
              Host Name (12)    DESKTOP-9PEA63H
              Client FQDN (81)  DESKTOP-9PEA63H.coolweathercoat.com
              Requested IP (50) 10.7.10.47
              Vendor class (60) MSFT 5.0

22:39:22.850  DHCP ACK       10.7.10.9:67 → 255.255.255.255:68
              Your IP           10.7.10.47
              Subnet mask       255.255.255.0
              Router            10.7.10.1
              DNS server        10.7.10.9
              Domain name       coolweathercoat.com
```

**Reading the result:**

- **IP 10.7.10.47, MAC 80:86:5b:ab:1e:c4, hostname DESKTOP-9PEA63H** — answers to Q2, Q3, Q4.
- `MSFT 5.0` is the DHCP vendor class every Windows version since 2000 sends — evidence of a Windows PC.
- The DHCP reply also gives the **network facts**: 10.7.10.0/24 (mask 255.255.255.0), gateway 10.7.10.1, DNS and DHCP server 10.7.10.9, domain `coolweathercoat.com`.
- **Cross-check:** ordinary packets from this PC carry Src MAC `80:86:5b:ab:1e:c4`, and the NetBIOS (137) broadcast names `DESKTOP-9PEA63H` in domain `COOLWEATHERCOAT`. Two sources, same values.

!!! tip "When there is no DHCP"
    A capture that starts after the PC already had its IP has no DHCP. Then use NetBIOS names (udp 137/138 broadcast), the Kerberos cname ending in `$` (next step) or host details in SMB sessions.

**Ticket entry:**

```text
[251118 0015, Analyst] Identifying client IP, MAC, hostname and domain from DHCP - Found

[251118 0015, Analyst] Query: protocols == dhcp
230710 22:39:22 DHCP Request - client MAC 80:86:5b:ab:1e:c4, hostname DESKTOP-9PEA63H, FQDN DESKTOP-9PEA63H.coolweathercoat.com, requested IP 10.7.10.47, vendor MSFT 5.0
230710 22:39:22 DHCP ACK from 10.7.10.9 - 10.7.10.47, mask 255.255.255.0, router 10.7.10.1, DNS 10.7.10.9, domain coolweathercoat.com
```

---

## Step 2 — The DC and the user account (Q5) { #kerberos }

**Goal:** find the domain controller's name and the **user account** that logged on to this PC.

### The DC (DNS SRV) { #dc }

At logon a Windows PC asks DNS "where is this domain's DC?" with an **SRV record** query.

```text
host.dns == _ldap._tcp.dc._msdcs.*
```

| Piece | Meaning |
|---|---|
| `host.dns` | Names queried over DNS |
| `_ldap._tcp.dc._msdcs.*` | The standard "where is the DC's LDAP service?" query; `*` = any domain after it |

**Actual result (DNS answers in the session detail):**

```text
Query   _ldap._tcp.dc._msdcs.coolweathercoat.com  (SRV)
Answer  SRV  win-s3wt6lgqfvx.coolweathercoat.com
Query   win-s3wt6lgqfvx.coolweathercoat.com  (A)
Answer  10.7.10.9
```

→ **DC 10.7.10.9, name WIN-S3WT6LGQFVX.** `WIN-` + random letters is the default name of a Windows Server that was never renamed.

### The user (Kerberos) { #user }

```text
ip.src == 10.7.10.47 && protocols == krb5
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.7.10.47` | Connections started by the suspect PC |
| `&&` | AND |
| `protocols == krb5` | Kerberos sessions only |

SPI View → **krb5** → **Load All** (if only field names show, click the name or Load All).

**Actual result:**

```text
cname   desktop-9pea63h$   rwalters
Realm   COOLWEATHERCOAT.COM
sname   krbtgt/COOLWEATHERCOAT.COM   ...
```

**Reading the result:**

- **`desktop-9pea63h$`** ends in `$` — the **computer account**, matching step 1.
- **`rwalters`** has no `$` — the **user account**. Answer to Q5.
- 26 Kerberos sessions right after the capture starts (22:39:23~) fit step 1: the PC starting and **the user logging on**.

**Ticket entry:**

```text
[251118 0017, Analyst] Identifying DC from DNS SRV and user account from Kerberos - Found

[251118 0017, Analyst] Query: host.dns == _ldap._tcp.dc._msdcs.* -> SRV win-s3wt6lgqfvx.coolweathercoat.com -> A 10.7.10.9 (DC).
Query: ip.src == 10.7.10.47 && protocols == krb5 -> krb5.cname rwalters, desktop-9pea63h$; realm COOLWEATHERCOAT.COM.
```

---

## Step 3 — Odd domains in DNS { #dns }

**Goal:** the names a PC looks up show where it tried to go. Remove the normal names and see what is left.

**Query:**

```text
ip.src == 10.7.10.47 && protocols == dns
```

SPI View → **dns** → `host.dns` values; Sessions sorted by Start Time ascending shows the order.

**Actual result (in time order):**

```text
22:39:23-24  _ldap._tcp... / _kerberos._tcp... SRV, WIN-S3WT6LGQFVX, wpad.coolweathercoat.com  ← AD logon
22:39:23     dns.msftncsi.com                                      ← Windows "am I online?" check
22:39:33-34  api.msn.com, assets.msn.com, www.bing.com, r.bing.com, th.bing.com,
             fp.msedge.net, k-ring.msedge.net, l-ring.msedge.net, wac-ring.msedge.net,
             fp-as-nocache.azureedge.net, fp-vs.azureedge.net, fp-afd-nocache-ccp.azureedge.net,
             static-ecst.licdn.com, v20.events.data.microsoft.com,
             sat09prdapp01-canary-opaph.netmon.azure.com, <hex>.clo.footprintdns.com   ← Windows / Edge start-up
22:39:44     checkappexec.microsoft.com                            ← SmartScreen
22:39:46     evoke-windowsservices-tas.msedge.net, client.wns.windows.com   ← Windows services
22:39:47     623start.site        → 195.161.114.3                  ← ?
22:39:49     guiatelefonos.com    → 92.118.151.9                   ← ?
```

**Reading the result:**

- The burst of Microsoft, Bing, MSN and Azure CDN names at 22:39:33–34 is **normal noise** from Windows and Edge starting after logon. `msedge.net`, `footprintdns.com`, `azureedge.net` are Microsoft connection measurement and CDN services.
- **`checkappexec.microsoft.com` (22:39:44)** is where Windows Defender **SmartScreen** asks Microsoft "is this program/file safe to run?". A legitimate service, but it appears **when the user is about to run something**, three seconds before the suspicious traffic. (What was checked is encrypted — inferred.)
- The two left over, **`623start.site`** and **`guiatelefonos.com`**, are names a company PC has no reason to visit. `.site` is a cheap TLD frequently abused. Step 4 shows what HTTP did with them.
- **Note for later:** 194.26.135.119 (port 12432) is **not in this list**. The PC connected to the IP with no DNS lookup — typical of an IP **hard-coded** in the malware.

**Ticket entry:**

```text
[251118 0020, Analyst] Reviewing DNS queries for unusual domains - Found

[251118 0020, Analyst] Query: ip.src == 10.7.10.47 && protocols == dns -> AD SRV lookups, Microsoft/Bing/MSN/Azure CDN names (benign), checkappexec.microsoft.com 22:39:44 (SmartScreen), 623start.site 22:39:47 -> 195.161.114.3, guiatelefonos.com 22:39:49 -> 92.118.151.9 (unusual). No DNS for 194.26.135.119.
```

---

## Step 4 — Cleartext HTTP: PowerShell check-ins and a download { #http }

**Goal:** read the two HTTP sessions.

**Query:**

```text
ip.src == 10.7.10.47 && protocols == http
```

SPI View → **http** → Load All, then open both sessions in Sessions and read Source / Destination.

**Actual result — session 1 (195.161.114.3:80):**

```http
GET /?status=start&av=Windows%20Defender HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
Connection: Keep-Alive

GET /?status=install HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Jul 2023 22:39:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 14
Server: Apache/2.4.6 (CentOS) PHP/7.4.33
X-Powered-By: PHP/7.4.33

404 HTTP Error
```

**Reading the result:**

- **`WindowsPowerShell/5.1` in the User-Agent** — the default value added by PowerShell's `Invoke-WebRequest` / `Invoke-RestMethod`. Not a person in a browser: **a PowerShell script made the request**. (User-Agents can be faked, but malware rarely pretends to be PowerShell, so this is a fairly reliable clue.)
- Split the URIs:

```text
/?status=start                 → "the script has started"
&av=Windows%20Defender         → "the antivirus here is Windows Defender"  (%20 = space; CyberChef URL Decode)
/?status=install               → "now installing (next stage)"
```

  The infected PC **reports its status and antivirus to the attacker** — a check-in. Attackers can pick a payload based on the antivirus.
- The response is odd: **status `200 OK` (success) but the body says `404 HTTP Error`** (14 bytes). A real "not found" would have status 404. Possibly camouflage so that a quick glance says "page did not exist". Either way the server only **records the check-ins**.

**Actual result — session 2 (92.118.151.9:80):**

```http
GET /data/czx.jpg HTTP/1.1
Host: guiatelefonos.com
Connection: Keep-Alive
```

```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.20.2
Location: https://guiatelefonos.com:443/data/czx.jpg
```

**Reading the result:**

- This request has **no User-Agent at all**. Browsers always send one. Only `Host` and `Connection` = **a minimal request built by a program** (for example .NET's basic web client).
- The server **redirects (301) to HTTPS**, so the file itself comes over encrypted 443 — no longer visible in cleartext.
- The name ends in `.jpg`, but there is no reason to fetch an "image" right after a PowerShell check-in — suspect a **payload disguised as an image**.
- Timing: 22:39:47.579 start → 22:39:48.415 install → **0.8 s later** 22:39:49.250 czx.jpg. It reported "install" and went straight for the payload.

**Ticket entry:**

```text
[251118 0025, Analyst] Reviewing cleartext HTTP (PowerShell user agent, downloads) - Found

[251118 0025, Analyst] Query: ip.src == 10.7.10.47 && protocols == http -> 2 sessions.
230710 22:39:47.579UTC 10.7.10.47 49741 195.161.114.3 80 GET 200 623start.site /?status=start&av=Windows%20Defender 1.1 Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
230710 22:39:48.415UTC 10.7.10.47 49741 195.161.114.3 80 GET 200 623start.site /?status=install 1.1 (same UA). Body "404 HTTP Error" with status 200.
230710 22:39:49.250UTC 10.7.10.47 49742 92.118.151.9 80 GET 301 guiatelefonos.com /data/czx.jpg 1.1 (no User-Agent) -> https://guiatelefonos.com:443/data/czx.jpg
```

---

## Step 5 — The HTTPS download and JA3 { #step-5 }

**Goal:** after the 301, what and how much came over HTTPS?

**Query:**

```text
ip.dst == 92.118.151.9 && port.dst == 443
```

| Piece | Meaning |
|---|---|
| `ip.dst == 92.118.151.9` | Connections to guiatelefonos.com's IP |
| `port.dst == 443` | HTTPS port |

**Actual result (session detail):**

```text
Time          2023/07/10 22:39:49.323 - 22:39:49.874 UTC   (0.55 s)
Src           10.7.10.47:49743   Packets 61    Databytes 413
Dst           92.118.151.9:443   Packets 263   Databytes 353,715
TLS           SNI guiatelefonos.com   TLSv1.2   Cipher 0xc02f (ECDHE_RSA_WITH_AES_128_GCM_SHA256)
              JA3  3b5074b1b5d032e5620f69f9f700ff0e
              JA3S 389ed42c02ebecc32e73aa31def07e14
Certificate   Subject CN guiatelefonos.com   SAN guiatelefonos.com, www.guiatelefonos.com
              Issuer  CN R3, O Let's Encrypt
              Not Before 2023-07-08 16:17:07 UTC   Not After 2023-10-06
```

**Reading the result:**

- **Server → PC 353,715 bytes, PC → server 413 bytes**: one request, about 345 KB received in half a second. Encrypted, but this is the `czx.jpg` from step 4 requested again over HTTPS. (TLS record overhead makes it a little bigger than the file; per the Unit 42 answers the file is a 348,160-byte RedLine executable.)
- **The certificate is a proper Let's Encrypt certificate**, not self-signed — not suspicious on its own; attackers get free certificates easily. It was issued **2 days before** (07-08), but Let's Encrypt certificates are renewed every 90 days anyway, so that is weak evidence. What makes this download suspicious is **the context, not the certificate**: PowerShell check-in → request with no User-Agent → `.jpg` disguise.

### What does JA3 show? { #ja3 }

This PCAP is a good test of the idea "new JA3 values after infection are evidence of infection".

```text
ip.src == 10.7.10.47 && protocols == tls
```

SPI View → **tls** → **JA3**:

```text
JA3                                  count   destinations (SNI)
6271f898ce5be7dd52b0fc260d0662b3     14      www.bing.com, r.bing.com, th.bing.com, *.msedge.net, *.azureedge.net,
                                             static-ecst.licdn.com, netmon.azure.com, checkappexec.microsoft.com
3b5074b1b5d032e5620f69f9f700ff0e      3      evoke-windowsservices-tas.msedge.net (22:39:46), client.wns.windows.com (22:39:46),
                                             guiatelefonos.com (22:39:49)  ← the payload download
37f463bf4616ecd445d4a1937da06e19      2      api.msn.com, assets.msn.com
28a2c9bd18a11de089ef85a160da29e4      1      v20.events.data.microsoft.com
```

- The payload download (`guiatelefonos.com`) has **the same JA3 that Windows services (WNS etc.) used three seconds earlier**, because PowerShell/.NET uses the built-in Windows TLS stack. So **no new JA3 appeared after the infection**.
- And the C2 (12432) **is not TLS at all**, so it has no JA3.
- In this case, "a change in the number of JA3 values" would not have caught the infection. A JA3 change is **strong evidence when present, but its absence does not mean clean**. On the other hand, the same JA3 going to an **odd destination (SNI)** instead of Microsoft services stands out — read JA3 together with destinations.

**Ticket entry:**

```text
[251118 0030, Analyst] Reviewing HTTPS download from guiatelefonos.com (size, certificate, JA3) - Found

[251118 0030, Analyst] 230710 22:39:49.323-22:39:49.874UTC 10.7.10.47 49743 -> 92.118.151.9 443 tls, SNI guiatelefonos.com, server databytes 353,715 / client 413 (download).
Certificate CN=guiatelefonos.com, issuer Let's Encrypt R3, valid 2023-07-08 to 2023-10-06. JA3 3b5074b1b5d032e5620f69f9f700ff0e (same as Windows services in this capture). JA3S 389ed42c02ebecc32e73aa31def07e14.
```

---

## Step 6 — Find the C2 by unusual port { #c2-hunt }

**Goal:** formally find the port 12432 session seen in step 0 — a method that works on any PCAP.

**Query:**

```text
ip.src == 10.7.10.47 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.7.10.47` | Connections started by the suspect PC |
| `ip.dst != 10.0.0.0/8` | Destination **not** internal |
| `ip.dst != 224.0.0.0/4` | Without multicast (224–239): mDNS, IGMP noise |
| `port.dst != 80 && … != 443 && … != 53` | Without web, HTTPS, DNS |

**Actual result:**

```text
22:39:50.151  10.7.10.47:49744 → 194.26.135.119:12432   tcp   Packets 380/407   Databytes 542,386 / 7,179
```

Exactly one session remains.

**Reading the result:**

- **Port 12432** is not used by any standard service.
- As step 3 showed, **no DNS lookup** points to this IP — it is built into the program.
- It starts **0.3 s** (22:39:50.151) after the payload download ended (22:39:49.874) — the downloaded file ran and connected immediately.
- Above all, **the PC sent 75 times more data (542,386 bytes) than it received (7,179 bytes)**: an upload, i.e. **exfiltration**.

**Ticket entry:**

```text
[251118 0035, Analyst] Hunting outbound connections on non-standard ports - Found

[251118 0035, Analyst] Query: ip.src == 10.7.10.47 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53 -> 1 session: 194.26.135.119:12432. No DNS query for this IP (hard-coded).
```

---

## Step 7 — Reading the C2 session: protocol and flow { #c2-session }

**Goal:** which protocol the 12432 session uses and what was exchanged when.

```text
ip.dst == 194.26.135.119 && port.dst == 12432
```

Open the session. Arkime has no parser for this protocol, so Protocols shows **only `tcp`** and there is no HTTP or TLS section. Read the packet content (Source / Destination) as `ascii` — or, since it is long, download **Source Raw** and use CyberChef **Strings**.

**Actual result — the first bytes the PC sent:**

```text
00 01 00 01 02 02 1f  net.tcp://194.26.135.119:12432/  03 08 0c ...
```

```text
net.tcp://194.26.135.119:12432/
http://tempuri.org/Contract/MSValue1
Authorization   c75a68098b33270de4b87af925fb5ffd
```

**Reading the result:**

- `net.tcp://` is the **.NET WCF (Windows Communication Foundation) net.tcp protocol**: SOAP messages in a binary format over plain TCP instead of HTTP. Not as neat as cleartext HTTP, but the strings are readable. RedLine is written in .NET, so it uses this.
- **`http://tempuri.org/`** is the **default placeholder namespace** .NET tools insert when the developer sets none. Nothing is actually fetched from it. Real products usually change it before release, so `tempuri.org` in traffic to an external IP points to a quickly built .NET program — malware included.
- **`MSValue1`, `MSValue2`, `MSValue3`** are the method names called, renamed to hide their meaning.
- **`Authorization c75a6809…`** looks like a key identifying this malware build (inferred) — useful for finding other infections from the same operator.

**Flow (time order):**

```text
22:39:50.151  TCP connect (SYN → SYN-ACK → ACK)
22:39:50.425  PC → server   41 B      net.tcp preamble (address)
22:39:50.732  server → PC    1 B      preamble ack
22:39:50.753  PC → server   218 B     MSValue1  (check-in with Authorization key)
22:39:51.037  server → PC   159 B     MSValue1Response
22:39:51.042  PC → server   166 B     MSValue2  ("give me my settings")
22:39:51.347  server → PC   6,899 B   MSValue2Response  ← target list (step 8)
              ... about 5 seconds: the malware collects data on the PC ...
22:39:56.522  PC → server   541,961 B MSValue3  ← stolen data (step 9), 373 segments until 22:39:57.806
22:39:58.311  server → PC   120 B     MSValue3Response (ack)
```

- **"Get settings → collect for 5 seconds → upload in one go"** — the textbook infostealer flow.
- Unlike Trickbot, there is **no beacon**: no connection held open for minutes, no repeated check-ins. A **one-shot** session finished in 8 seconds — infostealers often "steal and leave". In the ticket's C2 field: "single short session, no repeating beacon".

**Ticket entry:**

```text
[251118 0040, Analyst] Reviewing C2 session to 194.26.135.119:12432 (protocol, direction, timing) - Found

[251118 0040, Analyst] 230710 22:39:50.151-22:39:58.364UTC 10.7.10.47 49744 -> 194.26.135.119 12432 tcp, Src 380 pkts 542,386 databytes / Dst 407 pkts 7,179 databytes.
.NET net.tcp binary SOAP, http://tempuri.org/Contract/MSValue1/2/3, Authorization c75a68098b33270de4b87af925fb5ffd.
Phases: MSValue1 check-in 22:39:50.753; MSValue2 config 22:39:51.042 -> 6,899 B response; MSValue3 upload 22:39:56.522-57.806 (541,961 B); ack 22:39:58.311.
```

---

## Step 8 — The server's instructions: what to steal (Q6) { #target-list }

**Goal:** read what `MSValue2Response` (server → PC, 6,899 bytes) tells the malware to steal.

Read the session's **Destination** side (what the server sent) as `ascii`, or **Destination Raw** → CyberChef **Strings**.

**Actual result (excerpt):**

```text
%userprofile%\Desktop|*.txt,*.doc*,*key*,*wallet*,*seed*|0
%userprofile%\Documents|*.txt,*.doc*,*key*,*wallet*,*seed*|0

%USERPROFILE%\AppData\Local\Google\Chrome\User Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data
%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data
%USERPROFILE%\AppData\Roaming\Opera Software\
%USERPROFILE%\AppData\Local\Vivaldi\User Data
%USERPROFILE%\AppData\Local\Yandex\YandexBrowser\User Data
... (about 40 Chromium-based browsers)
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox
%USERPROFILE%\AppData\Roaming\Thunderbird
%USERPROFILE%\AppData\Roaming\Waterfox
%USERPROFILE%\AppData\Local\Steam
%USERPROFILE%\AppData\Local\Battle.net

Armory  *.wallet      Atomic      Binance     Coinomi\Coinomi\wallets
Electrum\wallets      Ethereum\wallets        Exodus\exodus.wallet
Guarda                com.liberty.jaxx        Monero\wallets

nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
bfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
... (about 30 wallet browser extensions)

AWS_ACCESS_KEY_ID  AWS_SECRET_ACCESS_KEY  AZURE_CLIENT_SECRET  AZURE_PASSWORD
GH_TOKEN  GITLAB_USER_LOGIN  DOCKER_PASSWORD  DOCKERHUB_PASSWORD  NPM_AUTH_TOKEN
SLACK_TOKEN  STRIPE_API_KEY  TWILIO_ACCOUNT_SID  HEROKU_API_KEY  VAULT_TOKEN ...
```

**Reading the result — four groups:**

| Group | Content | Meaning |
|---|---|---|
| **File grabber** | `*.txt`, `*.doc*`, `*key*`, `*wallet*`, `*seed*` on Desktop and in Documents | Notepad passwords, documents, wallet recovery phrases (seed). <code>&#124;0</code> looks like an option such as folder depth (inferred) |
| **Browsers** | `User Data` of about 40 Chromium-based browsers; Firefox-based (Firefox, Waterfox, Thunderbird, Pale Moon …); Steam, Battle.net | Saved passwords, cookies (logged-in sessions), autofill, cards |
| **Crypto wallets** | Desktop wallets (Armory, Atomic, Electrum, Exodus, Monero …) and wallet extensions (Metamask, Phantom, Coinbase …). 32-letter strings like `nkbihf…` are **Chrome extension IDs** | Wallet files and keys |
| **API keys / tokens** | `AWS_…`, `AZURE_…`, `GH_TOKEN`, `DOCKER_PASSWORD`, `SLACK_TOKEN` … | Cloud and developer secrets stored in **environment variables** on developer PCs |

This is the answer to **Q6 (what it tried to steal)**. Importantly, the list is **not built into the malware: the server sends it at run time**. The operator can change the targets by changing the server config, so this response tells you exactly what **this** operator was after.

**Ticket entry:**

```text
[251118 0045, Analyst] Reviewing C2 server instructions (target list) - Found

[251118 0045, Analyst] Server MSValue2Response (6,899 bytes): Desktop and Documents |*.txt,*.doc*,*key*,*wallet*,*seed*|; ~40 Chromium browser User Data paths; Firefox, Waterfox, Thunderbird, Pale Moon; Steam, Battle.net; wallets Armory, Atomic, Binance, Coinomi, Electrum, Ethereum, Exodus, Guarda, Jaxx, Monero; ~30 wallet extension IDs (Metamask, Phantom, Coinbase ...); env vars AWS_ACCESS_KEY_ID, AZURE_CLIENT_SECRET, GH_TOKEN, DOCKER_PASSWORD, SLACK_TOKEN, STRIPE_API_KEY, VAULT_TOKEN ...
```

---

## Step 9 — What was actually uploaded { #exfil }

**Goal:** read what `MSValue3` (PC → server, 541,961 bytes) contained. This fills the ticket's exfil fields (time, what, bytes, method).

Download **Source Raw** and open it in CyberChef; add **Strings** to the recipe to see readable text.

**Actual result (excerpt, password masked):**

```text
3154E784D973FE3C24082CC1E80F37A9                 ← hardware ID (victim identifier)
(UTC) Coordinated Universal Time                  ← time zone
rwalters                                          ← user name
Windows 10 Pro for Workstations x64               ← OS
English (United States)                           ← language
{Width=1440, Height=900}                          ← screen size
Windows Defender                                  ← antivirus
ID: 576, Name: csrss.exe, CommandLine:
ID: 4624, Name: explorer.exe, CommandLine: C:\Windows\Explorer.EXE
ID: 5760, Name: smartscreen.exe, CommandLine: C:\Windows\System32\smartscreen.exe -Embedding
ID: 3952, Name: powershell.exe, CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command"
    "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass };
     & 'C:\Users\rwalters\Documents\mystery_file.ps1'"
...
Total of RAM  32765.05 MB
Intel(R) Core(TM) i5-10200H CPU @ 2.40GHz
Microsoft_[Edge]  Default  https://www.overcoats-r-us.com/  rwalters@coolweathercoat.com  My_p@******
Top_secret_ducment.docx  C:\Users\rwalters\Documents\Top_secret_ducment.docx  PK ... word/document.xml ...
‰PNG ... IHDR (1536 x 864) ... IDAT ... IEND      ← 534,297-byte screenshot
```

**Reading the result — one by one:**

**1. System details** — user, OS, language, screen size, antivirus, CPU, RAM, hardware ID. Used to identify the victim and judge whether the PC is "worth something" (high-spec, corporate domain).

**2. Process list and how it started** — the most important clue is here:

```text
powershell.exe "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\rwalters\Documents\mystery_file.ps1'"
```

| Piece | Meaning |
|---|---|
| `Get-ExecutionPolicy` | Check the current PowerShell script execution policy |
| `-ne 'AllSigned'` | If it is **not** "only signed scripts" … |
| `Set-ExecutionPolicy -Scope Process Bypass` | … **bypass** the policy for this PowerShell window only |
| `& '…\mystery_file.ps1'` | Run `mystery_file.ps1` from Documents |

This command line is exactly what Windows builds when you right-click a `.ps1` file in Explorer and choose **"Run with PowerShell"** — strong evidence that **the user ran a downloaded script themselves** (inferred). The SmartScreen check at 22:39:44 (step 3) and the `smartscreen.exe` process fit the same picture. This is the **execution** stage.

**3. Password saved in Edge** — the account `rwalters@coolweathercoat.com` for `https://www.overcoats-r-us.com/` and its password were uploaded **in cleartext**. Again the username is a company e-mail — check whether the company password is the same.

**4. A document** — `C:\Users\rwalters\Documents\Top_secret_ducment.docx`, caught by the "`*.doc*` in Documents" rule from step 8. The whole docx follows, starting with `PK` (a `.docx` is really a zip). Its text: `This is a top secret document. For my eyes only! Do not view this!` — a practice document, but in real life this is a **confidential document leak** to report.

**5. A screenshot** — a **534,297-byte** PNG (1536×864) from `‰PNG` (hex `89 50 4E 47`) to `IEND`. **98% of the upload is this image.** Use CyberChef **Extract Files**, or cut from the `0x89` byte and use **Render Image**.

!!! note "Capture loss breaks the image"
    **One TCP segment (1,459 bytes) is missing** from the upload in this PCAP (Arkime/Wireshark: "previous segment not captured"). Only about **the top third of the image** decodes; the rest is corrupted. The intact part shows the desktop and a **PowerShell window** displaying `404 HTTP Error` and `StatusCode : 200` — the response from `623start.site`. So the script ran **without hiding its window**, and it matches the HTTP response from step 4 exactly.

**Summary — exfil checklist:**

```text
Time     22:39:56.522 - 22:39:57.806 UTC (upload), acknowledged 22:39:58.311
What     screenshot (534 KB), system info, process list, 1 Edge credential, Top_secret_ducment.docx
Bytes    541,961 (MSValue3), 542,386 total client data in the session
Method   .NET net.tcp binary SOAP over raw TCP 12432 to 194.26.135.119 (unencrypted)
```

**Ticket entry:**

```text
[251118 0050, Analyst] Reviewing data uploaded to C2 (exfil content) - Found

[251118 0050, Analyst] Client MSValue3 upload (541,961 bytes): HWID 3154E784D973FE3C24082CC1E80F37A9, user rwalters, Windows 10 Pro for Workstations x64, 1440x900, AV Windows Defender;
process list incl. powershell.exe ... & 'C:\Users\rwalters\Documents\mystery_file.ps1'; CPU i5-10200H, RAM 32765 MB;
Edge credential https://www.overcoats-r-us.com/ | rwalters@coolweathercoat.com | My_p@****** (masked);
Top_secret_ducment.docx; PNG screenshot 1536x864 534,297 bytes (one 1,459-byte segment missing -> partly corrupted).
```

---

## Step 10 — Scope { #scope }

**Goal:** check whether the PC tried to spread to other internal hosts.

```text
ip.src == 10.7.10.47 && ip.dst == 10.7.10.0/24 && ip.dst != 10.7.10.9
```

| Piece | Meaning |
|---|---|
| `ip.dst == 10.7.10.0/24` | Connections to the internal network |
| `ip.dst != 10.7.10.9` | Without the DC |

**Actual result:**

```text
22:39:23.138  udp 137 → 10.7.10.255:137   (NetBIOS name broadcast)
22:39:26.828  udp 138 → 10.7.10.255:138   (NetBIOS browser broadcast)
```

**Reading the result:** only two broadcasts (`.255`); no SMB, RPC or RDP to other hosts. **No lateral movement.** This PCAP has no other internal PCs, so "are other PCs infected?" cannot be answered here. In a real network, search for other hosts talking to the IOC IPs, as in [Trickbot step 18](arkime-only-credential-theft-tls-c2.md#other-victims):

```text
ip.dst == [195.161.114.3, 92.118.151.9, 194.26.135.119] && ip.src != 10.7.10.47
```

**Ticket entry:**

```text
[251118 0055, Analyst] Checking for lateral movement to other internal hosts - Not Found

[251118 0055, Analyst] Query: ip.src == 10.7.10.47 && ip.dst == 10.7.10.0/24 && ip.dst != 10.7.10.9 -> only NetBIOS broadcast to 10.7.10.255. No SMB/RDP/RPC to other hosts.
```

---

## Conclusion { #conclusion }

```text
22:39:22  PC boots / user rwalters logs on (DHCP, Kerberos, LDAP)
22:39:44  SmartScreen check (checkappexec.microsoft.com)
22:39:47  mystery_file.ps1 runs → PowerShell reports "start, AV = Windows Defender" to 623start.site
22:39:48  reports "install"
22:39:49  fetches czx.jpg from guiatelefonos.com → 301 → HTTPS download (~345 KB, RedLine)
22:39:50  RedLine connects to 194.26.135.119:12432 (net.tcp), gets target list
22:39:56  uploads screenshot, system info, Edge password, document (~542 KB)
22:39:58  server acknowledges — done in 11 seconds from first check-in
```

## Timeline { #timeline }

| UTC (2023-07-10) | Event |
|---|---|
| 22:39:22 | DHCP: DESKTOP-9PEA63H gets 10.7.10.47 |
| 22:39:23–24, 22:39:32–33 | Domain logon (DNS SRV, LDAP, Kerberos `rwalters`, SMB/RPC to DC) |
| 22:39:33–35 | Windows/Edge start-up traffic (MSN, Bing, Microsoft CDN) |
| 22:39:44 | SmartScreen check `checkappexec.microsoft.com` |
| 22:39:47.579 | PowerShell → `623start[.]site/?status=start&av=Windows%20Defender` |
| 22:39:48.415 | PowerShell → `623start[.]site/?status=install` |
| 22:39:49.250 | `guiatelefonos[.]com/data/czx.jpg` (HTTP, no User-Agent) → 301 |
| 22:39:49.323–49.874 | About 353 KB downloaded over HTTPS |
| 22:39:50.151 | Connection to 194.26.135.119:12432 (net.tcp) |
| 22:39:51.347 | Server sends the target list (6,899 B) |
| 22:39:56.522–57.806 | Exfil upload 541,961 B |
| 22:39:58.311 | Server acknowledges; capture ends |

## Indicators of compromise { #iocs }

| Type | Indicator | Role |
|---|---|---|
| URL | `hxxp://623start[.]site/?status=start&av=`, `/?status=install` | PowerShell check-ins |
| IP | `195.161.114[.]3` | 623start.site |
| URL | `hxxp://guiatelefonos[.]com/data/czx.jpg`, `hxxps://guiatelefonos[.]com/data/czx.jpg` | Payload |
| IP | `92.118.151[.]9` | guiatelefonos.com |
| IP:port | `194.26.135[.]119:12432` (`net.tcp://194.26.135[.]119:12432/`) | RedLine C2 and exfil |
| String | `Authorization c75a68098b33270de4b87af925fb5ffd` | Build / bot key (inferred) |
| File path | `C:\Users\rwalters\Documents\mystery_file.ps1` | Initial execution script |
| User-Agent | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031` | PowerShell downloader |
| SHA256 (Unit 42) | `3c42b93801f02696487de64bb623f81cf7baf73a379a46e1459ca19ae7dc2454` | RedLine executable (348,160 B) |
| SHA256 (Unit 42) | `f754d7674a3a74969cccb7d834c99b72b9f79c29dc8d0e9c15854a6bfb1a9c97` | PowerShell launcher script (800 B) |

The two hashes cannot be computed from the PCAP (HTTPS download; the script never crossed the network) and come from the Unit 42 answers.

## ATT&CK mapping { #attack }

| Technique | Evidence |
|---|---|
| T1204.002 User Execution: Malicious File | "Run with PowerShell" style command line (inferred) |
| T1059.001 PowerShell | `mystery_file.ps1`, `WindowsPowerShell` User-Agent |
| T1518.001 Security Software Discovery | `av=Windows%20Defender` report |
| T1105 Ingress Tool Transfer | `czx.jpg` download |
| T1036 Masquerading | Executable named `.jpg` |
| T1082 System Information Discovery, T1057 Process Discovery | Uploaded system details and process list |
| T1555.003 Credentials from Web Browsers | Saved Edge password |
| T1005 Data from Local System | `Top_secret_ducment.docx`, file-grabber rules |
| T1113 Screen Capture | PNG screenshot |
| T1571 Non-Standard Port, T1095 Non-Application Layer Protocol | TCP 12432, net.tcp |
| T1041 Exfiltration Over C2 Channel | MSValue3 upload |

## Compared with the Trickbot case { #compare }

Two malware families that both steal data leave very different shapes on the network. Knowing the differences helps narrow down the family in the next PCAP.

| | [Trickbot (2020)](arkime-only-credential-theft-tls-c2.md) | RedLine Stealer (2023) |
|---|---|---|
| Initial execution | Script (`WinHttp.WinHttpRequest.5`) downloads an EXE | User runs a `.ps1`; PowerShell checks in |
| Payload disguise | EXE named `.png` | EXE named `.jpg`, fetched over HTTPS |
| C2 protocol | HTTP POST (8082) + TLS (447/449, self-signed) | .NET net.tcp (SOAP), unencrypted, port 12432 |
| C2 address | Raw IP | Raw IP (no DNS) |
| Traffic pattern | C2 held open for minutes + module downloads, stays active | Get config → collect → upload once, **done in 8 seconds** |
| Stolen | Browser passwords, Firefox tokens, recon (nltest etc.) | Screenshot, system details, browser password, document, (per list) wallets and API keys |
| Next move | Domain recon, SMB lateral-movement attempt | No lateral movement |
| Stand-out clues | Hostname and bot ID in URI, fake IE7 UA | `WindowsPowerShell` UA, `tempuri.org`, upload ≫ download |

Also remember what they share: **raw-IP connections, non-standard ports, disguised file names and sessions whose upload dwarfs the download** were key clues in both.

---

## Compared with the official Unit 42 answers { #official-answers }

| Question | This analysis | Unit 42 answer | Match |
|---|---|---|---|
| Infection start | 2023-07-10 22:39 UTC (22:39:47) | 2023-07-10 22:39 UTC | ✓ |
| IP | 10.7.10.47 | 10.7.10[.]47 | ✓ |
| MAC | 80:86:5b:ab:1e:c4 | 80:86:5b:ab:1e:c4 | ✓ |
| Hostname | DESKTOP-9PEA63H | DESKTOP-9PEA63H | ✓ |
| User | rwalters | rwalters | ✓ |
| Targeted information | Desktop/Documents files, browser data, wallets, API keys and credentials + actual upload contents | Same categories (files, browsers, wallets, API keys and credentials) | ✓ |

The official write-up found the hostname via NetBIOS and the account via Kerberos; this page used DHCP and Kerberos. Different routes, same answers — two sources are better than one.

---

## The incident ticket { #ticket }

Template rules are the same as in the [Trickbot case](arkime-only-credential-theft-tls-c2.md#ticket-rules). Specific to this case:

- **C2 field:** no beacon, so the state is written as "single short session, no repeating beacon".
- **Exfil field:** time, content, bytes and method from the step 9 checklist.
- **Lateral fields:** none, so left blank (template rule).
- The password is masked. Operator, ticket link and evidence paths are placeholders; operation-log times are illustrative.

```text
#INDEX ENTRY#

[] -- 230710 2239 -- 10.7.10.47 DESKTOP-9PEA63H -- RedLine Stealer infection: PowerShell script, payload download, data exfil over raw TCP 12432 -- <ticket-link>


#TICKET METADATA#

OPERATORS: <Analyst>

TIME OF INCIDENT: 230710 22:39:47 UTC

RELATED TICKETS:
N/A

DESCRIPTION OF INVESTIGATION:

At 230710 22:39:47 UTC DESKTOP-9PEA63H (10.7.10.47, user rwalters, domain COOLWEATHERCOAT) ran a PowerShell script (process list shows powershell.exe executing C:\Users\rwalters\Documents\mystery_file.ps1 with ExecutionPolicy Bypass). The script sent two HTTP GET requests (port 80) to 195.161.114.3 (623start[.]site) with User-Agent "WindowsPowerShell/5.1": /?status=start&av=Windows%20Defender (reports the installed antivirus) and /?status=install (both answered "404 HTTP Error" with status 200). At 22:39:49 the host requested /data/czx.jpg from 92.118.151.9 (guiatelefonos[.]com) over HTTP with no User-Agent, was redirected (301) to HTTPS, and downloaded about 353 KB over TLS 443 (Let's Encrypt certificate issued 230708); the file name ends in .jpg but the size and timing indicate the malware payload (reported by Unit 42 as a 348,160-byte RedLine Stealer executable).

At 22:39:50 the host connected directly (no DNS lookup) to 194.26.135.119 on non-standard TCP port 12432 using .NET net.tcp binary SOAP (tempuri.org namespace, methods MSValue1-3, Authorization c75a68098b33270de4b87af925fb5ffd). This is the C2 channel; it is a single short session, not a repeating beacon. The server sent a 6,899-byte target list (Desktop/Documents files *.txt, *.doc*, *key*, *wallet*, *seed*; Chromium and Firefox browser profiles; about 40 crypto wallets and wallet extensions; cloud/CI/developer API keys in environment variables). Between 22:39:56 and 22:39:57 the host uploaded 541,961 bytes (exfil): a 534 KB PNG desktop screenshot, system details (user, OS, language, screen size, antivirus, CPU, RAM, process list), one saved Microsoft Edge credential for rwalters@coolweathercoat[.]com, and the document C:\Users\rwalters\Documents\Top_secret_ducment.docx. The server acknowledged at 22:39:58. Determination: MALICIOUS - RedLine Stealer information stealer (C2 protocol, target list and data layout match RedLine; confirmed by Unit 42 answers). No lateral movement seen. Credentials for rwalters are compromised.


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:
10.7.10.47 DESKTOP-9PEA63H (user rwalters, MAC 80:86:5b:ab:1e:c4, Windows 10 Pro for Workstations x64)

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

LATERAL DESTINATION IP/s & HOSTNAME/s: (If No Lateral Leave Blank.)

LATERAL DESTINATION PORT/s: (If No Lateral OR If Ephemeral Leave Blank.)


#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:
195.161.114.3 (623start[.]site) - PowerShell status check-ins (HTTP 80)
92.118.151.9 (guiatelefonos[.]com) - payload czx.jpg (HTTP 80 redirect, HTTPS 443 download)
194.26.135.119 - RedLine C2 and exfil (TCP 12432, no domain)

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

EXTERNAL DESTINATION PORT/s:
Port 80 - HTTP
Port 443 - TLS
Port 12432 - .NET net.tcp (non-standard)


#SEARCH QUERIES#

ARKIME (MOLOCH):
ip == 10.7.10.47 && ip == [195.161.114.3, 92.118.151.9, 194.26.135.119]
ip.src == 10.7.10.47 && port.dst == 12432

SPLUNK: (not run - equivalent Zeek query)
index=zeek sourcetype=conn:zeek id_orig_h=10.7.10.47 AND id_resp_h IN (195.161.114.3, 92.118.151.9, 194.26.135.119)


#EVIDENCE LOCATIONS#

Team1: /home/<analyst>/evidence/230710_DESKTOP-9PEA63H_powershell_http_checkin.pcap
Team1: /home/<analyst>/evidence/230710_DESKTOP-9PEA63H_czx_jpg_download.pcap
Team1: /home/<analyst>/evidence/230710_DESKTOP-9PEA63H_redline_c2_12432.pcap
(Exported from Arkime "Download PCAP". Full credential is in the C2 PCAP only - masked in this ticket.)


#OPERATION LOG / ANALYST NOTES#

[251118 0010, Analyst] Establishing data time range and session count - Found
[251118 0012, Analyst] Reviewing protocols and internal hosts - Found
[251118 0015, Analyst] Identifying client IP, MAC, hostname and domain from DHCP - Found
[251118 0017, Analyst] Identifying DC from DNS SRV and user account from Kerberos - Found
[251118 0020, Analyst] Reviewing DNS queries for unusual domains - Found
[251118 0025, Analyst] Reviewing cleartext HTTP (PowerShell user agent, downloads) - Found
[251118 0030, Analyst] Reviewing HTTPS download from guiatelefonos.com (size, certificate, JA3) - Found
[251118 0035, Analyst] Hunting outbound connections on non-standard ports - Found
[251118 0040, Analyst] Reviewing C2 session to 194.26.135.119:12432 (protocol, direction, timing) - Found
[251118 0045, Analyst] Reviewing C2 server instructions (target list) - Found
[251118 0050, Analyst] Reviewing data uploaded to C2 (exfil content) - Found
[251118 0055, Analyst] Checking for lateral movement to other internal hosts - Not Found

[Time -- Operator]

Tool Output / Notes:

[251118 0010, Analyst] Data range 2023-07-10 22:39:22 - 22:39:58 UTC (36 seconds), about 120 sessions. Capture starts with a DHCP request: host was just starting up / logging on.

[251118 0012, Analyst] Only one internal client: 10.7.10.47 (118 sessions as source). Server 10.7.10.9. Protocols: dns, krb5, ldap, smb, dcerpc, ntp, nbns, mdns, igmp, dhcp (normal AD logon), tls (20 sessions), http (2 sessions), plus one tcp session to port 12432.

[251118 0015, Analyst] Query: protocols == dhcp
230710 22:39:22 DHCP Request from 0.0.0.0 - client MAC 80:86:5b:ab:1e:c4, hostname DESKTOP-9PEA63H, FQDN DESKTOP-9PEA63H.coolweathercoat.com, requested IP 10.7.10.47, vendor class MSFT 5.0
230710 22:39:22 DHCP ACK from 10.7.10.9 - yiaddr 10.7.10.47, mask 255.255.255.0, router 10.7.10.1, DNS 10.7.10.9, domain coolweathercoat.com

[251118 0017, Analyst] Query: host.dns == _ldap._tcp.dc._msdcs.* -> SRV win-s3wt6lgqfvx.coolweathercoat.com -> A 10.7.10.9 (DC).
Query: ip.src == 10.7.10.47 && protocols == krb5 -> krb5.cname rwalters, desktop-9pea63h$; realm COOLWEATHERCOAT.COM.

[251118 0020, Analyst] Query: ip.src == 10.7.10.47 && protocols == dns -> AD SRV lookups, Microsoft/Bing/MSN/Azure CDN names (benign), checkappexec.microsoft.com 22:39:44 (SmartScreen app reputation check), then 623start.site 22:39:47 -> 195.161.114.3 and guiatelefonos.com 22:39:49 -> 92.118.151.9 (unusual).

[251118 0025, Analyst] Query: ip.src == 10.7.10.47 && protocols == http -> 2 sessions.
230710 22:39:47.579UTC 10.7.10.47 49741 195.161.114.3 80 GET 200 623start.site /?status=start&av=Windows%20Defender 1.1 Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
230710 22:39:48.415UTC 10.7.10.47 49741 195.161.114.3 80 GET 200 623start.site /?status=install 1.1 (same UA)
  Responses: Server Apache/2.4.6 (CentOS) PHP/7.4.33, Content-Length 14, body "404 HTTP Error" with status 200.
230710 22:39:49.250UTC 10.7.10.47 49742 92.118.151.9 80 GET 301 guiatelefonos.com /data/czx.jpg 1.1 (no User-Agent) -> Location https://guiatelefonos.com:443/data/czx.jpg (nginx/1.20.2)

[251118 0030, Analyst] 230710 22:39:49.323-22:39:49.874UTC 10.7.10.47 49743 -> 92.118.151.9 443 tls, SNI guiatelefonos.com, server databytes 353,715 / client 413 (download).
Certificate CN=guiatelefonos.com, issuer Let's Encrypt R3, valid 2023-07-08 to 2023-10-06. JA3 3b5074b1b5d032e5620f69f9f700ff0e (same JA3 as Windows services client.wns.windows.com and evoke-windowsservices-tas.msedge.net in this capture). JA3S 389ed42c02ebecc32e73aa31def07e14.

[251118 0035, Analyst] Query: ip.src == 10.7.10.47 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53 -> 1 session: 194.26.135.119:12432. No DNS query resolves to this IP (hard-coded).

[251118 0040, Analyst] 230710 22:39:50.151-22:39:58.364UTC 10.7.10.47 49744 -> 194.26.135.119 12432 tcp, Src 380 pkts 542,386 databytes / Dst 407 pkts 7,179 databytes. Dst MAC 00:b0:64:98:ad:54 (gateway).
Payload: .NET Message Framing "net.tcp://194.26.135.119:12432/", binary SOAP, http://tempuri.org/Contract/MSValue1/2/3, Authorization c75a68098b33270de4b87af925fb5ffd.
Phases: 22:39:50.753 MSValue1 (218 B) -> 22:39:51.037 response (159 B); 22:39:51.042 MSValue2 (166 B) -> 22:39:51.347 response (6,899 B, target list); 22:39:56.522-22:39:57.806 MSValue3 upload (541,961 B); 22:39:58.311 response (120 B).

[251118 0045, Analyst] Server MSValue2Response (6,899 bytes): %userprofile%\Desktop and \Documents |*.txt,*.doc*,*key*,*wallet*,*seed*|; Chromium browser User Data paths (Chrome, Edge, Brave, Opera, Vivaldi, Yandex ...); Firefox, Waterfox, Thunderbird, Pale Moon; wallets Armory, Atomic, Binance, Coinomi, Electrum, Ethereum, Exodus, Guarda, Jaxx, Monero; wallet extension IDs (Metamask, Phantom, Coinbase, Tronlink, Ronin ...); env vars AWS_ACCESS_KEY_ID, AZURE_CLIENT_SECRET, GH_TOKEN, DOCKER_PASSWORD, SLACK_TOKEN, STRIPE_API_KEY, VAULT_TOKEN ...

[251118 0050, Analyst] Client MSValue3 upload (541,961 bytes) contents:
 Hardware ID 3154E784D973FE3C24082CC1E80F37A9, time zone (UTC), user rwalters, Windows 10 Pro for Workstations x64, English (United States), screen 1440x900, AV Windows Defender
 Process list incl. powershell.exe "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\rwalters\Documents\mystery_file.ps1'"
 CPU Intel Core i5-10200H, RAM 32765 MB
 Microsoft_[Edge] Default: https://www.overcoats-r-us.com/ | rwalters@coolweathercoat.com | My_p@****** (masked)
 File Top_secret_ducment.docx (C:\Users\rwalters\Documents\), text "This is a top secret document. For my eyes only! Do not view this!"
 PNG screenshot 1536x864, 534,297 bytes (desktop with PowerShell window showing "404 HTTP Error"); one 1,459-byte TCP segment missing from the capture, so the lower part of the image is corrupted.

[251118 0055, Analyst] Query: ip.src == 10.7.10.47 && ip.dst == 10.7.10.0/24 && ip.dst != 10.7.10.9 -> only NetBIOS broadcast to 10.7.10.255 (udp 137/138). No SMB/RDP/RPC to other hosts. No lateral movement.

RECOMMENDATIONS:
- Isolate DESKTOP-9PEA63H (10.7.10.47); host triage for mystery_file.ps1 and the dropped executable.
- Reset rwalters domain password and the overcoats-r-us.com password; check reuse.
- Treat Top_secret_ducment.docx as disclosed.
- Block 623start[.]site, guiatelefonos[.]com, 194.26.135.119 (and port 12432 egress).
- Hunt for other hosts with outbound sessions to 194.26.135.119 or URIs /?status=start&av=.
```

For a blank template see the [Trickbot case's blank ticket template](arkime-only-credential-theft-tls-c2.md#ticket-template).

---

## Copy-ready query sheet { #query-sheet }

Replace `<…>`.

**Host information**

```text
protocols == dhcp
```

```text
host.dns == _ldap._tcp.dc._msdcs.*
```

```text
ip.src == <host-IP> && protocols == krb5
```

**Finding the suspicious traffic**

```text
ip.src == <host-IP> && protocols == dns
```

```text
ip.src == <host-IP> && protocols == http
```

```text
http.user-agent == *WindowsPowerShell*
```

```text
ip.src == <host-IP> && protocols == tls
```

```text
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

```text
ip.dst == <C2-IP> && port.dst == <port>
```

**Big uploads (exfil candidates)**

```text
ip.src == <host-IP> && databytes.src > 100000 && ip.dst != <internal-CIDR>
```

**Scope**

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

**CyberChef recipes used**

| Recipe | Used for |
|---|---|
| URL Decode | URIs like `av=Windows%20Defender` |
| Strings | Readable text from net.tcp data exported with Source/Destination Raw |
| Extract Files | Carving the PNG and docx out of the upload |
| Render Image | Viewing the carved screenshot |
| Unzip | Reading `word/document.xml` inside the docx (a zip) |

---

## Lessons learned { #lessons }

- **The shorter the PCAP, the faster "one unknown port" shows.** Group the ports by role and 12432 jumps out of the normal AD traffic.
- **DHCP gives IP, MAC and hostname at once.** A capture that starts with DHCP was recording from the moment the PC came up.
- **A `WindowsPowerShell` User-Agent and a request with no User-Agent** both mean "a program, not a person".
- **Responses that contradict themselves** (status 200 with a "404" body) may be camouflage.
- **A proper certificate (Let's Encrypt) does not mean safe.** Judge by context.
- **No JA3 change does not mean clean.** Here the payload download shared a JA3 with Windows services and the C2 was not even TLS.
- **Sessions where upload ≫ download are the first exfil candidates** (`databytes.src`).
- **Unencrypted C2 shows both the orders and the loot.** Report "what was targeted" (the server's list) separately from "what was lost" (the upload).
- **Record capture loss.** A missing segment damaged part of the evidence (the screenshot) — the ticket should say so.

## References { #references }

- [Crossing the Line: Unit 42 Wireshark Quiz for RedLine Stealer](https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/) — questions and where to get the PCAP
- [Answers to Unit 42 Wireshark Quiz for RedLine Stealer](https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer-answers/) — official answers and hashes
- [malware-traffic-analysis.net exercise list](https://www.malware-traffic-analysis.net/training-exercises.html)
