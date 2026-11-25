---
title: IcedID (Cold as Ice) — from a redirect, Firebase and a fake gzip to an HTTPS beacon and BackConnect (Arkime analysis)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - icedid
  - loader
  - c2
---

# IcedID (Cold as Ice) — from a redirect, Firebase and a fake gzip to an HTTPS beacon and BackConnect { #icedid-cold-as-ice }

!!! abstract "Case summary"
    One of three Windows PCs in the `boogienights.live` domain opened a **link made of a bare IP address** (`80.77.25.175/main.php`) in Edge. That server sent the PC on to **Google Firebase Storage**, where it downloaded `Scan_Inv.zip`. When the **IcedID installer** inside the archive ran, it sent details about the PC **hidden in cookies** and received a malicious file **disguised as `application/gzip`**. From then on the PC contacted an HTTPS C2 with a **self-signed certificate** **every 5 minutes** (for about 6 hours). About 5 hours after the infection a remote-control channel called **BackConnect** opened, and the attacker typed `net group "Domain Computers" /domain` and browsed the drives and folders by hand. Unlike the 36-second RedLine PCAP, this is a **6-hour PCAP**, so the way you search is different.

| | |
|---|---|
| **Evidence** | Unit 42 Wireshark quiz April 2023 PCAP ("Cold as Ice"), 2023-04-19 15:26:28 – 21:22:36 UTC (about 5 h 56 min), about 1,640 sessions |
| **Environment** | Closed network assumed (no hash or reputation lookups). Order and queries for Arkime, decoding in CyberChef |
| **Output** | Answers to the 6 quiz questions |
| **Related pages** | [Arkime-only analysis — Trickbot case](arkime-only-credential-theft-tls-c2.md) · [RedLine Stealer case](redline-stealer-powershell-nettcp-c2.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) |

!!! warning "Want to solve it yourself first?"
    The answers start below. If you want to try first, stop here and answer these 6 questions.

    1. Date and time (UTC) the infection started
    2. IP address of the infected Windows PC
    3. MAC address
    4. Hostname
    5. User account name
    6. Was there any follow-up malicious activity after the infection? If so, what?

!!! note "About the numbers on this page"
    This page analysed the PCAP directly with Python to calculate the values Arkime would show (sessions, bytes, fields), and pairs them with the Arkime queries that find them. Some numbers such as session counts may differ slightly from your Arkime screen, so check them as you follow along. The results were [compared](#official-answers) with the official Unit 42 answers.

!!! tip "How to read this page"
    Same order as the two earlier cases. Each step: **goal → query → query explained → actual result → reading the result**. Copy queries with the **copy button** on the right of each code block. Basics such as the time range, time zone and SPI View are covered in detail in [steps 0–1 of the Trickbot case](arkime-only-credential-theft-tls-c2.md#step-0).

## Answers at a glance { #answers }

| # | Question | Answer | Status |
|---|---|---|---|
| 1 | Infection start | **2023-04-19 15:31 UTC** (first malicious request: 15:31:07 `GET /main.php`) | Confirmed |
| 2 | IP | **10.4.19.136** | Confirmed |
| 3 | MAC | **14:58:d0:2e:c5:ae** | Confirmed |
| 4 | Hostname | **DESKTOP-SFF9LJF** | Confirmed |
| 5 | User | **csilva** (LDAP full name Cornelius Silva) | Confirmed |
| 6 | Follow-up | **Yes — BackConnect.** From 20:48 UTC a remote shell and a file manager opened to 193.149.176.100:443 (not TLS). The attacker ran `net group "Domain Computers" /domain` and listed the drives and C:\ | Confirmed |

| Item | Value |
|---|---|
| Network | 10.4.19.0/24, gateway 10.4.19.1, DC/DNS **10.4.19.19 (WIN-GP4JHCK2JMV)**, domain `boogienights.live` |
| Clients | 10.4.19.136 DESKTOP-SFF9LJF (infected), 10.4.19.138 DESKTOP-RETP4BU, 10.4.19.143 DESKTOP-JAL4D68 |
| Starting link | `hxxp://80.77.25[.]175/main.php` → 302 → Firebase Storage `Scan_Inv.zip` |
| gzip loader | `hxxp://skigimeetroc[.]com/` (192.153.57.233), PC details in cookies, 520,803-byte response |
| HTTPS C2 | `askamoshopsi[.]com` · `spakernakurs[.]com` (104.168.53.18), `skansnekssky[.]com` (217.199.121.56, 5-minute beacon) |
| BackConnect | **193.149.176.100:443** (raw TCP) |
| Extra | 10.4.19.138 downloaded a zip (.wsf) resembling Qakbot distribution at 17:17 — [step 11](#second-host) |

---

## Step 0 — Data range and the big picture { #step-0 }

**Goal:** Learn the start and end of the data, its size and the internal PCs first.

**Query:** Set the time range to **All**, leave the search bar empty and press Search. In Sessions, sort Start Time ascending / Stop Time descending to see the start and end (method in [Trickbot case step 1](arkime-only-credential-theft-tls-c2.md#data-range)).

**Actual result:**

```text
Start  2023/04/19 15:26:28 UTC
End    2023/04/19 21:22:36 UTC   (duration 05:56:08)
Sessions about 1,640
Src IP 10.4.19.138 (833)   10.4.19.136 (718)   10.4.19.143 (85)   10.4.19.19 (4)
```

SPI View → General → Dst Port (session count, protocol/port):

```text
udp 53 (586)   tcp 443 (483)   tcp 389 (114)   tcp 445 (85)   udp 389 (73)   tcp 135 (67)
tcp 49669 (63) tcp 88 (63)     tcp 80 (47)     tcp 49684 (12) tcp 139 (11)   udp 1900 (9)
tcp 53 (6)     udp 137 (5)     udp 138 (4)     udp 123 (3)    udp 111 (3)    udp 5353 (2)   udp 5355 (1)
```

**Reading the result:**

- The capture is **almost 6 hours long**. You cannot just scan the session list by eye like in the RedLine case (36 seconds). This time we use a **"filter out, then look at what is left"** approach.
- There are 4 internal IPs. 10.4.19.19 starts almost no sessions (4) and mostly receives them, so it is a **server** (confirmed as the DC later). The other **3 are client PCs**. The quiz also says "3 clients, only one infected".
- Grouping the ports by role:

| Port | Protocol | Verdict |
|---|---|---|
| 53, 88, 389, 445, 135, 139, 49669·49684 (dynamic RPC), 123 | DNS, Kerberos, LDAP, SMB, RPC, NTP | **Normal AD traffic**. Mostly to 10.4.19.19 |
| 137/138, 1900, 5353, 5355, 111 | NetBIOS, SSDP, mDNS, LLMNR, RPC portmapper | Local noise |
| **443 (483)** | HTTPS | Mostly Microsoft and Bing services. We have to find what is hiding inside |
| **80 (47)** | HTTP | **Cleartext** — we can read everything, so always look |

- **Unlike RedLine, there is no "unknown port".** That means the malicious traffic is hiding inside 80 and 443. So the order is: **identify the 3 PCs → odd names in DNS → cleartext HTTP → HTTPS (certificates, intervals) → port 443 that is not TLS**.

---

## Step 1 — IP, MAC and hostname of the 3 clients (Q2–Q4) { #hosts }

**Goal:** We do not yet know which PC is infected, so we first record **who all 3 are**. When we later find "which PC went somewhere odd", we can name it straight away.

### Check DHCP first

```text
protocols == dhcp
```

**Actual result:** `0 sessions`

There is **no DHCP** in this PCAP. The capture started after the PCs already had their IPs. As the tip in the RedLine case says, we use **Kerberos, NetBIOS and the Ethernet MAC** instead.

### Kerberos computer accounts

```text
ip.src == 10.4.19.0/24 && protocols == krb5
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.4.19.0/24` | Connections started by PCs in the internal network (CIDR notation) |
| `&&` | and |
| `protocols == krb5` | Kerberos sessions only |

SPI View → **krb5** → **Load All** on `krb5.cname`. In the same screen open `ip.src` and `mac.src` under **General**. Click a value and choose **"and"** to narrow the search to that value, so you can check the cname for each IP one by one.

**Actual result:**

```text
Src IP        Src MAC             krb5.cname (computer account, ends in $)
10.4.19.136   14:58:d0:2e:c5:ae   desktop-sff9ljf$  (+ user account csilva → step 3)
10.4.19.138   00:90:27:cd:92:90   desktop-retp4bu$
10.4.19.143   00:02:a5:7c:61:08   desktop-jal4d68$
10.4.19.19    00:21:5a:86:39:8f   (server, DC)
```

### Cross-check with NetBIOS

```text
ip.src == 10.4.19.0/24 && port.dst == [137, 138]
```

| Piece | Meaning |
|---|---|
| `port.dst == [137, 138]` | List notation. 137 (NetBIOS name) **or** 138 (NetBIOS datagram) |

Open a session and the names appear inside the broadcasts.

```text
15:26:37  10.4.19.19   WIN-GP4JHCK2JMV   BOOGIENIGHTS   __MSBROWSE__
15:33:47  10.4.19.136  DESKTOP-SFF9LJF   BOOGIENIGHTS
17:06:20  10.4.19.138  DESKTOP-RETP4BU   BOOGIENIGHTS
```

**Reading the result:**

- Kerberos and NetBIOS give the same names. When **two sources agree**, you can be sure.

| IP | MAC | Hostname |
|---|---|---|
| 10.4.19.136 | 14:58:d0:2e:c5:ae | DESKTOP-SFF9LJF |
| 10.4.19.138 | 00:90:27:cd:92:90 | DESKTOP-RETP4BU |
| 10.4.19.143 | 00:02:a5:7c:61:08 | DESKTOP-JAL4D68 |
| 10.4.19.19 | 00:21:5a:86:39:8f | WIN-GP4JHCK2JMV (DC) |

- **A MAC only means something inside the same LAN.** When these PCs' packets go outside, `mac.dst` is always **00:02:17:5c:e6:13**, which is not the remote server but the **gateway (10.4.19.1)**. The answer to Q3 comes from `mac.src` on packets the PC sent.
- The DC name being `WIN-` plus random characters is the same as in the RedLine case (default Windows Server name).
- We still do not know which PC is infected. The next step finds it.

---

## Step 2 — Odd names in DNS, narrowing down the infected PC { #dns }

**Goal:** From the names the 3 PCs looked up, **filter out the normal ones and see what is left**. The PC that looked up the leftovers is the candidate.

**Query:**

```text
ip.src == 10.4.19.0/24 && protocols == dns
```

SPI View → **dns** → `host.dns` → **Load All**. If the list is long, look at one PC at a time (`ip.src == 10.4.19.136 && protocols == dns`).

**Actual result (10.4.19.136, some of its 51 names grouped by type):**

```text
AD / internal  WIN-GP4JHCK2JMV.boogienights.live, _ldap._tcp.dc._msdcs.boogienights.live, wpad.boogienights.live
Microsoft      *.msn.com, *.bing.com, *.microsoft.com, *.msedge.net, *.windowsupdate.com, *.live.com,
               *.office.com, ecn.dev.virtualearth.net, fp-afd.azurefd.us ...
Other normal   update.googleapis.com, acroipm2.adobe.com
?              firebasestorage.googleapis.com   15:31:10
???            skigimeetroc.com                  15:35:39  → 192.153.57.233
???            askamoshopsi.com                  15:36:41  → 104.168.53.18
???            skansnekssky.com                  15:36:43  → 217.199.121.56  (re-queried about every 30 min after that)
???            spakernakurs.com                  20:12:16  → 104.168.53.18
```

**Reading the result:**

- `skigimeetroc`, `askamoshopsi`, `skansnekssky`, `spakernakurs` — there are 4 **.com names that look like random words no person would choose**. The same PC (10.4.19.136) looked up all four.
- `firebasestorage.googleapis.com` is a **normal Google service**. But attackers often abuse it to host files for free. Do not delete it from your list just because the name is normal — remember the time (15:31).
- `askamoshopsi` and `spakernakurs` resolve to the **same IP** (104.168.53.18). Different names, same server.
- Odd names cluster in a short window, **15:31 → 15:35 → 15:36**. That is a strong clue to the infection time.

Check straight away whether any other PC looked these names up.

```text
host.dns == [skigimeetroc.com, askamoshopsi.com, skansnekssky.com, spakernakurs.com]
```

| Piece | Meaning |
|---|---|
| `host.dns == [a, b, c, d]` | Sessions that looked up **any** of these four names |

**Actual result:** Every session has `ip.src` **10.4.19.136**. → **The infected PC is 10.4.19.136 (DESKTOP-SFF9LJF).** Q2, Q3 and Q4 come straight from the table in step 1.

!!! note "10.4.19.138 also has odd names"
    The DNS of 10.4.19.138 shows `nobpc.joansstudio.store` and `dlmfz.joansstudio.store` (both **NXDOMAIN**, names that do not exist) at 17:12–17:15 and `cotecsecuritygroup.com` at 17:17. These are completely different from 10.4.19.136's names. We look at them separately in [step 11](#second-host). 10.4.19.143 only looked up internal names.

---

## Step 3 — Finding the user account (Q5) { #user }

**Goal:** Find the user account logged on to 10.4.19.136.

### Kerberos

```text
ip.src == 10.4.19.136 && protocols == krb5
```

**Actual result:**

```text
Time      19:30:50 – 19:34:48 (12 sessions)
cname     csilva   desktop-sff9ljf$
Realm     BOOGIENIGHTS.LIVE
sname     krbtgt/BOOGIENIGHTS.LIVE ...
```

**Reading the result:**

- **`csilva`, without a `$`, is the user account**. That is the answer to Q5.
- But Kerberos only appears **at 19:30**. The capture started **after** the user logged on (the same reason there is no DHCP). The Kerberos at 19:30 looks like a ticket renewal or a shared-drive connection (at the same time there is an SMB connection to `\\WIN-GP4JHCK2JMV\For_Shared_Drive`). Remember that **in a long PCAP, Kerberos may not be at the start**.

### Full name from LDAP

```text
ip.src == 10.4.19.136 && ip.dst == 10.4.19.19 && port.dst == 389
```

| Piece | Meaning |
|---|---|
| `ip.dst == 10.4.19.19` | Connections to the DC |
| `port.dst == 389` | LDAP |

Open the 19:34:48 session in the list and view it as **ASCII**. There is a line like this.

```text
CN=Cornelius Silva,CN=Users,DC=boogienights,DC=live
```

!!! tip "Use Hunt when you do not know where it is"
    **Hunt** in Arkime's top menu searches packet contents for a string. Narrow the target with `ip.src == 10.4.19.136 && port.dst == 389` in the search bar, then hunt for the ASCII string `CN=Users`; only the sessions that contain user DNs are left. You can search the results again with the `huntId` tag.

- User **csilva = Cornelius Silva**. This value is confirmed **once more** in [step 6](#gzip-loader) by the cookie the malware sent.

---

## Step 4 — Cleartext HTTP: the first malicious request and the redirect (Q1) { #http }

**Goal:** Look at all of 10.4.19.136's cleartext HTTP, filter out normal Windows traffic and read the requests that are left.

**Query:**

```text
ip.src == 10.4.19.136 && protocols == http
```

SPI View → **http** → `host.http` → **Load All**.

**Actual result (`host.http`, request count):**

```text
msedge.b.tlu.dl.delivery.mp.microsoft.com (37)   ctldl.windowsupdate.com (8)   go.microsoft.com (5)
dmd.metaservices.microsoft.com (5)   acroipm2.adobe.com (2)   adl.windows.com (1)   ocsp.digicert.com (1)
www.ssl.com (1)   80.77.25.175 (1)   skigimeetroc.com (1)
```

Microsoft updates, certificate checks (OCSP, CTL) and Adobe are normal. Three are left: **`80.77.25.175`, a bare IP address**, `www.ssl.com` and `skigimeetroc.com`. Start with the first in time order.

```text
host.http == 80.77.25.175
```

**Actual result (session detail → request and response):**

```text
15:31:07  10.4.19.136:51112 → 80.77.25.175:80

GET /main.php HTTP/1.1
Host: 80.77.25.175
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
            Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.48
Cookie: _subid=17dk1e9d14f; 34ab8=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1wic3RyZWFtc1wiOntcIjIzOFwiOjE2ODE5MTc2NDF9LFwiY2FtcGFpZ25zXCI6e1wiNTBcIjoxNjgxOTE3NjQxfSxcInRpbWVcIjoxNjgxOTE3NjQxfSJ9.9LQVO7Pp3-oH0HEmBnzaa7p8B8jot16pqisEvgs-bII

HTTP/1.1 302 Moved Temporarily
Server: nginx
Set-Cookie: PHPSESSID=ocno7kgfbvjnu3lho0d6pftkge; path=/
Set-Cookie: 34ab8=eyJ0eXAi...(new JWT); expires=Thu, 20-Apr-2023 15:31:10 GMT
Set-Cookie: _subid=17dk1e9d14g; expires=Thu, 20-Apr-2023 15:31:10 GMT
Location: https://firebasestorage.googleapis.com/v0/b/serene-cathode-377701.appspot.com/o/XSjwp6O0pq%2FScan_Inv.zip?alt=media&token=a716bdce-1373-44ed-ae89-fdabafa31c61
```

### Reading the cookie with CyberChef

The value after `34ab8=` is three chunks separated by dots (`.`) — a **JWT** (JSON Web Token). Put the first two chunks into CyberChef.

| Recipe | Settings |
|---|---|
| **JWT Decode** | Default (paste the whole JWT and the JSON comes out) |
| or **From Base64** | Alphabet `URL safe (A-Za-z0-9-_)`. One chunk at a time |

**Result:**

```text
{"typ":"JWT","alg":"HS256"}
{"data":"{\"streams\":{\"238\":1681917641},\"campaigns\":{\"50\":1681917641},\"time\":1681917641}"}
```

`1681917641` is UNIX time. CyberChef **From UNIX Timestamp** (Units: Seconds) → `Wed 19 April 2023 15:20:41 UTC`.

**Reading the result:**

- **15:31:07 is the first malicious request visible in this PCAP**. The answer to Q1 is **2023-04-19 15:31 UTC**.
- **The address is an IP, not a domain**, and there is no DNS lookup. The user clicked a link that was an IP from the start. The User-Agent is a real **Edge 112**, so a person opened it in a browser (whether the link came from an email cannot be told from the PCAP).
- The response has no content, only **302 (go elsewhere)**, and it sends the browser to **`Scan_Inv.zip` on Firebase Storage**. A server that "picks visitors and sends them on to the next place" like this is called a **TDS (Traffic Distribution System)**. `_subid` and the `streams` / `campaigns` in the JWT look like the values a TDS uses to count "which campaign this visitor came from" (inferred).
- An interesting point: the browser **already had** this cookie when it made the request, and the time inside the cookie is **15:20:41**. That is before the capture started (15:26:28). It suggests **this PC had visited this server 10 minutes earlier** (inferred). The first malicious traffic visible in the PCAP is still 15:31, so the report uses 15:31 and keeps this as a note.
- The file name `Scan_Inv` (scanned invoice) is a common name when disguising as business email.

!!! note "Why Firebase?"
    `firebasestorage.googleapis.com` is a normal domain with a Google certificate, so it is rarely on block lists and passes reputation checks easily. Attackers **parking files on normal cloud services** is very common. So **"who sent the browser to that address (the source of the 302)"** matters more than "the domain is normal".

---

## Step 5 — HTTPS download: Scan_Inv.zip from Firebase { #firebase }

**Goal:** Check what, and how much, was actually downloaded from Firebase after the 302.

**Query:**

```text
ip.src == 10.4.19.136 && host.http == firebasestorage.googleapis.com
```

| Piece | Meaning |
|---|---|
| `host.http` | The HTTP Host header, and **the HTTPS server name (SNI)** also goes in this field |

**Actual result:**

```text
15:31:14  10.4.19.136 → 142.251.32.234:443   tls   SNI firebasestorage.googleapis.com
          Src databytes 1,524   Dst databytes 273,619       ← download
15:31:14  10.4.19.136 → 142.251.32.234:443   tls   SNI firebasestorage.googleapis.com
          Src databytes 591     Dst databytes 5,848
```

**Reading the result:**

- **7 seconds** after the 302, the PC downloaded **about 273 KB** over HTTPS. It is encrypted so we cannot see the content, but the size matches the `Scan_Inv.zip` Unit 42 reported (262,343 bytes) plus TLS overhead.
- According to Unit 42 this zip is **password-protected (1235)** and contains **`Scan_Inv.exe` (the IcedID installer)**. A password-protected archive is a common way to get past antivirus scanning at the mail gateway.

### The next 4 minutes — time for the user to unzip and run it

The next odd connection (skigimeetroc.com) is at **15:35:39**. In between, at 15:34:33, there is this request.

```text
15:34:33  GET http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt
          User-Agent: Microsoft-CryptoAPI/10.0      → 200, application/pkix-cert, 1,519 bytes
```

- `Microsoft-CryptoAPI` is the User-Agent **Windows uses when it checks certificates**. The OS sent this request, not a person.
- If an executable is **signed with a code-signing certificate issued by SSL.com**, Windows fetches the root certificate while it checks the signature before running it. The timing fits the moment the user ran `Scan_Inv.exe`. But this is **inferred**. To confirm it, check the file's signature on the host.
- So the flow is **15:31 download → about 3–4 minutes to unzip and run → 15:35 first malware traffic**.

---

## Step 6 — The gzip loader: PC details in the cookie { #gzip-loader }

**Goal:** Read the first request the installer sent. At this point IcedID **hides details about the PC in cookies**.

**Query:**

```text
host.http == skigimeetroc.com
```

**Actual result:**

```text
15:35:39  10.4.19.136:51136 → 192.153.57.233:80   Src databytes 295   Dst databytes 520,954

GET / HTTP/1.1
Connection: Keep-Alive
Cookie: __gads=422998217:1:1808:131; _gid=A0CA96894E9D; _u=4445534B544F502D534646394C4A46:6373696C7661:46353431423635424230383346354633; __io=21_1181811818_1193560798_2439418475; _ga=1.591597.1635208534.1022; _gat=10.0.22621.64
Host: skigimeetroc.com

HTTP/1.1 200 OK
Server: nginx
Content-Type: application/gzip
Content-Length: 520803
```

Start of the response body (Destination Raw → CyberChef **To Hex**):

```text
1f 8b 08 08 00 00 00 00 00 00 54 61 69 6c 2e 74 78 74 00 ...
                              T  a  i  l  .  t  x  t
```

**Query explained — what is odd:**

| Clue | Why it is odd |
|---|---|
| **No User-Agent** | Browsers always send a User-Agent. Without one, **a program built the request itself** |
| Cookie names `__gads`, `_ga`, `_gat`, `_gid` | They imitate Google ad and analytics cookie names. But **it is a first visit and there are already cookies**, and the values look nothing like Google's |
| 520 KB of `application/gzip` for `GET /` | It asked for the home page and got a compressed file |
| File name `Tail.txt` inside the gzip | The name field of the gzip header (`1f 8b 08 08`). It pretends to be text but is 520 KB |

### Decoding the cookie with CyberChef

Split the `_u` value at the colons (`:`) and put each part into **From Hex**.

```text
4445534B544F502D534646394C4A46     → DESKTOP-SFF9LJF
6373696C7661                       → csilva
46353431423635424230383346354633   → F541B65BB083F5F3
```

Read the other values against the meanings described in published IcedID analyses.

| Cookie | Value | Meaning (per public analyses) |
|---|---|---|
| `_u` | the hex above | **computer name : user name : identifier** |
| `_gat` | `10.0.22621.64` | Windows version 10.0, **build 22621** (Windows 11 22H2), 64-bit |
| `__io` | `21_1181811818_1193560798_2439418475` | Parts of the **domain SID** → `S-1-5-21-1181811818-1193560798-2439418475` |
| `__gads` | `422998217:1:1808:131` | Campaign ID, flag, a time value, number of running processes |
| `_ga` | `1.591597.1635208534.1022` | CPU information (CPUID) |
| `_gid` | `A0CA96894E9D` | Value built from the network card address |

**Reading the result:**

- `_u` shows **DESKTOP-SFF9LJF and csilva** as they are. The malware itself **confirmed the answers** from steps 1 and 3. We now have three sources (Kerberos, NetBIOS, cookie).
- This request is IcedID's **gzip loader (GZIPLOADER)** stage. According to public analyses, this "fake gzip" holds the encrypted IcedID core and a configuration file (`license.dat`), which the installer unpacks to create the **persistent malware**.
- **Even if you Gunzip it in CyberChef**, what you see inside is encrypted data, so no readable text comes out. For network analysis it is enough to write "**a large file pretending to be gzip, fetched by a request with no User-Agent**".
- The download runs 15:35:39–15:36:41 (about a minute), and as soon as it ends the HTTPS C2 starts at **15:36:41** (next step).

!!! tip "Arkime cookie fields"
    Arkime stores cookie names and values separately (`http.cookie.key`, `http.cookie.value` — the names can differ between versions, so check in SPI View). With them you can use `http.cookie.key == __gads && http.cookie.key == _gat` to find **IcedID requests of the same shape in other PCAPs**. The values change per PC, but the **combination of cookie names** stays the same, which makes it a good behaviour clue.

---

## Step 7 — HTTPS C2: self-signed certificates { #https-c2 }

**Goal:** Look at the TLS sessions to the C2 domains found in step 2. The content is encrypted, so we judge by **certificate, size, time and JA3**.

**Query:**

```text
ip.src == 10.4.19.136 && host.http == [askamoshopsi.com, skansnekssky.com, spakernakurs.com]
```

SPI View → **tls** and **cert** sections → **Load All**.

**Actual result:**

```text
askamoshopsi.com  104.168.53.18:443    3 sessions  15:36:41 – 15:37:50
                  databytes (src / dst)  1,286 / 2,217    1,733 / 1,764    472 / 1,907,262   ← 1.9 MB down
skansnekssky.com  217.199.121.56:443  69 sessions  15:36:44 – 21:17:46
spakernakurs.com  104.168.53.18:443    1 session   20:12:16 – 21:22:21   3,603 / 4,094

cert (same format on all 3 servers):
  Subject   CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
  Issuer    CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
  Valid     2023-04-11 → 2024-04-10   (askamoshopsi/spakernakurs 12:36:03, skansnekssky 13:09:00)
  SAN       (none)
tags      cert:self-signed
TLS       TLSv1.2, cipher 0xc030 (ECDHE_RSA_WITH_AES_256_GCM_SHA384)
```

**Reading the result:**

- **Subject and Issuer are identical** → a **self-signed certificate** the server issued to itself (the method is the same as the [certificate explanation in the Trickbot case](arkime-only-credential-theft-tls-c2.md)). Arkime also adds the `cert:self-signed` tag.
- `Internet Widgits Pty Ltd`, `Some-State` and `AU` are **the default values OpenSSL fills in when you create a certificate and just press Enter without changing anything**. A real company website would not use a certificate like this. And because the CN is `localhost`, it **does not match the name the PC connected to (SNI)** either.
- The three servers' certificates were created **on the same day (04-11), about half an hour apart**. That looks like infrastructure the same operator prepared in one go.
- At 15:36:42 the PC downloaded **1.9 MB** from `askamoshopsi.com`. The content is encrypted, but a large download right after the C2 connection is inferred to be an **additional module**.
- `skansnekssky.com` is contacted **69 times**. The next step measures the interval.
- `spakernakurs.com` first appears **4.5 hours after the infection** and stays connected for over an hour. Same IP (104.168.53.18) but a **different JA3** (below). And **36 minutes** after this session starts, BackConnect (step 9) opens.

```text
cert.issuer.on == "Internet Widgits Pty Ltd"
```

| Piece | Meaning |
|---|---|
| `cert.issuer.on` | Organisation name (O) of the certificate issuer |
| `"..."` | Values with spaces go in quotes |

This one query finds **every server using an OpenSSL default certificate**. In this PCAP only the three servers above appear. It is a "behaviour" query you can reuse in other PCAPs straight away.

### What about JA3? { #ja3 }

Let us check again, with this PCAP, the claim from the Trickbot discussion that "more JA3 values after infection is evidence of infection".

```text
ip.src == 10.4.19.136 && protocols == tls
```

SPI View → **tls** → `tls.ja3` → **Load All**.

**Actual result (summary):**

```text
Distinct JA3 values on 10.4.19.136: 61
  JA3 seen before 15:31:07 (before infection, about 5 minutes): 5
  JA3 first seen after 15:31:07: 56
    - 54 of them: www.msn.com, assets.msn.com, api.msn.com, ecn.dev.virtualearth.net, edge.microsoft.com,
                  th.bing.com ...  (almost all used only once)
    - 3c293bdf2a25c07559b560ba86debc77 (77 times): askamoshopsi.com 3 + skansnekssky.com 69
                                                  + self.events.data.microsoft.com 5  ← Windows telemetry
    - 6a5d235ee78c6aede6a61448b4e9ff1e (once):     spakernakurs.com (20:12:16)

10.4.19.138: 3c293bdf... 0 times
```

**Reading the result:**

- **56 new JA3 values appeared after the infection, but 54 of them are normal Edge traffic**. Recent Chrome/Edge (110 and later) **shuffle the order of TLS extensions randomly** on every connection. JA3 includes that order in its hash, so **the same browser gets a different JA3 on each connection.** That is why "the number of JA3 values went up" cannot, on its own, be evidence of infection. **JA4** fixes this (it sorts the extensions before hashing). Recent Arkime versions have a `tls.ja4` field.
- **IcedID's C2 JA3 (`3c293bdf…`) is the same value as Windows' own telemetry (`self.events.data.microsoft.com`)**. IcedID uses the built-in Windows networking (WinHTTP/Schannel). It is exactly the same lesson as the RedLine case. **If you put "this bad JA3" on a block list, you block normal Windows traffic too.**
- On the other hand, **`6a5d235e…` (spakernakurs.com) is a new JA3 that appeared exactly once on this PC, just before the follow-up activity**. This is a case where the instructor's "new JA3 after infection" **actually meant something**. But even here it was not JA3 alone: it meant something because **a never-seen domain + a self-signed certificate + a long session + BackConnect right after** all came together.
- Conclusion: read JA3 **within the same PC, together with the destination (SNI) and certificate**. Just as 10.4.19.138 never shows `3c293bdf…`, the same Windows can produce different JA3 values on different PCs (build, settings), so be careful comparing directly with other PCs too.

---

## Step 8 — Measuring the beacon interval { #beacon }

**Goal:** Check whether the 69 connections to `skansnekssky.com` are **a program's regular check-ins (a beacon)** rather than a person.

**Query:**

```text
ip.dst == 217.199.121.56
```

In Sessions, sort by **Start Time ascending** and add the **Src Databytes / Dst Databytes** columns (column header menu → add field). In the **SPI Graph** tab, choosing `ip.dst` also shows it as a time graph.

**Actual result (excerpt):**

```text
Start      Src DB  Dst DB
15:36:44   4,717   2,324    ← first contact (registration): large
15:41:42     581   1,707
15:46:45     581   1,707
15:51:47     581   1,707
15:56:49     581   1,707
16:01:50     581   1,707
 ...         (every 5 minutes)
17:52:51     585   1,707
 ...
19:28:30     585   1,707
19:32:00   1,100   1,707    ← one gap of 3 min 30 s, slightly more sent
19:37:02     585   1,707
 ...
21:17:46     585   1,707    ← last (capture ends 21:22:36)

69 sessions, start-to-start interval: median 302 s, min 210 s, max 307 s
```

**Reading the result:**

- It connects **almost exactly every 5 minutes (about 300 seconds plus a few)**, nonstop for 6 hours. People do not use websites like this. It is a typical **beacon**.
- The sizes are almost **identical every time** (sent 581–585, received 1,707). It looks like "any new commands?" → "no", over and over. **Only the first contact being large** (4,717 bytes) is also a common beacon trait, because it registers the PC's details first.
- It opens a new TLS connection every time and closes it quickly: a **"short and frequent" beacon**. This is different from the "holds on for minutes" type in the Trickbot case (see [two kinds of beacon](arkime-only-credential-theft-tls-c2.md)).
- DNS is not looked up every time, only **about every 30 minutes** (17:07, 17:52, 18:23, 18:53 …). Because of the DNS cache, counting DNS lookups misses beacons. **Count sessions.**

!!! tip "A general way to find beacons quickly"
    1. Collect TLS with `ip.src == <PC> && protocols == tls` and look at the **session count** per `ip.dst` in SPI View. An IP that is not a normal service but appears dozens of times is a candidate.
    2. Search for the candidate IP and check whether the Start Time interval and Databytes are **regular**.
    3. Regular interval + regular size + self-signed certificate → almost certainly C2.

---

## Step 9 — Port 443 that is not TLS: finding the follow-up activity (Q6) { #non-tls-443 }

**Goal:** Find Q6, the "follow-up activity". After infection IcedID often pulls down extras such as **BackConnect** (remote control), **VNC** or **Cobalt Strike**. From April 2023 BackConnect used **port 443 but not TLS**. So we look for "sessions on 443 that are not TLS".

**Query:**

```text
ip.src == 10.4.19.136 && port.dst == 443 && protocols != tls
```

| Piece | Meaning |
|---|---|
| `port.dst == 443` | Connections to the HTTPS port |
| `protocols != tls` | Sessions Arkime **did not recognise as TLS**. On 443, not being TLS is odd |

**Actual result:**

```text
20:48:00 – 21:22:36  10.4.19.136:51534 → 193.149.176.100:443   pkts 74/73   databytes 827 / 629
20:49:11 – 20:49:22  10.4.19.136:51535 → 193.149.176.100:443   pkts 19/21   databytes 727 / 41
20:49:33 – 20:49:46  10.4.19.136:51537 → 193.149.176.100:443   pkts 12/15   databytes 770 / 26
15:27:07 – 20:59:30  10.4.19.136:49769 → 40.83.247.108:443      (Microsoft, explained below)
15:36:58             10.4.19.136:50171 → 20.25.241.18:443       (Microsoft, explained below)
```

**Reading the result:**

- There are **three sessions to 193.149.176.100**. This IP has **no DNS lookup** (the IP is built into the program). The first session opens at 20:48:00 and two more open about a minute later.
- The two Microsoft sessions start with `17 03 03` in Source Raw. That is a **TLS "application data" record**. The connection was set up before the capture, or the handshake (`16 03 …`) was not captured, so Arkime could not label it TLS — but it is real TLS. You can **tell them apart by the first bytes** like this.
- The 193.149.176.100 sessions start with something like `f8 7f 92 46 …` in Source Raw, which **does not look like TLS (`16 03`, `17 03`) at all.** It uses 443 but runs **its own protocol**, not TLS.

| First bytes | Meaning |
|---|---|
| `16 03 0x` | Start of a TLS handshake (first packet of normal HTTPS) |
| `17 03 03` | TLS data (HTTPS captured mid-stream) |
| Anything else | Not TLS → another protocol borrowing port 443 |

---

## Step 10 — Reading BackConnect: the commands the attacker typed { #backconnect }

**Goal:** Read what passed in each of the three sessions. In BackConnect only the start is binary; the commands and output after it are **cleartext** and can be read as they are.

**Query:**

```text
ip.dst == 193.149.176.100
```

Open the three sessions one at a time and view them as **ASCII**. Direction is shown by colour (red = PC → server, blue = server → PC). If they are long, download **Source Raw / Destination Raw** and look at them with CyberChef **Strings**.

### Session 1 (port 51534) — control channel

```text
20:48:00  PC → server  249 bytes (binary, registration)
20:48:00  server → PC   17 bytes
20:49:00  PC → server   17 bytes      ← from here, 17 bytes each way exactly every 60 seconds
20:49:11  server → PC   17 bytes      ← session 2 opens at this exact moment
20:49:33  server → PC   17 bytes      ← session 3 opens at this exact moment
 ...
21:22:36  (1-minute interval kept until the end of the capture)
```

- **17 bytes every minute** is an "are you alive?" signal (keep-alive). It **keeps the connection open** so the attacker can give commands immediately whenever they want.
- New sessions open **in the very second** the server sends 17 bytes. It looks like the control channel ordered "open a shell", "open the file manager".

### Session 2 (port 51535) — remote shell

```text
20:49:11  PC → server  249 bytes (binary header)
20:49:12  PC → server  Active code page: 65001
                       c:\>
20:49:17  server → PC  net group "Domain Computers" /domain
20:49:17  PC → server  The request will be processed at a domain controller for domain boogienights.live.

                       Group name     Domain Computers
                       Comment        All workstations and servers joined to the domain

                       Members
                       -------------------------------------------------------------------------------
                       DESKTOP-JAL4D68$         DESKTOP-RETP4BU$         DESKTOP-SFF9LJF$
                       The command completed successfully.
                       c:\>
```

- `Active code page: 65001` and `c:\>` are the text the **Windows command prompt (cmd.exe)** shows when it starts. The PC **handed a shell to the attacker** (reverse shell).
- The command the attacker typed: **`net group "Domain Computers" /domain`** — "show me the list of computers joined to this domain". As a result, **all 3 names** went to the attacker. This is **reconnaissance** to pick the next target.
- At the same time (20:49:17) there is an **SMB session** from 10.4.19.136 → DC (10.4.19.19:445) (sent 10,200 / received 7,165 bytes). That traffic is created when `net group … /domain` asks the DC. **The command and the network trace line up exactly in time.**
- Because a person typed it, there are a few seconds between steps (20:49:12 prompt → 20:49:17 command). This is called **hands-on-keyboard** (the attacker operating directly).

### Session 3 (port 51537) — file manager

```text
20:49:34  server → PC  DISK
20:49:34  PC → server  C:\|548934774784|512594530304|3|
                       Z:\|257024847872|237367189504|4|
20:49:37  server → PC  CDDIR Z:\
20:49:37  PC → server  Z:\|||  ..||1620461211|22
20:49:41  server → PC  CDDIR C:\
20:49:41  PC → server  C:\|||  $Recycle.Bin||1651901090|22  Documents and Settings||1681839040|9238
                       DumpStack.log.tmp|12288|1681838906|38  pagefile.sys|3087007744|1681838906|38
                       PerfLogs||1651901090|16  Program Files||1651901090|17  Program Files (x86)||...
                       ProgramData||...  Recovery||...  swapfile.sys|16777216|...  System Volume Information||...  Users||...
```

**Query explained — how to read the format:** each line is `name|size|time|attributes`.

| Value | Meaning |
|---|---|
| `DISK` | "give me the drive list" |
| <code>C:\&#124;548934774784&#124;512594530304&#124;3&#124;</code> | Drive C:, about 549 GB total, about 513 GB free, type **3 = fixed disk** |
| <code>Z:\&#124;…&#124;4&#124;</code> | Drive Z:, type **4 = network drive** (looks like the `For_Shared_Drive` share from step 3) |
| `CDDIR C:\` | "give me the contents of C:\" |
| `1681839040` | UNIX time (CyberChef From UNIX Timestamp → 2023-04-18 17:30:40 UTC) |

**Reading the result:**

- The attacker looked around in the order **drive list → Z:\\ → C:\\**. They **did not upload or download files** yet (the session ends at 20:49:46 and only a few hundred bytes moved).
- Answer to Q6: **there was follow-up malicious activity, and it was IcedID BackConnect**. The attacker used a remote shell to list the domain computers and a file manager to look at the drives and folders.
- This PCAP has **no trace of Cobalt Strike or VNC** (Unit 42 reached the same conclusion). But listing the domain computers is a sign the attacker is **about to move to the next stage (lateral movement, ransomware preparation)**. In a real incident, isolate the PC right at this point.

---

## Step 11 — Scope check and the second PC { #scope }

**Goal:** Check (1) whether other PCs contacted the same IOCs, (2) whether 10.4.19.136 tried to spread to other PCs, and (3) what 10.4.19.138, flagged in step 2, did.

### Other PCs contacting the IOCs

```text
ip.dst == [80.77.25.175, 142.251.32.234, 192.153.57.233, 104.168.53.18, 217.199.121.56, 193.149.176.100] && ip.src != 10.4.19.136
```

**Actual result:** `0 sessions`. 10.4.19.143 has **no outbound sessions at all.**

### Lateral movement

```text
ip.src == 10.4.19.136 && ip.dst == 10.4.19.0/24 && ip.dst != 10.4.19.19
```

| Piece | Meaning |
|---|---|
| `ip.dst == 10.4.19.0/24` | Connections into the internal network |
| `ip.dst != 10.4.19.19` | Excluding the DC |

**Actual result:** apart from broadcast and multicast, **0**. 10.4.19.136 never went to the other clients (.138, .143) over SMB, RDP or RPC.

- There is SMB to the DC (`IPC$`, `SYSVOL`) **about every 15 minutes**, which is Windows checking Group Policy — **normal behaviour**. Because the timing is regular it can look like a beacon, so do not be confused. If the destination is the **DC** and the share names are `IPC$` / `SYSVOL`, it is normal.

### The second PC: 10.4.19.138 { #second-host }

Follow `cotecsecuritygroup.com` from step 2.

```text
ip.src == 10.4.19.138 && host.http == cotecsecuritygroup.com
```

**Actual result:**

```text
17:17:10  10.4.19.138 → 66.29.147.117:80
GET /wicd/643d0491bcea1.zip HTTP/1.1
Host: cotecsecuritygroup.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/112.0.1722.48

HTTP/1.1 200 OK
Server: Apache
Content-Disposition: attachment; filename="643d0491bcea1.zip"
Content-Encoding: gzip
Content-Length: 5673
Content-Type: application/zip
```

Download the response body as Destination Raw, then CyberChef **Gunzip** → **Unzip** (look at the file list only, never run anything):

```text
Complaint_Copy_634917.wsf    16,173 bytes   (2023-04-19 15:16:56)
```

And 28 seconds later:

```text
ip.src == 10.4.19.138 && ip.dst == 85.239.53.73
```

```text
17:17:38 – 17:18:53  10.4.19.138:49773 → 85.239.53.73:80   SYN ×5, RST ×1, data 0   (no DNS lookup)
```

**Reading the result:**

- The user of 10.4.19.138 used Edge to download a file shaped like **`/folder/hex.zip`**, and inside is a **`.wsf` (Windows Script File)**. A document-like name (`Complaint_Copy`) with a script extension is a typical lure. The `*.joansstudio.store` names looked up just before (17:12–17:15) **did not exist (NXDOMAIN)**.
- This shape (**a .wsf inside a zip with a hex name**) matches the **Qakbot distribution reported on this very day (2023-04-19).** The family is **inferred**, though.
- 28 seconds later the PC **tried 5 times to connect directly to an IP** (no DNS), 85.239.53.73:80, and **failed** (no data, RST). It is **possible** that the script ran and failed to fetch its next stage (inferred — the network alone cannot confirm the script ran).
- After that there is no suspicious traffic from 10.4.19.138. So it fits the quiz's statement that **"one PC (10.4.19.136) was infected"**. But in real work you should record it not as "clean" but as **"further analysis required"** and request a host check. That is why the report ends this line with **Further Analysis Required**.

---

## Overall conclusion { #conclusion }

```text
15:20:41  (cookie time) earlier visit to the TDS — before the capture starts
15:31:07  user opens hxxp://80.77.25.175/main.php in Edge → 302 to Firebase Storage
15:31:14  Scan_Inv.zip downloaded over HTTPS (~273 KB)
15:34:33  Windows fetches SSL.com root certificate (user likely runs Scan_Inv.exe)
15:35:39  installer → skigimeetroc.com, cookie with host/user/SID → fake gzip 520 KB
15:36:41  HTTPS C2 starts: askamoshopsi.com (+1.9 MB), skansnekssky.com every 5 min
20:12:16  new C2 session spakernakurs.com, new JA3
20:48:00  BackConnect to 193.149.176.100:443 (not TLS)
20:49:17  operator runs net group "Domain Computers" /domain
20:49:34  operator lists drives and C:\
21:22:36  capture ends — beacon and BackConnect still alive
```

## Timeline { #timeline }

| UTC (2023-04-19) | Event |
|---|---|
| 15:20:41 | (time inside the cookie) inferred first TDS visit, before the capture |
| 15:26:28 | Capture starts |
| 15:31:07 | DESKTOP-SFF9LJF (10.4.19.136) Edge → `hxxp://80.77.25[.]175/main.php` → 302 |
| 15:31:14 | HTTPS download of `Scan_Inv.zip` from Firebase Storage (273,619 B) |
| 15:34:33 | `Microsoft-CryptoAPI` → `www.ssl.com` root certificate (inferred executable signature check) |
| 15:35:39 | `skigimeetroc[.]com` GET / (no User-Agent, IcedID cookies) → `application/gzip` 520,803 B |
| 15:36:41–15:37:50 | `askamoshopsi[.]com` 104.168.53.18 HTTPS ×3, 1.9 MB download |
| 15:36:44 | First beacon to `skansnekssky[.]com` 217.199.121.56 (4,717 B) |
| 15:41 ~ 21:17 | Beacon every 5 minutes (69 times) |
| 17:17:10 | (other PC) DESKTOP-RETP4BU (10.4.19.138) downloads `643d0491bcea1.zip` (.wsf) |
| 17:17:38 | (other PC) failed connection to 85.239.53.73:80 |
| 20:12:16 | New session to `spakernakurs[.]com` 104.168.53.18, new JA3 |
| 20:48:00 | BackConnect control channel 193.149.176.100:443 |
| 20:49:11 | BackConnect remote shell |
| 20:49:17 | `net group "Domain Computers" /domain` (+ SMB to the DC) |
| 20:49:33 | BackConnect file manager: `DISK`, `CDDIR Z:\`, `CDDIR C:\` |
| 21:22:36 | Capture ends (beacon and control channel still alive) |

## Indicators of compromise (IOC) { #iocs }

| Type | Indicator | Role |
|---|---|---|
| URL | `hxxp://80.77.25[.]175/main.php` | TDS redirect |
| URL | `hxxps://firebasestorage.googleapis[.]com/v0/b/serene-cathode-377701.appspot.com/o/XSjwp6O0pq%2FScan_Inv.zip?alt=media&token=a716bdce-1373-44ed-ae89-fdabafa31c61` | `Scan_Inv.zip` (abused legitimate service) |
| Domain / IP | `skigimeetroc[.]com` / `192.153.57[.]233` | gzip loader |
| Domain / IP | `askamoshopsi[.]com`, `spakernakurs[.]com` / `104.168.53[.]18` | HTTPS C2 |
| Domain / IP | `skansnekssky[.]com` / `217.199.121[.]56` | HTTPS C2 beacon |
| IP:port | `193.149.176[.]100:443` (not TLS) | BackConnect |
| Certificate | `CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU` (self-signed, issued 2023-04-11) | Shared by all 3 C2 servers |
| Cookie names | `__gads`, `_gid`, `_u`, `__io`, `_ga`, `_gat` (request with no User-Agent) | IcedID installer |
| JA3 | `3c293bdf2a25c07559b560ba86debc77` (same as Windows default — not for blocking), `6a5d235ee78c6aede6a61448b4e9ff1e` | Reference only |
| SHA256 (Unit 42) | `fc96c893a462660e2342febab2ad125ce1ec9a90fdf7473040b3aeb814ba7901` | `Scan_Inv.zip` (262,343 B, password 1235) |
| SHA256 (Unit 42) | `bd24b6344dcde0c84726e620818cb5795c472d9def04b259bf9bff1538e5a759` | `Scan_Inv.exe` (333,408 B, IcedID installer) |
| (other PC) URL / IP | `hxxp://cotecsecuritygroup[.]com/wicd/643d0491bcea1.zip` / `66.29.147[.]117`, `85.239.53[.]73:80` | zip/.wsf lure (inferred Qakbot-style) |

The two hashes cannot be calculated from the PCAP (HTTPS download), so they are taken from the Unit 42 write-up.

!!! warning "IP typos in the official write-up"
    The IOC list in the Unit 42 write-up gives the gzip loader as `192.153.57[.]223` and the TDS as `80.77.24[.]175`, but the PCAP's DNS answers and sessions show **192.153.57.233** and **80.77.25.175**. **Always re-check IOCs against the original data.**

## ATT&CK mapping { #attack }

| Technique | Evidence |
|---|---|
| T1566.002 Phishing: Spearphishing Link (inferred) | A link made of an IP opened in the browser. The link's source is not in the PCAP |
| T1608.001 / T1105 Ingress Tool Transfer | `Scan_Inv.zip` hosted on Firebase Storage, gzip loader |
| T1027.002 / T1027 Obfuscated Files | Password-protected zip, encrypted payload disguised as gzip |
| T1204.002 User Execution: Malicious File | User ran `Scan_Inv.exe` (Unit 42) |
| T1082 System Information Discovery, T1033 System Owner/User Discovery | OS build, CPU, host, user and SID in the cookies |
| T1071.001 Web Protocols, T1573 Encrypted Channel | Self-signed HTTPS C2, 5-minute beacon |
| T1095 Non-Application Layer Protocol | BackConnect: its own non-TLS protocol on 443 |
| T1059.003 Windows Command Shell | BackConnect remote shell |
| T1018 Remote System Discovery, T1069.002 Domain Groups | `net group "Domain Computers" /domain` |
| T1083 File and Directory Discovery | `DISK`, `CDDIR` |

## Compared with the two earlier cases { #compare }

| | [Trickbot (2020)](arkime-only-credential-theft-tls-c2.md) | [RedLine (2023)](redline-stealer-powershell-nettcp-c2.md) | IcedID (2023) |
|---|---|---|---|
| Capture length | About 44 minutes | 36 seconds | **About 6 hours** |
| Start | Script downloads an EXE | `.ps1` run | **IP link → TDS 302 → Firebase zip** |
| Payload disguise | EXE named `.png` | EXE named `.jpg` | **Disguised as `application/gzip` + password zip** |
| First check-in | Hostname and bot ID in the URI | `status=start&av=` in the URI | **Host, user and SID in hex in cookies** |
| C2 | HTTP POST + self-signed TLS (447/449) | net.tcp, port 12432, cleartext | **Self-signed HTTPS (443), 5-minute beacon** |
| Certificate | Self-signed `example.com` | Let's Encrypt (legitimate) | **Self-signed `localhost` / Internet Widgits** |
| Beacon | Holds on for a long time | None (one upload) | **Short and frequent (5 min)** |
| Follow-up | Recon + SMB lateral movement attempt | None | **BackConnect: remote shell, file manager** |
| JA3 | — | No new JA3 (same as Windows) | C2 JA3 = Windows, **one new JA3 just before follow-up**, Edge gets a new JA3 every time |
| Key to finding it | Odd ports and URIs | One unknown port | **Odd names in DNS → certificate → interval → 443 that is not TLS** |

Across all three cases, the key clues were **direct IP connections, files whose name and content do not match, self-signed certificates and regular intervals**. IcedID is one step harder because it **hides inside a normal port (443) and a normal service (Firebase)**.

---

## Compared with the official Unit 42 answers { #official-answers }

| Question | This analysis | Unit 42 answer | Match |
|---|---|---|---|
| Infection start | 2023-04-19 15:31 UTC (15:31:07) | 2023-04-19 15:31 UTC | ✓ |
| IP | 10.4.19.136 | 10.4.19[.]136 | ✓ |
| MAC | 14:58:d0:2e:c5:ae | 14:58:d0:2e:c5:ae | ✓ |
| Hostname | DESKTOP-SFF9LJF | DESKTOP-SFF9LJF | ✓ |
| User | csilva (Cornelius Silva) | csilva (Cornelius Silva, LDAP) | ✓ |
| Follow-up | BackConnect (193.149.176.100:443) | BackConnect | ✓ |

**What this page looked at beyond that**: 15:20:41 inside the TDS cookie (inferred visit before the capture), decoding the `_u`, `__io` and `_gat` cookies, the 302-second beacon interval, the role of each of the three BackConnect sessions and the actual commands, the JA3 comparison, and the zip/.wsf download on 10.4.19.138. The last one is outside the quiz, but in real work it must be reported separately.

---

## Copy-ready query sheet { #query-sheet }

Replace the `<…>` parts.

**Identifying PCs (when there is no DHCP)**

```text
protocols == dhcp
```

```text
ip.src == <internal-CIDR> && protocols == krb5
```

```text
ip.src == <internal-CIDR> && port.dst == [137, 138]
```

```text
ip.src == <host-IP> && ip.dst == <DC-IP> && port.dst == 389
```

**Odd names → narrowing down the infected PC**

```text
ip.src == <internal-CIDR> && protocols == dns
```

```text
host.dns == [<domain-1>, <domain-2>, <domain-3>]
```

**Cleartext HTTP**

```text
ip.src == <host-IP> && protocols == http
```

```text
host.http == <IP-or-domain>
```

**HTTPS C2**

```text
ip.src == <host-IP> && host.http == [<domain-1>, <domain-2>]
```

```text
cert.issuer.on == "Internet Widgits Pty Ltd"
```

```text
tags == cert:self-signed && ip.src == <host-IP>
```

```text
ip.src == <host-IP> && protocols == tls
```

**Beacon**

```text
ip.dst == <C2-IP>
```

**Port 443 that is not TLS (things like BackConnect)**

```text
ip.src == <host-IP> && port.dst == 443 && protocols != tls
```

**Scope**

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

**CyberChef recipes used**

| Recipe | Use |
|---|---|
| JWT Decode / From Base64 (URL safe) | TDS cookie `34ab8=` |
| From UNIX Timestamp | Time inside the JWT, times in the file manager listing |
| From Hex | IcedID `_u` cookie → hostname, user |
| To Hex | First bytes of the response (`1f 8b 08 08` gzip), first bytes of a session (`16 03` / `17 03`) |
| Strings | Pulling commands and output out of BackConnect Raw |
| Gunzip → Unzip | **File list only** of the zip the other PC downloaded |
| Defang URL / Defang IP | Writing IOCs in the report |

---

## Lessons { #lessons }

- **Filter long PCAPs.** You cannot scan 6 hours by eye. Remove the normal names (Microsoft, internal) from the DNS list and start with what is left.
- **You can identify PCs without DHCP.** Kerberos computer accounts (`$`), NetBIOS, `mac.src` — and even the details the malware sent itself (cookies).
- **URLs made of an IP, requests with no User-Agent, and requests that carry cookies on a first visit** are all signs of "not a person".
- **Normal services (Firebase) are abused too.** Look at **"who sent the browser there"** (the source of the 302) rather than whether the domain is normal.
- **An OpenSSL default certificate (`Internet Widgits Pty Ltd`) is a strong clue by itself.** You can find it directly with `cert.issuer.on`.
- **Beacons have a regular interval and size.** Count sessions. DNS appears less often because of caching.
- **Not everything on 443 is TLS.** Use `port.dst == 443 && protocols != tls`, and tell them apart by the first bytes (`16 03` / `17 03`).
- **A "change in the number of JA3 values" means almost nothing with modern browsers** (Edge's JA3 changes on every connection). Instead, look for the combination **a JA3 never seen before on the same PC + a never-seen domain + self-signed**. Use JA4 where you can.
- **Line up commands and network traces by time.** `net group … /domain` (20:49:17) and the SMB to the DC (20:49:17) are in the same second.
- **Look beyond the quiz.** Even if the conclusion is "one infected PC", record an odd download on another PC in its own report.

## References { #references }

- [Cold as Ice: Unit 42 Wireshark Quiz for IcedID](https://unit42.paloaltonetworks.com/wireshark-quiz-icedid/) — questions and PCAP location
- [Cold as Ice: Answers to Unit 42 Wireshark Quiz for IcedID](https://unit42.paloaltonetworks.com/wireshark-quiz-icedid-answers/) — official answers, IOCs, hashes
- [IcedID GZIPLOADER Analysis — Binary Defense](https://binarydefense.com/resources/blog/icedid-gziploader-analysis) — the fake gzip stage
- [ICEDID network infrastructure — Elastic Security Labs](https://www.elastic.co/security-labs/icedids-network-infrastructure-is-alive-and-well) — meaning of the cookie values
- [IcedID's updated photoloader — sysopfb](https://sysopfb.github.io/malware,/icedid/2020/04/28/IcedIDs-updated-photoloader.html) — `_u`, `_gat`, `__io`, `_gid` explained
- [2023-04-19 Qakbot activity — malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2023/04/19/index.html) — zip/.wsf distribution on the same day
- [malware-traffic-analysis.net training exercises](https://www.malware-traffic-analysis.net/training-exercises.html)
