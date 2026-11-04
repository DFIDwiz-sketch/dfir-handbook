---
title: "Malicious Files on Good Sites, File Extraction, Frequent Requests, Bare-IP Connections"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# Malicious Files on Good Sites, File Extraction, Frequent Requests, Bare-IP Connections { #files-frequency-naked-ip }

!!! abstract "What this page covers"
    Spreading malware through reputable cloud-sharing services and the one clue left behind (the file itself), safely extracting files from HTTP traffic with Wireshark, tshark and Zeek, rules and tools for spotting the **frequent, regular GETs and POSTs** C2 produces, and why requests **straight to an IP with no domain** and POSTs to the site root (`/`) are suspicious. Practice questions with answers are at the end.

!!! note "Labels"
    **[Added]** = practical must-know, **[Changed]**/**[Caution]** = what changed recently and what is risky if done the old way. Beacon interval analysis is detailed in [Beaconing & C2 detection](../../../network/beaconing-c2.md) and file records in [Zeek files.log](../../../network/zeek/files-log.md).

## Eight key points { #key-points }

1. Attackers upload malware to **reputable services** such as Dropbox, OneDrive and Google Drive and send links. Host, User-Agent and method are all normal; only **the file itself** remains as a clue.
2. In an unencrypted HTTP capture, Wireshark's **File → Export Objects → HTTP** extracts files.
3. Handle extracted executables and scripts only **where a double-click can't run them** (a Linux analysis machine).
4. HTTP C2 must **keep checking in** to receive commands, leaving repeated GETs and POSTs.
5. Especially suspicious together: **many + regular + never-seen domain + to the site root (`/`) + encoded bodies**.
6. Rules like "more than 100 POSTs in an hour to a site outside the popular list" are simple and effective but miss slow beacons; add periodicity tools (RITA, etc.).
7. Normal internet traffic almost always uses **host names**. An **IP address in the Host header** is suspicious.
8. POSTs normally go to a script (`.php`) or API path; **a POST straight to `/`** is odd.

## Malicious files served from good sites { #malicious-files-on-good-sites }

**Why it's dangerous.** Nearly every organisation allows HTTP, making it an ideal delivery channel — especially via **reputable cloud services anyone can upload to** (Dropbox, OneDrive, Google Drive, …). In 2018, for example, the Lazarus group ran targeted phishing through Dropbox share links.

What an analyst can see in such a case:

| Field | State |
| --- | --- |
| Host | A "known good" service such as `www.dropbox.com` (whether policy allows it is a separate question) |
| User-Agent | The user's real browser |
| Referer | Absent or webmail when opened from an email |
| Method/path | An ordinary download GET |
| **File** | **The only clue left** |

The [good domain ≠ safe URL](evil-http-and-reputation.md#domain-vs-url) principle applies directly. Headers can't decide it, so you **extract the file** and examine it. Fortunately, if the connection is decrypted, you can carve the file out of the network stream or have tools extract it automatically.

## Extracting files from HTTP traffic { #file-extraction }

### Wireshark { #wireshark-export }

1. Open the capture.
2. Choose **File → Export Objects → HTTP** (the same menu also covers TFTP, SMB, IMF (email) and DICOM).
3. Pick the download transaction from the list.

```
Packet  Hostname                     Content Type               Size        Filename
1482    docs-share-cloud.example     application/octet-stream   1,245 kB    Remittance_2026-11.zip
1530    docs-share-cloud.example     text/html                  18 kB       view
```

- `Packet` — the packet where the object finished (jump there to see the transaction)
- `Hostname` — the Host header value
- `Content Type` — the type the server **claims** ([real type via magic bytes](../http/responses.md#content-type))
- `Size` — size
- `Filename` — taken from the end of the URL path or Content-Disposition

4. Click **Save**. Then hash it, check its signature, scan it, and look up the hash's reputation.

### tshark (command line) { #tshark-export }

For large or many captures the command line is easier:

```
$ mkdir -p /cases/2026-1104/objects
$ tshark -r capture.pcap --export-objects http,/cases/2026-1104/objects
$ sha256sum /cases/2026-1104/objects/*
9b2f...e41a  /cases/2026-1104/objects/Remittance_2026-11.zip
```

- `mkdir -p ...` — create a folder for the extracted files (`-p` creates parent folders too)
- `tshark -r capture.pcap` — read the capture (`-r` = read)
- `--export-objects http,<folder>` — export every HTTP object into that folder
- `sha256sum ...` — compute each file's SHA-256 hash for reputation lookups

### Automatic extraction with Zeek { #zeek-extraction }

Configured to do so, Zeek **hashes and extracts files automatically** as they pass, so you can find them in `files.log` later without re-searching captures. Fields and configuration are on [Zeek files.log](../../../network/zeek/files-log.md).

!!! warning "[Caution] Keep extracted files where they can't detonate"
    If the extracted file is a Windows executable, save it on **a non-Windows analysis machine (Linux, etc.)** so an accidental double-click can't run it. Treat scripts Windows runs on double-click (`.js`, `.vbs`, `.ps1`, `.hta`, `.bat`, …) the same way. It's easy to think you'd never slip, but one mistake means a machine you can no longer trust and must rebuild — a dedicated analysis machine is far cheaper. When handing files to others, put them in a password-protected ZIP (conventionally with the password `infected`) so antivirus doesn't delete them and nobody opens them by accident.

**[Added] If the traffic is encrypted.** The above only works for **decrypted (or plaintext) HTTP**. For HTTPS, realistic alternatives are a TLS-inspecting proxy's storage feature, the endpoint (EDR collecting downloaded files), or the mail gateway's attachment retention. HTTP/2 object export may not work depending on the tool and version; then inspect DATA frames via [Follow → HTTP/2 Stream](../http/new-standards.md#http2-wireshark) or use Zeek extraction.

## Frequent, regular GETs and POSTs { #high-frequency }

**Why they happen.** Malware using HTTP for C2 must **keep asking the server** for the attacker's commands (checking in). For a responsive remote shell it may ask several times a second; to stay quiet, perhaps once a day. Either way, it leaves **repeated requests**.

Especially suspicious together:

| Signal | Why |
| --- | --- |
| Many | People don't hit the same address hundreds or thousands of times a day |
| Regular | People are irregular; programs keep fixed intervals |
| Never-seen or untrusted domain | Not on popular-site lists |
| To the site root (`/`) | Normal requests usually go to specific paths or APIs |
| Encoded request/response bodies | [Base64](base64.md) and the like |

**A simple rule.** Something like "alert when more than 100 POSTs go to a site outside the top 1,000 within an hour". Counting similarly from Zeek logs:

```
$ cat http.log | zeek-cut id.orig_h host method | awk '$3=="POST"' | sort | uniq -c | sort -rn | head -5
   1440 10.1.5.77    sync-metrics-api.example   POST
    212 10.1.5.23    graph.microsoft.com        POST
     96 10.1.5.40    login.microsoftonline.com  POST
     41 10.1.5.12    collector.analytics.example POST
     12 10.1.5.31    forms.office.com           POST
```

- `zeek-cut id.orig_h host method` — keep source IP, Host and method
- `awk '$3=="POST"'` — keep lines whose third column (method) is POST
- `sort | uniq -c` — count identical (PC, host, method) combinations
- `sort -rn` — largest counts first (`-r` reverse, `-n` numeric)
- `head -5` — top five

Reading it:

- **Line 1** — one PC POSTs 1,440 times a day to a never-seen `sync-metrics-api.example` = **exactly once a minute** (24 h × 60 min). Top beacon suspect
- **Lines 2–3** — Microsoft services; filter with popular-site lists and baselines
- **Line 4** — an analytics collector; could be a site's tracking script — check

**[Added] Slow beacons can be caught too.** Count rules miss a beacon that calls once a day, so use tools that measure **interval regularity** directly. The open-source RITA (Real Intelligence Threat Analytics), for instance, scores how consistent connection intervals and data sizes are in Zeek logs, finding periodic signals even with long gaps. The method and how to compute it yourself are in [Beaconing & C2 detection](../../../network/beaconing-c2.md#interval-analysis-the-core-technique).

## Straight to an IP with no domain: naked IPs { #naked-ip }

**Why it's suspicious.** Normal internet traffic almost always uses **host names** — easier for people, and programs keep working when server IPs change. So a request **straight to an IP address** deserves attention, and the Host header tells you:

```
POST / HTTP/1.1
Host: 203.0.113.58
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Content-Type: application/octet-stream
Content-Length: 344

(binary data)
```

- `Host: 203.0.113.58` — an **IP address**, not a name; a host-name connection would show the name here
- `POST /` — data sent **straight to the server root (top folder)**. POSTs normally go to a server script like `login.php` or an API like `/api/v2/...`; the bare root is odd
- A short fake User-Agent with a platform but no browser name
- An opaque binary body

**[Added] Spotting bare-IP HTTPS.** TLS announces the site name via SNI, but by standard **IP addresses aren't put in SNI**. A direct-to-IP HTTPS connection therefore shows an **empty** `server_name` in Zeek `ssl.log`, and the server certificate often doesn't match the IP (errors in `validation_status`). "No SNI + never-seen external IP + regular interval" is a strong C2 signal.

**There are legitimate exceptions.** Vendor remote management, IoT devices, old internal apps and cloud VM metadata addresses (`169.254.169.254`, a normal address used only inside clouds) may talk by IP. Treat bare-IP traffic not as "malicious" but as **"needs an explanation"**, and identify the device and process.

## 2026 perspective { #trends }

!!! success "[Still valid in 2026]"
    "Reputable services carry malicious files", "extract and inspect files when decrypted", "C2 leaves repetition" and "bare-IP connections and root POSTs are suspicious" all hold.

!!! info "[Changed]"
    - **Popular-site ranking lists changed.** The once-ubiquitous Alexa ranking shut down in 2022; today people use the Tranco list, Cisco Umbrella's popularity list, Cloudflare Radar rankings and similar. Still, **popular ≠ safe** (popular cloud services get abused).
    - **The range of abused "good services" grew.** Beyond cloud storage: GitHub, Discord and Telegram file sharing, collaboration-tool links, and [free subdomains such as Cloudflare Workers or tunnels](../http/post-methods-headers.md#domain-fronting).
    - **File acquisition is endpoint-centred.** With most traffic HTTPS, network extraction is hard, so EDR collects downloaded files, and browser download history plus MotW (Mark of the Web, the tag Windows puts on internet-downloaded files) establish origin.
    - **C2 frameworks add jitter.** Cobalt Strike, Sliver and others randomise intervals by default to avoid "exactly 60 seconds", so statistical detection looking at interval mean/variance and size consistency (RITA, NDR products) matters more.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't blanket-exclude repeated requests to popular sites.** Attackers using cloud APIs (collaboration tools, storage APIs) as C2 sail straight through popularity filters; keep exclusions narrower than whole domains.
    - **Don't save extracted files on an analyst's everyday Windows PC.**
    - **Alerting on or blocking every bare-IP connection breaks business devices.** Manage exceptions with an asset list and baselines.

## Practice questions { #quiz }

### Question 1

A staff member downloaded `Remittance_2026-11.zip` (1.2 MB) from `docs-share-cloud.example` via an email link. You have a plaintext HTTP capture; Host, User-Agent and method all look ordinary. How do you extract the file, and what do you do next?

??? success "Answer and explanation"
    **Extract:** Wireshark **File → Export Objects → HTTP**, pick the transaction, Save — or on the command line `tshark -r capture.pcap --export-objects http,<folder>`. Save it **somewhere safe, such as a Linux analysis machine**.

    **Then:**

    1. Hash it with `sha256sum` and look up the reputation (hash first, before uploading anywhere public)
    2. **List the ZIP's contents without extracting** (`unzip -l`, etc.): any `.exe`, `.js`, `.lnk`, `.iso` or other runnable files?
    3. Confirm real types via magic bytes — names and Content-Type can lie
    4. If needed, observe behaviour in an isolated sandbox
    5. On the staff member's PC, check whether the ZIP was extracted and its contents run (Sysmon Event ID 11 file create, Sysmon 1 / 4688 process create)
    6. Find other recipients of the same link

    The headers look normal because the attacker used, or mimicked, a reputable sharing service — leaving **the file itself** as the only clue.

### Question 2

A day of Zeek `http.log` POSTs counted per (PC, host). What do you investigate first, and what's probably normal?

```
   1440 10.1.5.77    sync-metrics-api.example    POST
    212 10.1.5.23    graph.microsoft.com         POST
     24 10.1.5.88    203.0.113.58                POST
     12 10.1.5.31    forms.office.com            POST
```

??? success "Answer and explanation"
    **Investigate first:**

    - **Line 1** — 1,440 a day to a never-seen domain = **exactly once a minute**. Top beacon suspect
    - **Line 3** — few requests (24 = once an hour), but the Host is an **IP address**. At 24 a day it slips under count rules, yet bare IP + regular interval (hourly) is the shape of a slow beacon. Also check whether the path is `/` and the body is encoded

    **Probably normal:**

    - **Line 2** — the Microsoft Graph API, heavily used by Office apps (though Graph has been abused as C2, so confirming the source process is a genuine Office app is worthwhile)
    - **Line 4** — Microsoft Forms submissions

    Lesson: **ranking by count alone misses slow beacons like line 3** — look at bare IPs and interval regularity too.

### Question 3

Which of these two requests is more suspicious, and why? What would you check for each?

```
A: POST / HTTP/1.1
   Host: 203.0.113.58:8443
   Content-Type: application/octet-stream

B: GET /api/v1/status HTTP/1.1
   Host: 10.20.0.15
   User-Agent: PrinterAgent/3.2
```

??? success "Answer and explanation"
    **A is far more suspicious:**

    - Straight to an external IP (`203.0.113.58`) **with no name**, on non-standard port 8443
    - **A POST to the root `/`** — not a server script or API path
    - An opaque binary body

    Check: the process making the connection (Sysmon Event ID 3), the repetition interval to that IP, the IP's reputation and ownership (which hosting provider and country), the body (Base64? magic bytes?), and persistence on the PC.

    **B is probably an explainable exception:**

    - The destination is an **internal IP** (`10.20.0.15`) and the path a specific status API
    - The User-Agent looks like a printer-management agent

    Check: that `10.20.0.15` really is a printer (or management server) per the asset list, and that the agent is software the organisation installed. Once confirmed, add it to the baseline (known exceptions) to cut future noise.
