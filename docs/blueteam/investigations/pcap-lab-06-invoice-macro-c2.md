---
title: PCAP Lab 06 — Invoice Word Macro to Hancitor-Style C2
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
  - word-macro
  - hancitor
  - c2
---

# PCAP Lab 06 — Invoice Word Macro to Hancitor-Style C2 { #lab-06 }

!!! abstract "Case summary"
    A Windows 7 client in the `maricheika.net` domain downloaded `invoice_284615.doc` with Internet Explorer. The document carried an auto-run VBA macro. About two minutes later the host checked its public IP with `api.ipify.org`, began POSTing to `perranrowsin.com` every two minutes, and downloaded three more files from a hijacked WordPress site. The traffic pattern matches **Hancitor** (inferred; no hash lookup was possible offline).

| | |
|---|---|
| **Evidence** | `Phase1_PCAP_6.pcap`, 2018-10-01 18:37:28 – 18:58:35 UTC (21 min) |
| **Environment** | Offline Linux analysis VM, Zeek 4.x, tshark, no internet |
| **Main tool** | Zeek logs + `zeek-cut`, `awk`, `grep`; tshark where it is simpler |
| **Lab guide** | [Training → PCAP IR Labs → Lab 6](../../training/pcap-ir-labs/lab-guide.md#lab-6) |

## The questions { #questions }

1. Date and time (UTC) of the infection.
2. IP address of the infected client.
3. Hostname of the infected client.
4. MAC address of the infected client.
5. Windows user account name.
6. Hash of the Word document, and how you handled it safely.
7. Type of malware used in the initial infection.
8. Public IP address of the infected client.
9. Key network information (LAN range, gateway, domain, DC).
10. Explanation of the compromise.

## Answers at a glance { #answers }

| # | Answer | Status |
|---|---|---|
| 1 | **2018-10-01 18:38:00 UTC** (HTTP request for the document; file data first seen 18:38:01) | Confirmed |
| 2 | **172.16.1.125** | Confirmed |
| 3 | **Anatoliy-PC** | Confirmed |
| 4 | **b8:97:fa:74:de:c0** | Confirmed |
| 5 | **anatoliy.demchuk** | Confirmed |
| 6 | SHA256 `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` (MD5/SHA1 in [step 4](#safe-hash)) | Confirmed |
| 7 | Malicious Word document with an auto-run VBA macro (downloader); traffic consistent with **Hancitor** | Macro confirmed, family inferred |
| 8 | **31.44.188.95** | Confirmed |
| 9 | 172.16.1.0/24, gateway 172.16.1.1, domain maricheika.net, DC 172.16.1.3 Maricheika-DC | Confirmed |
| 10 | See the [report](#report) | — |

---

## Step 0 — Set up and generate the Zeek logs { #step-0 }

```bash
cd ~/Investigation_6
ls                                             # find the PCAP name
sha256sum Phase1_PCAP_6.pcap | tee pcap.sha256 # record the evidence hash first
mkdir zeek_full && cd zeek_full
zeek -C -r ../Phase1_PCAP_6.pcap local \
     frameworks/files/extract-all-files \
     policy/protocols/conn/mac-logging 2>/dev/null
ls
```

| Part | Why |
|---|---|
| `sha256sum ... \| tee pcap.sha256` | Proves later that the evidence did not change during analysis. `tee` prints the hash and saves it. |
| `mkdir zeek_full && cd zeek_full` | Zeek writes its logs into the **current folder**. A dedicated folder keeps them together and stops a later Zeek run from overwriting them. |
| `-C` | Ignore bad checksums. Captures taken on the sending host often have "wrong" checksums because the network card calculates them; without `-C` Zeek can drop those packets. |
| `-r ../Phase1_PCAP_6.pcap` | Read a file instead of a live interface. |
| `local` | Load the standard site policy (the same scripts a sensor would run). |
| `frameworks/files/extract-all-files` | Save every transferred file to `extract_files/` so it can be hashed and inspected later. |
| `policy/protocols/conn/mac-logging` | Add MAC address columns (`orig_l2_addr`, `resp_l2_addr`) to `conn.log`. |
| `2>/dev/null` | Hide warning messages. |

`ls` should now show `conn.log`, `dns.log`, `http.log`, `files.log`, `dhcp.log`, `kerberos.log`, `ssl.log` and the `extract_files/` folder.

---

## Step 1 — The big picture { #step-1 }

### Capture window { #capture-window }

```bash
zeek-cut -u ts < conn.log | sort | sed -n '1p;$p'
```

```text
2018-10-01T18:37:28+0000
2018-10-01T18:58:35+0000
```

- `zeek-cut -u ts` prints only the timestamp column, converted to UTC (`-u`).
- `sort` puts the times in order; `sed -n '1p;$p'` prints just the first and the last line.
- The capture covers **21 minutes**. Every later event must fit inside this window.

=== "tshark alternative"

    ```bash
    TZ=UTC capinfos -a -e ../Phase1_PCAP_6.pcap
    ```

    `capinfos` (installed with Wireshark) prints the first and last packet times directly. `TZ=UTC` forces UTC instead of the analysis machine's local time zone.

### Internal hosts { #internal-hosts }

```bash
zeek-cut id.orig_h < conn.log | grep -E "^10\.|^172\.|^192\.168\." | sort | uniq -c | sort -rn
```

```text
    160 172.16.1.125
```

- `id.orig_h` is the host that **started** each connection.
- The `grep` keeps private (RFC 1918) addresses only. Strictly, 172.16.0.0/12 is `172.16.`–`172.31.`; `^172\.` is a quick approximation that is fine here.
- `uniq -c` counts each address; `sort -rn` puts the busiest first.
- **Only one internal host started connections.** It is the only candidate for the infected client.

### Hostname and MAC from DHCP { #dhcp-identity }

```bash
zeek-cut -u ts client_addr mac host_name < dhcp.log
```

```text
2018-10-01T18:37:28+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:37:32+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:40:20+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:42:31+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:45:48+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:47:40+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
2018-10-01T18:52:29+0000   172.16.1.125   b8:97:fa:74:de:c0   Anatoliy-PC
```

A Windows client sends its own hostname (DHCP option 12) when it asks for an address, so `dhcp.log` ties **IP, MAC and hostname** together in one line. Every entry agrees: **172.16.1.125 · b8:97:fa:74:de:c0 · Anatoliy-PC** (answers 2–4).

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "dhcp.option.hostname" \
           -T fields -e ip.src -e eth.src -e dhcp.option.hostname | sort -u
    ```

    `-Y` filters for DHCP packets that carry a hostname; `-T fields -e` prints only the chosen fields. On Wireshark 2.x use `bootp.option.hostname`.

### User account and Domain Controller from Kerberos { #kerberos }

```bash
zeek-cut client id.resp_h < kerberos.log | sort | uniq -c
```

```text
      5 -                               172.16.1.3
      2 anatoliy.demchuk/MARICHEIKA     172.16.1.3
      5 anatoliy.demchuk/MARICHEIKA.NET 172.16.1.3
      2 anatoliy-pc$/maricheika.net     172.16.1.3
      2 anatoliy-pc$/MARICHEIKA.NET     172.16.1.3
     12 ANATOLIY-PC$/MARICHEIKA.NET     172.16.1.3
```

| Value | Meaning |
|---|---|
| `anatoliy.demchuk/...` | A **user** account: no `$` at the end → answer 5 |
| `anatoliy-pc$/...` | The **computer** account. Machine accounts always end in `$` and match the hostname |
| text after `/` | The Kerberos realm, i.e. the AD domain: **MARICHEIKA.NET** (short and long forms, any case, are the same domain) |
| `id.resp_h` = 172.16.1.3 | The server answering Kerberos (TCP/UDP 88) is the **Domain Controller** |

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "kerberos.CNameString" \
           -T fields -e ip.src -e ip.dst -e kerberos.CNameString -e kerberos.realm | sort | uniq -c
    ```

    `CNameString` is the client name in Kerberos requests and replies; the source and destination columns show the client and the DC (172.16.1.3) talking.

---

## Step 2 — Find the suspicious file { #step-2 }

```bash
zeek-cut -u ts tx_hosts rx_hosts source mime_type filename seen_bytes < files.log \
  | grep -i -E "msword|officedocument|ms-office|dosexec|zip"
```

```text
2018-10-01T18:38:01+0000   47.88.158.115   172.16.1.125   HTTP   application/msword   invoice_284615.doc   225280
```

| Column | Value | Meaning |
|---|---|---|
| `ts` | 18:38:01 | When Zeek first saw the file data (the start of the response body) |
| `tx_hosts` | 47.88.158.115 | Who **sent** the file (an external server) |
| `rx_hosts` | 172.16.1.125 | Who **received** it, the infected client |
| `mime_type` | `application/msword` | Zeek decides the type from the file's **content** (magic bytes), not its name |
| `filename` | `invoice_284615.doc` | An "invoice" lure, a classic malspam theme |

The `grep` searches for the type names Zeek gives Word documents (`msword`, `officedocument`, `ms-office`), executables (`dosexec`) and archives (`zip`). Only the Word document matched, and **no EXE followed it**. That matters later.

!!! tip "Pitfall: a misspelled field gives an empty column, not an error"
    The first run of this command used `seen_types` instead of `seen_bytes`. `zeek-cut` printed an empty last column and no error. If a column is unexpectedly empty, check the field name in the log header with `head -8 files.log`.

### The URL that served the document { #doc-url }

```bash
zeek-cut -u ts id.resp_h host uri status_code resp_mime_types user_agent < http.log | grep -i msword
```

```text
2018-10-01T18:38:00+0000   47.88.158.115   pitchbocaraton.com   /?82a1=APYBKsCs3LUw   200   application/msword
    Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
```

- Full URL = `host` + `uri` → `http://pitchbocaraton.com/?82a1=APYBKsCs3LUw`.
- `status_code 200` + `application/msword`: the server really returned the document.
- `Trident/7.0; rv:11.0` is **Internet Explorer 11**; `WOW64` means 32-bit IE on 64-bit Windows 7 (`NT 6.1`). The user fetched the file **with the browser**, most likely by clicking a link (in an email, inferred).
- `http.log` records the time the **request** started (18:38:00); `files.log` records when the file data was first seen (18:38:01). Answer 1 = **18:38:00 UTC**, noting the one-second difference.

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "http.request" -T fields \
           -e frame.time_utc -e ip.dst -e http.host -e http.request.uri -e http.user_agent
    ```

    Lists every HTTP request with its UTC time. It is useful for reading the whole browsing sequence in one view.

---

## Step 3 — Was anything malicious before the document? { #step-3 }

Before calling 18:38:00 the start of the infection, check that nothing suspicious happened earlier. The capture starts at 18:37:28, only **32 seconds** before the document request, so there is little room for earlier activity, but confirm it:

```bash
zeek-cut -u ts query answers < dns.log | awk -F'\t' '$1 <= "2018-10-01T18:38:01+0000"'
zeek-cut -u ts host uri < http.log     | awk -F'\t' '$1 <  "2018-10-01T18:38:00+0000"'
```

- `awk -F'\t'` splits on tabs (Zeek's separator); `$1` is the first column, the time.
- ISO timestamps can be compared **as text**: the biggest unit comes first (year → month → day → hour …), so alphabetical order equals time order.
- What to expect: Windows start-up lookups (`_ldap._tcp…` SRV records for the DC, `wpad`, `isatap`, `msftncsi`) and the lookup for `pitchbocaraton.com` just before the download. Any other unknown domain would push the start of the incident earlier. With nothing else suspicious, **the document download is the first malicious event**.

!!! tip "Two ways to look at what came before an event"
    - `grep -B 15 "msword"` shows the matching line **and the 15 lines before it** (`-A` = after, `-C` = both). It is fast for "what happened just before?".
    - `awk -F'\t' '$1 <= "…"'` cuts an exact time range. Use it for reports.

---

## Step 4 — Handle and hash the document safely (Q6) { #safe-hash }

### Get the file ID and the hashes Zeek already calculated { #fuid }

```bash
zeek-cut fuid mime_type seen_bytes md5 sha1 < files.log | grep -i msword
```

```text
F5VYtO3n6Uvp1v0TU1   application/msword   225280   41a3101af94fca79bbdb0db2a52994c0   103dc7e3100963f31c2280b129d8280b22194c72
```

- `fuid` is Zeek's ID for the file. The extracted copy is named `extract_files/extract-<time>-HTTP-<fuid>`, so the fuid finds it.
- Zeek calculates **MD5 and SHA1** by default, but not SHA256.

### Safe copy, file type, SHA256 { #safe-copy }

```bash
cp extract_files/*F5VYtO3n6Uvp1v0TU1 evidence.doc.bin   # .bin: will not open in Word on double-click
chmod a-x evidence.doc.bin                               # remove execute permission for everyone
file evidence.doc.bin                                    # identify by content, not extension
md5sum evidence.doc.bin; sha1sum evidence.doc.bin; sha256sum evidence.doc.bin
```

```text
extract-1538419081.436962-HTTP-F5VYtO3n6Uvp1v0TU1: Composite Document File V2 Document, Little Endian,
Os: Windows, Version 6.1, Code page: 1252, Title: , Author: 444555, Template: Normal.dotm,
Last Saved By: win7home, Revision Number: 2, Name of Creating Application: Microsoft Office Word,
Create Time/Date: Mon Oct  1 12:17:00 2018, Last Saved Time/Date: Mon Oct  1 12:17:00 2018,
Number of Pages: 1, Number of Words: 3, Number of Characters: 20, Security: 0

e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51
```

| Hash | Value |
|---|---|
| Size | 225,280 bytes (`seen_bytes` = size on disk → complete file) |
| MD5 | `41a3101af94fca79bbdb0db2a52994c0` |
| SHA1 | `103dc7e3100963f31c2280b129d8280b22194c72` |
| SHA256 | `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` |

**What the `file` metadata says**

| Field | Why it is suspicious |
|---|---|
| `Composite Document File V2` | Legacy OLE `.doc` format, which can carry VBA macros |
| Created and saved **Oct 1 2018** | The same date as the infection: a freshly built document |
| `Number of Words: 3`, `Characters: 20` | A real invoice has content. Malicious documents usually hold only an image saying "Enable content" |
| `Author: 444555`, `Last Saved By: win7home` | Throw-away names |

**Why this is safe**: the work happens in an isolated Linux VM with no network and no Microsoft Office, so the macro cannot run. The document is never opened, only read by `file`, `strings` and hash tools. The `.bin` name and `chmod a-x` protect against an accidental double-click. Only the **hash** would be looked up on VirusTotal (never upload the file). The sample is kept in a password zip (`zip -P infected evidence.zip evidence.doc.bin`).

=== "tshark alternative"

    ```bash
    mkdir objs && tshark -r ../Phase1_PCAP_6.pcap -q --export-objects http,objs
    file objs/* | grep -i composite        # find which carved file is the Word document
    sha256sum "objs/<name shown by file>"
    ```

    `--export-objects http,objs` carves every HTTP object into `objs/` (Wireshark's *File → Export Objects → HTTP*). File names come from the URI, so find the document by its type with `file`. The hash should equal Zeek's.

---

## Step 5 — Look for the macro without Office (Q7) { #macro }

`olevba` (oletools) is the usual tool, but it was not installed and the VM had no internet (`which olevba oleid` returned nothing). `strings` still works:

```bash
strings -n 6 evidence.doc.bin | grep -i -E "vba|autoopen|document_open|shell|powershell|cmd|http|createobject"
```

```text
http://ns.adobe.com/xap/1.0/  ... xmp:CreatorTool="Adobe Photoshop CC 2017 (Windows)" ...
<b:Sources ... xmlns:b="http://schemas.openxmlformats.org/officeDocument/2006/bibliography"> ...
1VBA.@Create
Document_Open
CreateObject
ShellV
```

- `strings -n 6` prints runs of 6 or more readable characters; `grep -i -E` keeps lines containing any keyword (case-insensitive).
- The `ns.adobe.com` and `schemas.openxmlformats.org` lines are **normal metadata**. The Photoshop XMP block shows an embedded image, most likely the "enable content" lure (inferred).

| String | Meaning |
|---|---|
| `VBA` | A VBA project is present |
| `Document_Open` | The macro runs **as soon as the document is opened** (after "Enable content") |
| `CreateObject` | Loads Windows COM objects (file system, shell, HTTP) |
| `Shell` | Runs a program or command |

That combination is a **malicious auto-run macro**. VBA source is compressed inside the file, so `strings` shows keywords and not the full code. No download URL appears, and no EXE was downloaded after the document. Hancitor-era macros often carried the payload **inside** the document and dropped it locally (inferred).

??? note "If oletools is available"
    ```bash
    oleid evidence.doc.bin      # summary: VBA macros present? encrypted?
    olevba -a evidence.doc.bin  # analysis table only: AutoExec / Suspicious / IOC
    olevba --decode evidence.doc.bin  # also decode obfuscated strings
    ```
    `AutoExec` + `Suspicious` (Shell, CreateObject) rows confirm the same thing, and `IOC` rows list any URLs.

---

## Step 6 — What happened after the document? { #post-infection }

```bash
zeek-cut -u ts id.resp_h host method uri status_code resp_mime_types user_agent < http.log \
  | awk -F'\t' '$1 >= "2018-10-01T18:38:01+0000"'
```

```text
18:40:20  54.243.179.137   api.ipify.org          GET   /                                          200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
18:40:20  62.109.30.243    perranrowsin.com       POST  /4/forum.php                               200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
18:40:21  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/1  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:27  62.109.30.243    perranrowsin.com       POST  /mlu/forum.php                             200  -           Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...)
18:40:29  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/2  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:29  205.186.179.236  stopfuckinaround.com   GET   /wp-content/plugins/google-sitemap-generator/3  200  -       Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:40:30  62.109.30.243    perranrowsin.com       POST  /d2/about.php                              200  -           Mozilla/4.0 (compatible; MSIE 7.0; ...)
18:42:30  62.109.30.243    perranrowsin.com       POST  /4/forum.php                               200  text/plain  Mozilla/5.0 (Windows NT 6.1; Win64; x64; ...)
18:44:31  ... POST /4/forum.php
18:46:31  ... POST /4/forum.php
18:48:32  ... POST /4/forum.php
18:50:33  ... POST /4/forum.php
18:52:34  ... POST /4/forum.php
18:54:34  ... POST /4/forum.php
18:56:35  ... POST /4/forum.php
```

*(Dates trimmed for width; all on 2018-10-01, UTC.)*

### Reading it { #reading-post-infection }

| Time | Event | Meaning |
|---|---|---|
| 18:38:00 | Document downloaded | Delivery |
| 18:38–18:40 | **No HTTP for ~2 min 20 s** | The user opened the document and clicked "Enable content" (inferred) |
| 18:40:20 | `GET api.ipify.org/` | Malware asks "what is my public IP?" |
| 18:40:20 | `POST /4/forum.php` | First C2 check-in, sending victim information |
| 18:40:21–29 | `GET .../google-sitemap-generator/1, /2, /3` | Three follow-up payloads from a **compromised WordPress site**. MIME type `-` means Zeek could not identify them, which is typical of encrypted payloads (inferred) |
| 18:40:27, 18:40:30 | `POST /mlu/forum.php`, `/d2/about.php` | Check-ins from **different** malware: the follow-up payloads now running (inferred) |
| 18:42:30 → 18:56:35 | `POST /4/forum.php` every **~120 s** | **Beaconing**: the main implant calls home on a fixed timer |

### The User-Agent tells you which program sent each request { #user-agent }

| Requests | User-Agent | Verdict |
|---|---|---|
| Document download | `Windows NT 6.1; WOW64; Trident/7.0; rv:11.0` | The user's real 32-bit IE 11 |
| ipify, `/4/forum.php`, WordPress `/1 /2 /3` | `Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0` | Looks like IE but **differs** from the real browser: a different program (the first-stage malware) |
| `/mlu/forum.php`, `/d2/about.php` | `Mozilla/4.0 (compatible; MSIE 7.0; …)` | IE 7 on a 2018 Windows 7 host is not plausible: a hard-coded string in **another** program |

One host, one real browser, two malware User-Agents. Comparing User-Agents per destination is one of the fastest ways to separate user browsing from malware.

### Measure the beacon interval { #beacon-interval }

```bash
zeek-cut ts uri < http.log | grep "/4/forum.php" | awk '{ if (prev) print $1 - prev; prev = $1 }'
```

- Without `-u`, `ts` stays in epoch seconds, so `awk` can subtract.
- The difference between consecutive POSTs is about **120 seconds** each time (from the timestamps above: 18:42:30 → 18:44:31 → 18:46:31 …). Regular timing is a beacon; a human is never that regular.

### Why "Hancitor" (and why it stays inferred) { #family }

This sequence is a well-documented 2018 Hancitor pattern:

1. Word document with a macro;
2. `api.ipify.org` IP check;
3. POST to `/4/forum.php`;
4. GETs for numbered files under a hijacked WordPress path;
5. Extra check-ins to `/mlu/forum.php` and `/d2/about.php` (follow-up stealer malware).

**Confirmed:** macro document → IP check → C2 POSTs → follow-up downloads → 2-minute beacon.
**Inferred:** the family name. The lab was offline, so no hash lookup was possible. Write *"consistent with Hancitor"*, not *"Hancitor"*.

---

## Step 7 — Public IP of the client (Q8) { #public-ip }

The client uses a private address, and NAT on the gateway swaps it for a public address on the way out. A capture taken inside the LAN never shows that public address in packet headers. The **IP-check service's answer** does: `api.ipify.org` replies with the caller's public IP as plain text.

```bash
zeek-cut host uri resp_fuids < http.log | grep ipify   # find the response's file ID
cat extract_files/*FGnsSi1OKpfguaYN9d; echo              # print the response body
```

```text
31.44.188.95
```

- `resp_fuids` is the ID of the response body. Zeek saved that body as a file, like any other download.
- `echo` only adds the missing newline so the prompt does not join the IP.

=== "tshark alternative (simpler)"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y 'http.response and http.response_for.uri contains "ipify"' \
           -T fields -e http.file_data
    ```

    One command, no file ID needed: it prints the response body of the ipify request directly. If your tshark version prints hex, add `| xxd -r -p`. In Wireshark: right-click the request → *Follow → HTTP Stream*, and the IP is in the blue (server) text.

**Answer 8: 31.44.188.95** (confirmed).

---

## Step 8 — Key network information (Q9) { #network-info }

### Domain and DC hostname { #dc-name }

```bash
zeek-cut service < kerberos.log | sort | uniq -c
```

```text
      4 -
      1 anatoliy-pc$
      1 ANATOLIY-PC$
      2 anatoliy-pc$@MARICHEIKA.NET
      3 cifs/maricheika-dc.maricheika.net
      1 host/anatoliy-pc.maricheika.net
      1 krbtgt/MARICHEIKA
      1 krbtgt/maricheika.net
      9 krbtgt/MARICHEIKA.NET
      2 ldap/Maricheika-DC.maricheika.net
      1 ldap/Maricheika-DC.maricheika.net/maricheika.net
      2 LDAP/Maricheika-DC.maricheika.net/maricheika.net
```

`service` is the service a ticket was requested for. `krbtgt/<REALM>` is the domain's ticket service; `ldap/…` and `cifs/…` (file sharing) are services **on the DC**. The name after the `/` is the DC: **Maricheika-DC.maricheika.net**.

```bash
zeek-cut query answers < dns.log | grep -i -E "_ldap|_kerberos" | sort -u
```

```text
_ldap._tcp.dc._msdcs.maricheika.net                                   maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.domaindnszones.maricheika.net  maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.forestdnszones.maricheika.net  maricheika-dc.maricheika.net
_ldap._tcp.default-first-site-name._sites.maricheika.net              maricheika-dc.maricheika.net
...
```

`_ldap._tcp.dc._msdcs.<domain>` is the DNS SRV question Windows asks to mean "who are the DCs of this domain?". The answer confirms the DC name.

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_6.pcap -Y "dns.flags.response == 1 && dns.qry.type == 33" \
           -T fields -e dns.qry.name -e dns.srv.target | sort -u
    ```

    `dns.qry.type == 33` is SRV; `dns.srv.target` is the host the SRV record points to.

!!! note "`dhcp.log` says `localdomain`, so why is the domain `maricheika.net`?"
    `zeek-cut domain < dhcp.log` returned `localdomain`. That is the **DHCP server's** default suffix (common on VMware NAT and home routers), not the Active Directory domain. The AD domain comes from Kerberos and DNS: **maricheika.net**. It also shows that the DHCP server is a separate device from the DC.

### Subnet mask and gateway { #mask-gateway }

`dhcp.log` has no mask or gateway columns. A Zeek event script can print them, but tshark does it in one line, so tshark is the better tool here:

```bash
tshark -r ../Phase1_PCAP_6.pcap -Y dhcp -T fields \
       -e ip.src -e dhcp.option.subnet_mask -e dhcp.option.router | sort -u
```

```text
0.0.0.0
172.16.1.125
172.16.1.254    255.255.255.0    172.16.1.1
```

| Line | Who sent it | Why |
|---|---|---|
| `0.0.0.0` | Client without an address yet (Discover / Request) | Clients have no mask or router to report → empty fields |
| `172.16.1.125` | Client renewing or informing after it has an address | Still a client message → empty fields |
| `172.16.1.254 255.255.255.0 172.16.1.1` | **DHCP server** (Offer / ACK) | Only the server hands out option 1 (mask) and option 3 (router) |

`sort -u` collapses identical lines, which is why many DHCP packets become three. Mask `255.255.255.0` = `/24`. With client IP 172.16.1.125, the LAN is **172.16.1.0/24**, the gateway is **172.16.1.1**, and the DHCP server is **172.16.1.254**.

??? note "Zeek-only ways to get the gateway"
    **By MAC address** (needs the `mac-logging` script used in step 0). Traffic to the internet is addressed to the gateway's MAC:

    ```bash
    zeek-cut id.resp_h resp_l2_addr < conn.log | grep -v "^172\.16\." | awk '{print $2}' | sort | uniq -c
    zeek-cut id.resp_h resp_l2_addr < conn.log | grep "^172\.16\." | grep <gateway-MAC> | sort -u
    ```

    **Event script** (prints mask and router from server replies; run it in an empty folder so the existing logs are not overwritten):

    ```bash
    zeek -C -r ../Phase1_PCAP_6.pcap -e 'event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) { if (!is_orig) print c$id$resp_h, options?$subnet_mask ? fmt("%s", options$subnet_mask) : "-", options?$routers ? fmt("%s", options$routers) : "-"; }'
    ```

### Answer 9 { #answer-9 }

```text
LAN segment range:  172.16.1.0/24 (172.16.1.0 - 172.16.1.255)
Default gateway:    172.16.1.1
DHCP server:        172.16.1.254
Domain:             maricheika.net
Domain Controller:  172.16.1.3 - Maricheika-DC
Infected client:    172.16.1.125 - Anatoliy-PC - b8:97:fa:74:de:c0 - anatoliy.demchuk
Public IP (NAT):    31.44.188.95
```

---

## Timeline { #timeline }

| UTC (2018-10-01) | Event | Source |
|---|---|---|
| 18:37:28 | Capture starts; Anatoliy-PC gets 172.16.1.125 by DHCP | dhcp.log |
| 18:38:00 | IE 11 requests `pitchbocaraton.com/?82a1=APYBKsCs3LUw` | http.log |
| 18:38:01 | `invoice_284615.doc` (225,280 bytes) seen in the response | files.log |
| 18:40:20 | Public IP check, `api.ipify.org` → 31.44.188.95 | http.log, extracted body |
| 18:40:20 | First C2 POST `perranrowsin.com/4/forum.php` | http.log |
| 18:40:21–29 | Three follow-up files from `stopfuckinaround.com/wp-content/plugins/google-sitemap-generator/1–3` | http.log |
| 18:40:27, 18:40:30 | POST `/mlu/forum.php`, `/d2/about.php` (MSIE 7 UA) | http.log |
| 18:42:30 – 18:56:35 | POST `/4/forum.php` every ~2 minutes | http.log |
| 18:58:35 | Capture ends | conn.log |

## Indicators of compromise { #iocs }

| Type | Indicator | Role |
|---|---|---|
| URL | `hxxp://pitchbocaraton[.]com/?82a1=APYBKsCs3LUw` | Word document download |
| IP | `47.88.158[.]115` | pitchbocaraton.com |
| File | `invoice_284615.doc`, SHA256 `e2b0c9f57dcf08c0e14456f5cb54d8e50714c8e7a3a88cf818896dc8ba1dba51` | Macro document |
| URL | `hxxp://perranrowsin[.]com/4/forum.php`, `/mlu/forum.php`, `/d2/about.php` | C2 check-ins |
| IP | `62.109.30[.]243` | perranrowsin.com |
| URL | `hxxp://stopfuckinaround[.]com/wp-content/plugins/google-sitemap-generator/1` (`/2`, `/3`) | Follow-up payloads |
| IP | `205.186.179[.]236` | Compromised WordPress host |
| Domain | `api.ipify[.]org` | Legitimate service abused for IP discovery (context, not block-worthy on its own) |
| User-Agent | `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; …)` | Follow-up malware |

## ATT&CK mapping { #attack }

| Technique | Evidence |
|---|---|
| T1566.002 Phishing: Spearphishing Link | Document fetched by the browser from a link (delivery channel inferred) |
| T1204.002 User Execution: Malicious File | User opened the document and enabled content (inferred from the 2-minute gap) |
| T1059.005 Command and Scripting Interpreter: Visual Basic | `Document_Open`, `CreateObject`, `Shell` in the document |
| T1016.001 System Network Configuration Discovery: Internet Connection Discovery | `api.ipify.org` lookup |
| T1071.001 Application Layer Protocol: Web Protocols | HTTP POST C2 to `/forum.php` |
| T1105 Ingress Tool Transfer | `/1`, `/2`, `/3` downloads |

## Report (Q10) { #report }

> At 18:38 UTC on 2018-10-01, user anatoliy.demchuk on Anatoliy-PC (172.16.1.125) used Internet Explorer to download a Word file, invoice_284615.doc, from pitchbocaraton.com. The file had an auto-run macro. About 2 minutes later, the PC checked its public IP (31.44.188.95) with api.ipify.org. It then sent C2 POSTs to perranrowsin.com every 2 minutes and downloaded 3 more files from another site. This matches Hancitor (not confirmed by hash). The PC should be isolated and rebuilt, and the user's password reset.

## Detection ideas { #detection }

=== "Zeek"

    ```bash
    # POSTs to forum.php / about.php gates
    zeek-cut -u ts id.orig_h host uri method < http.log | awk -F'\t' '$5=="POST" && $4 ~ /(forum|about)\.php$/'
    # Hosts that ask an IP-check service (worth a look, not proof)
    zeek-cut -u ts id.orig_h host < http.log | grep -i -E "ipify|checkip|icanhazip|ip-api|myexternalip"
    # Old-IE User-Agents from modern Windows
    zeek-cut id.orig_h host user_agent < http.log | grep "MSIE 7.0" | sort | uniq -c
    ```

=== "Snort 2"

    ```text
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Hancitor-style gate POST forum.php"; flow:established,to_server; content:"POST"; http_method; content:"/forum.php"; http_uri; pcre:"/\/(4|mlu)\/forum\.php$/U"; classtype:trojan-activity; sid:1000601; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL External IP lookup api.ipify.org"; flow:established,to_server; content:"Host: api.ipify.org"; http_header; nocase; classtype:policy-violation; sid:1000602; rev:1;)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http method=POST uri IN ("*/forum.php", "*/about.php")
    | stats count min(_time) as first max(_time) as last values(uri) as uris by id.orig_h host
    | eval span_min=round((last-first)/60,1)
    ```

    Index and sourcetype names depend on how Zeek logs are ingested; adjust them. See [Beaconing & C2](../../network/beaconing-c2.md) for interval analysis with `streamstats`.

## Lessons learned { #lessons }

- **One internal host** makes triage fast, but still confirm IP, MAC and hostname from two sources (DHCP + Kerberos/conn).
- **"No EXE after the document"** does not mean "no infection". The payload can be inside the document; watch the traffic that follows instead.
- **Compare User-Agents.** A browser string that differs from the user's real browser, or an impossible one (IE 7 in 2018), points to malware.
- **Use the right tool for each question.** Zeek is best for overview, files and HTTP; tshark is simpler for DHCP options and for reading a single response body.
- **Typo check.** An empty `zeek-cut` column usually means a misspelled field name.
- **Separate confirmed from inferred,** especially malware family names when no hash lookup is possible.
