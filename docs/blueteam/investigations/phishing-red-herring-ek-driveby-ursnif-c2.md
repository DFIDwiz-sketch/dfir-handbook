---
title: Phishing Red Herring to Exploit-Kit Drive-by — Angler-like EK, Ursnif-like C2, CAB Exfil (Splunk + Arkime + Snort)
tags:
  - blue-team
  - pcap
  - email-analysis
  - phishing
  - splunk
  - zeek
  - arkime
  - snort
  - exploit-kit
  - c2
---

# Phishing Red Herring to Exploit-Kit Drive-by — Angler-like EK, Ursnif-like C2, CAB Exfil { #phishing-red-herring-ek }

!!! abstract "Case summary"
    An after-hours SOC analyst receives **seven malicious emails** that slipped past the spam filter, an **employee list**, and a **12-minute PCAP** of a host that raised alerts. The emails are analysed first (headers, MIME, base64, zip internals) and look like the obvious cause. The traffic then shows something else: the host — **Dekker-PC, the Finance Director's workstation** — was infected by **visiting a compromised website**. A Flash-based gate sent the browser to an **exploit kit** (pattern consistent with **Angler EK**), which exploited an outdated **Flash Player 15.0.0.189** and delivered an encrypted payload. Eight seconds later the host began **C2 check-ins** (pattern consistent with **Ursnif / Gozi-ISFB**), downloaded a further encrypted module and **uploaded four CAB-compressed files** to the C2. The emails were a **red herring for this capture** — and a separate lead for other hosts. The case ends with **11 Snort rules tested against the PCAP** and a complete incident report.

| | |
|---|---|
| **Evidence** | 7 `.eml` files (dangerous attachments), an employee list (CSV), one PCAP: 2016-02-05 21:24:05 – 21:36:39 UTC (12 min 34 s), 321 Zeek connections |
| **Environment** | Closed network (no VirusTotal, no OSINT). Splunk with Zeek logs, Arkime v5.6.4 web UI, Snort 2.9 on the analyst workstation |
| **Deliverables** | Email IOC analysis, network analysis, Snort rules that find the traffic again, leads for the host operator |
| **Related pages** | [Spotting exploit kits](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md) · [Base64](../../training/blue-team-essentials/http-analysis/base64.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Beaconing & C2](../../network/beaconing-c2.md) · [Snort rules (DC/SMB)](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) |

!!! tip "How to read this page"
    It is written so a complete beginner can follow it from the first click to the finished report. Every step uses the same order:

    1. **Goal** — what the step tries to find out
    2. **Query / command** — copy it with the **copy button** on the code block
    3. **Explained** — what each piece (each line, each option) means
    4. **Actual result** — what appeared on screen in this case
    5. **Reading the result** — what it means and why it matters

    **Question** boxes are real questions asked during the analysis. **Correction** boxes are places where a first reading was wrong and later evidence fixed it — they are kept on purpose, because spotting and correcting your own mistakes is part of the job.

!!! warning "Indicators on this page are real"
    Domains, IPs and hashes come from real 2016 malware traffic and real spam. They are defanged (`hxxp`, `[.]`) in prose and tables; inside code blocks (queries, rules, raw output) they are left exactly as typed. **Never browse to them. Never open the attachments outside an isolated analysis VM.**

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Host in the PCAP | **10.41.245.114 Dekker-PC**, MAC `00:17:31:7d:52:ba` (ASUSTek NIC), Windows 7 + IE11 — user **Justini Dekker, Finance Director** | Confirmed (DHCP + employee list) |
| Cause of infection | **Web drive-by**: compromised site `www.source-werbeartikel[.]com` → gate `lsbery[.]tk` (85.93.0.32) → exploit kit `bsbkxs.zdxwx3m[.]pw` (86.106.93.167) | Confirmed |
| First malicious event | **21:28:24 UTC** — `GET /shop.php?sid=<86 hex>` to the gate, which returned a Flash file | Confirmed |
| Exploit and payload | Flash exploit `/charge.zhtml` (38,557 bytes) against **Flash 15.0.0.189**; encrypted payload `/today.jst` (360,468 bytes) at 21:28:32 | Confirmed |
| C2 | `tplandthepropforcontent[.]com` (round-robin **185.86.77.12**, **192.210.137.123**), `/images/<base64>/*.gif\|jpeg\|bmp`, from **21:28:41** | Confirmed |
| Exfiltration | **4 POST uploads** of CAB files (`MSCF`) named `XXXX.bin` (21:28:52, 21:30:54, 21:33:16, 21:35:15) | Confirmed |
| Phishing emails | 7 emails, 3 campaigns, zipped `.js` downloaders to 5 users — **no trace in this capture** | Confirmed (not related to this capture) |
| EK family | Angler-like (Flash gate, `/index.php?PHPSESSID=…&action=…` landing, random-English-word parameters, fake extensions) | Inferred |
| Malware family | Ursnif / Gozi-ISFB-like (`/images/` base64 path C2, `upload_file` CAB uploads) | Inferred |
| IDS coverage | Existing Snort alert data contained **nothing** for this host — 11 new rules written, all fired as expected, 0 false positives in the capture | Confirmed |

---

## Part A — The scenario and the given items { #scenario }

### What was given { #given }

The exercise brief, paraphrased:

- You are the only analyst in a 24/7 SOC after hours, and alerts fire for suspicious activity.
- You identified the IP and pulled the related traffic (**the PCAP**).
- You were already examining **malicious emails** that got through the spam filter (**7 `.eml` files**, in a folder named `..._emails_DANGER`).
- You retrieved a **list of people on the network** during the alert window (**employee CSV**: name, login name, job title, work email, phone).
- Leave leads for the **host operator**, and **create Snort rules to find the traffic again**.

---

### The plan { #plan }

1. Analyse the emails (they are already on hand) and pull out IOCs.
2. Use Splunk (Zeek logs) to understand the capture: who, when, what.
3. Test whether the emails explain the traffic — and follow the evidence when they don't.
4. Confirm everything at packet level in Arkime, save evidence, record hashes.
5. Write Snort rules and **test them against the PCAP**.

---

## Part B — Email analysis { #emails }

### Step B0 — Safety first { #email-safety }

!!! danger "The folder is called DANGER for a reason"
    - Work only inside an **isolated Linux analysis VM**. On Windows, double-clicking a `.js` file runs it with `wscript.exe`.
    - Opening an `.eml` in a **text editor** is safe — it is just text.
    - Listing a zip (`unzip -l`), hashing (`sha256sum`) and decoding one line of base64 are safe — nothing executes.
    - Never upload samples to online services. Look up **hashes** only, and only where policy allows (here: closed network, no lookups at all).
    - Rename anything you extract with a `.bin` or `.infected` suffix.

### Step B1 — Read `Received:` headers bottom-up { #received }

Every mail server that handles a message **adds one `Received:` line at the top**. So:

- the **bottom** `Received:` line = where the message started
- the **top** line = the moment it reached our server (`mx1`)

Read them **bottom to top** to follow the path in time order. In each line:

| Part | Meaning |
|---|---|
| `from NAME (… [IP])` | Who connected. **The IP in square brackets is what *our* server saw on the wire — it cannot be forged by the sender.** The name before it is only what the sender claimed |
| `by NAME` | The server that wrote this line |
| `with ESMTP` / `with ESMTPS` | SMTP without / **with** TLS encryption (the `S`) |
| `with local` | The message was created **by a program on that same server** (e.g. a PHP script), not received from another server |
| `for <address>` | The recipient |
| date `-0500`, `+0300` | The server's local time and its offset from UTC. Convert to UTC: `09:25 -0800` = 17:25 UTC |

!!! tip "Which IP is the IOC?"
    The bracketed IP in the **top** `Received:` line (the one that connected to our MX) is the most reliable IOC. But if that server is a **legitimate ISP mail relay** (Mediacom, Telstra …), do not block it — find the real origin further down instead.

### Step B2 — The other headers that matter { #headers }

| Header | What to look for |
|---|---|
| `From:` | Display name vs real address. Fully forgeable |
| `Sender:` / `X-Authenticated-Sender:` / `X-Authentication-Info:` | The account that actually sent it. If it differs from `From:`, someone sent on someone else's behalf — or an account was hijacked |
| `X-PHP-Originating-Script:` / `X-PHP-Script:` | Added by PHP/cPanel hosting: **a PHP script sent this mail**. Typical of mailers uploaded to hacked websites. `X-PHP-Script: site/path.php for <IP>` also reveals **which IP called the script** |
| `X-Mailer:` | The claimed mail client. A "Windows Live Mail" claim next to a PHP header is a forgery |
| `Date:` | Compare with the `Received:` times. Big differences or an impossible time zone = forged or queued |
| `Message-ID:` | Must be `<unique@domain>`. An empty domain (`<…@>`) is malformed |
| `Content-Type: multipart/mixed; boundary=…` | The message has several parts separated by the boundary string |
| `Content-Transfer-Encoding:` | How the part is encoded (see [B4](#encodings)) |
| `Content-Disposition: attachment; filename=…` | This part is an attachment, and its name |

### Step B3 — Getting the file name inside a zip attachment { #zip-inside }

**Goal:** know what is *inside* the attachment without running anything.

The attachment headers show only the **zip name**:

```text
Content-Type: application/x-zip-compressed;
        name="invoice304-18.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
        filename="invoice304-18.zip"
```

- `Content-Type: application/x-zip-compressed` — the part claims to be a zip.
- `name=` / `filename=` — the name the recipient sees.
- `Content-Transfer-Encoding: base64` — the binary zip was turned into text so it can travel in email.
- `Content-Disposition: attachment` — a separate attachment, not inline content.

The name of the file **inside** the zip is hidden in the base64 block. Three ways to read it:

#### Method 1 — decode only the first line of base64 { #b64-first-line }

```bash
echo 'UEsDBBQAAAAIAJFhRUhPkndCTgsAAGUdAAAQAAAAaW52b2ljZTMwNC0xOC5qc41ZW4+jyBV+718x' | base64 -d | xxd | head -4
```

- `echo '…'` — print the first base64 line.
- `| base64 -d` — decode base64 back to bytes (`-d` = decode).
- `| xxd` — show the bytes as hex next to printable characters (if `xxd` is missing: `od -A x -t x1z`).
- `| head -4` — first 4 lines only.

Actual result:

```text
00000000: 504b 0304 1400 0000 0800 9161 4548 4f92  PK.........aEHO.
00000010: 7742 4e0b 0000 651d 0000 1000 0000 696e  wBN...e.......in
00000020: 766f 6963 6533 3034 2d31 382e 6a73 8d59  voice304-18.js.Y
```

The right-hand column shows **`invoice304-18.js`** — a JavaScript file.

**Why `UEsDB` means zip:** every zip starts with the bytes `PK` (Phil Katz). `PK\x03\x04` in base64 is always `UEsDB`. Memorise a few:

| base64 starts with | Real file type |
|---|---|
| `UEsDB` | ZIP (also .docx, .xlsx, .jar — they are zips) |
| `TVqQ` | Windows executable `MZ` (.exe/.dll) |
| `JVBERi` | PDF (`%PDF`) |
| `0M8R4K` | Old Office (.doc/.xls, OLE) |
| `iVBORw0K` | PNG |
| `/9j/` | JPEG |

**The zip local file header, byte by byte:**

| Bytes (hex) | Meaning | Value |
|---|---|---|
| `50 4b 03 04` | Zip signature | `PK..` |
| `14 00` | Version needed | 2.0 |
| `00 00` | Flags | No encryption |
| `08 00` | Compression method | 8 = Deflate |
| `91 61` / `45 48` | DOS time / date | 2016-02-05 12:12:34 (local time of the PC that made it) |
| `4f 92 77 42` | CRC-32 | — |
| `4e 0b 00 00` | **Compressed size** | 0x0B4E = 2,894 bytes |
| `65 1d 00 00` | **Uncompressed size** | 0x1D65 = **7,525 bytes (~7.5 KB)** |
| `10 00` | File-name length | 0x10 = 16 characters |
| `00 00` | Extra-field length | 0 |
| `69 6e 76 …` | **File name** | `invoice304-18.js` |

!!! note "Little-endian"
    Zip stores numbers **backwards**. `65 1d` is read as `1d65` = 7,525. `10 00` is `0010` = 16, so the next 16 bytes are the name.

The **last 2–3 lines** of the base64 block hold the zip's central directory and end record. Decode them the same way to see the name again and the **number of files** in the zip.

#### Method 2 — extract the attachment and list the zip { #extract-list }

```bash
mkdir ~/email1_attach && cd ~/email1_attach
python3 -c "
import email, sys
msg = email.message_from_file(open(sys.argv[1]))
for part in msg.walk():
    name = part.get_filename()
    if name:
        open(name, 'wb').write(part.get_payload(decode=True))
        print('saved:', name)
" ~/PCAPS/.../Phase2_PCAP_1_email_092704UTC.eml
unzip -l invoice304-18.zip
sha256sum invoice304-18.zip
unzip -p invoice304-18.zip | sha256sum
```

- `email.message_from_file(...)` — parses the `.eml` into its MIME parts.
- `msg.walk()` — visits every part (text, HTML, attachments).
- `part.get_filename()` — only attachments have a file name.
- `get_payload(decode=True)` — base64-decodes the part back to the original zip bytes.
- `unzip -l` — **lists** the zip without extracting (`-l` = list). Nothing is written to disk.
- `sha256sum` — the hash for the report (look up hashes, never upload files).
- `unzip -p … | sha256sum` — `-p` streams the inner file to the next command without writing it, so you can hash the `.js` itself.

Expected `unzip -l` output:

```text
Archive:  invoice304-18.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     7525  2016-02-05 12:12   invoice304-18.js
---------                     -------
     7525                     1 file
```

The same name and size as Method 1. `zipinfo -v` shows more (compressed size, CRC, extra fields).

#### Method 3 — other tools { #other-tools }

- **CyberChef** (offline): paste the base64 → `From Base64` → `Unzip`. Shows names and contents (nothing executes).
- **Arkime** shows the attachment name (`email.fn`) for cleartext SMTP, but not what is inside the zip.
- **Zeek `files.log`** shows the zip name, hash and MIME type, not the inner names.

### Step B4 — Is email always base64? { #encodings }

!!! question "Question: Is email always sent as base64?"
    No. SMTP was built for **7-bit ASCII text** with lines under 1,000 characters. **MIME** lets each part declare its encoding in `Content-Transfer-Encoding`. All five appear in these seven emails:

    | Encoding | Meaning | Typical use | In this case |
    |---|---|---|---|
    | `7bit` | Plain ASCII, unchanged | English body | Emails 3, 4 body |
    | `8bit` | Unchanged, may contain non-ASCII | Body (when servers support 8BITMIME) | Email 2 body |
    | `quoted-printable` | Mostly unchanged, special bytes as `=XX` | Mostly-English text with a few special characters | Emails 1, 5, 6, 7 body |
    | `base64` | Everything turned into A–Z a–z 0–9 + / | **Attachments**, images | All 7 attachments |
    | `binary` | Raw bytes | Rare | — |

**Reading quoted-printable** (Email 1 body):

```text
We=A0are sorry to=A0inform you,=A0but the item you have=A0purchased is=A0=
```

- `=A0` — byte 0xA0, a non-breaking space in windows-1251.
- `=20` — a normal space (written out so a trailing space is not lost).
- `=` at the **end of a line** — soft line break: the sentence continues on the next line.
- `=3D` — the `=` character itself (`bgColor=3D#ffffff` = `bgColor=#ffffff`).

**Headers can be encoded too** (encoded-words):

```text
Subject: =?UTF-8?B?7ZmY67aI?=
Subject: =?UTF-8?Q?Refund_=E2=80=93_Order?=
```

`?B?` = base64, `?Q?` = quoted-printable. Phishers sometimes encode subjects this way to slip past keyword filters — a header-based IDS rule will miss them.

!!! question "Question: So base64 means there is an executable attachment?"
    No. base64 only means "content that could not travel as plain text". Normal mail is full of it: signature logos, PDFs, Office files, even whole bodies with non-English text. When you see base64, check three things:

    1. **Attachment or inline?** `Content-Disposition: attachment` = a file the user opens; `inline` or `Content-ID:` = an image shown in the body.
    2. **What does it claim to be?** `Content-Type` and `filename=` — written by the sender, so they can lie.
    3. **What is it really?** Decode the first line and read the magic bytes (table in [B3](#b64-first-line)). Only `TVqQ` (`MZ`) is a real Windows executable — and filters usually block those.

    Dangerous attachments are wider than "executables": **scripts** (.js .vbs .wsf .hta .ps1 .bat), **macro documents** (.docm, .xlsm, macro .doc/.xls), **shortcuts and disk images** (.lnk, .iso, .img), **HTML** (fake login pages), **PDF** (links, JavaScript). A zip — or a **zip inside a zip** — around them is a common filter bypass. So when you see a zip, always read the name of the file inside.

### Step B5 — Email 1 (09:27:04 UTC, to mtsutsumi) { #email-1 }

**Recipient:** mtsutsumi — Maki Tsutsumi, Network Security Engineer.

**Path (bottom-up):**

```text
Received: by host5.t1host.ru (Postfix, from userid 33)
        id C7640600993F; Fri,  5 Feb 2016 12:25:56 +0300 (MSK)
Received: from host5.t1host.ru (static.213-133-123-17.clients.your-server.de [213.133.123.17])
        by mx1.<customer-domain> with ESMTPS id u159R1H1038361
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO)
        for <mtsutsumi@<customer-domain>>; Fri, 5 Feb 2016 09:27:04 GMT
```

- Created on `host5.t1host[.]ru` by Postfix **from userid 33** (a web-server user) at 12:25:56 MSK = **09:25:56 UTC**.
- Delivered from **213.133.123.17** (reverse name `your-server.de`, a German hosting provider) at **09:27:04 UTC**, over **TLS** (`ESMTPS`).

**Headers:**

| Header | Value | Reading |
|---|---|---|
| From | `"Lewis Mckay" <elit@faucibusidlibero[.]com>` | Name and domain unrelated. "faucibus id libero" is Lorem-ipsum text — a fake domain |
| Subject | `Refund for the Order #284822` | Refund lure |
| X-PHP-Originating-Script | `33:configsese.php` | Sent by a **PHP script** on a hacked web server |
| X-Mailer | `Microsoft Windows Live Mail 16.4.3528.331` | Contradicts the PHP header — forged |
| Date | `Fri, 5 Feb 2016 09:25:35 -0800` | = 17:25 UTC, eight hours **after** it arrived. The sender wrote its UTC clock with a wrong `-0800` offset |
| Message-ID | `<1AE0A0968D5975568A8FC67F6BB04CFB@faucibusidlibero.com>` | Fake domain again |

**Attachment:** `invoice304-18.zip` (`application/x-zip-compressed`) → **`invoice304-18.js`**, 2,894 bytes compressed, 7,525 bytes uncompressed, zip time 12:12:34.

**Assessment:** a **JavaScript downloader** — the classic early-2016 pattern (Nemucod-style droppers that fetch ransomware). If run, `wscript.exe` executes it and downloads an `.exe`.

### Step B6 — Email 2 (09:34:13 UTC, to jdekker) — a different campaign { #email-2 }

**Recipient:** jdekker — **Justini Dekker, Finance Director**.

**Path (bottom-up):**

```text
Received: from love2dat by server.hoast.com with local (Exim 4.86)
        (envelope-from <love2dat@server.hoast.com>)
        id 1aQpdL-0004cE-9d; Wed, 03 Feb 2016 00:05:39 -0500
Received: from server.hoast.com (server.hoast.com [67.222.128.148])
        by mx1.<customer-domain> with ESMTPS id u159YBT4009585
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=NO)
        for <jdekker@<customer-domain>>; Fri, 5 Feb 2016 09:34:13 GMT
```

- `from love2dat` + `with local` — created **inside** `server.hoast[.]com` by the local hosting account `love2dat`, not received from another server. Exim is the default MTA on cPanel hosting.
- Created **Wed 3 Feb 00:05:39 -0500 = 05:05:39 UTC**; delivered **Fri 5 Feb 09:34:13 UTC** — **about 52 hours** later. Bulk spam sitting in a queue, or repeated retries. Either way the campaign **started two days earlier**, so other organisations may already have published IOCs.
- `verify=NO` — mx1 did not verify the sender's certificate. Normal between mail servers; not suspicious by itself.

**Who really sent it — five headers:**

```text
From: "Finance Department" <wgygbcgync@love2date.us>
Sender:  <love2dat@server.hoast.com>
X-Get-Message-Sender-Via: server.hoast.com: authenticated_id: love2dat/from_h
X-Authenticated-Sender: server.hoast.com: wgygbcgync@love2date.us
X-PHP-Script: love2date.us/headers/wrigs61.php for 185.60.133.27
```

- `From` — "Finance Department", but the address is a random string at a dating-site domain.
- `Sender` — the account that really sent it.
- `X-Get-Message-Sender-Via` / `X-Authenticated-Sender` — **cPanel** adds these to trace spam to a hosting account: the hosting account `love2dat` sent it, taking the From address from the header (`from_h`).
- **`X-PHP-Script: love2date.us/headers/wrigs61.php for 185.60.133.27`** — the PHP file `/headers/wrigs61.php` on `love2date[.]us` sent it, and **185.60.133.27 called that script over the web**. A dating site has no reason for a randomly named script under `/headers/` → the site was hacked and a mailer uploaded. 185.60.133.27 is the closest IP to the attacker — record it as a **threat-intel IOC** (it never talked to our network).

```text
185.60.133.27 --(web request)--> love2date.us/headers/wrigs61.php (on server.hoast.com)
   -> Exim creates the mail (Feb 3 05:05 UTC)
   -> 67.222.128.148 (server.hoast.com) --(SMTP over TLS)--> mx1 (Feb 5 09:34 UTC)
   -> jdekker mailbox
```

**Other oddities:**

- `To:` appears **twice** — a sloppy mailer.
- `Message-ID: <211504694.20160203000538@>` — **empty domain**, malformed. The number contains the creation time 2016-02-03 00:05:38.
- `Date: Wed, 3 Feb 2016 0:05:38 -0500` — matches the bottom `Received:` line, so this Date is genuine (unlike Email 1). Another sign of a **different tool**.
- No `X-Mailer` at all.

**Body** (`text/html`, `8bit`): "NOTICE! You have received a remittance … Money Order can be cashed at any branch or bank in Your city . … Division of Payments WU000076846645". Greed lure aimed at a finance director; capital `Your` mid-sentence; a space before the full stop; image `alt="western unioun"`.

```html
<IMG ... alt="western unioun" ... src="https://www.cehost.ro/templates/cehostv3/html/images/westernunion_logo_big.gif">
```

!!! tip "A remote image tells you who opened the email"
    The logo is **loaded from another website** instead of being embedded. When anyone opens the HTML, their PC makes a **DNS query for `www.cehost[.]ro`** and an **HTTPS connection** to it (the name is visible in the TLS SNI). Both appear in Zeek `dns.log` / `ssl.log` — so you can find **who opened the email and when** without reading the mail. `cehost[.]ro` looks like a Romanian hosting company being hot-linked; treat it as an **"opened" indicator**, not a block IOC.

**Attachment — a zip inside a zip:**

```text
Content-Type: application/octet-stream;
 name="WU7328899085.zip"
Content-transfer-encoding: base64
Content-Disposition: attachment;
 filename="WU7328899085.zip"
```

`application/octet-stream` ("just bytes") hides the type, unlike Email 1. Decode the first two base64 lines together:

```bash
echo 'UEsDBAoAAAAAAIEoQ0gqQtZfwgYAAMIGAAAIABwAZmlsZS56aXBVVAkAA0GKsVZ9irFWdXgLAAEEAAAAAAQAAAAAUEsDBBQACAAIAPWiQkgAAAAAAAAAAAAAAAAWAAAAaW52b2ljZV9zY2FuX0RneUVmbC5qc' | base64 -d | xxd
```

(The tail is cut mid-character, so `base64` may warn `invalid input` — the start decodes fine.)

```text
00000000: 504b 0304 0a00 0000 0000 8128 4348 2a42  PK.........(CH*B
00000010: d65f c206 0000 c206 0000 0800 1c00 6669  ._............fi
00000020: 6c65 2e7a 6970 5554 0900 0341 8ab1 567d  le.zipUT...A..V}
00000030: 8ab1 5675 780b 0001 0400 0000 0004 0000  ..Vux...........
00000040: 0000 504b 0304 1400 0800 0800 f5a2 4248  ..PK..........BH
00000050: 0000 0000 0000 0000 0000 0000 1600 0000  ................
00000060: 696e 766f 6963 655f 7363 616e 5f44 6779  invoice_scan_Dgy
00000070: 4566 6c2e 6a                             Efl.j
```

**Two `PK` signatures = two zips.**

Outer zip `WU7328899085.zip`:

| Bytes | Meaning | Value |
|---|---|---|
| `0a 00` | Version | 1.0 |
| `00 00` | Compression | **0 = stored** (a zip is already compressed) |
| `81 28` / `43 48` | Time / date | 2016-02-03 05:04:02 |
| `c2 06 00 00` ×2 | Compressed = uncompressed size | 1,730 bytes |
| `08 00` / `1c 00` | Name length / extra length | 8 / 28 |
| name | | **`file.zip`** |
| `UT …` `ux …` | Extra fields | Unix timestamp + Unix UID → built with Linux `zip`. `UT` time = **2016-02-03 05:04:01 UTC**, 1.5 min before the mail was created |

Inner zip `file.zip` (starts at byte 0x42 = 66 = 30 + 8 + 28):

| Bytes | Meaning | Value |
|---|---|---|
| `08 00` (flags) | Bit 3 set | Sizes written **after** the data (streamed creation) — so CRC and sizes here are 0 |
| `08 00` | Compression | Deflate |
| `f5 a2` / `42 48` | Time / date | 2016-02-02 20:23:42 |
| `16 00` | Name length | 22 |
| name | | **`invoice_scan_DgyEfl.js`** (random suffix per recipient) |

The real sizes are in the central directory at the end (decode the last base64 lines): **1,572 bytes compressed, 4,500 bytes uncompressed** — a different script from Email 1's 7,525 bytes.

**Why two zips?** Many mail gateways open only **one** layer. One layer shows just `file.zip`, so the `.js` inside slips through.

Confirming with the full file:

```bash
unzip -l WU7328899085.zip
unzip -p WU7328899085.zip file.zip > file.zip
unzip -l file.zip
sha256sum WU7328899085.zip file.zip
```

```text
Archive:  WU7328899085.zip
     1730  2016-02-03 05:04   file.zip
Archive:  file.zip
     4500  2016-02-02 20:23   invoice_scan_DgyEfl.js
```

### Step B7 — Email 3 (11:42:38 UTC, to smunro) — hijacked ISP account { #email-3 }

**Recipient:** smunro — Shane Munro, Help Desk Technician.

```text
Received: from localhost ([162.17.68.145])
        by njtocomv02.mcomdc.com with bizsmtp
        id EbiZ1s00Q38388201bicbg; Fri, 05 Feb 2016 06:42:37 -0500
Received: from [68.66.77.76] ([68.66.77.76:32973] helo=dsmdc-mail-smtp.mcomdc.com)
        by mx1.<customer-domain> (envelope-from <tglorfield@mchsi.com>)
        (ecelerity 2.2.3.49 r(42060/42061)) with ESMTP
        id 14/B9-03142-DAA84B65; Fri, 05 Feb 2016 06:42:38 -0500
X-Authenticated-Sender: tglorfield@mchsi.com
```

- First injected from **162.17.68.145** into Mediacom's outbound server, then relayed by `dsmdc-mail-smtp.mcomdc[.]com` **[68.66.77.76]** to mx1 at 06:42:38 -0500 = **11:42:38 UTC**, **plain ESMTP** (no TLS).
- `X-Authenticated-Sender: tglorfield@mchsi[.]com` — the sender **logged in** to a real Mediacom account → most likely a **hijacked account**, not a PHP mailer.
- So 68.66.77.76 is a **legitimate ISP relay — do not block it**. The real origin is **162.17.68.145**.

| Header | Value | Reading |
|---|---|---|
| From | `"Dorian Potter" <tglorfield@mchsi[.]com>` | Name ≠ address |
| Subject | `URGENT - There is a problem with your parcel #362630` | Delivery/urgency lure. Note: no space after `Subject:` |
| Body | `Respected Customer, Dorian Potter …` | Greets the **sender's fake name**, not the recipient |
| X-ThreatReport (base64) | decodes to `VirusName: ThreatSeeker` | An upstream filter **flagged it as a threat but it was still delivered** |

Decoding a security header (safe — it is text):

```bash
echo 'VmlydXNOYW1lOiBUaHJlYXRTZWVrZXIKU2Nhbm5lcnM6IENDQSgxKSxBVVRIKDIwMTYwMjA1MDkyNiksVGhyZWF0U2Vla2VyKDEp' | base64 -d
```

```text
VirusName: ThreatSeeker
Scanners: CCA(1),AUTH(201602050926),ThreatSeeker(1)
```

**Attachment:** `Dorian Potter.zip` (`application/zip`) → **`Dorian Potter.js`**, 4,613 / 7,068 bytes. Zip time **11:42:30** vs mail Date **11:42:31** — built **one second before sending**: a bulk tool generating a new attachment per recipient, so **hashes will differ per email**.

### Step B8 — Email 4 (13:30:37 UTC, to mtraugott) — same campaign as Email 3 { #email-4 }

**Recipient:** mtraugott — Matthias Traugott, Application Support Engineer.

```text
Received: from localhost ([186.50.4.59])
        by nschwcmgw06p with BigPond Outbound
        id EdWU1s00A1GPwME01dWXeb; Fri, 05 Feb 2016 13:30:33 +0000
Received: from nschwcmgw06p ([61.9.190.166]) by nschwmtas02p.mx.bigpond.com ...
Received: from nschwmtas02p.mx.bigpond.com (nschwmtas02p.mx.bigpond.com [61.9.189.140])
        by mx1.<customer-domain> with ESMTPS id u15DUYUi002575
        (version=TLSv1.2 cipher=DHE-RSA-AES256-GCM-SHA384 bits=256 verify=FAIL)
        for <mtraugott@<customer-domain>>; Fri, 5 Feb 2016 13:30:37 GMT
X-Authentication-Info: Submitted using ID jock_margie@bigpond.com
```

- Origin **186.50.4.59** (186.x is usually a LACNIC / Latin-America allocation — confirm with WHOIS) → Telstra BigPond relays 61.9.190.166 → **61.9.189.140** → mx1, over TLS.
- `Submitted using ID jock_margie@bigpond[.]com` — logged into a real BigPond account → **hijacked account**. 61.9.x.x are legitimate Telstra servers — **do not block**.
- `From: "Emmett Summers" <jock_margie@bigpond.com.au>` — the authenticated ID is `@bigpond.com`, the From is `@bigpond.com.au`.
- Subject `URGENT - There is a delay with your purchase #422585`; body `Respected Customer, Emmett Summers` — almost word-for-word Email 3 (package→order, shipping→logistics, 10→5 business days).
- **Attachment:** `Emmett Summers.zip` → **`Emmett Summers.js`**, 4,604 / 7,054 bytes, zip time **13:30:24**, Date **13:30:25** — again built a second before sending.

**Pattern for this campaign:** the fake sender name is reused as the greeting **and** the zip/js name.

### Step B9 — Email 5 (13:40:27 UTC, to smunro) — Email 1's twin { #email-5 }

```text
Received: by b106.mac7.ru (Postfix, from userid 48)
        id F00EB6885CF; Fri,  5 Feb 2016 16:19:59 +0300 (MSK)
Received: from b106.mac7.ru (b106.mac7.ru [212.232.52.106])
        by mx1.<customer-domain> with ESMTP id u15DeP6g020511
        for <smunro@<customer-domain>>; Fri, 5 Feb 2016 13:40:27 GMT
```

- Left `b106.mac7[.]ru` [**212.232.52.106**] at 16:19:59 MSK = 13:19:59 UTC, reached mx1 at 13:40:27 UTC (~20 min queued), plain ESMTP.
- `X-PHP-Originating-Script: 48:configsese.php` — the **same script name** as Email 1 (the number is the server's UID, so it differs per hacked server).
- Subject `Refund for the Order #284822` — **the same order number**.
- From `"Ferdinand Barber" <ipsum.Donec@odioauctor[.]org>` — Lorem-ipsum domain again; `X-Mailer: Windows Live Mail 15.4.3538.513` (forged); `Date: 13:19:15 -0800` (the same wrong-offset mistake).
- **Attachment:** `invoice304-3.zip` → **`invoice304-3.js`**, 2,928 / 7,413 bytes, zip time **12:12:24**.

**Same batch as Email 1:** `invoice304-18.js` was stamped 12:12:34 — **ten seconds apart**. The number after `invoice304-` is the item number in one batch.

!!! warning "Shane Munro was targeted twice"
    smunro received Email 3 (11:42, campaign B) **and** Email 5 (13:40, campaign A). Help-desk staff often have elevated access — a high-value target. If you can, check their host after **both** times.

### Step B10 — Email 6 (18:23:42 UTC, to jdekker via **mx2**) { #email-6 }

```text
Received: by b106.mac7.ru (Postfix, from userid 48)
        id A96CC729DE6; Fri,  5 Feb 2016 18:07:01 +0300 (MSK)
Received: from b106.mac7.ru (b106.mac7.ru [212.232.52.106])
        by mx2.<customer-domain> with ESMTP id u15INfdw020639
        for <jdekker@<customer-domain>>; Fri, 5 Feb 2016 18:23:42 GMT
```

- Same server, UID 48, `configsese.php`, subject `Refund for the Order #284822`.
- From `"Chaney Vinson" <vestibulum@ullamcorpermagnaSed[.]edu>`; Date `15:06:34 -0800` (same mistake); X-Mailer WLM 16.4.3528.331.
- **Delivered by `mx2`** — the company has **two MX servers**. Any search filtered on mx1's IP misses this email.
- **Attachment:** `invoice304-25.zip` → **`invoice304-25.js`**, 2,922 / 7,571 bytes.
- jdekker is the **second user targeted twice** (Emails 2 and 6).

!!! note "Correction — the attacker's clock"
    This zip also carried an **NTFS extra field**, whose times are always **UTC**. Its modification time was **08:12:38 UTC**, while the DOS time was 12:12:38 — so the attacker's PC clock was **UTC+4**, not MSK (UTC+3) as first assumed. All four `invoice304-N.js` files (DOS 12:12:24, 12:12:34, 12:12:38, 12:12:40) were therefore created at **~08:12 UTC within 16 seconds**, then sent from different servers at different times all day.

    How the NTFS time was read: the extra field holds three little-endian 64-bit FILETIME values (100-ns ticks since 1601-01-01):

    ```bash
    python3 -c "
    import datetime, struct
    v = struct.unpack('<Q', bytes.fromhex('005fe6f9ec5fd101'))[0]
    print(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=v//10))"
    ```

    ```text
    2016-02-05 08:12:38
    ```

### Step B11 — Email 7 (18:23:43 UTC, to culyanova) { #email-7 }

- Same server `b106.mac7[.]ru`, UID 48, `configsese.php`, subject `Refund for the Order #284822`, delivered by **mx1**.
- From `"Linus Kirk" <in.aliquet@nislMaecenasmalesuada[.]com>`; X-Mailer WLM **14.0.8117.416** (the version changes per email); Date `15:06:27 -0800`.
- **Attachment:** `invoice304-27.zip` → **`invoice304-27.js`**, 2,983 / 7,715 bytes, zip time 12:12:40 (= 08:12:40 UTC, same batch).
- **Recipient is the System Administrator** — the highest-impact target.

!!! note "Correction — why Emails 6 and 7 arrived three hours late"
    At first it looked like mx1 rejected Email 6 and it was retried to mx2. Email 7 disproves that: Emails 6 and 7 left the attacker's server **4 seconds apart** (18:07:01 / 18:06:57 MSK) and arrived **1 second apart** (mx2 18:23:42 / mx1 18:23:43), both ~3 h 17 min late. The delay was on the **sender's queue**, which then delivered to both MX servers at once.

### Step B12 — All seven emails, grouped into campaigns { #email-campaigns }

| # | Arrived (UTC) | MX | Recipient | Campaign | Connecting IP | Attachment → inner file |
|---|---|---|---|---|---|---|
| 1 | 09:27:04 | mx1 (TLS) | mtsutsumi — Network Security Engineer | A | 213.133.123.17 | invoice304-18.zip → .js |
| 2 | 09:34:13 | mx1 (TLS) | jdekker — Finance Director | C | 67.222.128.148 | WU7328899085.zip → file.zip → invoice_scan_DgyEfl.js |
| 3 | 11:42:38 | mx1 | smunro — Help Desk Technician | B | 68.66.77.76 (origin 162.17.68.145) | Dorian Potter.zip → .js |
| 4 | 13:30:37 | mx1 (TLS) | mtraugott — Application Support Engineer | B | 61.9.189.140 (origin 186.50.4.59) | Emmett Summers.zip → .js |
| 5 | 13:40:27 | mx1 | smunro | A | 212.232.52.106 | invoice304-3.zip → .js |
| 6 | 18:23:42 | **mx2** | jdekker | A | 212.232.52.106 | invoice304-25.zip → .js |
| 7 | 18:23:43 | mx1 | culyanova — System Administrator | A | 212.232.52.106 | invoice304-27.zip → .js |

- **Campaign A** — PHP mailer `configsese.php` on hacked `.ru` hosts; lure "Refund for the Order #284822"; `invoice304-N.zip`; Lorem-ipsum sender domains (`faucibusidlibero[.]com`, `odioauctor[.]org`, `ullamcorpermagnaSed[.]edu`, `nislMaecenasmalesuada[.]com`); forged X-Mailer; Date with a wrong `-0800`.
- **Campaign B** — hijacked ISP webmail accounts (`tglorfield@mchsi[.]com`, `jock_margie@bigpond[.]com`); lure "URGENT - There is a …"; `<fake name>.zip` → `<fake name>.js` built seconds before sending.
- **Campaign C** — PHP mailer on hacked `love2date[.]us` (`server.hoast[.]com`, called by 185.60.133.27); Western Union lure; zip-in-zip; remote image from `www.cehost[.]ro`.

All three deliver a **zipped JavaScript downloader**. If run: `wscript.exe` executes the `.js` → downloads an `.exe` → C2.

### Step B13 — What a network sensor can see of these emails { #starttls }

!!! warning "STARTTLS hides the mail"
    `with ESMTPS … TLSv1.2` in the top `Received:` line means the hop **into our MX was encrypted**. A sensor on that link sees only TLS — no subject, no attachment name.

    - **Encrypted (ESMTPS):** Emails 1, 2, 4
    - **Cleartext (ESMTP):** Emails 3, 5, 6, 7

    So content-based Snort rules can only fire on 3, 5, 6, 7 (unless a later internal hop — MX to mail server, POP3/IMAP, webmail — is cleartext). IP-based rules still work, and Zeek `ssl.log` (port 25, matching time and cipher) still proves delivery.

Splunk check for encrypted delivery (in a capture that contains SMTP):

```spl
index=zeek sourcetype=zeek:ssl id_resp_p=25
| table _time id_orig_h id_resp_h version cipher server_name
```

- `id_resp_p=25` — TLS sessions whose server port is 25 (SMTP with STARTTLS).
- If `213.133.123.17` appears at 09:27 with `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`, it matches Email 1's `Received:` header exactly.

### Step B14 — Email IOCs and email detection rules { #email-iocs }

| Type | Value | Note |
|---|---|---|
| IP | 213.133.123.17, 212.232.52.106 | Campaign A senders |
| IP | 67.222.128.148 | Campaign C sender (server.hoast[.]com) |
| IP | 185.60.133.27 | Called the campaign C PHP mailer — threat intel only |
| IP | 162.17.68.145, 186.50.4.59 | Campaign B origins (relays 68.66.77.76, 61.9.189.140 are legitimate ISPs — do not block) |
| Script | `configsese.php`, `love2date.us/headers/wrigs61.php` | PHP mailers |
| Domain | faucibusidlibero[.]com, odioauctor[.]org, ullamcorpermagnaSed[.]edu, nislMaecenasmalesuada[.]com, love2date[.]us | Sender domains |
| Account | tglorfield@mchsi[.]com, jock_margie@bigpond[.]com | Hijacked accounts |
| Subject | `Refund for the Order #284822`, `URGENT - There is a …`, `Western Union: Money Transfer For You` | |
| Files | invoice304-N.zip/.js, `<Name>.zip/.js`, WU7328899085.zip → file.zip → invoice_scan_DgyEfl.js | |
| "Opened" indicator | www.cehost[.]ro | Remote image in Email 2 |

Header-based Snort rules for the emails (Snort 2). **Not tested** — this PCAP contains no mail traffic; remember the STARTTLS caveat above:

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign A configsese.php mailer invoice304 zip"; flow:to_server,established; content:"X-PHP-Originating-Script|3a|"; nocase; content:"configsese.php"; nocase; distance:0; content:"invoice304-"; nocase; distance:0; classtype:trojan-activity; sid:1000001; rev:1;)
alert tcp [213.133.123.17,212.232.52.106] any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign A known sender servers"; flow:to_server,established; classtype:trojan-activity; sid:1000002; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign B URGENT delivery lure with zip"; flow:to_server,established; content:"URGENT - There is a"; nocase; content:"Respected Customer,"; nocase; distance:0; content:"application/zip"; nocase; distance:0; classtype:trojan-activity; sid:1000003; rev:1;)
alert tcp $EXTERNAL_NET any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign C Western Union lure"; flow:to_server,established; content:"Western Union|3a| Money Transfer"; nocase; content:".zip"; nocase; distance:0; classtype:trojan-activity; sid:1000004; rev:1;)
alert tcp 67.222.128.148 any -> $HOME_NET 25 (msg:"LOCAL PHISH Campaign C sender server.hoast.com"; flow:to_server,established; classtype:trojan-activity; sid:1000005; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL PHISH Campaign C email opened - DNS cehost.ro"; content:"|06|cehost|02|ro|00|"; nocase; classtype:trojan-activity; sid:1000006; rev:1;)
```

- `|3a|` = `:` in hex, `|22|` = `"`. `distance:0` = the next string must appear **after** the previous one (header → body → attachment order).
- sid 1000003 matches the subject text without `Subject:` because Email 3 has no space after the colon (`Subject:URGENT`).
- sid 1000006 uses the DNS wire format: `|06|cehost|02|ro|00|` = 6 letters "cehost", 2 letters "ro", end.
- Rules are explained in detail in [Part F](#rule-anatomy).

---

## Part C — Splunk (Zeek logs) { #splunk }

### Step C0 — Time traps before the first search { #splunk-time }

!!! question "Question: I cannot find the user name / Preferences menu to set the time zone to UTC"
    The user menu is the **account name** at the far left of the top-right menu bar (`Administrator`, `admin`, or a person's name) — it is not labelled "user name". On a narrow window the bar may collapse into `☰`. With admin rights you can also use **Settings → Users → your account → Time zone**. Training kits often lock this. If so, use the two methods below — they are more reliable anyway.

1. **Show Zeek's own time.** Splunk's `_time` is converted to *your account's* time zone. Zeek's `ts` field is the original event time in **UTC** (epoch seconds). Put `ts` next to `_time`, or convert it with `strftime`.
2. **Use epoch numbers for time limits.** `earliest="02/05/2016:09:00:00"` is read in your account's time zone. Epoch numbers are the same instant everywhere:

| UTC | epoch |
|---|---|
| 2016-02-05 00:00 | 1454630400 |
| 2016-02-05 09:00 | 1454662800 |
| 2016-02-05 10:00 | 1454666400 |
| 2016-02-06 00:00 | 1454716800 |

1 hour = 3600, 1 minute = 60. Example: 09:27 = 1454662800 + 27×60 = 1454664420.

In this case the search bar showed `before 11/18/26 10:21:37 AM` while the local time (Adelaide, UTC+10:30) was 20:53 — i.e. **the Splunk UI was already showing UTC**. Checking the "before …" time against your clock is a quick way to work out the UI's time zone.

### Step C1 — Which indexes and sourcetypes exist? { #data-discovery }

**Goal:** learn the real index/sourcetype names before writing any search.

```spl
| tstats count where index=* by index sourcetype
| sort index sourcetype
```

- `| tstats` — counts from the index metadata without reading each event (fast). The leading `|` means the search starts with a command.
- `where index=*` — all indexes. (If your policy forbids `index=*`, use the **Data Summary** button instead.)
- `by index sourcetype` — one row per combination.
- Time range: **All time** (the data is from 2016).

**Actual result:**

| index | sourcetype | count |
|---|---|---|
| main | csv | 55,893 |
| zeek | zeek:conn | 321 |
| zeek | zeek:dhcp | 5 |
| zeek | zeek:dns | 79 |
| zeek | zeek:files | 245 |
| zeek | zeek:http | 255 |
| zeek | zeek:packet_filter | 1 |
| zeek | zeek:ssl | 113 |
| zeek | zeek:x509 | 28 |

**Reading:**

- Sourcetypes are `zeek:conn` style (**not** `conn:zeek`) — use these exact names.
- There is **no `zeek:smtp`**, no Kerberos, no NTLM — Zeek saw no SMTP.
- Only **321 connections** — not a whole company's day but **one alerting host's traffic**. The emails are probably **not** in this PCAP; they are reference material. That changes the plan: *who is this host → what did it do → which email (if any) explains it*.
- No Suricata index. `main`/`csv` (55,893 rows) needs checking.

**Field names:** run `index=zeek sourcetype=zeek:conn | head 1` and look at the field list: `id_orig_h` (underscore), `id_orig_p`, `id_resp_h`, `id_resp_p`, `uid`, `ts` (numeric `#`), `timestamp`, `local_orig`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `service` … Underscores are used, so no quoting is needed.

### Step C2 — Which hosts are in the capture? { #hosts }

```spl
index=zeek sourcetype=zeek:conn
| stats count by id_orig_h
| sort - count
```

- `stats count by id_orig_h` — number of connections started by each source IP.
- `sort - count` — descending (`-`).

**Actual result:** one row — **`10.41.245.114` 321**. Every connection was started by one host. **This is the host of interest.**

!!! question "Question: why did `min(timestamp)` / `max(timestamp)` show `none`?"
    `timestamp` is a **string** field here, and `min`/`max` returned nothing useful for it. Use the numeric **`ts`** (see [C6](#time-range)).

### Step C3 — Is there any mail traffic? Are the email IPs here? { #mail-check }

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (25, 110, 143, 465, 587, 993, 995)
| stats count by id_orig_h id_resp_h id_resp_p service
```

- `id_resp_p IN (...)` — server port is one of: 25/465/587 SMTP (sending), 110/995 POP3 (995 = TLS), 143/993 IMAP (993 = TLS).

**Actual result:** `No results found.`

```spl
index=zeek sourcetype=zeek:conn (id_orig_h IN (213.133.123.17, 212.232.52.106, 67.222.128.148, 68.66.77.76, 61.9.189.140, 185.60.133.27) OR id_resp_h IN (213.133.123.17, 212.232.52.106, 67.222.128.148, 68.66.77.76, 61.9.189.140, 185.60.133.27))
| table timestamp uid id_orig_h id_orig_p id_resp_h id_resp_p service orig_bytes resp_bytes conn_state
```

- The **outer parentheses matter**: without them Splunk binds `index=… sourcetype=… id_orig_h IN (…)` first and attaches the `OR` afterwards, which can match other indexes.

**Actual result:** `No results found.` — "Not found" is a result too; it goes in the report.

```text
[261118 2102, Analyst] Looking for mail traffic (25/110/143/465/587/993/995) in PCAP - Not Found
[261118 2103, Analyst] Looking for phishing email sender IPs in PCAP - Not Found
```

### Step C4 — What is `main` / `csv`? (Snort alert data) { #snort-csv }

```spl
index=main sourcetype=csv
| stats count by source
```

**Actual result:** `source = /home/<analyst>/snort/alert.log` — 55,893.

```spl
index=main sourcetype=csv "10.41.245.114"
| head 5
```

- A quoted string with no field name searches the **raw text** of every event — useful when you don't know which column holds the IP.

**Actual result:** `No results found.` Also `("213.174.33.141" OR "85.93.0.32" OR …)` → none.

`index=main sourcetype=csv | head 3` shows lines like:

```text
04/24-10:33:29.804769 ,1,1000100,0,"test",TCP,10.0.0.167,51671,40.97.190.2,993,AC:16:2D:F5:37:E5,20:E5:2A:B6:93:F1,0x62,***AP***,...
```

How to read Snort 2's `alert_csv` columns:

| # | Value | Meaning |
|---|---|---|
| 1 | `04/24-10:33:29.804769` | Alert time (no year) |
| 2 | `1` | Generator (1 = rules engine) |
| 3 | `1000100` | **sid** |
| 4 | `0` | rev |
| 5 | `"test"` | **msg** |
| 6 | `TCP` | Protocol |
| 7–8 | `10.0.0.167`, `51671` | Source IP, port |
| 9–10 | `40.97.190.2`, `993` | Destination IP, port |
| 11–12 | MACs | Source / destination MAC |
| rest | `***AP***`, `0x…` | TCP flags, seq/ack, TTL, IDs, lengths |

**Reading:** a **test rule** (sid 1000100, msg "test", fires on every TCP packet) on **unrelated 2025-04-24 traffic**. There is **no existing IDS alert for this incident** — hence the task to write Snort rules.

!!! note "Why the field list showed `0`, `1`, `53`, `1000100`, `04_24_09_45_43_474446`"
    Snort's CSV has **no header row**. Splunk treated the **first data row as column names**, so the fields are garbage. To use this data properly you would define the field names yourself (e.g. with `rex` or a props/transforms extraction).

```text
[261118 2104, Analyst] Locating IDS alerts for 10.41.245.114 (index=main sourcetype=csv) - Not Found: only test rule sid 1000100 "test" on unrelated 2025-04-24 traffic; new Snort rules required
```

### Step C5 — Who is 10.41.245.114? (DHCP) { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp
| table _time client_addr assigned_addr mac host_name domain msg_types
```

- DHCP is how a PC asks for network settings. PCs usually send their **computer name** with the request.
- `client_addr` / `assigned_addr` — the client's IP / the IP the server gave.
- `mac` — hardware address; changes much less often than IP.
- `host_name` — **the computer name**.
- `msg_types` — DHCP message types.

**Actual result (5 rows):**

| _time | client_addr | assigned_addr | mac | host_name | msg_types |
|---|---|---|---|---|---|
| 2026-11-18 08:46:31 | 10.41.245.114 | - | 00:17:31:7d:52:ba | **Dekker-PC** | REQUEST |
| 2026-11-18 08:46:31 | 10.41.245.114 | - | 00:17:31:7d:52:ba | Dekker-PC | INFORM |
| … | | | | | REQUEST / INFORM / INFORM |

**Reading:**

- **Dekker-PC** — only one Dekker in the employee list: **Justini H. Dekker, Finance Director**, login `justini.dekker`, `jdekker@`, 555-5189. She received **Email 2** and **Email 6**.
- `REQUEST` = "may I keep this IP?"; `INFORM` = "I already have an IP, tell me the other settings (DNS, proxy…)". `assigned_addr` is `-` because the server's ACK is not in the capture — not important.

```text
[261118 2115, Analyst] Identifying host 10.41.245.114 via DHCP - Found: Dekker-PC, MAC 00:17:31:7d:52:ba (Justini Dekker, Finance Director - recipient of Email 2 and Email 6)
```

### Step C6 — The `_time` trap and the real time range { #time-range }

Look again at `_time` above: **2026-11-18 08:46:31** for 2016 traffic — and **every event has the same value**.

!!! warning "Trap: `_time` is the ingest time here"
    Splunk could not read the timestamp inside these Zeek logs when they were loaded, so it stamped every event with **the time the logs were loaded**. Always sanity-check `_time` on new data. If every event has the same time, or the date is impossible, use the log's own time field — here the numeric **`ts`** — for everything, including the report.

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) as first max(ts) as last
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
```

- `min(ts)` / `max(ts)` — earliest and latest Zeek timestamps (epoch seconds).
- `eval` — computes new values. `strftime(number, "format")` turns epoch seconds into a readable date. `%Y-%m-%d %H:%M:%S` → `2016-02-05 21:24:05`. A comma lets one `eval` set two fields.

**Actual result:** `321  2016-02-05 21:24:05  2016-02-05 21:36:39` (UTC).

**Reading:** a **12.5-minute** capture. Compare with Dekker's emails: Email 2 arrived 09:34 (≈12 h earlier), Email 6 at 18:23 (≈3 h earlier). Not impossible — but see what the traffic says.

```text
[261118 2116, Analyst] Note: Splunk _time = index time (all events 2026-11-18 08:46:31); Zeek ts used for event times
[261118 2125, Analyst] Establishing PCAP time range - Found: 2016-02-05 21:24:05 to 21:36:39 UTC
```

### Step C7 — Where did the host connect? { #conn-destinations }

```spl
index=zeek sourcetype=zeek:conn
| stats count sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `by id_resp_h id_resp_p service` — one row per destination IP + port + protocol.
- `sum(orig_bytes) as sent` — bytes our host sent; `sum(resp_bytes) as received` — bytes the server sent back.
- `min(ts) as first` — first contact (originally written with `_time`, which gave the useless 08:46:31 for every row — use `ts`).
- `sort first` — read the rows in the order things happened.

**Actual result (59 rows; selected):**

| id_resp_h | port | service | count | sent | received |
|---|---|---|---|---|---|
| 10.2.41.7 | 53 | dns | 51 | 1,958 | 4,840 |
| 10.2.41.8 | 53 | dns | 10 | 388 | 886 |
| 10.41.245.1 / 255.255.255.255 | 67 | dhcp | 2 / 3 | | |
| 10.41.245.255 | 137 | dns (NetBIOS) | 4 | 1,716 | 0 |
| 148.251.255.26 | 80 | http | 7 (+1 failed) | 15,264 | 389,660 |
| **213.174.33.141** | 80 | http | 6 | 37,240 | **1,694,410** |
| **85.93.0.32** | 80 | http | 2 | 757 | 2,839 |
| **86.106.93.167** | 80 | http | 3 | 2,568 | **500,259** |
| 128.183.114.107 | 80 | - / http | 3 / 1 | 193 | 4,786 |
| **185.86.77.12** | 80 | http | 2 | **2,506** | **616** |
| **192.210.137.123** | 80 | - / http | **8** / 4 | 0 / 12,408 | 0 / 231,436 |
| 80.247.235.238 | 80 | - / http | 5 / 8 | 14,404 | 439,601 |
| 185.21.102.206 | 80 | - / http | 1 / 57 | 24,331 | 2,859,887 |
| 204.79.197.200 | 443 | ssl | 34 | 303,179 | 1,806,037 |
| 216.58.x, 31.13.70.x, 54.231.x, 98.136.x, 131.253.61.x … | 80/443 | http/ssl | | | |

**Reading:**

- Many rows look like big services (Google-, Microsoft-, Facebook-, Yahoo-, Amazon-like ranges) — normal browsing. Confirm owners with WHOIS later.
- **Large HTTP downloads** from un-named IPs (213.174.33.141, 86.106.93.167, 148.251.255.26, 192.210.137.123) — something was downloaded.
- **Failed connections** (`service` = `-`, 0 bytes) — malware often tries several servers.
- **Upload-heavy** 185.86.77.12 (sent > received) — normal browsing receives far more than it sends; the reverse can be a **check-in** reporting data.

These are only suspicions until the HTTP details are read.

### Step C8 — HTTP summary per server { #http-summary }

```spl
index=zeek sourcetype=zeek:http
| stats count min(ts) as first sum(response_body_len) as bytes values(method) as method values(status_code) as status values(resp_mime_types) as mime values(user_agent) as ua by id_resp_h host
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `sum(response_body_len) as bytes` — total body bytes the server returned (closest to real file sizes).
- `values(method)` — GET (fetch) / POST (send).
- `values(status_code)` — 200 OK, 404 not found, 302 redirect, 408 timeout …
- `values(resp_mime_types)` — what Zeek **detected from the content** (hard to fake).
- `values(user_agent)` — which program made the request.

**Actual result (21 rows; key rows):**

| id_resp_h | count | first | bytes | method | status | mime | ua |
|---|---|---|---|---|---|---|---|
| 173.223.52.193 | 1 | 21:24:12 | 14 | GET | 200 | text/plain | **Microsoft NCSI** |
| 148.251.255.26 | 36 | 21:27:15 | 527,492 | GET | 200 | images, html | IE11 |
| 213.174.33.141 | 88 | 21:28:17 | 1,663,151 | GET | 200 | font-woff, images, html | IE11 |
| **85.93.0.32** | 2 | 21:28:24 | 2,447 | GET | 200 | **x-shockwave-flash**, text/html | IE11 |
| **86.106.93.167** | 5 | 21:28:26 | 499,066 | GET, **POST** | 200, 404 | **-**, **x-shockwave-flash**, text/html | IE11 **+ a different IE11 string** |
| **184.28.188.184** | 1 | 21:28:27 | 349 | GET | 404 | text/html | **Shockwave Flash** |
| **128.183.114.107** | 1 | 21:28:39 | 4,491 | GET | 200 | text/plain | **Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)** |
| **185.86.77.12** | 4 | 21:28:41 | **0** | GET, **POST** | 200 | - | **MSIE 8.0** |
| **192.210.137.123** | 6 | 21:31:03 | 230,507 | GET, **POST** | 200 | **-** | IE11 |
| 80.247.235.238 | 30 | 21:32:20 | 431,328 | GET | 200, 404 | images, html | IE11 |
| 185.21.102.206 | 57 | 21:35:06 | 2,845,667 | GET | 200 | fonts, images, html | IE11 |

!!! warning "Trap: `host` shows `workstation` on every row"
    Zeek's `host` field (the website name) collided with Splunk's built-in `host` field (the machine that sent the logs), and Splunk's value won. Get the website name another way: the `referrer` field, DNS (`zeek:dns`), or Arkime. (`spath` did not help — these Zeek logs are **TSV**, not JSON.)

**Reading the User-Agents:**

| UA | Meaning |
|---|---|
| `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko` | **Windows 7 + Internet Explorer 11** — the user's browser |
| `Microsoft NCSI` | Windows checking "am I online?" — normal, the PC just joined the network (matches DHCP) |
| **`Shockwave Flash`** | Requested by the **Flash player itself** — a Flash file ran |
| **`Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`** | Claims **IE8** on a PC that runs **IE11** → a **non-browser program pretending to be IE**. Common in malware |

**Reading the MIME types:** two Flash files, and `-` (Zeek could not identify the content) with hundreds of KB. Normal files start with magic bytes Zeek recognises (`PK`, `MZ`, `%PDF` …); **encrypted** data starts with random bytes — the typical look of an encrypted malware payload.

### Step C9 — File types (Zeek files.log) { #files }

```spl
index=zeek sourcetype=zeek:files
| stats count sum(seen_bytes) as bytes by mime_type
| sort - count
```

- `mime_type` — the real type from the file's first bytes (the same idea as reading base64 magic bytes in the emails).
- `seen_bytes` — bytes Zeek actually saw.

**Actual result:**

| mime_type | count | bytes |
|---|---|---|
| image/jpeg | 91 | 2,560,922 |
| image/png | 64 | 676,249 |
| text/plain | 37 | 2,240,106 |
| image/gif | 22 | 11,008 |
| text/html | 11 | 416,827 |
| application/javascript | 5 | 679,778 |
| **application/vnd.ms-cab-compressed** | **4** | **10,036** |
| **-** | **3** | **593,407** |
| image/x-icon | 3 | 3,706 |
| application/vnd.ms-fontobject | 2 | 42,717 |
| **application/x-shockwave-flash** | **2** | **40,540** |
| application/font-woff | 1 | 23,892 |

No `application/x-dosexec` — **no Windows executable was downloaded in clear form**.

!!! note "Correction — the four CAB files"
    At first the four `vnd.ms-cab-compressed` files were taken for Windows downloading its certificate trust list (a normal CAB download). Arkime later showed they are the **four CAB files the malware uploaded to its C2** ([E6](#c2-upload)). They were **sent, not received**.

### Step C10 — Do the emails explain this traffic? { #email-check }

**Goal:** test the obvious hypothesis (Email 2 or Email 6 was opened) before accepting it.

```spl
index=zeek ("cehost" OR "love2date" OR "hoast" OR "mac7" OR "t1host" OR "faucibus" OR "odioauctor")
| table _raw
```

- No sourcetype, so **every Zeek log** (conn, dns, http, ssl …) is searched for these words in the raw text.
- `_raw` — the whole original log line.

**Actual result:** `No results found.`

**Reading:**

- If Email 2's HTML had been opened in this window, `www.cehost[.]ro` would appear (DNS/SNI). It does not.
- If an attachment `.js` had run, we would expect an **exe download right after the mail time** with a script/no UA. There is no `x-dosexec`, the capture starts 3–12 hours after the emails, and instead there is **Flash plus unidentifiable files**.

!!! question "Question: so this traffic is not related to all those emails?"
    **Within this capture, no.** But be precise about what that proves:

    - Proven: this infection started with **a website visit**, and **no email activity** is visible in these 12 minutes.
    - Not proven: that Dekker never opened an attachment. The capture is 12 minutes; Email 2 arrived 12 h earlier and Email 6 3 h earlier. What happened in between is outside this evidence. Write "**not observed in this capture**", not "did not happen".
    - Dekker being targeted by two phishing emails *and* infected via the web on the same day may be coincidence — or a sign that the finance director was being targeted by several routes. Hence the emails become a **separate lead** for all five recipients.

    Why the emails were in the scenario: (1) **a bias test** — "she got phishing, so it must be the phishing"; (2) together with the employee list they turned `Dekker-PC` into **the Finance Director**, which raises severity; (3) they are a **real threat to other hosts**. **Correlation is not causation — form hypotheses, but let the evidence decide.**

```text
[261118 2126, Analyst] Comparing capture with Dekker emails (Email 2 09:34Z, Email 6 18:23Z) - Not Found: no email IOC strings in any Zeek log; no exe/attachment download pattern
[261118 2127, Analyst] Reviewing HTTP user agents and file types - Found: "Shockwave Flash" UA, non-browser "MSIE 8.0" UA, 2x Flash, 3x unknown mime (encrypted) files
```

### Step C11 — Follow the referrer chain { #referrer-chain }

`referrer` = "the page that made the browser send this request". Following it backwards shows where the user started and where they were taken.

```spl
index=zeek sourcetype=zeek:http id_resp_h IN (85.93.0.32, 86.106.93.167, 184.28.188.184, 128.183.114.107, 185.86.77.12, 192.210.137.123)
| eval t=strftime(ts, "%H:%M:%S")
| table t id_resp_h method uri referrer status_code resp_mime_types request_body_len response_body_len user_agent
| sort t
```

- `request_body_len` — bytes the PC **uploaded** (POST body); `response_body_len` — bytes the server returned.

**Actual result (19 rows; key rows):**

| t | id_resp_h | method | uri | referrer |
|---|---|---|---|---|
| 21:28:24 | 85.93.0.32 | GET | `/shop.php?sid=4046AAB187AB2C1563B214BE7AC6702950B304E2E9E1696E18244B8501B268FD92DA0D313D2273E24C283B` | `http://www.source-werbeartikel.com/` |
| 21:28:25 | 85.93.0.32 | GET | `/hot.php?id=4046AAB187AB…283B` (same value) | `http://www.source-werbeartikel.com/` |
| 21:28:26 | 86.106.93.167 | GET | `/civis/index.php?PHPSESSID=3.b7&action=714324p02212u2q4548f8` | `http://lsbery.tk/hot.php?id=4046AAB…` |
| 21:28:27 | 184.28.188.184 | GET | `/get/flashplayer/update/current/install/version.xml15.0.0.189~installVector=1&lang=en&cpuWordLength=32&playerType=ax&os=win&osVer=13` | - |
| 21:28:29 | 86.106.93.167 | GET ×2 | `/charge.zhtml?dead=sVShjH&society=KgXs1bcH&level=O29Gm9T3&go=VdL&once=XN3S3cuYQ&way=Z41t&nothing=sTJVXv7X&art=Jw` | `http://bsbkxs.zdxwx3m.pw/civis/index.php?PHPSESS…` |
| 21:28:29 | 86.106.93.167 | POST | `/civis/so.cpg?directly=-pf&commission=&important=n0IP&color=xMZn&and=&analysis=doL0EY&hundred=nJBKRWWP4&name=Xe5tZx&any=bMXK&certain=aWh-AJtz7&rather=PEd` | landing page |
| 21:28:32 | 86.106.93.167 | GET | `/today.jst?technical=_MNsOrB&captain=&something=gxPx-&own=&themselves=T_wh7g5&eye=l3_LBg&citizen=zdelxIDGFLQvZFA8KbsEuiX` | `http://lsbery.tk/hot.php?id=…` |
| 21:28:39 | 128.183.114.107 | GET | `/planetary/text/nasa_pr_20001220.txt` | - |
| 21:28:41 | 185.86.77.12 | GET | `/images/INKuKE6Kg4Dzd25MNG/AX7HTCjk9/Km4MvXqg_2BRotklsjoc/…/Gi905Y3Ja/4.gif` | - |
| 21:28:52 | 185.86.77.12 | POST | `/images/78F8mFk5QY/l0D9o4Pskv0nsdTeJ/c1L_2F8SJVz_/…/CTU.bmp` | - |
| 21:30:43 | 185.86.77.12 | GET | `/images/N6bsv2yg/…/3.gif` | - |
| 21:30:54 | 185.86.77.12 | POST | `/images/yGOF1OPRgpsNLYRRXk/…/uD27YPGr.bmp` | - |
| 21:31:03 | 192.210.137.123 | GET | `/images/lYPocsAb06v/…/i.jpeg` | - |
| 21:32:39 | 192.210.137.123 | GET | `/images/_2BL34iAt/…/i.gif` | - |
| 21:33:03 | 192.210.137.123 | GET | `/images/tflgmImOzp/…/lron1.jpeg` | - |
| 21:33:16 | 192.210.137.123 | POST | `/images/u0oFNKi5H86jc9OSaYE4/…/qS.bmp` | - |
| 21:35:00 | 192.210.137.123 | GET | `/images/SIMu3u0tCE_/…/B9F.jpeg` | - |
| 21:35:15 | 192.210.137.123 | POST | `/images/tLL_2FR9qqixlfXoDE/…/Pspw_2F.bmp` | - |

**Reading — signal by signal:**

- **Same ID through the gate.** `/shop.php?sid=` and `/hot.php?id=` carry the same 86-hex value — a tracking value for one visitor. Injected code on the site sent the visitor to the gate; the gate passed them to the kit.
- **Odd domains.** `lsbery[.]tk` and `bsbkxs.zdxwx3m[.]pw` — random letters on cheap/free TLDs (`.tk`, `.pw`), common in malicious infrastructure.
- **Random English words as parameter names** (`dead`, `society`, `level`, `technical`, `captain` …) — widely reported for **Angler EK** in early 2016, as are landing URLs like `/civis/index.php?PHPSESSID=…&action=…`. Confirm with OSINT when available.
- **Lying extensions.** `.zhtml`, `.jst`, `.cpg` — but the content is Flash or unidentifiable.
- **Outdated Flash.** `version.xml15.0.0.189` — Flash 15 dates from late 2014; by February 2016 it had many public exploits.
- **C2 URL shape.** `/images/<long random segments>/<short>.gif|jpeg|bmp`. `_2F` and `_2B` stand for `/` and `+` — **base64 data hidden in the path**. Looks like image requests, but the responses are not images. GET uses `.gif`/`.jpeg`, POST uses `.bmp` — a fixed rule that real browsing never shows. This URL style is widely reported for **Ursnif (Gozi-ISFB)**.
- **Periodic.** 192.210.137.123 every ~1–2 minutes — a beacon.

```text
[261118 2132, Analyst] Following HTTP referrer chain - Found: www.source-werbeartikel.com -> lsbery.tk (85.93.0.32) -> bsbkxs.zdxwx3m.pw (86.106.93.167)
[261118 2133, Analyst] Identifying exploit delivery - Found: Flash exploit /charge.zhtml and encrypted payload /today.jst from 86.106.93.167; client Flash 15.0.0.189 (outdated)
[261118 2134, Analyst] Identifying post-infection traffic - Found: non-browser UA "MSIE 8.0" to 128.183.114.107 and 185.86.77.12; /images/<base64>/*.gif|bmp|jpeg C2 pattern to 185.86.77.12 and 192.210.137.123
```

### Step C12 — Flash and unidentified files { #files-detail }

```spl
index=zeek sourcetype=zeek:files mime_type IN ("-", "application/x-shockwave-flash")
| eval t=strftime(ts, "%H:%M:%S")
| table t tx_hosts rx_hosts id_orig_h id_resp_h source mime_type seen_bytes total_bytes md5 sha1
| sort t
```

- `tx_hosts` / `rx_hosts` — sender / receiver of the file (newer Zeek uses `id_orig_h`/`id_resp_h`; both are listed so whichever exists fills in).
- `seen_bytes` = `total_bytes` → the whole file was seen.
- `md5`, `sha1` — hashes (if Zeek is configured to compute them).

**Actual result:**

| t | tx_hosts | rx_hosts | mime_type | seen_bytes |
|---|---|---|---|---|
| 21:28:24 | 85.93.0.32 | 10.41.245.114 | application/x-shockwave-flash | 1,983 |
| 21:28:29 | 86.106.93.167 | 10.41.245.114 | - | 2,432 |
| 21:28:30 | 86.106.93.167 | 10.41.245.114 | application/x-shockwave-flash | 38,557 |
| 21:28:33 | 86.106.93.167 | 10.41.245.114 | **-** | **360,468** |
| 21:31:04 | 192.210.137.123 | 10.41.245.114 | **-** | **230,507** |

`md5`/`sha1` are `-` — **this Zeek does not compute file hashes**. Arkime will provide MD5s ([E8](#hashes)).

### Step C13 — Map IPs to domain names (DNS) { #dns }

```spl
index=zeek sourcetype=zeek:dns
| search query IN ("*werbeartikel*", "*lsbery*", "*zdxwx3m*") OR answers IN ("85.93.0.32", "86.106.93.167", "185.86.77.12", "192.210.137.123", "128.183.114.107")
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers
| sort t
```

- `search` filters again: names containing these strings, **or** DNS answers equal to a suspicious IP.

**Actual result:**

| t | query | answers |
|---|---|---|
| 21:28:15 | www.source-werbeartikel.com | 213.174.33.141 |
| 21:28:16 | www.source-werbeartikel.com | 213.174.33.141 |
| 21:28:23 | lsbery.tk | 85.93.0.32 |
| 21:28:25 | bsbkxs.zdxwx3m.pw | 86.106.93.167 |
| 21:28:39 | nssdc.gsfc.nasa.gov | 128.183.114.107 |

**Reading:** the compromised site is **213.174.33.141** (not 148.251.255.26, an earlier site visited at 21:27:15). `nssdc.gsfc.nasa[.]gov` is a legitimate NASA site — the malware fetched a text file there to **check internet access**: a behavioural indicator, not an IOC to block. The two C2 IPs did not appear… see the correction below.

### Step C14 — The C2 domain *was* resolved { #dns-correction }

Arkime later showed a Host header `tplandthepropforcontent[.]com` for both C2 IPs ([E3](#arkime-gate)). Searching that name directly:

```spl
index=zeek sourcetype=zeek:dns query="*tplandthe*"
```

**Actual result (2 events, raw TSV):**

```text
1454707720.899691  CvTG1D2bMwxcqkxT0g  10.41.245.114  56313  10.2.41.7  53  udp  44886  0.399232  tplandthepropforcontent.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  185.86.77.12,192.210.137.123  59.000000,59.000000  F
1454707862.298827  CNTOOz3i9s4JTqCth5  10.41.245.114  56397  10.2.41.7  53  udp  49787  0.114467  tplandthepropforcontent.com  1  C_INTERNET  1  A  0  NOERROR  F  F  T  T  0  192.210.137.123,185.86.77.12  43.000000,43.000000  F
```

How to read a Zeek `dns.log` line:

| Value | Field |
|---|---|
| `1454707720.899691` | ts (epoch) |
| `CvTG1D2bMwxcqkxT0g` | uid |
| `10.41.245.114` / `56313` | client / port |
| `10.2.41.7` / `53` | DNS server / port |
| `udp` | protocol |
| `tplandthepropforcontent.com` | **query** |
| `A` | query type (IPv4 address) |
| `NOERROR` | success |
| `185.86.77.12,192.210.137.123` | **answers** |
| `59.000000,…` | TTLs (seconds an answer may be cached) |

Converting ts: 1454707720 − 1454630400 (2016-02-05 00:00 UTC) = 77,320 s = **21:28:40.9**; the second is **21:31:02.3**.

| DNS time | Answer order | Next connection |
|---|---|---|
| 21:28:40.9 | 185.86.77.12, 192.210.137.123 | 21:28:41 → **185.86.77.12** |
| 21:31:02.3 | 192.210.137.123, 185.86.77.12 | 21:31:03 → **192.210.137.123** |

!!! note "Correction — why the earlier query said 'no DNS for the C2 IPs'"
    These logs are **TSV**. A field with several values (like `answers`) is stored as **one comma-joined string**: `185.86.77.12,192.210.137.123`. `answers IN ("185.86.77.12", …)` needs an **exact** match, so it missed. Use wildcards for such fields:

    ```spl
    index=zeek sourcetype=zeek:dns answers="*185.86.77.12*"
    ```

    Lesson: before writing "Not Found", check the query could actually have matched the data's format. In the report, add a **correction line** — do not delete the wrong one; others need to follow the reasoning.

!!! note "Correction — not 'first and second C2', but round-robin DNS"
    One domain has two IPs, and the DNS server **rotates their order** on each answer. The host took the first IP each time. The short TTLs (59 s, 43 s) let the operator change IPs quickly — common in malicious infrastructure. Block the **domain and both IPs**.

```text
[261118 2140, Analyst] Resolving domains for suspicious IPs via zeek:dns - Found: www.source-werbeartikel.com=213.174.33.141, lsbery.tk=85.93.0.32, bsbkxs.zdxwx3m.pw=86.106.93.167, nssdc.gsfc.nasa.gov=128.183.114.107
[261118 2205, Analyst] CORRECTION: C2 domain tplandthepropforcontent.com WAS resolved via 10.2.41.7 at 21:28:40Z (answers 185.86.77.12,192.210.137.123, TTL 59) and 21:31:02Z (answers reversed, TTL 43) - round-robin DNS; earlier "no DNS" result was a query error (TSV comma-joined answers field)
```

---

## Part D — What is an exploit kit? { #what-is-ek }

An **exploit kit (EK)** is an automated attack server package that **infects a visitor just for opening a web page**. No click or download is needed: it uses vulnerabilities in the browser or plugins (Flash, Java, Silverlight …). This is a **drive-by download**.

*Analogy:* you drop your car at a garage; a mechanic quietly checks your door-lock model, picks the matching master key, and hides a tracker in the car. You notice nothing.

| Stage | What happens | In this case |
|---|---|---|
| 1. Entry | The user visits a **compromised legitimate site** or a page with a malicious ad | `www.source-werbeartikel[.]com` (a German promotional-goods shop, Magento 1 layout `/skin/frontend/…`, `/media/…`) — 21:28:17 |
| 2. Gate | Injected code filters visitors and silently forwards them to the EK (it may skip analysts and security tools) | `lsbery[.]tk` (85.93.0.32) — Flash gate `/shop.php`, redirect `/hot.php` — 21:28:24 |
| 3. Landing page | Profiles the browser, OS and plugin versions and **chooses an exploit** | `bsbkxs.zdxwx3m[.]pw/civis/index.php` (~100 KB, obfuscated) — 21:28:26 |
| 4. Exploit | Sends the exploit file. Flash was the most common target then | `/charge.zhtml` → Flash 38,557 bytes; client Flash 15.0.0.189 — 21:28:29 |
| 5. Payload | On success, an **encrypted** payload is downloaded and decrypted in memory. Security tools cannot identify the file type | `/today.jst` → 360,468 bytes, Zeek mime `-` — 21:28:32 |
| 6. Post-infection | The installed malware contacts its C2 | 21:28:39 connectivity check → 21:28:40 C2 DNS → 21:28:41 C2 |

Stages 1–6 took **about 25 seconds**. The user was just browsing a promotional-goods shop.

**How to spot EK traffic:** strange URLs (random domains on `.tk`/`.pw`, meaningless English-word parameters, fake extensions); it is **fast** (gate to payload in seconds); the payload is **encrypted** (unknown type, hundreds of KB); a **non-browser UA** appears right after; **referrers chain** site → gate → EK.

**History:** 2014–2016 was the EK peak — Angler, Neutrino, Nuclear, RIG, Magnitude spread ransomware and banking trojans. Angler disappeared around June 2016. After Flash reached end of life (end of 2020) and browsers hardened, EKs became rare. Today the same "site → gate" structure is more often used with **fake browser-update pages** that make the user run a file. The analysis method — referrer chain, odd URLs, encrypted payload, post-infection C2 — is the same.

More background: [Spotting exploit kits](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md).

---

## Part E — Arkime (packet-level confirmation) { #arkime }

Splunk/Zeek are **summaries**; Arkime shows the **actual packets**. Evidence in the report should be confirmed — and saved — at packet level. (In the browser the Arkime tab is titled **SPIView**.)

### Step E1 — Time range and the infection-chain query { #arkime-chain }

Set the time range to **All** (or Custom 2016/02/05 21:24:05 – 21:36:43); filtering on the host IP means the time zone does not matter. Set **Settings → General → Timezone Format → UTC** if you can.

```text
ip == 10.41.245.114 && ip.dst == [213.174.33.141, 85.93.0.32, 86.106.93.167, 185.86.77.12, 192.210.137.123]
```

- `ip == 10.41.245.114` — sessions where our host is source **or** destination.
- `&&` — AND.
- `ip.dst == [ … ]` — destination is any IP in the bracketed list (Arkime list syntax).

**Actual result:** `Showing 1 - 21 of 21 entries`, 2016/02/05 21:28:17 – 21:36:39 UTC. Columns: Start/Stop Time, Src IP/Port, Dst IP/Port, Packets, Databytes/Bytes, Arkime Node, Info (protocols + URIs). The Info column already shows `lsbery.tk/shop.php?sid=…`, `bsbkxs.zdxwx3m.pw/today.jst?…`, `tplandthepropforcontent.com/images/…`.

### Step E2 — Session pairs to the C2 that carry no HTTP { #idle-sessions }

Next to each C2 HTTP session there is a **tcp-only** session with **7 packets, 0 bytes from the client and 420 bytes from the server** (source ports 49304, 49318, 49331, 49381).

**Reading:** the client never sent a request, the server sent ~420 bytes and closed — consistent with a client opening a **spare connection in advance** and the server timing it out (e.g. an HTTP `408 Request Timeout`). Open one (natural view) to confirm what the 420 bytes are. Snort later confirmed **no HTTP request** ever went over these four connections ([F5](#snort-results)).

### Step E3 — The gate sessions { #arkime-gate }

```text
ip == 85.93.0.32
```

Click `+` on a session to open **General** (left) and **HTTP** (right).

**`/shop.php` (src port 49257):**

| Field | Value | Reading |
|---|---|---|
| Time | 2016/02/05 21:28:24 – 21:28:25 UTC | |
| Src Ethernet | `00:17:31:7d:52:ba` OUI **ASUSTek** | Dekker-PC's NIC (matches DHCP) |
| Dst Ethernet | `88:43:e1:6c:b4:5a` OUI **Cisco** | The company gateway router |
| Dst IP/Port | 85.93.0.32 : 80 { RIPE } | European allocation |
| Hosts | `lsbery.tk` | |
| User Agents | IE11 | |
| Request Headers | accept, accept-encoding, accept-language, connection, host, referer, user-agent, **x-flash-version** | |
| referer Header | `http://www.source-werbeartikel.com/` | |
| content-type Header | `application/x-shockwave-flash` | |
| server Header | `Apache/2.2.15 (CentOS)` | Attacker server fingerprint |
| **Body MD5s** | **`5e251668b8a3e02e9da376d6f7da8229`** | Hash of the response body (the gate Flash) |
| QS Keys | `sid` | |

**`/hot.php` (49258):** same referer, response `text/html; charset=UTF-8`, no `x-flash-version`.

**Reading:** IE adds **`x-flash-version`** to requests made **from inside the Flash player**. So: code injected into the shop loaded the gate's **Flash file** (`shop.php`); that Flash opened `hot.php`; `hot.php` forwarded to the kit. A **Flash-based gate** — widely reported for the **EITest** campaign in early 2016 (confirm with OSINT).

**OUI:** the first 6 hex digits of a MAC identify the manufacturer — useful for the host operator to find the physical device.

```text
[261118 2204, Analyst] Reviewing gate lsbery.tk sessions - Found: /shop.php returned Flash (x-flash-version request header, Body MD5 5e251668b8a3e02e9da376d6f7da8229), /hot.php returned HTML redirect; server Apache/2.2.15 (CentOS)
```

### Step E4 — The exploit-kit sessions { #arkime-ek }

```text
ip == 86.106.93.167
```

**Landing + POST (49279, 21:28:25 – 21:29:37):** GET (1) + POST (1), status 200, Host `bsbkxs.zdxwx3m.pw`, IE11, referers = the landing page and `lsbery.tk/hot.php?id=…`, content-type `text/html`, server **nginx/1.2.1**, Dst databytes 100,536, Body MD5s `49143103a3e0a8e6fb35d02c61aa710e`, `f51880eb438f66a8de9fd674e1a036fb`, `27776220a96b24954d66fb137f4ff01a`, QS Keys `PHPSESSID commission name action color hundred certain important any directly analysis and rather`.

- A ~100 KB landing page: profiling code is **heavily obfuscated**, so it is large.

**Flash exploit (49278, 21:28:25 – 21:29:37):** **GET (2)**, status **200 and 404**, request header **x-flash-version**, referer = landing page, content-type `application/x-shockwave-flash` + `text/html`, nginx/1.2.1, **Body MD5 `cf90ba155fda322eeadd2fdeb4368849`**, libfile content type `application/x-shockwave-flash`, QS Keys `dead once nothing way society level art go`.

- Same URL requested twice: the first gets the exploit (200), the second **404**. EKs often serve an exploit **once per visitor** so analysts cannot fetch it again.
- `libfile content type` = Arkime's own content check (like Zeek's mime) — it agrees: Flash.

**Payload (49284, 21:28:32 – 21:29:37):** GET (1), 200, `application/octet-stream`, nginx/1.2.1, Dst databytes 360,732, **Body MD5 `4466cd2032944d03ffe9d4d7d74083c2`**, QS Keys `themselves own citizen technical eye captain something`.

- **Different User-Agent:** `Mozilla/5.0 (Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; rv:11.0) like Gecko` — the request came from a different code path (likely the code the exploit launched).
- Referer is the **gate** (`lsbery.tk/hot.php`), not the landing page.

**DNS session (21:28:25):** `10.41.245.114:49890 → 10.2.41.7:53`, Query A `bsbkxs.zdxwx3m.pw` → 86.106.93.167, NOERROR, flags RD RA.

```text
[261118 2210, Analyst] Reviewing EK sessions on 86.106.93.167 (nginx/1.2.1) - Found: landing /civis/index.php (~100KB), Flash exploit /charge.zhtml served once (2nd request 404, MD5 cf90ba155fda322eeadd2fdeb4368849), payload /today.jst application/octet-stream 360,732 bytes (MD5 4466cd2032944d03ffe9d4d7d74083c2)
```

### Step E5 — The C2: reading a check-in in natural view { #arkime-c2 }

```text
ip == 185.86.77.12
```

Four sessions: DNS at 21:28:40 and 21:31:02 (`tplandthepropforcontent.com`), and HTTP 49296 (21:28:41 – 21:30:39) and 49297 (21:30:43 – 21:32:28), each with one GET and one POST.

Open 49297 and set the packet view to **natural** (buttons above the packets: packet count, natural/ascii/hex, Src/Dst, UnXOR, Unbase64):

```text
GET /images/N6bsv2yg/nfRgMYDABPReeAWPINrTWFk/poF_2BnOQ_/2BzZdMiGngbMC_2Bj/LwXI5n7HJmpw/UMW04zx41qk/_2B8jTW4BGt8uc/lkpkQfGDZPqz2O1MOE4Pa/h6JH8GwlbikbY0dh/0z8VQjCJgAu_2BZ/QPYTXoSJXUZ9/3.gif HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Host: tplandthepropforcontent.com
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 21:30:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 0
Connection: keep-alive
```

**Reading:**

- Asked for a `.gif`; got **0 bytes**. Not an image request — a **check-in**. An empty answer usually means "no tasks right now".
- **No `Accept`, `Accept-Language`, `Accept-Encoding`** headers. A real IE always sends them. Header order `User-Agent → Host → Connection → Cache-Control` is what a program calling the Windows WinINet API directly produces — a strong **non-browser** sign (and usable in a Snort rule).
- `Host: tplandthepropforcontent.com` — same Host on both C2 IPs → **one C2 infrastructure**.

### Step E6 — The C2 upload: a CAB file { #c2-upload }

Further down the same session:

```text
POST /images/yGOF1OPRgpsNLYRRXk/ppY6ugq7p/AuVcfBXKaWwzpZnFmHWD/NP_2FE_2FtpGrGVR2wW/l8egMVa_2F2J3bVzYEopSE/9x13eCEuxGald/4PZpn53I/YHK3C6JsADqCyAvI5P5xFE2/ppdGcrvGHI/J4gDhoNmBEN9YEg_2/FbT4TaRl6abW/uD27YPGr.bmp HTTP/1.1
Content-Type: multipart/form-data; boundary=---------------------------693976939769397
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Host: tplandthepropforcontent.com
Content-Length: 430
Connection: Keep-Alive
Cache-Control: no-cache

-----------------------------693976939769397
Content-Disposition: form-data; name="upload_file"; filename="6D45.bin"
Content-Type: application/octet-stream

MSCF....(binary)....
-----------------------------693976939769397--

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 21:30:59 GMT
Content-Length: 0
```

**Reading line by line:**

- `multipart/form-data` — the format web forms use to **upload files**.
- `name="upload_file"; filename="6D45.bin"` — a file called `6D45.bin` is uploaded.
- **`MSCF`** — the magic bytes of a **Microsoft Cabinet (.cab)** file (same idea as `PK` for zip).

The malware **compresses collected data into a CAB file and uploads it to the C2**. Early uploads are typically system information (computer name, user, installed software); later ones can include browser-captured credentials and banking data — very serious on a finance director's PC. Four such POSTs exist (`CTU.bmp`, `uD27YPGr.bmp`, `qS.bmp`, `Pspw_2F.bmp`) — the four CAB files in Zeek's `files.log`.

The `upload_file` + `XXXX.bin` CAB upload and the `/images/<base64>/` URLs are widely reported characteristics of **Ursnif (Gozi-ISFB)**. Inferred, not confirmed.

```text
[261118 2212, Analyst] Reviewing C2 session 185.86.77.12:80 (Host tplandthepropforcontent.com) - Found: GET /images/<b64>/3.gif -> 200 Content-Length 0 (beacon); POST /images/<b64>/uD27YPGr.bmp multipart upload_file "6D45.bin" starting "MSCF" (CAB) - data exfiltration
[261118 2213, Analyst] CORRECTION: 4x application/vnd.ms-cab-compressed in zeek:files are the 4 CAB uploads to C2 (CTU.bmp, uD27YPGr.bmp, qS.bmp, Pspw_2F.bmp), not Windows CTL downloads
[261118 2214, Analyst] Assessment: C2 URL/upload pattern consistent with Ursnif (Gozi/ISFB) family - Further Analysis Required (hash lookup / OSINT)
```

### Step E7 — The C2 module download and the server clock { #c2-module }

```text
ip == 192.210.137.123
```

Session 49303 (21:31:03 – 21:32:39), natural view:

```text
GET /images/lYPocsAb06v/c8XQqRymQmAJFP/h_2B5m1KKRf5r1Y4_2B3G/oZmZCYB7EfcekWtW/Z1Y39RsTdnI08N6/cKQZGqmzVSGNWyTKcD/mU2QZV17k/dpJggBEqg1bEhLhkbq1f/hid9gA6NIhk22NhvpaS/kdbnxdC3W3/i.jpeg HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Host: tplandthepropforcontent.com
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 05 Feb 2016 22:28:56 GMT
Content-Type: application/octet-stream
Connection: keep-alive
Content-Length: 230507

(random-looking bytes …)
```

General/HTTP panels: Dst IP 192.210.137.123 { ARIN }, Dst databytes 230,666, libfile content type `application/octet-stream`, **Body MD5 `032557398230f49a5310a9a60f00e33b`**.

**Reading:**

- A `.jpeg` request answered with **230,507 bytes of `octet-stream`** that look random → an **encrypted module or configuration**.
- The UA switched from `MSIE 8.0` (until 21:30:54) to an **IE11 string** (from 21:31:03), but there are still **no `Accept` headers** — so it is still not a real browser; the malware changed its UA string (perhaps after new config/module).

!!! note "Correction — 'hidden inside the browser'?"
    Earlier, the switch to an IE11 UA was read as possible injection into IE. The missing `Accept` headers point instead to **the malware changing its own UA string**. Injection remains a question for the host operator (memory analysis), not a network finding.

**Server clocks differ:**

| C2 | HTTP `Date` header | Capture time | Difference |
|---|---|---|---|
| 185.86.77.12 (RIPE) | 21:30:48 | 21:30:48 | none |
| 192.210.137.123 (ARIN) | **22:28:56** | 21:31:03 | **~58 min ahead** |

Two physically different servers behind one domain; a badly kept clock can also suggest a borrowed/compromised server.

```text
[261118 2220, Analyst] Reviewing C2 session 192.210.137.123:80 (49303) - Found: GET /images/<b64>/i.jpeg returned application/octet-stream 230,507 bytes (encrypted module/config), Body MD5 032557398230f49a5310a9a60f00e33b; UA switched MSIE 8.0 -> IE11 string at 21:31:03Z, no Accept headers (non-browser)
[261118 2221, Analyst] Note: 192.210.137.123 HTTP Date header 22:28:56 GMT vs capture 21:31:03Z (~58 min skew) - separate server from 185.86.77.12 behind same C2 domain
```

### Step E8 — Hashes in a closed network { #hashes }

!!! question "Question: the network is closed, so VirusTotal lookups are impossible — what now?"
    1. **Record the hashes anyway.** They are IOCs for others: write "Hash reputation lookup not performed – closed network. Hashes recorded for MC / intel cell follow-up."
    2. **Add SHA256.** Arkime shows MD5 only; intel sharing usually uses SHA256. Extract the objects from the saved PCAP (below).
    3. **Check internal intel** if the kit has one (an offline MISP or earlier incident IOC lists).
    4. **Rely on behaviour.** The referrer chain, EK URL shapes, encrypted payload, C2 check-ins and CAB uploads are all network-behaviour evidence — that is the core of a network-countermeasures conclusion.
    5. **Name families as "consistent with … – unconfirmed"**, never as fact.

Offline SHA256 with tshark (inside the analysis VM):

```bash
mkdir ~/evidence/http_objects
tshark -r ~/evidence/261118_dekker-pc_full.pcap --export-objects http,$HOME/evidence/http_objects
ls -l ~/evidence/http_objects
sha256sum ~/evidence/http_objects/*
md5sum ~/evidence/http_objects/*
```

- `tshark` — Wireshark's command-line version. `-r` reads a PCAP.
- `--export-objects http,<folder>` — saves **every file carried over HTTP** into the folder (= Wireshark *File → Export Objects → HTTP*).
- `ls -l` — find the files by size (38,557 Flash; 360,468 payload; 230,507 module).
- If an `md5sum` value equals Arkime's **Body MD5**, you extracted the right file.
- Never move these files out of the VM; rename them with `.bin`.

| Stage | Server / session | URI | Size | Body MD5 |
|---|---|---|---|---|
| Gate Flash | 85.93.0.32 / 49257 | `/shop.php?sid=` | 1,983 | 5e251668b8a3e02e9da376d6f7da8229 |
| EK Flash exploit | 86.106.93.167 / 49278 | `/charge.zhtml` | 38,557 | cf90ba155fda322eeadd2fdeb4368849 |
| EK payload | 86.106.93.167 / 49284 | `/today.jst` | 360,468 | 4466cd2032944d03ffe9d4d7d74083c2 |
| C2 module | 192.210.137.123 / 49303 | `/images/…/i.jpeg` | 230,507 | 032557398230f49a5310a9a60f00e33b |
| (EK landing) | 86.106.93.167 / 49279 | `/civis/index.php` … | ~100 KB | 49143103…, f51880eb…, 27776220… |

```text
[261118 2222, Analyst] Hash reputation lookup - Not performed: closed network. MD5s recorded; SHA256 to be generated from exported PCAP (tshark --export-objects http) for MC/intel follow-up
```

### Step E9 — Saving the evidence PCAP { #export-pcap }

!!! question "Question: must I apply the filter query when saving? Why not save the whole PCAP — it's small anyway"
    Saving everything is not wrong. Best practice is **both**:

    - **The full original — for preservation.** You already have it (the file you were given). Rather than re-exporting it, record its path and **SHA256** (`sha256sum <file>`) — proof the analysed original was not changed (chain of custody). A re-export may differ in packet order/format.
    - **A filtered capture — the "traffic of interest".** The receiver sees only the chain instead of 321 connections; Snort tests become cleaner (malicious-only file for detection, full file for false positives); you share less unrelated user browsing; and on real sensors (tens of GB per hour) filtering is a must.

    In this exercise the full PCAP was saved — then say in the report which time window and IPs to look at.

A better filter than the one in [E1](#arkime-chain) — it also keeps the **DNS** sessions (which go to the internal resolver, not the destination IPs):

```text
ip == 10.41.245.114 && (ip.dst == [213.174.33.141, 85.93.0.32, 86.106.93.167, 185.86.77.12, 192.210.137.123] || host.dns == [www.source-werbeartikel.com, lsbery.tk, bsbkxs.zdxwx3m.pw, tplandthepropforcontent.com])
```

- `( … || … )` — either condition.
- `host.dns == [ … ]` — sessions whose DNS query name is in the list.

**Saving:** run the search → **Actions (⋯) → Export PCAP → Matching items**; or copy the original:

```bash
mkdir -p ~/evidence
cp <original-pcap> ~/evidence/261118_dekker-pc_full.pcap
sha256sum ~/evidence/261118_dekker-pc_full.pcap
```

---

## Part F — Writing and testing Snort rules { #snort }

### Step F0 — Preparation { #snort-prep }

```bash
snort -V
grep -n "ipvar HOME_NET" /etc/snort/snort.conf
grep -n "local.rules" /etc/snort/snort.conf
grep -n "RULE_PATH" /etc/snort/snort.conf | head -3
```

- `snort -V` — version. **2.9.x** → the rules below work as-is (the `alert.log` CSV format already suggested Snort 2). Snort 3 uses different syntax.
- `grep -n "text" file` — show matching lines with line numbers.
- **`ipvar HOME_NET`** — what Snort treats as "inside". If it is e.g. `10.0.0.0/24`, our host `10.41.245.114` is not "inside" and **no rule using `$HOME_NET` will fire**. For testing use `10.0.0.0/8` or `any`.
- **`include $RULE_PATH/local.rules`** — must not start with `#`.
- `RULE_PATH` — where `local.rules` lives (e.g. `/etc/snort/rules/local.rules`). `find / -name snort.conf 2>/dev/null` if the config is elsewhere.
- Comment out (`#`) the old **test rule sid 1000100** — it fires on every packet and buries the results.

### Step F1 — Anatomy of a rule { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"..."; ...options...; sid:1000101; rev:1;)
└─┬─┘ └┬┘ └───┬───┘ └┬┘ └┬┘ └─────┬─────┘ └────┬────┘ └──────────────────┬──────────────────┘
action proto  src IP  src port dir  dst IP     dst port                 options (in brackets)
```

**Header** — which packets to look at: `alert` (log an alert), `tcp`/`udp`, `$HOME_NET`/`$EXTERNAL_NET`/`$HTTP_PORTS` (variables from `snort.conf`), `->` (direction).

**Options** — what to look for inside:

| Option | Meaning |
|---|---|
| `msg:"…"` | Alert title |
| `flow:established,to_server` | Only data after the handshake, going **to the server** (`to_client` = the reverse) |
| `content:"text"` | This text must be present. `\|3a\|` = hex bytes (`3a` = `:`, `22` = `"`) |
| `content:!"text"` | This text must **not** be present |
| `nocase` | Ignore case |
| `http_uri` / `http_header` / `http_method` / `http_client_body` | Where in HTTP to look for the preceding `content` (URI / headers / GET-POST / POST body) |
| `depth:8` | Only within the first 8 bytes |
| `distance:0` | Must appear **after** the previous match |
| `pcre:"/regex/U"` | Regular expression; `U` = match against the URI |
| `urilen:>150` | URI longer than 150 characters |
| `flowbits` | Set / test a flag on a connection (see sid 1000107/1000108) |
| `flags:S` | TCP SYN (connection start) only |
| `classtype` | Alert class |
| `sid` / `rev` | Rule ID / revision. Local rules use **1,000,000 and above** |

!!! warning "One rule = one line"
    In Snort 2 each rule must be on **one line**. Copy carefully — no line breaks inside a rule.

Two kinds of rules:

- **IOC rules** — exact domains/IPs from this case. Precise, but useless once the attacker changes them.
- **Behaviour rules** — the **shape** of the attack. Survive domain/IP changes if the same tooling is used; slightly higher false-positive risk.

### Step F2 — The rules, one by one { #snort-rules }

#### A. IOC — DNS queries (sid 1000101–1000103) { #rules-dns }

```text
alert udp $HOME_NET any -> any 53 (msg:"LOCAL EK gate DNS query lsbery.tk"; content:"|06|lsbery|02|tk|00|"; nocase; classtype:trojan-activity; sid:1000101; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL EK server DNS query *.zdxwx3m.pw"; content:"|07|zdxwx3m|02|pw|00|"; nocase; classtype:trojan-activity; sid:1000102; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL C2 DNS query tplandthepropforcontent.com"; content:"|17|tplandthepropforcontent|03|com|00|"; nocase; classtype:trojan-activity; sid:1000103; rev:1;)
```

- DNS writes names as **length + label** instead of dots: `|06|lsbery|02|tk|00|` = 6 letters, 2 letters, end.
- `|07|zdxwx3m|02|pw|00|` leaves out `bsbkxs.` on purpose — EKs rotate subdomains, so matching the parent catches any `xxxx.zdxwx3m.pw`.
- `|17|` — hex 17 = 23, the length of `tplandthepropforcontent`.
- `-> any 53` — whichever DNS server is asked.

Compute the wire format for any domain:

```bash
python3 -c "
d='tplandthepropforcontent.com'
print(''.join('|%02x|%s' % (len(l), l) for l in d.split('.')) + '|00|')"
```

#### B. IOC — connection attempts to the C2 IPs (sid 1000104) { #rules-ip }

```text
alert tcp $HOME_NET any -> [185.86.77.12,192.210.137.123] any (msg:"LOCAL C2 connection attempt to known C2 IP"; flags:S; classtype:trojan-activity; sid:1000104; rev:1;)
```

- `[a,b]` — a list of IPs.
- `flags:S` — **only the SYN** (first packet of a connection). Without it, an IP-only rule fires on **every packet** — hundreds of alerts. Always narrow IP-only rules.

#### C. Behaviour — gate URL shape (sid 1000105) { #rules-gate }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EK gate request /shop.php or /hot.php with long hex id"; flow:established,to_server; content:".php?"; http_uri; pcre:"/\/(?:shop|hot)\.php\?s?id=[0-9A-F]{64,}$/U"; classtype:trojan-activity; sid:1000105; rev:1;)
```

- `content:".php?"; http_uri;` — a cheap pre-filter before the slower regex (good habit).
- The regex: `\/(?:shop|hot)\.php` = `/shop.php` or `/hot.php`; `\?s?id=` = `?id=` or `?sid=`; `[0-9A-F]{64,}` = 64+ upper-case hex characters (this ID was 86); `$` = end of URI.
- No domain — it catches the gate even if the domain changes.

#### D. Behaviour — EK landing (sid 1000106) { #rules-landing }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Angler-like EK landing index.php?PHPSESSID=&action="; flow:established,to_server; content:"/index.php?PHPSESSID="; http_uri; content:"&action="; http_uri; distance:0; classtype:trojan-activity; sid:1000106; rev:1;)
```

- `PHPSESSID` normally travels as a **cookie**. In the URL, followed by `&action=`, it is this landing page's fingerprint.

#### E. Behaviour — EK payload with flowbits (sid 1000107–1000108) { #rules-payload }

The payload is a **server response**, and `application/octet-stream` alone could be any download. So: mark requests that came **via the gate**, then check only those connections' responses.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EK request referred by gate hot.php - set flowbit"; flow:established,to_server; content:"/hot.php?id="; http_header; flowbits:set,ek.from_gate; flowbits:noalert; classtype:trojan-activity; sid:1000107; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL EK payload download (octet-stream after gate referral)"; flow:established,to_client; flowbits:isset,ek.from_gate; content:"application/octet-stream"; http_header; nocase; classtype:trojan-activity; sid:1000108; rev:1;)
```

- Rule 1: the gate URL in a **request header** (the Referer) → `flowbits:set,ek.from_gate` marks the connection; `flowbits:noalert` = no alert of its own.
- Rule 2: reverse direction (`to_client`) — the **server's response**; `flowbits:isset` = only marked connections; `application/octet-stream` → alert.
- In this capture two requests have a `hot.php` referer: the landing page (response `text/html`) and the payload (`octet-stream`). Only the payload should alert.

#### F. IOC — C2 Host header (sid 1000109) { #rules-host }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL C2 HTTP request Host tplandthepropforcontent.com"; flow:established,to_server; content:"Host|3a| tplandthepropforcontent.com"; http_header; nocase; classtype:trojan-activity; sid:1000109; rev:1;)
```

- `Host|3a| ` = `Host: `. Catches the C2 even if the IPs change.

#### G. Behaviour — C2 beacon shape (sid 1000110) { #rules-beacon }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Ursnif-like C2 beacon - long /images/ base64 path, no Accept header"; flow:established,to_server; content:"GET"; http_method; content:"/images/"; http_uri; depth:8; urilen:>150; content:!"Accept"; http_header; pcre:"/^\/images\/(?:[A-Za-z0-9_]+\/){6,}[A-Za-z0-9_]+\.(?:gif|jpeg|bmp)$/U"; classtype:trojan-activity; sid:1000110; rev:1;)
```

All conditions must hold:

- `GET` method.
- URI **starts with** `/images/` (`depth:8`).
- `urilen:>150` — real image URLs are not this long.
- `content:!"Accept"; http_header;` — **no Accept header** (real browsers always send one).
- Regex: `/images/` + **6 or more** folders of letters/digits/`_` + `name.gif|jpeg|bmp`.

No domain, no IP — the same malware with a new C2 still matches.

#### H. Behaviour — CAB upload / exfil (sid 1000111) { #rules-exfil }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Ursnif-like exfil - POST upload_file .bin containing CAB (MSCF)"; flow:established,to_server; content:"POST"; http_method; content:"name=|22|upload_file|22|"; http_client_body; content:".bin|22|"; http_client_body; distance:0; content:"MSCF"; http_client_body; distance:0; classtype:trojan-activity; sid:1000111; rev:1;)
```

- `http_client_body` — look inside what was **POSTed**.
- `name=|22|upload_file|22|` = `name="upload_file"`; then `.bin"`; then `MSCF` (CAB magic) — **in that order** (`distance:0`). Exactly the upload seen in Arkime.

### Step F3 — Testing against the PCAP { #snort-test }

1. Paste the 11 lines into `local.rules` (e.g. `sudo nano /etc/snort/rules/local.rules`) and comment out sid 1000100.
2. Check syntax:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

- `-T` — test the configuration and rules only. Success ends with `Snort successfully validated the configuration!`. Errors name the line — usually a missing `"` or `;`, or a line break inside a rule.

3. Run against the PCAP:

```bash
mkdir -p /tmp/snorttest
sudo snort -c /etc/snort/snort.conf -r ~/Downloads/Investigation1.pcap -A console -q -k none -U -l /tmp/snorttest
```

- `-r file` — read a **PCAP** instead of a live interface.
- `-A console` — print alerts to the screen.
- `-q` — quiet (no start-up banner).
- **`-k none`** — **turn off checksum verification**. Captures often contain packets with "bad" checksums (NIC offloading); Snort would drop them and rules would silently not fire. A very common PCAP-testing trap.
- `-U` — timestamps in **UTC**, so they match the timeline.
- `-l /tmp/snorttest` — log directory for the test, so the real `alert.log` (read by Splunk) is not polluted.

4. Count alerts per rule:

```bash
sudo snort -c /etc/snort/snort.conf -r ~/Downloads/Investigation1.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `grep -o "…"` — keep only the `[1:sid:rev] title` part of each alert.
- `sort | uniq -c` — group identical lines and count them.

### Step F4 — Reading an alert line { #alert-line }

```text
02/05-21:28:23.927822  [**] [1:1000101:1] LOCAL EK gate DNS query lsbery.tk [**] [Classification: A Network Trojan was detected] [Priority: 1] {UDP} 10.41.245.114:61377 -> 10.2.41.7:53
```

- `02/05-21:28:23.927822` — packet time (UTC because of `-U`).
- `[1:1000101:1]` — `[generator:sid:rev]` — which rule fired.
- message, classification, priority.
- `{UDP} src -> dst` — the packet that matched.

### Step F5 — Actual results { #snort-results }

**Actual output (in printed order):**

```text
02/05-21:28:23.927822  [1:1000101:1] LOCAL EK gate DNS query lsbery.tk  {UDP} 10.41.245.114:61377 -> 10.2.41.7:53
02/05-21:28:24.629939  [1:1000105:1] LOCAL EK gate request /shop.php or /hot.php with long hex id  {TCP} 10.41.245.114:49257 -> 85.93.0.32:80
02/05-21:28:25.642147  [1:1000102:1] LOCAL EK server DNS query *.zdxwx3m.pw  {UDP} 10.41.245.114:49890 -> 10.2.41.7:53
02/05-21:28:25.211436  [1:1000105:1] LOCAL EK gate request /shop.php or /hot.php with long hex id  {TCP} 10.41.245.114:49258 -> 85.93.0.32:80
02/05-21:28:40.899691  [1:1000103:1] LOCAL C2 DNS query tplandthepropforcontent.com  {UDP} 10.41.245.114:56313 -> 10.2.41.7:53
02/05-21:28:33.836130  [1:1000108:1] LOCAL EK payload download (octet-stream after gate referral)  {TCP} 86.106.93.167:80 -> 10.41.245.114:49284
02/05-21:28:26.013021  [1:1000106:1] LOCAL Angler-like EK landing index.php?PHPSESSID=&action=  {TCP} 10.41.245.114:49279 -> 86.106.93.167:80
02/05-21:28:41.299346  [1:1000104:1] LOCAL C2 connection attempt to known C2 IP  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:41.571373  [1:1000109:1] LOCAL C2 HTTP request Host tplandthepropforcontent.com  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:41.571373  [1:1000110:1] LOCAL Ursnif-like C2 beacon - long /images/ base64 path, no Accept header  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:52.293726  [1:1000109:1] LOCAL C2 HTTP request Host tplandthepropforcontent.com  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:28:52.293726  [1:1000111:1] LOCAL Ursnif-like exfil - POST upload_file .bin containing CAB (MSCF)  {TCP} 10.41.245.114:49296 -> 185.86.77.12:80
02/05-21:31:02.298827  [1:1000103:1] LOCAL C2 DNS query tplandthepropforcontent.com  {UDP} 10.41.245.114:56397 -> 10.2.41.7:53
02/05-21:30:43.307105  [1:1000104:1] LOCAL C2 connection attempt to known C2 IP  {TCP} 10.41.245.114:49297 -> 185.86.77.12:80
02/05-21:30:43.576908  [1:1000109:1] … 49297    02/05-21:30:43.576908  [1:1000110:1] … 49297
02/05-21:30:54.719242  [1:1000109:1] … 49297    02/05-21:30:54.719242  [1:1000111:1] … 49297
02/05-21:31:03.097060  [1:1000104:1] … 49304 -> 192.210.137.123:80
02/05-21:31:03.096988  [1:1000104:1] … 49303 -> 192.210.137.123:80
02/05-21:31:03.312196  [1:1000109:1] … 49303    02/05-21:31:03.312196  [1:1000110:1] … 49303
02/05-21:32:39.328746  [1:1000104:1] … 49317
02/05-21:32:39.753652  [1:1000109:1] … 49317    02/05-21:32:39.753652  [1:1000110:1] … 49317
02/05-21:33:03.499851  [1:1000109:1] … 49317    02/05-21:33:03.499851  [1:1000110:1] … 49317
02/05-21:33:16.085131  [1:1000109:1] … 49317    02/05-21:33:16.085131  [1:1000111:1] … 49317
02/05-21:35:00.140031  [1:1000104:1] … 49331
02/05-21:35:00.139959  [1:1000104:1] … 49330
02/05-21:35:00.286958  [1:1000109:1] … 49330    02/05-21:35:00.286958  [1:1000110:1] … 49330
02/05-21:32:39.328970  [1:1000104:1] … 49318
02/05-21:35:15.789369  [1:1000104:1] … 49381
02/05-21:35:15.789133  [1:1000104:1] … 49380
02/05-21:35:15.950613  [1:1000109:1] … 49380    02/05-21:35:15.950613  [1:1000111:1] … 49380
```

(Shortened: `[**]`, classification and priority removed; `…` = `10.41.245.114:<port> -> <C2>:80`.)

| sid | Rule | Expected | **Actual** | Where |
|---|---|---|---|---|
| 1000101 | DNS lsbery.tk | 1 | **1** ✅ | 21:28:23 |
| 1000102 | DNS *.zdxwx3m.pw | 1 | **1** ✅ | 21:28:25 |
| 1000103 | DNS C2 domain | 2 | **2** ✅ | 21:28:40, 21:31:02 |
| 1000104 | C2 IP SYN | = TCP connections to C2 | **10** | 185.86.77.12 ×2, 192.210.137.123 ×8 |
| 1000105 | Gate URL shape | 2 | **2** ✅ | 49257 (`shop.php`), 49258 (`hot.php`) |
| 1000106 | EK landing | 1 | **1** ✅ | 49279 |
| 1000108 | EK payload (flowbits) | 1 | **1** ✅ | 86.106.93.167 → 49284 |
| 1000109 | C2 Host header | 10 | **10** ✅ | GET ×6, POST ×4 |
| 1000110 | C2 beacon shape | 6 | **6** ✅ | 49296, 49297, 49303, 49317 ×2, 49330 |
| 1000111 | CAB upload | 4 | **4** ✅ | 49296, 49297, 49317, 49380 |

**Reading:**

1. **The flowbits worked.** sid 1000108 fired on the payload session (49284) only; the landing session (49279), also marked, answered `text/html` and stayed quiet.
2. **The four SYN-only connections** (49304, 49318, 49331, 49381) — only sid 1000104, no Host/beacon alert: the "7-packet empty connections" from [E2](#idle-sessions). Snort confirms **no HTTP request was ever sent** on them.
3. **Zero false positives.** The capture also holds Google, Microsoft, Facebook, Yahoo and the compromised shop; every alert is on the chain IPs or their DNS lookups.

!!! question "Question: why is the output not in time order?"
    For HTTP, Snort **reassembles the TCP stream** before checking the rules, so an alert is printed when reassembly completes — sometimes later than other alerts. The **timestamp** on each alert is still the real packet time. Build timelines by **timestamp**, not by print order.

### Step F6 — Ideas for more practice { #snort-more }

- **Flash exploit rule** for `/charge.zhtml`: random-English-word parameters + `x-flash-version` header.
- **Outdated Flash (policy rule):** `version.xml15.0.0.` in the URI finds **unpatched PCs** before anyone attacks them.
- **Convert the rules to Snort 3** syntax (sticky buffers) if the team kit moves to Snort 3.

```text
[261118 2230, Analyst] Writing Snort rules for gate/EK/C2/exfil (sid 1000101-1000111) - Found
[261118 2345, Analyst] Testing Snort rules sid 1000101-1000111 against full PCAP (snort -A console -q -k none -U) - Found: all rules fired as expected, 0 alerts on benign traffic
```

---

## Part G — Timeline, IOCs and leads { #results }

### Timeline (UTC, 2016-02-05) { #timeline }

| Time | Event |
|---|---|
| 08:12 | Campaign A builds `invoice304-3/18/25/27.js` (attacker clock UTC+4) |
| 09:27:04 | Email 1 → mtsutsumi (TLS) |
| 09:34:13 | Email 2 → jdekker (TLS; created 3 Feb 05:05) |
| 11:42:38 | Email 3 → smunro |
| 13:30:37 | Email 4 → mtraugott (TLS) |
| 13:40:27 | Email 5 → smunro |
| 18:23:42 | Email 6 → jdekker (mx2) |
| 18:23:43 | Email 7 → culyanova |
| **21:24:05** | **PCAP start**; DHCP REQUEST/INFORM, Microsoft NCSI (Dekker-PC joins the network) |
| 21:27:15 | Browsing (148.251.255.26) |
| 21:28:15 | DNS `www.source-werbeartikel[.]com` → 213.174.33.141 |
| 21:28:17 | Compromised shop loaded (88 requests) |
| 21:28:23 | DNS `lsbery[.]tk` → 85.93.0.32 |
| **21:28:24** | **First malicious event**: `GET /shop.php?sid=…` → gate Flash (1,983 B) |
| 21:28:25 | `GET /hot.php?id=…` → redirect; DNS `bsbkxs.zdxwx3m[.]pw` → 86.106.93.167 |
| 21:28:26 | EK landing `/civis/index.php?PHPSESSID=3.b7&action=…` (~100 KB) |
| 21:28:27 | Flash Player version check: **15.0.0.189** |
| 21:28:29 | `GET /charge.zhtml?…` → **Flash exploit** (38,557 B); POST `/civis/so.cpg` |
| 21:28:32 | `GET /today.jst?…` → **encrypted payload** (360,468 B) |
| 21:28:39 | Malware connectivity check `nssdc.gsfc.nasa[.]gov` (UA MSIE 8.0) |
| 21:28:40 | DNS `tplandthepropforcontent[.]com` → 185.86.77.12, 192.210.137.123 (TTL 59) |
| **21:28:41** | **First C2 check-in** (185.86.77.12) |
| **21:28:52** | **First CAB upload** (`CTU.bmp`) |
| 21:30:43 / 21:30:54 | Check-in / CAB upload `uD27YPGr.bmp` ("6D45.bin") |
| 21:31:02 | DNS C2 again (answers reversed, TTL 43) |
| 21:31:03 | C2 switches to 192.210.137.123; **module download 230,507 B**; UA string now IE11 |
| 21:32:39 / 21:33:03 | Check-ins (`i.gif`, `lron1.jpeg`) |
| 21:33:16 | CAB upload `qS.bmp` |
| 21:35:00 | Check-in (`B9F.jpeg`) |
| 21:35:15 | CAB upload `Pspw_2F.bmp` |
| **21:36:39** | **PCAP end** — C2 still active |

### IOC table { #iocs }

| Type | Value | Role | Action |
|---|---|---|---|
| Host | 10.41.245.114 / Dekker-PC | Victim (Finance Director) | Isolate / triage |
| MAC | 00:17:31:7d:52:ba (ASUSTek) | Victim NIC | Locate device |
| Domain / IP | www.source-werbeartikel[.]com / 213.174.33.141 | Compromised legitimate site (Magento) | Monitor / notify owner (shared hosting) |
| Domain / IP | lsbery[.]tk / 85.93.0.32 | EK gate (Flash), Apache/2.2.15 CentOS | Block |
| Domain / IP | bsbkxs.zdxwx3m[.]pw (*.zdxwx3m[.]pw) / 86.106.93.167 | Exploit kit, nginx/1.2.1 | Block |
| Domain | tplandthepropforcontent[.]com | C2 (round-robin) | Block |
| IP | 185.86.77.12 (RIPE), 192.210.137.123 (ARIN) | C2 | Block |
| URI pattern | `/images/<base64 segments>/<x>.gif\|jpeg\|bmp` | C2 beacon / upload | Detect |
| URI pattern | `/shop.php?sid=<64+ hex>`, `/hot.php?id=<64+ hex>` | EK gate | Detect |
| URI pattern | `/index.php?PHPSESSID=<x>&action=<x>` | EK landing | Detect |
| UA | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)` on Win7/IE11 hosts | Malware | Hunt |
| Upload | multipart `name="upload_file" filename="XXXX.bin"`, body `MSCF` | Exfil | Detect |
| MD5 | cf90ba155fda322eeadd2fdeb4368849 | EK Flash exploit | Intel lookup |
| MD5 | 4466cd2032944d03ffe9d4d7d74083c2 | EK payload (encrypted) | Intel lookup |
| MD5 | 032557398230f49a5310a9a60f00e33b | C2 module (encrypted) | Intel lookup |
| MD5 | 5e251668b8a3e02e9da376d6f7da8229 | Gate Flash | Intel lookup |
| Software | Adobe Flash Player 15.0.0.189 | Exploited | Remove / patch |
| Behaviour | Text-file fetch from nssdc.gsfc.nasa[.]gov | Malware connectivity check | Context only (legitimate site) |

### Leads for the host operator { #host-leads }

An EK infection leaves different host traces from an email attachment: the parent is **`iexplore.exe` or the Flash plugin**, not `wscript.exe`.

1. **Isolate** Dekker-PC; **capture memory before reboot** — the payload arrived encrypted and may run only in memory.
2. Window: **21:28:17 – 21:28:41 UTC** (exploit → first C2).
3. **Process creation** — *Sysmon Event ID 1* (process created, with command line) / *Security 4688* (a new process was created): unexpected children of `iexplore.exe` or Flash around 21:28:30–21:28:40.
4. **Network connections** — *Sysmon Event ID 3* (a process made a network connection): which process talked to 185.86.77.12 / 192.210.137.123.
5. **Injection** — *Sysmon Event ID 8* (CreateRemoteThread: a process started a thread inside another) and *Event ID 10* (one process opened another's memory) into `iexplore.exe`/`explorer.exe`.
6. **Files** — *Sysmon Event ID 11* (file created): new executables/DLLs in `%TEMP%` / `%APPDATA%` around 21:28; CAB files named `XXXX.bin`.
7. **Persistence** — *Sysmon Event ID 13* (registry value set; Run/RunOnce keys) and *Security 4698* (a scheduled task was created).
8. **Remove/upgrade Flash 15.0.0.189.**
9. Ursnif-family malware steals credentials and banking data → **reset Justini Dekker's domain and finance/banking credentials** and review finance-system access after 21:28.

### Other leads — the emails { #other-leads }

The seven emails are not in this capture but are a **real threat to five users** (priority: culyanova — sysadmin; smunro and jdekker — targeted twice). Recommend pulling their traffic / host triage, and searching all mailboxes for the subjects and attachment names from [B12](#email-campaigns).

---

## Copy-ready query sheet { #query-sheet }

Replace `<…>`. Splunk time range: **All time** for old data; use `ts`, not `_time`, if `_time` looks wrong.

**Splunk — discovery**

```spl
| tstats count where index=* by index sourcetype
```

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) as first max(ts) as last by id_orig_h
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - count
```

```spl
index=zeek sourcetype=zeek:dhcp
| table _time client_addr assigned_addr mac host_name domain msg_types
```

**Splunk — what did the host do**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=<host-IP>
| stats count sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=<host-IP>
| stats count min(ts) as first sum(response_body_len) as bytes values(method) as method values(status_code) as status values(resp_mime_types) as mime values(user_agent) as ua by id_resp_h
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```spl
index=zeek sourcetype=zeek:http id_resp_h IN (<IP1>, <IP2>)
| eval t=strftime(ts, "%H:%M:%S")
| table t id_resp_h method uri referrer status_code resp_mime_types request_body_len response_body_len user_agent
| sort t
```

```spl
index=zeek sourcetype=zeek:files
| stats count sum(seen_bytes) as bytes by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:dns (query="*<domain-part>*" OR answers="*<IP>*")
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers TTLs
| sort t
```

```spl
index=zeek ("<ioc-string-1>" OR "<ioc-string-2>")
| table _raw
```

**Splunk — if the capture contains mail**

```spl
index=zeek sourcetype=zeek:smtp
| table ts uid id_orig_h id_resp_h helo mailfrom rcptto from subject tls last_reply fuids
```

```spl
index=zeek sourcetype=zeek:ssl id_resp_p=25
| table ts id_orig_h id_resp_h version cipher server_name
```

```spl
index=zeek sourcetype=zeek:conn id_resp_p=25
| stats count dc(id_orig_h) as senders by id_resp_h
```

**Arkime**

```text
ip == <host-IP> && ip.dst == [<IP1>, <IP2>]
ip == <host-IP> && (ip.dst == [<IP1>, <IP2>] || host.dns == [<domain1>, <domain2>])
host.dns == *<domain-part>*
host.http == *<domain-part>*
http.uri == *<string>*
email.fn == <attachment-name>
ip.src == <host-IP> && http.method == POST
```

**Email / files (analysis VM)**

```bash
echo '<first base64 line>' | base64 -d | xxd | head -4
unzip -l <file>.zip
unzip -p <file>.zip | sha256sum
tshark -r <file>.pcap --export-objects http,<folder>
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r <file>.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

---

## Lessons learned { #lessons }

1. **The obvious cause is a hypothesis, not a conclusion.** Phishing to the same user on the same day looked decisive; time, missing email artefacts and a complete web chain said otherwise. Let the evidence decide — and write "not observed in this capture" rather than "did not happen".
2. **Check the data before trusting it.** `_time` was the ingest time; Splunk's `host` hid Zeek's `host`; `answers` was a comma-joined string; the Snort CSV had no header. Each one produced a wrong first answer.
3. **Correct openly.** Four corrections are in the report (DNS for C2, the CAB files, the attacker's time zone, the "browser injection" reading). Add correction lines; do not erase.
4. **User-Agents and headers tell you *who* made a request.** `Shockwave Flash`, IE8 on an IE11 PC, and no `Accept` header separated browser, plugin and malware.
5. **Referrers rebuild the chain.** site → gate → EK, in seconds.
6. **`-` (unknown MIME) of hundreds of KB = probably encrypted.** Magic bytes matter on the wire as much as in email.
7. **Closed network ≠ no conclusion.** Record hashes for others, rely on behaviour, and label families "consistent with … – unconfirmed".
8. **Test your rules on the PCAP** (`-k none`, check `HOME_NET`, count per sid) and against benign traffic for false positives.
9. **STARTTLS hides email** from a sensor; IP rules and `ssl.log` still prove delivery.

## References { #references }

- [Spotting exploit kits](../../training/blue-team-essentials/http-analysis/exploit-kits-practice.md) · [Base64 in traffic](../../training/blue-team-essentials/http-analysis/base64.md) · [User-Agents and cookies](../../training/blue-team-essentials/http-analysis/user-agents-cookies.md)
- [Zeek: conn](../../network/zeek/conn-log.md) · [dns](../../network/zeek/dns-log.md) · [http](../../network/zeek/http-log.md) · [files](../../network/zeek/files-log.md)
- [Arkime search syntax](../../network/arkime/search-syntax.md) · [Arkime offline PCAP guide](../../network/arkime/offline-pcap-guide.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Data discovery and time](../splunk/data-discovery.md)
- [Snort rules for DC/SMB attacks](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) · [Beaconing & C2](../../network/beaconing-c2.md)
- [Playbook: compromised workstation](../playbooks/compromised-workstation.md) · [Playbook: data exfiltration](../playbooks/data-exfiltration.md)
