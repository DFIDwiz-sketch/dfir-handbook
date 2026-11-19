---
title: "Reading Email Headers — Trace Headers, Message Headers, Body, Interpreting Received Lines"
tags:
  - training
  - blue-team
  - email
  - smtp
---

# Reading Email Headers — Trace Headers, Message Headers, Body, Interpreting Received Lines { #email-headers }

!!! abstract "What this page covers"
    The three parts of a received message's source (trace headers, message headers, body), who writes each part, and therefore how far each can be trusted. How to pull the source and headers out of each mail client, and how to handle them safely. Then reading Received headers from bottom to top to retrace the message's route, interpreting a single Received line field by field, and finding **the line written by our border server** to draw the trust boundary. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. All domains and IPs are invented for illustration. Continues from [Email Delivery and SMTP](delivery-smtp.md).

## The 8 key points { #key-points }

1. A message's source runs, from the top: **trace headers → message headers → body**.
2. **Trace headers** (Received and others) are **added one at a time, on top, by each server** that handles the message. Message headers and body are **written by the sender's mail program (or submission server).**
3. Received lines have **the newest at the top.** To follow the route, read **from bottom to top.**
4. One Received line = `from <EHLO name> (<PTR name> [<connecting IP>]) by <server that wrote this line> with <protocol> id <ID> for <recipient>; <date>`.
5. The **IP in brackets is what the receiving server saw itself**, so it is real as long as you trust that server. The EHLO name is written by the sender.
6. **The Received line written by our border MTA** is the trust boundary. Trust up to that line's `from` IP; **lines below it can be fabricated by the sender.**
7. A legitimate message forms a **chain from bottom to top where each `by` becomes the next line's `from`.** Breaks, time going backwards and unexpected servers are clues.
8. To receive a suspicious message for analysis, get it **forwarded as an attachment (.eml/.msg)** so the headers survive. A normal forward loses them.

## Why read headers { #why }

What a user sees in their mail client is the sender's name, subject and body. But as the previous page showed, **all of those can be written however the sender likes.** To judge "where did this message really come from?", you have to open the **source** behind the screen and read what the servers recorded.

Think of **parcel tracking history.** Anyone can write the "sender" sticker on the box, but each "arrived at depot X, 14:02" entry was recorded by that depot. An email's Received headers are those depot entries. There is one trap, though: **entries from before the parcel reached our depot could have been pre-written on the label by the sender.** So the core of this page is how to draw the line for what to trust.

## The three parts of a message source { #three-parts }

Below is the source of a message received by an employee of the invented organisation `victim.example`. Clicking "Show original" produces text like this.

```
Return-Path: <user1@freemail.example>
Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS
        id 7Hq2; Wed, 18 Nov 2026 22:41:07 +0000
Received: from out-7.freemail.example (out-7.freemail.example [198.51.100.71])
        by mx1.victim.example with ESMTPS id 4QzK7m1abc
        for <jsmith@victim.example>; Wed, 18 Nov 2026 22:41:05 +0000
Received: from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25])
        by smtp.freemail.example with ESMTPSA id e5so1909
        for <jsmith@victim.example>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
        Wed, 18 Nov 2026 14:41:02 -0800 (PST)
Authentication-Results: mx1.victim.example; spf=pass smtp.mailfrom=freemail.example;
        dkim=pass header.d=freemail.example; dmarc=pass header.from=freemail.example
From: "Kim User" <user1@freemail.example>
To: <jsmith@victim.example>
Subject: Meeting notes
Date: Wed, 18 Nov 2026 17:41:00 -0500
Message-ID: <013501d48651$07300ed0$15902c70$@freemail.example>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_8812"
X-Mailer: Microsoft Outlook 16.0

------=_Part_8812
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Notes from today attached.

------=_Part_8812
Content-Type: application/pdf; name="notes.pdf"
Content-Disposition: attachment; filename="notes.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjcKJeLjz9MKMSAwIG9iago8PC9UeXBlL0NhdGFsb2cvUGFnZXMgMiAwIFI+Pgpl
------=_Part_8812--
```

| Part | Where | Who writes it | What's in it |
| --- | --- | --- | --- |
| **Trace headers** | Top | **Each server** the message passes through, adding its own line on top | `Received:`, `Return-Path:`, authentication results (`Authentication-Results:`), `X-...` headers added by servers and security products |
| **Message headers** | Below that | **The sender's mail program** (MUA) or submission server | `From:`, `To:`, `Subject:`, `Date:`, `Message-ID:`, `MIME-Version:`, `Content-Type:`, `X-Mailer:` |
| **Body** | After a blank line, at the bottom | The sender | Text, HTML, images, attachments (usually Base64) |

The "who writes it" column is the same as **"how far you can trust it."** Message headers and body were written by the sender and can be false; trace headers were written by servers and can be trusted **only as far as you trust that server.**

### Trace headers line by line { #trace-lines }

- `Return-Path: <user1@freemail.example>` — the **envelope sender (MAIL FROM)** from the previous page, written in by the final delivering server. Take note if its domain differs from `From:`
- Top `Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example` — the most recent entry: the internal hop where our MX handed the message to our mailbox server (MDA)
- Middle `Received: from out-7.freemail.example (...[198.51.100.71]) by mx1.victim.example` — **the line written by our border MTA (mx1)**: a record that external server 198.51.100.71 connected to us. This line is the trust boundary (more below)
- Bottom `Received: from LAPTOP-7Q2 (...[203.0.113.25]) by smtp.freemail.example with ESMTPSA` — the oldest entry: the sender's PC (`LAPTOP-7Q2`, IP 203.0.113.25) logged in to the mail service's submission server and sent the message. **This line was written by freemail.example, so we can trust it only as far as we trust freemail.example**
- `Authentication-Results:` — the results of our mx1 checking SPF, DKIM and DMARC (covered in detail on later pages)

### Message headers line by line { #message-lines }

- `From:` / `To:` / `Subject:` — the values shown on screen, written by the sender
- `Date: Wed, 18 Nov 2026 17:41:00 -0500` — the time according to **the sender's PC clock and time zone.** -0500 is five hours behind UTC. It can hint at where the sender is, but it's just a PC setting and can be changed
- `Message-ID:` — a unique ID attached to each message. The domain after `@` and the shape of the first part **follow each mail program's habits** (the `$...$...$@` shape here is an Outlook habit). If `From:` says Gmail but the Message-ID looks like a completely different program's, that's a clue
- `MIME-Version: 1.0` — the body uses the MIME format, which carries several kinds of content (text, HTML, attachments)
- `Content-Type: multipart/mixed; boundary="----=_Part_8812"` — "the body has several parts, separated by `------=_Part_8812` lines"
- `X-Mailer: Microsoft Outlook 16.0` — the sending mail program. Headers starting with `X-` are non-standard extras. Phishing kits and bulk-sending scripts often leave unusual values here, or omit it entirely

### Body and attachments { #body }

- Blank line — end of headers, start of body
- `------=_Part_8812` — start of the first part. `Content-Type: text/plain` = a plain-text part
- Second part `Content-Type: application/pdf; name="notes.pdf"` with `Content-Disposition: attachment` — this is **an attachment**
- `Content-Transfer-Encoding: base64` — the file is carried **converted to Base64** text. SMTP was designed to carry only text, so binary data such as files is converted to Base64 for transport
- `JVBERi0x...` — the Base64 data. The leading `JVBERi0` decodes to `%PDF-`, so you can tell it really is a PDF ([guessing file types from Base64 prefixes](../http-analysis/base64.md))
- `------=_Part_8812--` — a trailing `--` marks the end of the last part

**[Supplement]** If the body says `Content-Transfer-Encoding: quoted-printable`, you'll see transformed characters such as `=3D` (the = sign) and `=20` (a space). Phishing messages sometimes wrap their HTML in this encoding or in Base64 to dodge simple keyword checks. If an HTML body arrives alongside `text/plain` as `multipart/alternative`, check whether the two versions differ (an innocent sentence in plain text, a phishing link in the HTML).

## How to view the source and headers { #how-to-view }

| Environment | How |
| --- | --- |
| Outlook (classic desktop) | **Open the message in its own window** → File → Properties → the "Internet headers" box. The box is small, so `Ctrl+A`, copy, and paste into an editor |
| New Outlook / Outlook on the web | The message's `...` → View → View message details |
| Gmail | `⋮` at the top right of the message → **Show original.** The full headers and body appear as plain text, along with an SPF/DKIM/DMARC summary. "Download original" saves an `.eml` |
| Thunderbird and others | View → Message Source (`Ctrl+U`) |
| Header analysis tools | Microsoft **Message Header Analyzer** (MHA), Google Admin Toolbox **Messageheader** — paste the headers and they lay out the Received order and delays as a table |

**[Caution] Handling it safely.**

- **Ask users to "forward as attachment", not to forward normally.** A normal forward strips the original message's trace headers and turns it into a new message sent by the person forwarding. Use Outlook's "Forward as Attachment", Gmail's "Forward as attachment", or receive it as an `.eml`/`.msg` file. In many organisations a "Report phishing" button does this for you
- Viewing the plain-text source is relatively safe, but **rendering the HTML can load remote images (tracking pixels), signalling to the attacker that "this address is live and the message was opened."** Turn off remote content loading in your analysis environment
- Don't click links; defang them when recording (`hxxps`, `[.]`). Open attachments only in an isolated environment or sandbox
- A message source contains the recipient's personal information, so check your organisation's rules before pasting it into a public analysis site

## Retracing a message's route with Received headers { #tracing }

### Read from bottom to top { #bottom-to-top }

Each time a server receives a message, it **adds its own entry on top.** So Received lines are in reverse order: **newest at the top, oldest at the bottom.** To follow the route in the order the message actually travelled, **start at the bottom and move up.**

Below are only the Received lines of a message sent by a user of an external mail service to an organisation on Microsoft 365 (shortened for illustration). They're numbered from the bottom.

```
[6] Received: from AM9PR01MB7421.eurprd01.prod.outlook.example by AM9PR01MB7421.eurprd01.prod.outlook.example; Wed, 18 Nov 2026 22:41:09 +0000
[5] Received: from DB8PR04CA0012.eurprd04.prod.outlook.example (2603:10a6:10:12a::22) by AM9PR01MB7421.eurprd01.prod.outlook.example; Wed, 18 Nov 2026 22:41:08 +0000
[4] Received: from DB1EUR03FT041.eop-EUR03.prod.protection.outlook.example (2603:10a6:10:12a:cafe::5) by DB8PR04CA0012.outlook.office365.example; Wed, 18 Nov 2026 22:41:07 +0000
[3] Received: from out-7.freemail.example (out-7.freemail.example [198.51.100.71]) by DB1EUR03FT041.mail.protection.outlook.example; Wed, 18 Nov 2026 22:41:06 +0000
[2] Received: by out-7.freemail.example with SMTP id e5so1909 for <jsmith@victim.example>; Wed, 18 Nov 2026 14:41:05 -0800 (PST)
[1] Received: from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example with ESMTPSA; Wed, 18 Nov 2026 14:41:03 -0800 (PST)
```

Building the story from bottom to top:

- **[1]** The sender's laptop `LAPTOP-7Q2` (IP 203.0.113.25, whose reverse DNS shows a static IP from some ISP) **logged in (the A in ESMTPSA)** to the mail service's submission server `smtp.freemail.example` and submitted the message. Because it was sent from a mail program (Outlook, Thunderbird and the like), the PC name and IP were recorded. **Had it been sent from webmail**, this line would usually show only the mail service's own servers, without the user's IP
- **[2]** Another server inside freemail.example, `out-7`, received it. This line has no `from`; that sometimes happens between servers inside the same organisation and isn't a concern
- **[3]** **This is where it crosses the organisational border.** freemail.example's border server `out-7` (IP 198.51.100.71) connected to the receiving organisation's Microsoft 365 entry point (`...mail.protection.outlook...`, the receiving organisation's MX). **This line was written by the receiving side (Microsoft 365)**, so you can trust that 198.51.100.71 really connected
- **[4]–[6]** Microsoft 365 internal servers hand it along until the final mailbox server (internal hops commonly use IPv6 addresses)

**Checking the chain:** [3]'s `by DB1EUR03FT041` continues as [4]'s `from DB1EUR03FT041`, and [4]'s `by DB8PR04CA0012` continues as [5]'s `from`. When **each line's `by` becomes the `from` of the line above it**, the route is natural.

**Checking the times:** **convert** the time at the end of each line **to UTC** and compare. [1] `14:41:03 -0800` = UTC 22:41:03, [2] = 22:41:05, [3] 22:41:06, … [6] 22:41:09. Normally time **increases from bottom to top.** Take note if time goes backwards, if one hop is delayed by hours (it could be queueing or greylisting), or if the time zone notation looks odd. Servers use different time zones, so comparing without converting to UTC is an easy way to fool yourself.

### How far can you trust it: the trust boundary { #trust-boundary }

This is the most important part of this page.

- SMTP is TCP, so the IP a server records as "who connected to me" is real **if that server is honest**
- We trust **our own border MTA** (or the entry point of the cloud mail service we use) to be honest. So **the `from` IP on the line our border MTA wrote is real** — [3] in the example above
- But [1] and [2] are **lines written by the sending side's servers.** If the sender is a legitimate large mail service, those entries are generally reliable too, but **if the sender is an attacker, they can fabricate lines like [1] and [2] wholesale and include them in the message in advance.** Our server only adds its own line on top of the message it receives; it doesn't check the lines below

```
  ┌──────────── written by our side: trust ────────────┐
  [6] [5] [4]   internal hops (our servers / our cloud tenant)
  [3]  from ... [198.51.100.71]  by OUR border MTA   ← trust boundary: this IP is real
  └─────────────────────────────────────────────────────┘
  [2] [1]       written by the sender's side: claims only
```

So the analysis order is:

1. **Know the name of our MX (border)** — the MX lookup from the previous page, or the name of the mail service or security gateway the organisation uses
2. **Work down from the top and find "the last line with one of our servers in `by`"** — that line is the boundary
3. **Investigate that line's `from` IP** — this is the message's real origin (at least, the server that handed it to us). Check its ASN, reverse DNS, reputation, and whether it is a legitimate sending server for the `From:` domain (checked with SPF, next page)
4. **Treat the lines below as "claims" only** — use them as reference if the sender is a legitimate large service; be suspicious if the servers look odd

**[Supplement] An example of forged Received lines.** If an attacker sends something like the following, a quick read tells a story of "it started from inside the bank".

```
Received: from mail.bank.example (unknown [203.0.113.77]) by mx1.victim.example with ESMTP; Wed, 18 Nov 2026 22:50:12 +0000
Received: from internal-relay.bank.example ([10.40.1.12]) by mail.bank.example with ESMTP; Wed, 18 Nov 2026 22:50:10 +0000
Received: from ops-pc17.bank.example ([10.40.8.33]) by internal-relay.bank.example; Wed, 18 Nov 2026 22:50:09 +0000
```

But look at the top line — **the line our mx1 wrote**: the connecting IP 203.0.113.77 has no reverse DNS (`unknown`), and only the EHLO claims to be `mail.bank.example`. Check whether 203.0.113.77 is really bank.example's mail server (is it in that domain's MX or SPF, is the ASN the bank's?) and the lie shows. **The two lines below may be decoration the attacker wrote in advance.**

### Reading one Received line field by field { #anatomy }

Here's one line written by our server at the border, broken into fields.

```
Received: from mailer.promo-deals.example (unknown [203.0.113.149])
        by mx1.victim.example with ESMTP id 922034ljg
        for <jsmith@victim.example>; Wed, 18 Nov 2026 22:26:53 +0000
```

| Field | Value | Set by | Meaning |
| --- | --- | --- | --- |
| Right after `from` | `mailer.promo-deals.example` | **The sender** (the name announced in EHLO/HELO) | May be false |
| First item in parentheses | `unknown` | The receiving server (**result of a PTR lookup** on the connecting IP) | Reverse DNS result; `unknown` if none. May or may not match the EHLO name |
| `[ ]` in parentheses | `203.0.113.149` | The receiving server (**seen directly** on the TCP connection) | **The unspoofable connecting IP** |
| `by` | `mx1.victim.example` | The receiving server | **The server that wrote this line** — the one that just received the message |
| `with` | `ESMTP` | The receiving server | The protocol used (table below) |
| `id` | `922034ljg` | The receiving server | That server's queue ID — the key for matching against server logs |
| `for` | `<jsmith@victim.example>` | The receiving server | The envelope recipient (RCPT TO). Optional |
| After `;` | Date and time | The receiving server | When it was received |

Reading this example: **IP 203.0.113.149, calling itself `mailer.promo-deals.example`, with no reverse DNS, connected to our mx1 without encryption (ESMTP, no S) and handed over the message.** An EHLO name that doesn't match the PTR (here, there's no PTR at all) is common for spam and malicious senders, so it's a weak signal.

The protocol notation in the `with` field reads like this (RFC 3848):

| Notation | Meaning |
| --- | --- |
| `SMTP` | Old SMTP without extensions (HELO) |
| `ESMTP` | Extended SMTP (EHLO), no encryption |
| `ESMTPS` | ESMTP + **TLS encryption** (STARTTLS) |
| `ESMTPA` | ESMTP + **login authentication** (the user logged in to the submission server) |
| `ESMTPSA` | TLS + login authentication. Common when a user sends from a mail program |
| `LMTP` | Internal delivery to a mailbox server |

**[Supplement] Trace headers worth checking besides Received.**

- `X-Originating-IP:` — "the IP the user connected from", once added by some webmail services. Many large services no longer include it, for privacy reasons
- Microsoft 365's `X-Forefront-Antispam-Report:` — contains `CIP:` (connecting IP), `SFV:` (spam verdict), `SCL:` (spam confidence level) and more; handy for quickly finding the border IP. `X-MS-Exchange-Organization-AuthAs: Anonymous` means the message came in from outside without authentication; `Internal` means it was authenticated inside the organisation
- `ARC-Seal:`, `ARC-Message-Signature:`, `ARC-Authentication-Results:` — when forwarding or a mailing list breaks the original authentication results, an intermediate server signs a record saying "authentication passed when I received it" (ARC, explained on a later page)

### Viewing it in Zeek and on the command line { #tools }

Zeek `smtp.log` pulls out some Received lines separately.

```
first_received=from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example ...
second_received=by out-7.freemail.example with SMTP id e5so1909 ...
path=203.0.113.10,198.51.100.71,203.0.113.25
```

- `first_received` / `second_received` — the **top two** Received lines in the header (the most recent at the point Zeek sees it)
- `path` — the IP path extracted from the Received lines, most recent first

If you have the `.eml` file, Python's standard library can print the Received lines **in the order the message actually travelled.**

```
$ python3 -c '
import email, sys
msg = email.message_from_binary_file(open(sys.argv[1], "rb"))
for n, h in enumerate(reversed(msg.get_all("Received", [])), 1):
    print(n, " ".join(h.split()))
' suspicious.eml
```

- `import email, sys` — the standard module for parsing mail, and the module for command-line arguments
- `email.message_from_binary_file(open(..., "rb"))` — opens the `.eml` file in binary mode and parses it into a message object
- `msg.get_all("Received", [])` — gets every Received header **in source order (newest first)**; an empty list if there are none
- `reversed(...)` — flips the order to **oldest first**
- `" ".join(h.split())` — unfolds headers that wrap across lines into one line for printing
- `suspicious.eml` — the file to analyse (passed as `sys.argv[1]`)

The output looks like this:

```
1 from LAPTOP-7Q2 (static-25-113-0-203.isp.example [203.0.113.25]) by smtp.freemail.example with ESMTPSA id e5so1909 for <jsmith@victim.example> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384); Wed, 18 Nov 2026 14:41:02 -0800 (PST)
2 from out-7.freemail.example (out-7.freemail.example [198.51.100.71]) by mx1.victim.example with ESMTPS id 4QzK7m1abc for <jsmith@victim.example>; Wed, 18 Nov 2026 22:41:05 +0000
3 from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS id 7Hq2; Wed, 18 Nov 2026 22:41:07 +0000
```

Line 1 is the start, line 2 is **our border (the line mx1 wrote)**, line 3 is our internal hop. The `[198.51.100.71]` in line 2 is the IP to investigate.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The three parts (trace headers, message headers, body), Received lines in reverse order read from bottom to top, the `from EHLO (PTR [IP]) by ...` format, the connecting IP being what the receiving server saw itself, and the principle that **the line written by our border MTA is the trust boundary** all still hold.

!!! info "[Changed] What has changed"
    - **Cloud mail makes headers long.** Passing through Microsoft 365 or Google Workspace adds many internal Received lines (internal IPv6 addresses are common) and dozens of service-specific `X-` headers (`X-Forefront-Antispam-Report`, `X-MS-Exchange-*`, `X-Google-*`). Rather than reading every line by hand, lay out the Received order with a tool such as MHA and focus on the border line and the authentication results.
    - **Less and less of the sender's IP is left.** Large webmail services don't put the user's IP in headers, and some strip it from the first Received line even when the message was sent from a mail program. Relay-address services such as Apple's "Hide My Email" have also grown. Expecting "the sender's IP is in the first Received line" now often fails.
    - **Email security products rewrite links.** Because of Microsoft Defender Safe Links and URL rewriting in other security gateways, links in the body look like `https://...safelinks.protection.outlook.com/?url=<encoded original URL>&...`. When analysing, URL-decode what follows `url=` to recover **the original address.**
    - **Header analysis has been automated.** A common flow: the user's "Report phishing" button → the mail platform (Defender for Office 365, Google Workspace) preserves the original → SOAR extracts headers, links and attachments and checks their reputation automatically. Even so, when the automated result is ambiguous, the judgement comes down to the reading skills on this page.
    - **Generative AI has made message bodies more natural.** Spotting phishing through spelling mistakes or awkward translation has become less reliable. That raises the weight of **technical records in the header** that a person can't edit (the border IP, authentication results, the consistency of the chain).

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't assume the bottom Received line (the oldest) is "the real origin".** An attacker can write it. The anchor is the line written by our border MTA.
    - **Don't trust the EHLO name as the origin.** Look at the `[IP]` in brackets.
    - **Don't receive suspicious mail by normal forward.** The headers disappear. Get it forwarded as an attachment, or pull the original from the mail platform.
    - **Don't compare times without aligning time zones.** Convert everything to UTC.
    - **Don't open an HTML body with remote content enabled.** Tracking pixels signal the attacker.

## Practice questions { #quiz }

### Question 1

The MX for `victim.example` is `mx1.victim.example`. In the following Received lines (in source order), which line is the **trust boundary**, and which IP should you investigate? How should you treat the lines below it?

```
Received: from mx1.victim.example (10.0.5.20) by mbx01.victim.example with ESMTPS; Wed, 18 Nov 2026 23:05:44 +0000
Received: from relay.payroll-portal.example (unknown [203.0.113.201]) by mx1.victim.example with ESMTP; Wed, 18 Nov 2026 23:05:42 +0000
Received: from hr-gw.victim.example ([10.0.9.4]) by relay.payroll-portal.example with ESMTP; Wed, 18 Nov 2026 23:05:40 +0000
Received: from HR-PC03.victim.example ([10.0.9.77]) by hr-gw.victim.example with ESMTPSA; Wed, 18 Nov 2026 23:05:39 +0000
```

??? success "Answer and explanation"
    **The boundary is the second line.** Working down from the top for the last line with one of our servers in `by`: the first line (`by mbx01`, our internal server) and the second line (`by mx1`, **our border MTA**). From the third line on it's `by relay.payroll-portal.example` — lines written by an external server.

    **IP to investigate: `203.0.113.201`.** It's the connecting IP our mx1 saw itself, with no reverse DNS (`unknown`) and no encryption (ESMTP).

    **The two lines below** make it look as though the message **started from a PC in our own HR team (HR-PC03) and our internal gateway (hr-gw.victim.example).** But those lines were written on the external `relay.payroll-portal.example` side, and there's no reason for our internal server to send mail back to us through an external relay. **They're most likely forged lines dressed up to look internal.** To confirm, check whether our hr-gw server logs have a record of that message at that time (if not, the forgery is confirmed).

### Question 2

Interpret the following Received line field by field and say what's suspicious.

```
Received: from mail.securebank.example (static-77-113-0-203.cheap-vps.example [203.0.113.77])
        by mx1.victim.example with ESMTP id 8Kd2Q
        for <finance@victim.example>; Wed, 18 Nov 2026 01:14:09 +0000
```

??? success "Answer and explanation"
    - `from mail.securebank.example` — the name the sender **announced for itself** in EHLO, claiming to be a bank mail server
    - `static-77-113-0-203.cheap-vps.example` — the **reverse DNS (PTR)** our mx1 looked up for the connecting IP: the name of a cheap VPS provider
    - `[203.0.113.77]` — the **connecting IP our mx1 saw itself** (cannot be spoofed)
    - `by mx1.victim.example` — the server that wrote this line = **our border MTA**, so this line is the trust boundary
    - `with ESMTP` — connected without encryption (no S) and without login
    - `id 8Kd2Q` — mx1's queue ID, the key to finding this message in mx1's logs
    - `for <finance@victim.example>` — the envelope recipient: the finance team
    - Time — 01:14 UTC

    **What's suspicious:** the name claiming to be a bank (EHLO) doesn't match the reverse DNS of the actual connecting IP (a cheap VPS). A real bank would normally send from its own or a large mail service's IPs and use encryption (ESMTPS). The recipient is the finance team, so this may be BEC impersonation. Next steps: look up the ASN and reputation of 203.0.113.77, check whether this IP is in the bank domain's SPF, check `Authentication-Results`, and find other messages from the same IP.

### Question 3

An employee says they received a suspicious message and sends it to the SOC mailbox using a **normal "Forward".** Opening the headers, you find the Received lines are all internal company servers and the sender is the employee. Why did this happen, and what do you need to do to analyse the original message?

??? success "Answer and explanation"
    **Why:** a normal forward **copies the original content into a new message that the employee sends again.** The new message's trace headers record only "employee PC → company mail server → SOC mailbox", and the original message's Received lines, Return-Path and Authentication-Results are gone. The mail program may also have altered links in the body.

    **Fix:**

    1. Ask the employee to **"Forward as attachment"** or save it as an `.eml`/`.msg` file and send that (or point them to the organisation's "Report phishing" button)
    2. With admin rights, pull the original directly from the mail platform — for example, download it from Microsoft 365 message trace or Defender's Explorer, or use Google Workspace's investigation tool
    3. In the original's Received lines, find the line written by our border MTA, investigate its `from` IP, and search for whether the same message reached other employees
    4. Advise the employee to use the report button or forward as attachment, rather than a normal forward, in future
