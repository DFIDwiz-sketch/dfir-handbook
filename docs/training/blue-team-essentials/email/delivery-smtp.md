---
title: "Email Delivery and SMTP — MUA, MTA, MDA, Ports, Reading an SMTP Conversation"
tags:
  - training
  - blue-team
  - email
  - smtp
---

# Email Delivery and SMTP — MUA, MTA, MDA, Ports, Reading an SMTP Conversation { #delivery-smtp }

!!! abstract "What this page covers"
    The three stages an email passes through from the sender's PC to the recipient's inbox (submission, relay, receiving), and what the MUA, MSA, MTA and MDA that handle each stage are. The protocol and port used at each stage, how MX records find the receiving server, and why the border MTA's IP is a value that "cannot be spoofed". Then reading an SMTP conversation line by line, the difference between envelope and header addresses, reply codes, Zeek `smtp.log`, and what a SOC looks for. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. All domains and IPs are invented for illustration (`.example`, documentation IPs).

## The 8 key points { #key-points }

1. Think of email delivery as three stages: **submission → relay → receiving**.
2. **MUA** (mail program) → **MSA/MTA** (sending servers) → **MTA** (receiving servers) → **MDA** (server that drops mail into the mailbox) → the recipient's **MUA**.
3. Each stage uses different protocols and ports: **server-to-server relay is SMTP on 25**, user submission is **587/465**, and reading is **IMAP/POP3** or **HTTPS** (webmail, Exchange/Microsoft 365, Gmail).
4. The receiving side's border server is found through the DNS **MX record**.
5. **The IP the sending border MTA connected to us from** is confirmed by a TCP connection, so it **cannot be spoofed.** It is the anchor for judging where an email came from.
6. SMTP is made of human-readable **plaintext commands** (EHLO, MAIL FROM, RCPT TO, DATA) and **three-digit reply codes**.
7. **Envelope addresses (MAIL FROM, RCPT TO) and header addresses (From:, To:) can differ.** Users see the header address, and it can say anything.
8. Every server the message passes through repeats the same SMTP conversation, and the traces pile up as **Received headers** — the subject of the next page.

## Why email matters { #why-email }

Email is still one of the **most common front doors** attackers use to get into an organisation. Malicious attachments, phishing links, messages that lure users to fake login pages, and impersonation messages asking to change payment details (BEC, Business Email Compromise) all arrive by email. So a SOC analyst needs to be able to judge independently "did this really come from that person, and where did it travel?"

The raw material for that judgement is the **email header**. But to read headers properly, you first need to know **which servers the message passes through and which protocols carry it**, because each server adds a line to the header. This page maps that route first.

## Three stages: submission, relay, receiving { #three-stages }

Think of **the post.** I write a letter and drop it in the local postbox (submission), post offices hand it along until it reaches the recipient's local post office (relay), that office puts it in the recipient's letterbox, and the recipient opens the letterbox and takes it out (receiving).

```
 Sender's org                                           Recipient's org
┌──────────────────────────────────────┐   Internet   ┌──────────────────────────────────────┐
│ MUA ─(1) submit─▶ MSA ─▶ MTA ─▶ Border MTA ═SMTP 25═▶ Border MTA ─▶ MTA ─▶ MDA ─(3) read─▶ MUA │
└──────────────────────────────────────┘  (2) relay   └──────────────────────────────────────┘
                                          found via DNS MX
```

| Name | Full name | What it does | Postal analogy | Examples |
| --- | --- | --- | --- | --- |
| MUA | Mail User Agent | The program a user writes and reads mail in. Submits outgoing mail to the server and displays received mail | Me (writing and reading letters) | Outlook, Thunderbird, Gmail web UI, phone mail apps |
| MSA | Mail Submission Agent | A submission-only server that first accepts the user's mail. Usually requires login (authentication) | The local postbox | `smtp.mail.example:587` |
| MTA | Mail Transfer Agent | A relay server that hands mail to the next server. Mail may pass through several | Post offices | Postfix, Exim, Exchange, email security gateways |
| Border MTA | Border MTA | The **last** server to touch the mail in the sending organisation, and the **first** to receive it in the receiving organisation | The border post office | On the receiving side, the server in the MX record |
| MDA | Mail Delivery Agent | Sorts mail per recipient and stores it in the mailbox | The postie putting it in the letterbox | Dovecot, Exchange mailbox servers |

The standards split names by role like this, but in practice one server often plays several roles, and webmail and cloud mail such as Microsoft 365 and Google Workspace blur the lines further. Still, thinking in roles lets you say precisely **"what traffic, and what logs, exist at this stage"**.

### Protocols and ports by stage { #ports }

| Segment | Protocol | Port | Notes |
| --- | --- | --- | --- |
| MUA → MSA (submission) | SMTP Submission | **587** (encryption started with STARTTLS) | Login required. The most common submission port |
| MUA → MSA (submission) | SMTP Submission over TLS | **465** (TLS from the start) | Once deprecated, recommended again by RFC 8314 |
| MTA → MTA (relay) | SMTP | **25** | Server to server. Accepting without authentication is normal (it's mail for the receiving organisation) |
| MDA → MUA (reading) | IMAP | 143 (STARTTLS) / **993** (TLS) | Mail stays on the server and is synchronised |
| MDA → MUA (reading) | POP3 | 110 (STARTTLS) / **995** (TLS) | Mail is downloaded and taken away |
| Submission and reading | HTTPS | **443** | Webmail, Exchange (MAPI/HTTP, EWS, ActiveSync), Microsoft Graph, Gmail API |

One important fact: **submission (stage 1) and reading (stage 3) may not be SMTP, but the server-to-server relay (stage 2) is always SMTP.** And the **Received headers we analyse are created in that SMTP relay segment.** Whether the user writes in webmail or Outlook, once the message reaches the first MTA, SMTP conversations carry it all the way to the receiving MDA.

### Finding the receiving server: MX records { #mx }

The sending border MTA asks DNS **MX (Mail Exchanger) records** "which server should I hand mail for `victim.example` to?" ([DNS records](../dns/understanding-dns.md#records)).

```
$ dig +short MX victim.example
10 mx1.victim.example.
20 mx2.victim.example.
```

- `dig` — the DNS lookup command
- `+short` — print only the answer
- `MX victim.example` — ask for this domain's mail servers
- `10 mx1...` / `20 mx2...` — the leading number is the **preference**. **Lower numbers are tried first**; if mx1 is unavailable, mail goes to mx2

For an organisation on cloud mail, the MX points to the cloud service, such as `victim-example.mail.protection.outlook.com` (Microsoft 365) or `aspmx.l.google.com` (Google). An organisation with an email security gateway in front will show that vendor's servers in its MX. **From the SOC's point of view, you need to know "where our MX is"** so that on the next page you can tell which Received lines were written by our side.

### The border MTA's IP cannot be spoofed { #border-ip }

Much of a header can be written however the sender likes. But **the IP address the sending border MTA connected to our border MTA from** is different. SMTP runs over TCP, and a TCP connection only exists after the **three-way handshake** (SYN → SYN-ACK → ACK). If you send a SYN from a fake IP, our server's SYN-ACK goes to that fake IP and the sender can't continue the conversation. So **the IP of a peer that actually completed an SMTP conversation is real.**

That is why, when judging an email's origin, the anchor is **the "received from (IP)" record written directly by our border MTA.** The SPF check on the following pages uses exactly this IP. Conversely, Received lines written before that point (inside the sending side) **can be fabricated by the sender.**

## Reading an SMTP conversation line by line { #smtp-conversation }

SMTP is a very simple protocol created in 1982. Commands and replies are **human-readable ASCII text**, and the server answers with **three-digit reply codes**, much like HTTP. Below, the mail server for `sender.example` hands one message to the MX for `victim.example`. `S:` is the receiving server; `C:` is the connecting client.

```
S: 220 mx1.victim.example ESMTP ready
C: EHLO mail.sender.example
S: 250-mx1.victim.example Hello mail.sender.example [198.51.100.25]
S: 250-SIZE 52428800
S: 250-8BITMIME
S: 250-STARTTLS
S: 250 SMTPUTF8
C: MAIL FROM:<alerts@sender.example>
S: 250 2.1.0 Sender OK
C: RCPT TO:<jsmith@victim.example>
S: 250 2.1.5 Recipient OK
C: DATA
S: 354 Start mail input; end with <CRLF>.<CRLF>
C: From: "IT Helpdesk" <helpdesk@victim.example>
C: To: jsmith@victim.example
C: Subject: Password expires today
C: Date: Wed, 18 Nov 2026 09:14:02 +1030
C: Message-ID: <a81f3c@mail.sender.example>
C:
C: Your password expires today. Re-validate here: hxxps://login-victim.example/reset
C: .
S: 250 2.0.0 Ok: queued as 4QzK7m1abc
C: QUIT
S: 221 2.0.0 Bye
```

Line by line:

- `220 mx1.victim.example ESMTP ready` — as soon as the connection opens, the server greets first (the banner). 220 = service ready. ESMTP means SMTP with extensions
- `EHLO mail.sender.example` — the connecting server **announces its own name.** The old command is `HELO`; `EHLO` is used to get extensions. **This name is self-reported and can be false**
- `250-... Hello mail.sender.example [198.51.100.25]` — the receiving server records "fine, that's your name, but **the IP you actually connected from is 198.51.100.25**." That IP is the unspoofable value from earlier. A `-` after the number (`250-`) means "more lines follow"; the last line is `250 ` (space)
- `SIZE`, `8BITMIME`, `STARTTLS`, `SMTPUTF8` — the extensions this server supports. `STARTTLS` means "we can switch to encryption now if you want" (see [Changed] below). A submission server (587) would also list `AUTH` (login methods) here
- `MAIL FROM:<alerts@sender.example>` — **the envelope sender (Envelope From).** If delivery fails, the bounce goes to this address, which is why it is also called the Return-Path or bounce address
- `250 2.1.0 Sender OK` — accepted. `2.1.0` is a more detailed enhanced status code
- `RCPT TO:<jsmith@victim.example>` — **the envelope recipient (Envelope To)**, where the mail is actually delivered. With multiple recipients this line appears several times
- `DATA` → `354 Start mail input...` — "send the message now; when you're done, send a line containing a single dot"
- `From: "IT Helpdesk" <helpdesk@victim.example>` — from here on is **the message itself.** This `From:` is **the header sender (Header From)**, the address shown in the recipient's mail client. It is **different** from the envelope's `alerts@sender.example` — and it impersonates the receiving organisation's own domain (`victim.example`)
- `To:`, `Subject:`, `Date:`, `Message-ID:` — the displayed recipient, subject, date and unique message ID. All **written by the sender**
- Blank line — marks the end of the headers and the start of the body
- Body — the actual content; here a fake password-reset link (defanged to `hxxps` when recorded)
- `.` — a line with a single dot = end of message
- `250 2.0.0 Ok: queued as 4QzK7m1abc` — received and queued. **`4QzK7m1abc` is this server's queue ID**, the key to finding this message in the mail server logs
- `QUIT` → `221 Bye` — connection closed

When the message moves to the next server, **the same conversation is repeated with that server.** If the receiving side has three internal servers, there are three conversations and three Received lines.

### Envelope versus header addresses { #envelope-vs-header }

This distinction is one of the most important concepts in email analysis.

| Kind | Where | In SMTP | Who sees it | Analogy |
| --- | --- | --- | --- | --- |
| Envelope | SMTP commands | `MAIL FROM`, `RCPT TO` | Servers (used for delivery). Kept in the header as `Return-Path:` | The address on the envelope |
| Header | The message inside DATA | `From:`, `To:`, `Cc:` | **The recipient, on screen** | The "From" written at the top of the letter |

The post office delivers by **the envelope** alone. You can write "From the Prime Minister" on the letter inside and the post office won't care. Email is the same: servers deliver according to `RCPT TO`, while users judge "who sent this" from `From:`. But **original SMTP has no rule that the two must match, and no mechanism to check.** So an attacker can keep the envelope on their own domain and put a bank or someone in your organisation in the header `From:`. SPF, DKIM and DMARC were created later to close this gap (covered on later pages).

**Bcc** works on the same principle: Bcc recipients appear only in `RCPT TO` and are never written into the header, so other recipients can't see them.

### Reading reply codes { #reply-codes }

| Code | Meaning | Common examples |
| --- | --- | --- |
| 2xx | Success | `220` ready, `250` OK, `221` closing |
| 3xx | Keep sending input | `354` send the body, `334` send authentication data |
| 4xx | **Temporary** failure, try again later | `421` service unavailable, `450`/`451` greylisting or temporary rejection |
| 5xx | **Permanent** failure | `550` no such user or policy rejection, `530` authentication required, `535` authentication failed, `554` transaction failed (spam, etc.) |

In enhanced status codes (three numbers like `5.7.1`), a middle `7` means a **security or policy** issue. A bounce showing `550 5.7.1` means "rejected by policy" (SPF failure, block list and so on), which is useful when checking whether a spoofed message was stopped.

**[Correction] Case rules.** SMTP commands (`EHLO`, `MAIL FROM` and so on) and domain names are case-insensitive. The part of an address before the `@` (the local part) is, per the SMTP standard (RFC 5321), something **the receiving server may treat as case-sensitive**, but in practice most mail services don't. Note that SMTP conversation rules are RFC 5321 and the mail message format (headers and body) is RFC 5322 — two different documents.

### Lab: try an SMTP conversation yourself { #smtp-lab }

It used to be a common exercise to connect with `telnet mail.example 25` and type the commands above by hand. Today most servers require encryption or refuse unfamiliar connections, so do this against **your own lab mail server (for example Postfix in your lab, or a test server such as MailHog or Mailpit).**

```
$ openssl s_client -starttls smtp -connect mail.lab.example:587 -crlf -quiet
```

- `openssl s_client` — connects to the server as a TLS client
- `-starttls smtp` — connects with plaintext SMTP first, then starts encryption with the `STARTTLS` command
- `-connect mail.lab.example:587` — the lab server's submission port
- `-crlf` — sends line endings as the CRLF (`\r\n`) SMTP requires
- `-quiet` — reduces certificate output. Then type `EHLO`, `MAIL FROM`… yourself

If typing each command is tedious, use `swaks` (Swiss Army Knife for SMTP).

```
$ swaks --server mail.lab.example:25 --from alerts@sender.example \
        --to jsmith@lab.example --header "Subject: test" --body "hello"
```

- `--server` — the server and port to connect to
- `--from` — the **envelope** sender (MAIL FROM)
- `--to` — the envelope recipient (RCPT TO)
- `--header "Subject: test"` — adds a message header
- The output prints the conversation with `<-` (server replies) and ` ->` (commands sent), which makes it great for study

**[Caution]** Don't send test messages like this to other people's mail servers or your organisation's production mail server. It can be mistaken for spoofing and get you onto block lists.

## How a SOC looks at it { #soc-view }

### Zeek `smtp.log` { #zeek-smtp }

When a network sensor sees **plaintext SMTP** (or decrypted SMTP), Zeek writes `smtp.log`. For the conversation above it would look roughly like this:

```
ts=2026-11-17T22:44:02Z  uid=CmXv2k3  id.orig_h=198.51.100.25  id.resp_h=203.0.113.10  id.resp_p=25
helo=mail.sender.example
mailfrom=alerts@sender.example
rcptto=jsmith@victim.example
from="IT Helpdesk" <helpdesk@victim.example>
to=jsmith@victim.example
subject=Password expires today
msg_id=<a81f3c@mail.sender.example>
last_reply=250 2.0.0 Ok: queued as 4QzK7m1abc
path=203.0.113.10,198.51.100.25
tls=F  fuids=-  is_webmail=F
```

- `id.orig_h` / `id.resp_h` — the IPs of the connecting side (the sending border MTA) and the receiving side (our MX). **`id.orig_h` is the unspoofable value**
- `helo` — the name given in EHLO (self-reported)
- `mailfrom` / `rcptto` — the **envelope** addresses
- `from` / `to` — the **header** addresses. The `mailfrom` domain (`sender.example`) and the `from` domain (`victim.example`) differ, and `from` is our own domain → suspected impersonation
- `subject`, `msg_id` — the subject and unique message ID (used to group messages from the same campaign)
- `last_reply` — the server's last reply. 250 means it was accepted
- `path` — the IP path the message travelled (extracted from the Received headers)
- `tls=F` — sent without encryption. If `T`, it was encrypted with STARTTLS, **the content isn't visible**, and most of this log stays empty
- `fuids` — if there are attachments, their file IDs in `files.log` ([Zeek files.log](../../../network/zeek/files-log.md))

**[Caution] Server-to-server SMTP is now mostly encrypted with STARTTLS.** So watching inbound internet mail with a network sensor is less common, and message content is mainly seen in **mail server and email security gateway logs**, Microsoft 365 **Message Trace** and Defender for Office 365 email records, and Google Workspace **Email Log Search**. Network sensors are used more for signals at the level of "who connected to whom on port 25" (`conn.log`).

### Signals to look for on the network { #network-signals }

| What you see | Why it's suspicious | What to check |
| --- | --- | --- |
| **An internal PC connecting directly to external port 25** | Normal PCs send through the company mail server (or cloud mail on 443). Going straight out on 25 suggests a spambot, malware sending mail, or exfiltration | Which process (Sysmon Event ID 3 — network connection record), number of connections and destinations |
| Inbound connections on 25 to a server that isn't our MX | An attempt to **bypass** the MX and email security gateway and avoid inspection | Why that server exposes port 25 to the internet |
| Repeated 587/465/IMAP login failures from one IP or against many accounts | Password guessing (password spraying, brute force) | Whether a success followed the failures, and what the successful account did next |
| An SMTP server inside the network you've never seen | A relay set up by an attacker, or a misconfigured device (printers and the like) | Who is sending through it, and whether it's an open relay |
| EHLO name completely different from the IP's reverse DNS (PTR) | Legitimate mail servers usually match them. Spam and malicious senders often write something careless | A weak signal. Judge together with other signals |

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The MUA/MSA/MTA/MDA structure, server-to-server relay over SMTP on port 25, finding the receiving server via MX, the border MTA's connecting IP as the anchor, the envelope-versus-header distinction, and headers piling up as the conversation repeats at each server all still hold.

!!! info "[Changed] What has changed"
    - **Server-to-server encryption is now the norm.** STARTTLS is "encrypt if possible", so a man in the middle who strips the `STARTTLS` line could force plaintext. To prevent that, **MTA-STS** (RFC 8461, publishing "our servers only accept mail over TLS" via HTTPS), **TLS-RPT** (RFC 8460, TLS failure reporting) and DNSSEC-based **DANE** are used. Most large mail services support them.
    - **Mail has largely moved to the cloud.** With Microsoft 365 or Google Workspace, submission and reading happen over HTTPS (Graph API, MAPI/HTTP, Gmail API), and analysis centres on **cloud mail logs and message trace** rather than network sensors. On-premises Exchange 2016 and 2019 reached end of support in October 2025.
    - **Basic authentication (username/password) for SMTP AUTH is being retired.** In its schedule updated in January 2026, Exchange Online will **disable SMTP AUTH basic authentication by default** for existing tenants from the end of December 2026 (admins can still re-enable it), with the final removal date to be announced in the second half of 2027. OAuth is the standard. Old printers and business apps logging into 587 with a password are also targets for password guessing.
    - **SMTP smuggling (2023).** This technique abuses the fact that servers interpret the end-of-message marker (`<CR><LF>.<CR><LF>`) slightly differently, **hiding a second, fake message inside one message** so that the next server accepts it as a separate email. Because it leaves through a legitimate sending server, it could produce spoofed mail that passes SPF and DMARC. Postfix, Exim, Sendmail and others have patched it, so keep mail servers current and configure them to reject non-standard line endings.
    - **Abuse of cloud mail "internal sending" features.** For example, phishing that abused Microsoft 365 Direct Send (inserting mail straight into the MX without authentication) to pose as internal staff was reported in 2025, and a setting to reject it was added. Close unauthenticated paths you don't use.
    - **The shape of email attacks has changed.** Common now: **QR codes** instead of links (scanned with a phone, bypassing corporate security controls), share links from legitimate cloud services, AiTM phishing that hijacks login sessions, ClickFix lures ("copy this command and run it"), and BEC written in natural language polished by generative AI.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't trust the header `From:` or the EHLO name as evidence of the sender.** Both are written by the sender. The anchor is the connecting IP recorded by our border MTA and the authentication results (SPF, DKIM, DMARC).
    - **Don't leave outbound port 25 open for company PCs.** Blocking outbound 25 for everything except mail servers is the baseline.
    - **Don't send test mail to other people's servers with telnet or swaks.**
    - **Don't read "there's no smtp.log on the network" as "there's no mail".** It's invisible because of encryption and the cloud. Mail platform logs need to go into the SIEM.

## Practice questions { #quiz }

### Question 1

What is suspicious in the following Zeek `smtp.log`? Which values can you trust, and which can't you?

```
id.orig_h=198.51.100.25  id.resp_h=203.0.113.10  id.resp_p=25
helo=mail.victim.example
mailfrom=billing@pay-notice.example
rcptto=finance@victim.example
from="CFO Office" <cfo@victim.example>
subject=Urgent: updated bank details for invoice 2219
tls=F
```

??? success "Answer and explanation"
    **Trustworthy:** `id.orig_h=198.51.100.25` — the real peer IP that completed the TCP connection. Check whether this IP is a mail server of `victim.example` (our organisation). If it isn't, this is mail that came from outside using our organisation's name.

    **Not trustworthy (written by the sender):**

    - `helo=mail.victim.example` — a name pretending to be our own mail server; it doesn't match the connecting IP
    - `from="CFO Office" <cfo@victim.example>` — the displayed sender, impersonating our CFO
    - `subject` — a classic BEC line: urgent, asking to change bank details

    **Summary of what's suspicious:** the envelope sender (`pay-notice.example`) and header sender (`victim.example`) have different domains, an external IP is using our organisation's name (in HELO and From), and the content is a bank-detail change request. **Treat it as a BEC impersonation email**: find other messages with the same `mailfrom`, connecting IP and subject that went to other recipients, and advise the finance team on the verification procedure (call back on a known phone number). Also check the SPF and DMARC results covered on later pages.

### Question 2

Firewall logs show that office PC `10.1.20.55` connected to **TCP port 25** on hundreds of different external IPs in the past hour. What do you suspect, and what do you need to check?

??? success "Answer and explanation"
    **Suspicion:** normal PCs send mail through the company mail server (or cloud mail on 443). Going **straight out to port 25 on many external hosts** means the PC is acting as its own MTA and spraying mail. Suspect a spambot (infected and sending spam or phishing as part of a botnet) or malware that exfiltrates data by email.

    **Checks:**

    1. Which process made the connections — Sysmon Event ID 3 (network connection: records which program connected to which IP and port) or EDR
    2. That process's path and parent process (Sysmon Event ID 1, Windows Event ID 4688 — a new process was created)
    3. Whether the destination IPs are the MX servers of various domains (a spam pattern)
    4. Whether the firewall actually allowed or blocked it. **In principle, outbound 25 from anything other than mail servers should be blocked**, so if it was allowed, fix the policy too
    5. Isolate and investigate the PC, and check whether the company IP has landed on spam block lists

### Question 3

A colleague says: "This phishing email's `From:` is `notice@bank.example`, so it really came from that bank's server." Using the structure of an SMTP conversation, explain why you can't say that, and say what you should look at instead.

??? success "Answer and explanation"
    **Why:** `From:` is a header the sender writes **inside the message body**, after the SMTP `DATA` command. Servers deliver using only the envelope addresses (`MAIL FROM`, `RCPT TO`), and original SMTP has no mechanism to verify that `From:` is genuine. Anyone can write `From: notice@bank.example` and send it — like writing "From the Bank" on a letter.

    **What to look at:**

    1. **The connecting IP recorded by our border MTA** — the IP of the server that actually handed the message over. Is it that bank's mail server (ASN, reverse DNS, reputation)?
    2. **The envelope sender (Return-Path)** — is its domain the same as `From:`?
    3. **The authentication results (Authentication-Results header)** — did SPF, DKIM and DMARC pass, and does the domain that passed align with the `From:` domain? (Covered in detail on later pages)
    4. Where links and attachments point, and their reputation
