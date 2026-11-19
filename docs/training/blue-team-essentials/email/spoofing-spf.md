---
title: "Email Spoofing and SPF — Why SMTP Trusts Anyone, Spoofed Injection, the Three Defences, How SPF Works"
tags:
  - training
  - blue-team
  - email
  - smtp
  - spf
---

# Email Spoofing and SPF — Why SMTP Trusts Anyone, Spoofed Injection, the Three Defences, How SPF Works { #spoofing-spf }

!!! abstract "What this page covers"
    Why the original SMTP design accepts any sender address without question, and what a spoofed message looks like at the SMTP level. How an attacker skips the login step that normal users go through by talking straight to the recipient's border MTA (spoofed email injection). The three standards built to close the gap — SPF, DKIM and DMARC — and which identity each one checks. Then SPF in detail: what the receiving server compares, why the connecting IP is the anchor, how to read an SPF record mechanism by mechanism with `dig`, how an evaluation is walked through, the 10-DNS-lookup and void-lookup limits, and what SPF does *not* protect. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. All domains and IPs are invented for illustration. Continues from [Reading Email Headers](email-headers.md).

## The 8 key points { #key-points }

1. SMTP was designed in an era when nobody expected abuse. **It does not check whether the sender is who they claim to be.** Any server can write any address in `MAIL FROM` and `From:`.
2. Normal users must **log in (SMTP AUTH)** to their own submission server before sending. An attacker simply **skips that step and connects straight to the recipient's border MTA on port 25**, which has to accept mail from the whole internet without a login.
3. Three standards fill the gap: **SPF** (was this sent from a server the domain authorised?), **DKIM** (was the message signed by the domain, and is it unchanged?), **DMARC** (does the visible `From:` domain match a domain that passed SPF or DKIM, and what should happen if not?).
4. SPF is **path-based**: the receiving MTA compares **the connecting IP** with a **list of allowed senders that the domain publishes in a DNS TXT record**.
5. The connecting IP is the anchor because **a TCP connection cannot be completed from a forged IP** — the handshake reply would go to the real owner of that address.
6. **[Correction]** SPF checks the **envelope sender (`MAIL FROM` / Return-Path)** and the `HELO` name, **not the `From:` header the user sees.** That gap is exactly what DMARC closes.
7. An SPF record is read **left to right; the first mechanism that matches decides the result**, and the qualifier in front (`+ - ~ ?`) says pass, fail, softfail or neutral. `all` at the end catches everything else.
8. One SPF evaluation may cause **at most 10 DNS lookups** (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`) and **at most 2 void lookups**. Exceed either and the result is **permerror** — SPF silently stops working.

## Why SMTP is so easy to spoof { #why-spoofable }

The first SMTP specification dates from 1982. The internet then was a small network of universities and research labs whose administrators largely knew each other. Nobody designed for an attacker who would lie about who they are, so the protocol has **no step where the receiving server asks "prove that you are allowed to send for this address."** The server simply records what it is told.

Think of the **old postal system**. You can write any return address you like on the back of an envelope, and the post office will still deliver it. Nobody at the post office checks whether you really live at the address you wrote. SMTP works the same way: the "return address" (`MAIL FROM`) and the "letterhead" (`From:` in the header) are both just text the sender types.

Here is what that looks like in practice. An attacker on a rented server at `203.0.113.66` connects to the mail server of `victim.example` and claims to be the company's own CEO.

```
$ nc mx1.victim.example 25
220 mx1.victim.example ESMTP Postfix
EHLO mail.victim.example
250-mx1.victim.example
250-PIPELINING
250-SIZE 52428800
250-STARTTLS
250 8BITMIME
MAIL FROM:<ceo@victim.example>
250 2.1.0 Ok
RCPT TO:<finance@victim.example>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: "Jane Park (CEO)" <ceo@victim.example>
To: finance@victim.example
Subject: Urgent - payment needed today

Please process the vendor payment I sent earlier before 3pm. I'm in meetings, reply by email only.
.
250 2.0.0 Ok: queued as 4QzK7m2XyZ
QUIT
221 2.0.0 Bye
```

Line by line:

- `nc mx1.victim.example 25` — open a raw TCP connection to the recipient's MX on the server-to-server SMTP port. No mail client is needed; SMTP is plain text.
- `220 ... ESMTP Postfix` — the server greets and announces its software.
- `EHLO mail.victim.example` — the attacker **introduces itself as the victim's own mail server.** This is just a string; nothing checks it.
- `250-...` lines — the server lists its extensions. Notice there is **no `AUTH`** offered here — a receiving MX does not ask outside servers to log in.
- `MAIL FROM:<ceo@victim.example>` — the **envelope sender**, set to the CEO. The server answers `250 Ok`: accepted without question.
- `RCPT TO:<finance@victim.example>` — the envelope recipient, the finance team. Accepted.
- `DATA` / `354` — the server is ready for the message itself.
- `From: "Jane Park (CEO)" <ceo@victim.example>` — the **header From**, the address the user will actually see. Also just text.
- The line containing only `.` ends the message. `250 2.0.0 Ok: queued as 4QzK7m2XyZ` means **the message has been accepted and queued for delivery.**

The only honest piece of information in this whole exchange is something the attacker never typed: the **IP address the TCP connection came from**, which `mx1` records in its Received line.

```
Received: from mail.victim.example (unknown [203.0.113.66])
        by mx1.victim.example (Postfix) with ESMTP id 4QzK7m2XyZ
        for <finance@victim.example>; Thu, 19 Nov 2026 01:12:40 +0000 (UTC)
```

As on the previous page: the EHLO name says `mail.victim.example`, but the reverse DNS is `unknown` and the bracketed IP is an outside address. Without an extra check, though, the finance team's mail client just shows "Jane Park (CEO)".

**[Supplement]** Many modern mail servers and cloud mail platforms add their own rule on top — "reject or quarantine mail from the internet that claims to be from our own domain" — precisely because this attack is so cheap. That rule exists *because* SMTP itself never had one.

## Spoofed email injection: skipping the login { #injection }

How does an honest employee send mail? Their mail client (MUA) talks to the company's **submission server** on port 587, and that server **requires a login** before it will accept anything.

```
$ openssl s_client -starttls smtp -connect smtp.victim.example:587 -quiet
250 smtp.victim.example
EHLO laptop-7q2
250-smtp.victim.example
250-AUTH LOGIN PLAIN
250-SIZE 52428800
250 8BITMIME
AUTH LOGIN
334 VXNlcm5hbWU6
amFuZUB2aWN0aW0uZXhhbXBsZQ==
334 UGFzc3dvcmQ6
************************
235 2.7.0 Authentication successful
MAIL FROM:<jane@victim.example>
250 2.1.0 Ok
```

- `openssl s_client -starttls smtp -connect ...:587` — connect to the submission port and upgrade to TLS with STARTTLS (so the login below is encrypted on the wire). `-quiet` hides the certificate dump.
- `250-AUTH LOGIN PLAIN` — this server **offers authentication** (the ESMTP AUTH extension). On a submission server, it is mandatory.
- `AUTH LOGIN` — the client starts a login.
- `334 VXNlcm5hbWU6` — the server's prompt in Base64. Decoded it is `Username:` ([Base64](../http-analysis/base64.md)). Base64 is encoding, not encryption — that is why TLS must already be on.
- `amFuZUB2aWN0aW0uZXhhbXBsZQ==` — the username in Base64 (`jane@victim.example`).
- `334 UGFzc3dvcmQ6` — `Password:`; the client then sends the Base64 password (masked here).
- `235 2.7.0 Authentication successful` — logged in. Only now will the server accept `MAIL FROM`, and a well-configured server will also check that Jane is allowed to use that sender address.

So the **sending side** does verify its own users. The problem is the **receiving side**:

```
 Normal path                                           Attacker's path
┌───────────┐ login (AUTH) ┌───────────────┐          ┌───────────────┐
│ Jane's MUA│─────────────▶│ victim.example│          │ Attacker's    │
└───────────┘   port 587   │ submission/MTA│          │ server        │
                           └──────┬────────┘          │ 203.0.113.66  │
                                  │ SMTP 25            └──────┬────────┘
                                  ▼ (no login)                │ SMTP 25 (no login)
                           ┌─────────────────────────────────────────┐
                           │  Recipient's border MTA (MX)           │
                           │  "Anyone may hand me mail for my users" │
                           └─────────────────────────────────────────┘
```

The recipient's border MTA **must** accept mail from any server on the internet without a login — otherwise nobody could email that organisation. So it cannot tell the difference between "a message that went through the sender's login check" and "a message an attacker handed over directly." Both arrive the same way, on port 25, from some IP, with a claimed sender. If the receiving MTA has no way to verify the claim, it believes what the headers say. For many years, that was simply how email worked.

The analogy: the honest letter goes through the sender's local post office, where the clerk checks ID. The forged letter is **walked straight to the recipient's local post office and dropped in the slot** — that office never sees the sender's ID check and has no idea it was skipped.

## Three ways to verify the source { #three-defences }

The ideas for closing the gap are simple, and each became a standard:

1. **Check that the sending server was pre-authorised** by the domain → **SPF** (Sender Policy Framework).
2. **Have the sending gateway sign the message with a private key**, and publish the public key so anyone can verify → **DKIM** (DomainKeys Identified Mail).
3. **Make sure the address the user sees is not a trick** — tie the visible `From:` domain to a domain that actually passed a check, and let the domain owner say what to do on failure → **DMARC** (Domain-based Message Authentication, Reporting and Conformance).

| | SPF | DKIM | DMARC |
| --- | --- | --- | --- |
| Type | **Path-based** (where did it come from?) | **Signature-based** (who signed it, is it intact?) | **Policy + alignment** (does it match what the user sees?) |
| What is checked | Connecting IP vs allowed list | Signature over chosen headers and body | That SPF or DKIM passed **for the same domain as `From:`** |
| Identity checked | Envelope `MAIL FROM` (and `HELO`) | The `d=` domain in the signature | The header `From:` domain |
| Published where | TXT record on the domain | TXT record at `selector._domainkey.domain` | TXT record at `_dmarc.domain` |
| Survives forwarding? | Usually **breaks** (new IP) | Usually **survives** if the message is not altered | Depends on which of the two survives |
| Covered on | This page | Next page | Later page |

The receiving server writes the outcome of all three into an **`Authentication-Results:`** trace header. The format was first standardised in 2009 (RFC 5451), revised several times, and the current version is RFC 8601. A typical line looks like this — the next pages take it apart field by field:

```
Authentication-Results: mx1.victim.example;
       spf=fail smtp.mailfrom=victim.example;
       dkim=none;
       dmarc=fail (p=reject) header.from=victim.example
```

## SPF in a nutshell { #spf-nutshell }

### What the receiving MTA compares { #what-is-compared }

For every incoming connection the receiving border MTA has two things:

- **A claimed domain** — taken from the envelope `MAIL FROM` (for `ceo@victim.example`, the domain `victim.example`), or from the `HELO`/`EHLO` name.
- **A real connecting IP** — the address at the other end of the TCP connection.

It then asks DNS: "What does `victim.example` say about which servers may send its mail?" and compares the answer with the connecting IP.

```
 Attacker 203.0.113.66 ──┐                      ┌── DNS TXT for victim.example:
                         │                      │   "v=spf1 ip4:198.51.100.0/28 ... -all"
 victim.example's MTA ───┼──▶ Recipient's MX ───┤
 198.51.100.5            │     1. Who is calling? (IP)
                         │     2. Who do they claim to be? (MAIL FROM domain)
                         │     3. Is that IP on the domain's list?
                         └──▶  198.51.100.5 → listed     → spf=pass
                               203.0.113.66 → not listed → spf=fail
```

Analogy: the receiving post office now has a **register of approved sorting offices** for each company, published by the company itself. A letter claiming to be from victim.example that arrives from an office not on the list is flagged.

### Why the connecting IP can be trusted { #why-ip }

Everything else in the SMTP exchange is text the sender chooses. The connecting IP is different because SMTP runs over **TCP**, and TCP will not let a connection open without a three-way handshake:

```
Attacker (real IP 203.0.113.66, pretending to be 198.51.100.5)
  1. SYN      src=198.51.100.5  →  mx1
  2. SYN-ACK  mx1  →  dst=198.51.100.5     ← goes to the REAL 198.51.100.5, not the attacker
  3. ACK      (attacker never saw step 2's sequence number, so cannot answer correctly)
  → No connection, so no SMTP conversation
```

The attacker can put a fake source address on a single packet, but the reply goes to the real owner of that address. Without the reply, the attacker cannot complete the handshake, so it can never get as far as `MAIL FROM`. That is why the IP that `mx1` records is real.

**[Supplement]** "Real" is not the same as "innocent." The IP is genuinely the machine that delivered the message — but that machine might be a cheap VPS the attacker rented, or a **legitimate server the attacker has compromised**, or a **legitimate mail platform the attacker has an account on.** In the last two cases SPF will happily pass. SPF answers "did an authorised server deliver this?", not "is this message safe?"

### [Correction] Which "from" SPF actually checks { #which-from }

It is common to read that SPF "looks at the From line." It does not look at the **header** `From:` the user sees. RFC 7208 defines two identities SPF checks:

| Identity | Where it comes from | When it is used |
| --- | --- | --- |
| `MAIL FROM` | The envelope sender in the SMTP conversation; later copied into `Return-Path:` | Always, for normal mail |
| `HELO` | The name in `HELO`/`EHLO` | Recommended as well; and the only identity when `MAIL FROM:<>` is empty (bounce messages) |

This matters enormously. An attacker can do this:

```
MAIL FROM:<bounce@mailer.lookalike-pay.example>     ← attacker's own domain, with a valid SPF record
...
From: "Jane Park (CEO)" <ceo@victim.example>        ← what the user sees
```

SPF checks `lookalike-pay.example`, finds the attacker's IP on the attacker's own list, and returns **pass**. The user still sees `ceo@victim.example`. **SPF alone does nothing about the address on screen.** DMARC's "alignment" requirement — the SPF-passing domain must match the `From:` domain — is what closes this.

## Reading an SPF record { #reading-spf }

### Looking it up with dig { #dig }

An SPF record is an ordinary DNS **TXT** record on the domain itself, starting with `v=spf1` ([DNS records](../dns/understanding-dns.md#records)).

```
$ dig +short TXT victim.example
"site-verification=Xa91kPq2v0m"
"v=spf1 ip4:198.51.100.0/28 ip6:2001:db8:25::/48 a:mail.victim.example mx include:_spf.mailvendor.example include:spf.crm-cloud.example -all"
```

- `dig` — the DNS lookup tool.
- `+short` — print only the answer data.
- `TXT victim.example` — ask for all TXT records of the domain. A domain often has several (site ownership proofs and so on). **Only the one starting with `v=spf1` is SPF**, and there must be **exactly one** — two `v=spf1` records give a **permerror**.

### The record piece by piece { #mechanisms }

| Part | Meaning | DNS lookups it costs |
| --- | --- | --- |
| `v=spf1` | Version tag. Must be first; it is what marks the TXT record as SPF | — |
| `ip4:198.51.100.0/28` | Any IPv4 address in this range (198.51.100.0–15) matches | 0 |
| `ip6:2001:db8:25::/48` | Any IPv6 address in this range matches | 0 |
| `a:mail.victim.example` | Look up the A/AAAA records of that host; match if the connecting IP is one of them. Plain `a` means "the domain's own A record" | 1 |
| `mx` | Look up the domain's MX hosts, then their addresses; match if the IP is one of the mail servers | 1 (+ address lookups of up to 10 MX hosts) |
| `include:_spf.mailvendor.example` | **Evaluate another domain's SPF record**; if that evaluation passes, this mechanism matches. This is how you authorise a mail provider | 1 + whatever the included record costs |
| `include:spf.crm-cloud.example` | Same, for a second service (a CRM platform that sends mail on the company's behalf) | 1 + its cost |
| `-all` | `all` matches **everything**. With `-` in front, anything not matched earlier **fails** | 0 |

Other parts you will meet:

- `exists:<domain>` — match if the domain has any A record; used with macros for advanced setups. Costs 1 lookup.
- `ptr` — match on reverse DNS. **Deprecated** in RFC 7208 (slow and unreliable); do not use it and treat its presence as a sign of an old record.
- `redirect=<domain>` — a **modifier**, not a mechanism: "if nothing here matched, use that domain's record instead." Common for organisations that manage many domains centrally. Costs 1.
- `exp=<domain>` — modifier pointing to an explanation text for rejections. Rarely seen.

### Qualifiers: what a match means { #qualifiers }

Each mechanism can have a prefix. If you write none, `+` is assumed.

| Qualifier | Result on match | Meaning to the receiver |
| --- | --- | --- |
| `+` (default) | **pass** | Authorised |
| `-` | **fail** | Explicitly not authorised — "hard fail" |
| `~` | **softfail** | Probably not authorised; accept but treat as suspicious |
| `?` | **neutral** | The domain makes no statement |

So the end of the record expresses the domain owner's confidence: `-all` ("anything else is definitely not us"), `~all` ("anything else is probably not us"), `?all` ("we're not saying"), or the dangerous `+all` ("**anyone in the world may send as us**" — effectively no SPF at all, and sometimes a sign of a misconfiguration or a tampered record).

### Following an include { #include }

`include` is a pointer to another list, so the receiver fetches that too.

```
$ dig +short TXT _spf.mailvendor.example
"v=spf1 ip4:192.0.2.0/25 include:_spf2.mailvendor.example ~all"

$ dig +short TXT _spf2.mailvendor.example
"v=spf1 ip6:2001:db8:ee::/48 ~all"

$ dig +short TXT spf.crm-cloud.example
"v=spf1 ip4:198.51.100.128/25 -all"
```

- The mail vendor's list has an IPv4 range **and** includes yet another list — includes can nest.
- An important subtlety: inside an `include`, the included record's own `~all`/`-all` only means "**no match here**"; it does not end the outer evaluation. The outer record carries on to its next mechanism.

### Walking through an evaluation { #walkthrough }

Take the spoofed message from the top of the page: `MAIL FROM:<ceo@victim.example>`, connecting IP `203.0.113.66`.

```
v=spf1                                   start
ip4:198.51.100.0/28           203.0.113.66 in 198.51.100.0-15?            no
ip6:2001:db8:25::/48          IPv4 address, IPv6 range                    no
a:mail.victim.example         mail.victim.example → 198.51.100.5          no   (lookup 1)
mx                            MX → mx1, mx2 → 198.51.100.2, .3            no   (lookup 2)
include:_spf.mailvendor...    192.0.2.0/25?                               no   (lookup 3)
   include:_spf2.mailvendor   2001:db8:ee::/48?                           no   (lookup 4)
   ~all                       → inner "no match", go back out
include:spf.crm-cloud...      198.51.100.128/25?                          no   (lookup 5)
-all                          matches everything                          → FAIL
```

Result: **`spf=fail`**. The receiver now knows that victim.example has stated this IP is not one of its senders. What it does with that — reject, send to junk, or just note it — is its own policy decision, and later DMARC lets the domain owner express a preference.

Now the honest message from Jane, sent via the company's server at `198.51.100.5`: the very first mechanism `ip4:198.51.100.0/28` matches with the default `+`, evaluation **stops immediately**, and the result is **`spf=pass`**. Order matters: the first match wins, so nothing after it is even looked up.

### The 10-lookup limit and void lookups { #limits }

Each SPF check could cause the receiver to make many DNS queries, which could be abused to make mail servers attack DNS servers. So RFC 7208 sets hard limits:

- **At most 10 DNS-querying terms** per evaluation: `include`, `a`, `mx`, `ptr`, `exists` and `redirect` each count 1, **including those inside nested includes.** `ip4`, `ip6` and `all` cost nothing.
- **At most 2 void lookups** — queries that come back with no answer or NXDOMAIN (for example an `include` pointing to a domain that no longer exists).
- Exceeding either gives **`permerror`** ("the record is broken").

Count the example: `a`(1) + `mx`(1) + `include` mailvendor(1) + its nested `include`(1) + `include` crm-cloud(1) = **5 of 10**. Fine. But a growing company that keeps adding services — mail suite, marketing platform, CRM, ticketing, HR system — each with its own nested includes, can quietly pass 10. Then every receiver gets `permerror` and, depending on its policy, treats the domain's mail as unauthenticated. **This is one of the most common real-world SPF failures**, and it often appears after a perfectly innocent change.

**[Supplement]** Other common record faults: two `v=spf1` records (permerror), a typo such as `ip4:198.51.100.0/33` or `inculde:` (permerror), a record longer than 255 characters not split into quoted strings, and an `include` of a service the company stopped using years ago (its domain may lapse and **be registered by someone else** — who could then authorise their own servers).

## How the SOC uses SPF { #soc-use }

- **Checking a suspicious message.** From the [border Received line](email-headers.md#trust-boundary) take the connecting IP; from the envelope (`Return-Path:`) take the domain. Read the receiver's `Received-SPF:`/`Authentication-Results:` result, and if needed run `dig TXT` yourself to see why. A message claiming to be from a bank but delivered from a VPS IP not in the bank's record is a strong signal.
- **"Partners say they got mail from us that we didn't send."** First check our own record: is there one, does it end in `-all` or `~all`, is it under 10 lookups? Without SPF (and DKIM/DMARC), other organisations have no way to tell our mail from forgeries.
- **Comparing Return-Path with From.** SPF pass on a Return-Path domain that has nothing to do with the `From:` domain is the classic sign that SPF alone was satisfied while the user was deceived.
- **[Supplement] Recon goes both ways.** An SPF record lists every service allowed to send for a company — mail suite, marketing tool, CRM. Attackers read it to learn which platforms to imitate or abuse; defenders should review it for forgotten services.
- **Watch for record changes.** A sudden change to your SPF record (especially a new `include` or `+all`) is worth an alert — it can mean DNS account compromise.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    SMTP itself still has no built-in sender authentication, and anyone can still connect to an MX on port 25 and type any `MAIL FROM` and `From:`. The three-layer answer (SPF for the path, DKIM for the signature, DMARC for alignment and policy) is still the model. SPF is still defined by RFC 7208, with the same mechanisms, qualifiers, 10-lookup limit and 2-void-lookup limit. The connecting IP is still the one fact the sender cannot fake.

!!! info "[Changed] What has changed"
    - **Big mailbox providers made authentication mandatory.** Since February 2024, Gmail and Yahoo require every sender to have SPF or DKIM, and bulk senders (roughly 5,000+ messages a day to their users) to have SPF **and** DKIM **and** a DMARC record, with the `From:` domain aligned. Microsoft applied similar rules to Outlook.com, Hotmail and Live addresses for high-volume senders from May 2025, rejecting non-compliant mail with `550 5.7.515`. In practice, legitimate senders without SPF have become rare, so "no SPF at all" is now a stronger warning sign than it used to be.
    - **The `Authentication-Results:` standard moved on.** The version first referenced in older material has been replaced; RFC 8601 is the current definition. The header looks the same to an analyst.
    - **DMARC is now a Proposed Standard.** The long-running "DMARCbis" revision was published in 2026 as RFC 9989–9991, replacing the old informational RFC 7489. SPF itself is unchanged, but some DMARC tags and behaviours changed — covered on the DMARC page.
    - **Shared cloud platforms changed what "pass" means.** Most organisations now include a large provider's whole range (`include:` of a cloud mail suite or marketing platform). An SPF pass therefore often only proves "it came from that platform," and abuse of legitimate platforms and compromised accounts has become a major source of phishing that passes SPF.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Do not read SPF pass as "the message is genuine."** It only means the envelope domain authorised that IP. Attackers register look-alike domains with perfect SPF, or send from compromised accounts. Always check alignment with the visible `From:` (DMARC).
    - **Do not believe SPF checks the `From:` header.** It checks `MAIL FROM`/`HELO`.
    - **Do not publish `+all` or use `ptr`.** `+all` authorises the whole internet; `ptr` is deprecated.
    - **Do not let your record exceed 10 lookups.** It fails as `permerror` without any obvious error on your side. Check after every new service is added.
    - **Do not reject mail on SPF fail alone without thinking about forwarding.** Forwarded mail arrives from the forwarder's IP and fails SPF legitimately. Modern practice is to let DMARC (which can rely on DKIM) make the decision.

## Practice questions { #quiz }

### Question 1

`payroll-portal.example` publishes this record. A message with `MAIL FROM:<notify@payroll-portal.example>` arrives from `192.0.2.140`. What is the SPF result, and at which mechanism does evaluation stop? What if it had come from `198.51.100.9`?

```
"v=spf1 ip4:192.0.2.128/26 include:_spf.sendgrid-like.example ~all"
```

(`_spf.sendgrid-like.example` contains `"v=spf1 ip4:203.0.113.0/24 -all"`.)

??? success "Answer and explanation"
    **From `192.0.2.140`: `pass`, stopping at the first mechanism.** `192.0.2.128/26` covers 192.0.2.128–191, so .140 matches. There is no qualifier, so `+` (pass) applies, and evaluation ends right there — the `include` is never looked up.

    **From `198.51.100.9`: `softfail`.** It is not in `192.0.2.128/26`. The `include` is evaluated: not in `203.0.113.0/24`, so the included record's `-all` matches — but inside an include that only means "no match here", not fail for the whole record. Back in the outer record, `~all` matches everything → **softfail** ("probably not authorised"). Note how the included record's `-all` did **not** turn the result into a hard fail.

### Question 2

Count the DNS lookups for this record. What result will every receiver get, and why might the company not notice?

```
"v=spf1 a mx include:_spf.mailsuite.example include:mkt.example include:crm.example include:helpdesk.example include:hr-system.example include:billing.example ~all"
```

Assume `_spf.mailsuite.example` contains 3 nested includes, and the others contain none.

??? success "Answer and explanation"
    `a` = 1, `mx` = 1, six `include`s = 6, plus the 3 nested includes inside the mail suite's record = 3. **Total 11 — over the limit of 10.**

    Result: **`permerror`** for everyone, on every message, regardless of which IP sent it. Receivers treat the domain as having a broken SPF record; with DMARC in place, mail will then rely entirely on DKIM, and any stream without DKIM may be junked or rejected.

    **Why nobody notices:** the company's own outgoing mail still leaves without errors — the failure only shows on the receiving side (in their `Authentication-Results`, or in DMARC aggregate reports if the company reads them). The usual cause is an innocent addition of one more service. Fixes: remove services no longer used, replace `a`/`mx` with `ip4`/`ip6` ranges where stable, or move some services to a subdomain with its own record.

### Question 3

A finance employee reports a message. Its headers show the following. SPF passed. Is the message from the company's real CEO? What does this tell you about the limits of SPF?

```
Return-Path: <bounce-7731@mail.lookalike-pay.example>
Received: from out-3.lookalike-pay.example (out-3.lookalike-pay.example [203.0.113.81])
        by mx1.victim.example with ESMTPS id 9Rt2Lq; Thu, 19 Nov 2026 02:41:10 +0000
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=mail.lookalike-pay.example
From: "Jane Park (CEO)" <ceo@victim.example>
Subject: Confidential - change of supplier bank details
```

??? success "Answer and explanation"
    **Almost certainly not.** Read the evidence in order:

    - `Received ... by mx1.victim.example` — our border line. The message came from `203.0.113.81`, which calls itself `out-3.lookalike-pay.example`, not from our own mail servers.
    - `spf=pass smtp.mailfrom=mail.lookalike-pay.example` — SPF passed **for `lookalike-pay.example`**, the domain in the envelope (`Return-Path`). The attacker owns that domain and listed their own server in its SPF record.
    - `From: ... <ceo@victim.example>` — the address the employee sees belongs to **our** company, a completely different domain. SPF never looked at it.

    **The lesson:** SPF only authenticates the envelope domain. It cannot stop a message whose visible `From:` is someone else's domain. That is the job of **DMARC alignment** — `victim.example` publishing a DMARC policy means that a message showing `From: ...@victim.example` must pass SPF or DKIM **for victim.example itself**, which this one cannot. Also note the internal-impersonation angle: a message from "our CEO" arriving from outside our servers should be blocked or tagged by an internal-impersonation rule regardless. Next steps: block the domain and IP, search for the same Return-Path domain in other mailboxes, and warn finance not to change bank details.
