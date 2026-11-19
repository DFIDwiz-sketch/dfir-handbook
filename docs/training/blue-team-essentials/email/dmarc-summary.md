---
title: "DMARC and the Email Wrap-up — How Many From Addresses, Alignment, Policy and Reports, What Authentication Proves"
tags:
  - training
  - blue-team
  - email
  - dmarc
---

# DMARC and the Email Wrap-up — How Many From Addresses, Alignment, Policy and Reports, What Authentication Proves { #dmarc-summary }

!!! abstract "What this page covers"
    The last gap left by SPF and DKIM: a message carries **more than one "from" address**, and the one the checks look at is not the one the user sees. A spoofed conversation that passes SPF and DKIM for the wrong domain, line by line. Then DMARC: what a domain owner publishes, what **alignment** means (SPF-aligned, DKIM-aligned, relaxed vs strict), the `_dmarc` record tag by tag (including the tags the 2026 revision added and removed), how a receiver evaluates it step by step, what the results look like in `Authentication-Results:`, and how to read an **aggregate report**. Then the traps DMARC does not close (look-alike domains, display names, `Reply-To:`, compromised accounts), and a wrap-up of the whole email section with a triage checklist. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. All domains, IPs, keys and report values are invented for illustration. Continues from [SPF Results and DKIM](spf-results-dkim.md). This page closes the email section.

## The 8 key points { #key-points }

1. A message has (at least) **two "from" addresses**: the **envelope** sender `MAIL FROM` (RFC 5321, becomes `Return-Path:`) and the **header** `From:` (RFC 5322, the one the mail client displays). They can be completely different.
2. **SPF checks the envelope domain; DKIM checks the `d=` domain; the user sees the `From:` domain.** Without something linking them, an attacker can pass both checks for *their own* domain while displaying *yours*.
3. **DMARC** links them. A message passes DMARC if **SPF passes *and* is aligned, or DKIM passes *and* is aligned** — one of the two is enough.
4. **Aligned** means the authenticated domain matches the `From:` domain. **Relaxed** (default) = same organisational domain (`mail.victim.example` ≈ `victim.example`); **strict** = exactly the same name.
5. The domain owner publishes a TXT record at **`_dmarc.<domain>`** that says what to do on failure (`p=none`, `quarantine` or `reject`) and where to send **reports** (`rua=`).
6. **Aggregate reports** are the big gift of DMARC: every major receiver tells the domain owner, daily, which IPs sent mail using its name and whether they passed. Before DMARC, a domain owner could not see who was spoofing them.
7. Passing SPF, DKIM **and** DMARC proves **"this really came from that domain."** It does **not** prove the content is safe: a compromised account, a look-alike domain or a malicious `Reply-To:` all pass.
8. Email wrap-up: SMTP is unauthenticated by design; trust headers only from your border MTA inward; publishing SPF/DKIM/DMARC protects **others** from mail forged in your name; **checking** them on incoming mail protects **you**; none of them vouches for the content.

## One last problem: how many "From" addresses? { #how-many-from }

Think of a paper letter. The **envelope** has a return address written on the outside; the post office uses it to send the letter back if it cannot be delivered. **Inside**, the letter itself is written on letterhead with a name and signature at the bottom. Nothing forces the two to match: you could post a letter in an envelope from "PO Box 12, Smalltown" whose letterhead says "Office of the Managing Director, Big Bank." The recipient opens it, throws the envelope away and reads only the letterhead.

Email is built exactly like that, because it grew out of two separate standards:

- **RFC 5321** describes the **transport** — the SMTP conversation between servers. The address typed after `MAIL FROM:` is the **envelope sender**, called **RFC5321.MailFrom**. The receiving server stores it at delivery time as the `Return-Path:` header, and that is where bounces go. ([Envelope vs header addresses](delivery-smtp.md#envelope-vs-header).)
- **RFC 5322** describes the **message format** — what is inside `DATA`. The `From:` header there is **RFC5322.From**. This is the one Outlook, Gmail or a phone app shows the user.

And SPF checks... the envelope ([which "from" SPF checks](spoofing-spf.md#which-from)). So the check and the display look at different places.

### A spoofed conversation that passes the checks { #spoofed-pass }

Here is an attacker who has learned that SPF and DKIM exist and decided to *pass* them instead of failing them. They registered a cheap domain, `cheap-hosting.example`, published an SPF record listing their own server `203.0.113.66`, and set up a DKIM key for it. Then they connect to the victim's MX:

```
S: 220 mx1.victim.example ESMTP
C: EHLO mail.cheap-hosting.example
S: 250-mx1.victim.example Hello [203.0.113.66]
C: MAIL FROM:<bounce@cheap-hosting.example>
S: 250 2.1.0 Ok
C: RCPT TO:<accounts@victim.example>
S: 250 2.1.5 Ok
C: DATA
S: 354 End data with <CR><LF>.<CR><LF>
C: From: "Payroll Team" <payroll@victim.example>
C: To: accounts@victim.example
C: Subject: Updated bank details for November salary run
C: Date: Thu, 19 Nov 2026 08:12:40 +0000
C:
C: Please use the attached details from today.
C: .
S: 250 2.0.0 Ok: queued as 4QvX2m
```

Line by line, the parts that matter:

- `EHLO mail.cheap-hosting.example` — the attacker's server names itself honestly. It has nothing to hide here.
- `MAIL FROM:<bounce@cheap-hosting.example>` — the **envelope** uses the attacker's own domain. This is what SPF will check, and the attacker's SPF record does list `203.0.113.66`, so SPF will **pass**.
- `From: "Payroll Team" <payroll@victim.example>` — the **header** `From:`, typed by the attacker inside `DATA`. It claims to be the victim's own payroll team. Nobody checked this line.
- The attacker's server also signs the message with `d=cheap-hosting.example` before sending (not shown in the conversation; it is a header inside `DATA`), so DKIM will **pass** too.

What the recipient's server writes, if it checks SPF and DKIM but **not** DMARC:

```
Return-Path: <bounce@cheap-hosting.example>
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra
From: "Payroll Team" <payroll@victim.example>
Subject: Updated bank details for November salary run
```

- `Return-Path:` — the envelope sender, recorded by our server. Attacker's domain.
- `spf=pass smtp.mailfrom=cheap-hosting.example` — a genuine pass, **for `cheap-hosting.example`**.
- `dkim=pass header.d=cheap-hosting.example` — a genuine pass, **for `cheap-hosting.example`**.
- `From: ... <payroll@victim.example>` — what the user sees. **Neither** check said anything about this domain.

The user sees "Payroll Team, payroll@victim.example," and if their client shows a "verified" indicator based on SPF/DKIM alone, it may even look trustworthy. This is not a bug in SPF or DKIM; both did exactly their jobs. The missing piece is a rule saying **"the domain you authenticated must be the domain you show."**

**[Supplement]** There are more "from"-like fields than these two, and attackers use all of them:

| Field | Who sets it | What it is for | Checked by |
| --- | --- | --- | --- |
| `MAIL FROM` → `Return-Path:` | Sending server (envelope) | Bounces | SPF |
| `HELO`/`EHLO` name | Sending server | Server's name | SPF (HELO check) |
| `d=` in `DKIM-Signature:` | Signing server | Who takes responsibility | DKIM |
| `From:` address | Sender (header) | **What the user sees as the sender** | DMARC (alignment) |
| `From:` display name (`"Payroll Team"`) | Sender | Friendly name shown instead of the address | **Nothing** |
| `Reply-To:` | Sender | Where replies go | **Nothing** |
| `Sender:` | Sender | "Sent on behalf of" | Nothing (rarely shown) |

## DMARC: tying the checks to the visible From { #dmarc }

**DMARC** (Domain-based Message Authentication, Reporting and Conformance) builds on SPF and DKIM. It adds no new cryptography and no new path check. What it adds is three things a domain owner can say, published in DNS:

1. **"Judge mail claiming to be from my domain by alignment."** Use SPF and DKIM results, but only count a pass that is for **my** domain — the one in `From:`.
2. **"Here is what to do when it fails."** Nothing (`none`), put it in junk (`quarantine`), or refuse it (`reject`).
3. **"Send me reports."** Tell me who is sending mail with my name and whether it passed.

Back to the letter analogy: DMARC is the bank publicly announcing "every genuine letter from us is either posted from our own mailroom **or** carries our own wax seal, *and* the letterhead says our name. If a letter's letterhead says our name but it has neither, bin it — and please send us a note about it."

### Alignment { #alignment }

To pass DMARC a message needs **at least one** of:

- **SPF aligned pass** — SPF result is `pass`, **and** the domain SPF checked (RFC5321.MailFrom) matches the RFC5322.From domain.
- **DKIM aligned pass** — a DKIM signature is `pass`, **and** its `d=` domain matches the RFC5322.From domain.

Why "or" and not "and"? Because each check breaks in different ordinary situations. SPF breaks when mail is **forwarded** (new IP); DKIM breaks when a list **modifies** the message. Requiring both would reject too much legitimate mail. Requiring one means a sender with a solid DKIM setup survives forwarding, and so on.

How exact must "matches" be? The owner chooses, separately for SPF (`aspf=`) and DKIM (`adkim=`):

- **Relaxed** (`r`, the default): the two domains must share the same **organisational domain** — the registered domain, the part someone actually bought. `bounce.mail.victim.example` and `victim.example` have the same organisational domain, `victim.example`, so they align.
- **Strict** (`s`): the names must be **identical**.

| `From:` domain | Authenticated domain | Relaxed | Strict |
| --- | --- | --- | --- |
| `victim.example` | `victim.example` | aligned | aligned |
| `victim.example` | `bounce.victim.example` (SPF) | aligned | **not aligned** |
| `news.victim.example` | `victim.example` (DKIM `d=`) | aligned | **not aligned** |
| `victim.example` | `victim-example.example` | **not aligned** | not aligned |
| `victim.example` | `cheap-hosting.example` | **not aligned** | not aligned |

The fourth row is the important one for analysts: a look-alike name is a **different organisational domain**, so it never aligns with the real one. (That does not stop a look-alike from passing *its own* DMARC — see [below](#limits).)

How does a receiver know where the organisational domain begins? Under the original DMARC it used the **Public Suffix List** (a community list of suffixes like `.com`, `.co.uk`, `.gov.au` under which people register names). **[Changed]** The 2026 revision replaced that with a **DNS tree walk**: the receiver walks up the name, label by label, looking for `_dmarc` records, and a domain can mark itself as a public suffix or an organisational domain with the new `psd=` tag. For an analyst, the answer is the same in almost every real case.

Now apply it to the spoofed conversation:

| Check | Result | Domain checked | `From:` domain | Aligned? |
| --- | --- | --- | --- | --- |
| SPF | pass | `cheap-hosting.example` | `victim.example` | no |
| DKIM | pass | `cheap-hosting.example` | `victim.example` | no |
| **DMARC** | **fail** | | | neither pass is aligned |

### The DMARC record { #dmarc-record }

A domain owner publishes the policy as a TXT record at `_dmarc.` in front of the domain:

```
$ dig +short TXT _dmarc.victim.example
"v=DMARC1; p=quarantine; sp=reject; np=reject; adkim=r; aspf=r; rua=mailto:dmarc-agg@victim.example,mailto:victim@reports.dmarc-vendor.example; ruf=mailto:dmarc-forensic@victim.example; fo=1"
```

- `dig +short TXT _dmarc.victim.example` — ask DNS for the TXT record at `_dmarc.victim.example` and print only the answer. If the answer is empty, the domain has **no DMARC policy** and receivers fall back to their own judgement.

Tag by tag:

| Tag | Example | Meaning |
| --- | --- | --- |
| `v=` | `DMARC1` | Version. Must come first. Still `DMARC1` after the 2026 revision |
| `p=` | `quarantine` | **Policy** for the domain itself when DMARC fails: `none` (monitor only), `quarantine` (treat as suspicious, usually junk folder), `reject` (refuse during SMTP) |
| `sp=` | `reject` | Policy for **subdomains** (`anything.victim.example`) if they have no record of their own. Defaults to `p=` |
| `np=` | `reject` | **[Changed] New in the 2026 revision:** policy for **non-existent** subdomains (names that do not exist in DNS at all, such as `payroll-secure.victim.example`). Attackers love inventing subdomains; this closes them off |
| `adkim=` | `r` | DKIM alignment mode: `r` relaxed (default) or `s` strict |
| `aspf=` | `r` | SPF alignment mode: `r` relaxed (default) or `s` strict |
| `rua=` | `mailto:...` | Where to send **aggregate** reports (daily XML summaries). Several addresses allowed, separated by commas |
| `ruf=` | `mailto:...` | Where to send **failure** reports (copies or extracts of individual failing messages). Few receivers send these today |
| `fo=` | `1` | When to generate failure reports: `0` (default) only if everything failed, `1` if anything failed, `d`/`s` for DKIM/SPF failures |
| `pct=` | `50` | **[Changed] Removed in the 2026 revision.** Used to mean "apply the policy to only N% of failing mail." Still seen in old records; ignored by updated receivers |
| `t=` | `y` | **[Changed] New in the 2026 revision:** test mode. `t=y` means "do not apply my `p=`, just report"; `t=n` (default) means apply it. Replaces the common `pct=0` trick |
| `psd=` | `n` | **[Changed] New in the 2026 revision:** marks a domain as a public suffix (`y`) or as an organisational domain (`n`) for the tree walk. Default `u` (unspecified) |

The `rf=` and `ri=` tags (report format and interval) were also removed in the revision; you will still see them in older records, and they are harmless.

**[Supplement]** Notice the second `rua` address is at a **different domain** (`reports.dmarc-vendor.example`, a reporting service). To stop anyone from directing reports at a stranger's mailbox, a receiver only sends there if that domain publishes permission:

```
$ dig +short TXT victim.example._report._dmarc.reports.dmarc-vendor.example
"v=DMARC1"
```

- The name is built as `<domain whose reports these are>._report._dmarc.<domain receiving the reports>`.
- `"v=DMARC1"` — "yes, we accept reports about victim.example." No answer means the receiver should not send there.

What a policy record tells **you** as an analyst, at a glance:

- `p=none` — the owner is only watching. Spoofed mail using this domain is **not blocked by DMARC anywhere**. Very common: many domains add a `p=none` record to meet the big providers' sender rules and never go further.
- `p=quarantine` — failing mail goes to junk. If a user found the spoof in their junk folder and moved it to the inbox, this is why it was there.
- `p=reject` — failing mail is refused. A spoof of this exact domain reaching an inbox means either the receiver does not enforce DMARC, or the message passed (compromised account, legitimate platform abuse).
- No record — the domain has no published policy. Its mail can be spoofed freely to receivers that do not apply their own rules.

### How a receiver evaluates DMARC, step by step { #evaluation }

For each incoming message, the receiving border MTA:

1. **Extracts the `From:` domain.** If there is no `From:`, or **more than one** `From:` header, or one header with several addresses from different domains, many receivers reject or treat the message as failing; a valid message has exactly one `From:` header.
2. **Looks up the policy.** TXT at `_dmarc.<From domain>`. If none, walks up to the organisational domain's record (and uses `sp=`/`np=` from there).
3. **Takes the SPF result** it already computed and checks whether the SPF domain is aligned.
4. **Takes each DKIM result** and checks whether any passing signature's `d=` is aligned.
5. **Decides:** at least one aligned pass → `dmarc=pass`. Otherwise → `dmarc=fail`.
6. **Applies the policy** (`none`/`quarantine`/`reject`) — or its own local override — and records what it did.
7. **Logs a line for the daily aggregate report** to `rua=`, and optionally sends a failure report to `ruf=`.

What it writes in the trace headers, for our spoofed message, with `victim.example` publishing `p=quarantine`:

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra;
       dmarc=fail (p=quarantine dis=quarantine) header.from=victim.example
```

- `dmarc=fail` — neither pass was aligned with `victim.example`.
- `p=quarantine` — the policy the owner published.
- `dis=quarantine` — the **disposition**, what the receiver actually did. It can differ from `p=`: a receiver may apply a local override (for example, a known forwarding source, or the old `pct=` sampling). If `p=reject` but `dis=none`, ask why.
- `header.from=victim.example` — the domain DMARC protected.

If the policy had been `p=reject`, the message would not have been delivered at all. The attacker's server would have seen something like this at the end of `DATA`:

```
S: 550 5.7.1 Unauthenticated email from victim.example is not accepted due to domain's DMARC policy
```

- `550` — permanent failure; do not retry.
- `5.7.1` — the enhanced status code family for "delivery not authorised / security policy."
- The text varies by provider, but this is what a sender sees in a bounce, and what you see in **your own mail platform's logs** as a rejected inbound attempt. Those logs are often the only trace of a blocked spoofing campaign against your users.

And for comparison, a genuine message from the real payroll system, which sends through a hosted platform but has DKIM set up for its own domain:

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=bounce.mailer-hub.example;
       dkim=pass header.d=victim.example header.s=hub2026 header.b=aR5tW0qL;
       dkim=pass header.d=mailer-hub.example header.s=k1 header.b=Zx81PqWe;
       dmarc=pass (p=quarantine dis=none) header.from=victim.example
```

- SPF passed but for the platform's bounce domain → **not aligned**.
- The **first** DKIM signature is by `victim.example` → **aligned pass**. That alone makes DMARC pass.
- The second signature is the platform's own; it is fine but irrelevant to DMARC.
- `dis=none` — passed, nothing done.

This "SPF not aligned, DKIM aligned" pattern is completely normal for mail sent through third-party platforms. That is the reason DMARC needs only one of the two.

### Aggregate reports: seeing who uses your name { #reports }

Before DMARC, a domain owner had no way to learn that someone in another country was sending a million phishing messages in their name. With `rua=`, every participating receiver sends a daily **aggregate report**: an XML file (usually zipped or gzipped and attached to an email) summarising every source IP that sent mail with your domain in `From:`.

A shortened example:

```xml
<feedback>
  <report_metadata>
    <org_name>bigmail.example</org_name>
    <email>noreply-dmarc@bigmail.example</email>
    <report_id>8842137765</report_id>
    <date_range><begin>1795046400</begin><end>1795132799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>victim.example</domain>
    <adkim>r</adkim><aspf>r</aspf>
    <p>quarantine</p><sp>reject</sp>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.24</source_ip>
      <count>18233</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>pass</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>victim.example</header_from></identifiers>
    <auth_results>
      <dkim><domain>victim.example</domain><selector>hub2026</selector><result>pass</result></dkim>
      <spf><domain>bounce.mailer-hub.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.66</source_ip>
      <count>412</count>
      <policy_evaluated>
        <disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers><header_from>victim.example</header_from></identifiers>
    <auth_results>
      <dkim><domain>cheap-hosting.example</domain><selector>k1</selector><result>pass</result></dkim>
      <spf><domain>cheap-hosting.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
```

Reading it:

- `<org_name>bigmail.example</org_name>` — **who** wrote the report: the receiving provider.
- `<date_range>` — the period, in Unix seconds: `1795046400` → `2026-11-19 00:00:00 UTC`, `1795132799` → `23:59:59` the same day. Convert with `date -u -d @1795046400`.
- `<policy_published>` — the policy the receiver found for us when it checked. Useful for spotting a DNS change that did not take effect.
- First `<record>`: `198.51.100.24` sent **18,233** messages. `policy_evaluated` shows the **DMARC-level** results: `dkim>pass` means *aligned* DKIM passed; `spf>fail` means SPF was not aligned (even though raw SPF passed — see `auth_results`). Disposition `none`. This is our legitimate hosted platform.
- Second `<record>`: `203.0.113.66` sent **412** messages claiming `victim.example`. Raw SPF and DKIM both passed **for `cheap-hosting.example`**, so at the DMARC level both are `fail`. Disposition `quarantine`. This is the spoofing campaign.

The trap to avoid: `policy_evaluated` and `auth_results` use the same words with different meanings. **`policy_evaluated` = aligned results (what DMARC decided); `auth_results` = raw SPF/DKIM results for whatever domain was checked.** A "pass" in `auth_results` next to a "fail" in `policy_evaluated` is the signature of an alignment failure.

Nobody reads hundreds of these XML files by hand; organisations send `rua=` to a reporting service or parse them into their SIEM. For a SOC, the useful questions are:

- **Unknown sources with high counts** claiming our domain → active spoofing, or a department using a new mail service nobody told IT about ("shadow" senders).
- **Known sources suddenly failing** → a broken DKIM key or SPF change, which will put our real mail in junk.
- **Failure reports** (`ruf=`) can contain message headers or content, so they are personal data; many large receivers do not send them for privacy reasons. Do not count on them.

### Rolling out DMARC on your own domain { #rollout }

The normal path, and why each step exists:

1. **`p=none` with `rua=`** — collect reports for some weeks. You will discover every service sending in your name (payroll, marketing, ticketing, the CEO's newsletter tool).
2. **Fix each legitimate source** so it passes aligned — usually by having it DKIM-sign with your domain, or by using a bounce subdomain of yours for SPF.
3. **`p=quarantine`**, optionally first with `t=y` (test mode: reports show what *would* happen) — then without.
4. **`p=reject`**, plus `sp=reject` and `np=reject` once subdomains are covered.
5. **Domains that never send mail** (parked or defensive registrations) should publish `v=spf1 -all` and `v=DMARC1; p=reject;` straight away. They are favourite spoofing targets precisely because nobody watches them.

### Forwarding, mailing lists and ARC { #forwarding }

DMARC inherits the weaknesses of its parts. A **plain forward** (an alias that resends unchanged) breaks SPF but keeps DKIM → still passes if DKIM was aligned. A **mailing list** that adds a subject tag or footer breaks DKIM as well → DMARC fails for a genuine message, and with `p=reject` it may be refused.

Two fixes are in use today:

- **From rewriting.** Many list servers rewrite `From:` to the list's own address, for example `From: "Kim Lee via Staff List" <staff-list@lists.victim.example>`. Then DMARC is evaluated for the list's domain, which the list can pass. When you see "via" in a display name, this is usually why.
- **ARC** (Authenticated Received Chain, [introduced on the previous page](spf-results-dkim.md#dkim-limits)). The list seals "DKIM and DMARC passed when I received it," and the final receiver may choose to honour that if it trusts the list. A receiver that honoured ARC may note it in its results (for example `dmarc=fail ... arc=pass` with a local override in `dis=`).

## What DMARC does *not* stop { #limits }

DMARC closes exactly one door: **using a domain you do not control in the `From:` address**. Every other door stays open, and attackers moved through them long ago.

- **Look-alike (cousin) domains.** `victim-payroll.example`, `vict1m.example`, or an [internationalised look-alike](../dns/blockchain-dns-and-idn.md). The attacker owns it, so they can publish perfect SPF, DKIM and `p=reject` DMARC — and pass all three. DMARC proves "from that domain"; it does not tell the user it is the wrong domain.
- **Display-name spoofing.** `From: "Payroll Team - victim.example" <payroll.team.4471@freemail.example>`. DMARC checks only the address domain (`freemail.example`), which passes. Most phone mail apps show only the display name.
- **`Reply-To:` redirection.** `From:` is genuine or a look-alike, `Reply-To: <payroll@victim-payroll.example>`. The user replies to the attacker. No authentication standard checks `Reply-To:`. This is a core move in business email compromise (BEC).
- **Compromised accounts.** If an attacker logs into a real employee's or supplier's mailbox, every message they send passes SPF, DKIM and DMARC perfectly, because it **is** genuine mail from that domain. The same goes for abuse of legitimate cloud platforms and file-sharing notifications.
- **Domains without a strict policy.** Any domain at `p=none` or with no record can still be spoofed outright.

So the rule is: **authentication tells you who sent it; it never tells you whether to trust what it says.**

## Email wrap-up { #wrap-up }

Pulling the whole section together:

- **A message *may* be traceable to its source through its headers — but there is no guarantee.** Webmail and cloud apps usually leave no client IP at all, and every `Received:` line written before your border MTA was written by someone you do not control and may be false ([trust boundary](email-headers.md#trust-boundary)). The one solid fact is the connecting IP your border server recorded.
- **SMTP is unauthenticated by nature.** It was designed for a small trusted network; security was bolted on later, and most of it works only for domains that opt in.
- **Without SPF, DKIM and DMARC, email is trivially spoofed** — envelope, header, display name, all of it ([spoofing](spoofing-spf.md#why-spoofable)).
- **Do not trust headers beyond your border MTA.** This applies to `Received:` and to `Authentication-Results:` ([forged results](spf-results-dkim.md#forged-results)).
- **Publishing SPF, DKIM and DMARC for your domains** stops attackers sending mail labelled as you — to your partners, your customers, and to yourself. It is mostly a favour to others; it does little against spam arriving at you from other domains. The important exception is **internal spoofing**: mail from outside pretending to be from your own domain, which your own `p=reject` (enforced by your own receiving server) blocks.
- **Checking SPF, DKIM and DMARC on incoming mail** is what protects your users from people spoofing *other* domains to them — but only as far as those domains have published policies.
- **None of them guarantees the content is good.**

### A triage checklist for a reported message { #triage }

| Step | Look at | Question |
| --- | --- | --- |
| 1 | Our top `Authentication-Results:` (authserv-id = our server) | What are `spf=`, `dkim=`, `dmarc=`? |
| 2 | `smtp.mailfrom`, `header.d`, `header.from` | Are the three domains the same organisation? Which one aligned? |
| 3 | `header.from` domain itself | Is it *our* domain, a partner's real domain, or a look-alike? Recently registered? |
| 4 | `From:` display name vs address, `Reply-To:` | Does the name match the address? Do replies go somewhere else? |
| 5 | Our border `Received:` line | Connecting IP and its reputation; does it match `client-ip` in `Received-SPF:`? |
| 6 | DMARC policy of the `From:` domain (`dig TXT _dmarc.<domain>`) | `none`, `quarantine`, `reject`? Did `dis=` match it? |
| 7 | Content: links, attachments, request | Even if everything passed: is the request unusual (bank change, credentials, urgency)? |
| 8 | Scope | Same sender IP/subject/URL in other mailboxes? Mail platform logs for rejected attempts? |

## How the SOC uses DMARC { #soc-use }

- **Read `dmarc=` first, then explain it.** `dmarc=pass` + unfamiliar domain → look-alike or compromised sender; `dmarc=fail` + our own domain in `From:` → someone spoofing us (check `dis=` and why it was delivered).
- **Know your own domains' policies.** Keep a list of every domain the organisation owns, its `p=`, and whether it sends mail. Parked domains at `p=none` are open spoofing targets.
- **Feed aggregate reports into monitoring.** New high-volume sources claiming your domain deserve an alert; known sources suddenly failing deserve a ticket to the mail team.
- **Check your receiving side enforces DMARC.** Publishing `p=reject` does nothing for inbound spoofs of your domain if your own gateway ignores DMARC or has an allow-list rule that bypasses it.
- **Do not stop at authentication.** For BEC-style messages the decisive evidence is usually the `Reply-To:`, the look-alike domain's registration date, and the request itself.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The two-"from"-addresses problem is unchanged: SPF still checks the envelope, the user still sees the header `From:`. DMARC's core idea — pass SPF or DKIM, *aligned* with `From:` — is unchanged, records still start `v=DMARC1`, `p=none/quarantine/reject` still mean the same, relaxed/strict alignment still work the same, and aggregate reports are still the main way a domain owner sees abuse of its name. "Authentication proves origin, not safety" is truer than ever.

!!! info "[Changed] What has changed"
    - **DMARC became a standard.** In 2026 the IETF published the DMARC revision as **RFC 9989** (core), **RFC 9990** (aggregate reports) and **RFC 9991** (failure reports), making the old informational RFC 7489 obsolete and moving DMARC onto the standards track. Existing records keep working.
    - **Tags changed.** `pct=`, `rf=` and `ri=` were removed; `np=` (non-existent subdomains), `t=` (test mode, replacing `pct=0` tricks) and `psd=` were added. The Public Suffix List was replaced by a **DNS tree walk** to find the organisational domain.
    - **The big mailbox providers made DMARC mandatory for bulk mail.** Gmail and Yahoo since February 2024 (SPF, DKIM, a DMARC record of at least `p=none`, aligned `From:`), with Gmail moving from warnings to temporary and permanent rejections of non-compliant bulk traffic from November 2025. Microsoft's Outlook.com consumer service has rejected non-compliant high-volume senders (over about 5,000 messages a day) since May 2025. As a result DMARC records are now extremely common — but a large share are still `p=none`, which protects nobody.
    - **Old adoption figures are meaningless now.** Statistics from the early 2020s about how few top sites had SPF or DMARC are out of date (and the "top sites" list they used was itself discontinued in 2022). Exact current figures vary by survey; check a current source if you need one.
    - **BIMI** (brand logos shown next to authenticated mail in some clients) requires an enforcing DMARC policy (`quarantine` or `reject`) and gave companies a marketing reason to move beyond `p=none`. Treat the logo as a sign of authentication only, not of safe content.
    - **Attacks moved around DMARC.** Phishing in 2026 leans on look-alike domains, compromised supplier accounts, legitimate cloud and e-signature platforms, and `Reply-To:` tricks — all of which pass authentication. AI-written lures remove the spelling mistakes analysts once relied on, which makes header and domain checks more important, not less.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Do not use `pct=` in new records.** It has been removed; updated receivers ignore it. Use `t=y` for testing.
    - **Do not leave domains at `p=none` forever.** It was meant as a monitoring phase. A `p=none` domain is as spoofable as one with no record.
    - **Do not forget parked and non-sending domains,** and set `sp=`/`np=` so attackers cannot invent subdomains.
    - **Do not read `dmarc=pass` as "safe."** It means the `From:` domain is genuine — which could be a look-alike the attacker owns, or a real account they compromised.
    - **Do not read `auth_results` pass in an aggregate report as "aligned."** Only `policy_evaluated` shows the DMARC-level result.
    - **Do not jump straight to `p=reject` without reports.** You will block your own payroll, ticketing or marketing mail.

## Practice questions { #quiz }

### Question 1

A user forwards a message as an attachment. Our border server wrote this. The user insists "it says payroll@victim.example, so it must be internal." What happened, and why was it delivered?

```
Return-Path: <bounce@cheap-hosting.example>
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=cheap-hosting.example;
       dkim=pass header.d=cheap-hosting.example header.s=k1 header.b=Qm7Lx2Ra;
       dmarc=fail (p=none dis=none) header.from=victim.example
From: "Payroll Team" <payroll@victim.example>
Reply-To: <payroll-updates@cheap-hosting.example>
Subject: Updated bank details for November salary run
```

??? success "Answer and explanation"
    **It is an outside sender impersonating our own domain.** SPF and DKIM both genuinely passed, but for `cheap-hosting.example` (`smtp.mailfrom`, `header.d`). The visible `From:` domain is `victim.example`, and **neither** pass is aligned with it, so `dmarc=fail`. The user is looking at the RFC 5322 `From:`, which the sender can type freely; the envelope (`Return-Path:`) shows the real origin domain.

    It was delivered because our own domain's DMARC policy is **`p=none`** (`dis=none`): we told every receiver, including ourselves, to take no action on failures. Also note the `Reply-To:` pointing to the attacker's domain — any reply goes to them.

    Actions: block the sending IP/domain, search other mailboxes for the same `Return-Path` domain and subject, warn payroll, and raise the case for moving `victim.example` to `p=quarantine` then `p=reject` (after checking aggregate reports that all legitimate senders pass aligned). Also consider a gateway rule flagging external mail that uses our own domain in `From:`.

### Question 2

Read this DMARC record and answer: (a) what happens to a message failing DMARC that claims to be from `victim.example`; (b) from `hr.victim.example` (which exists, with no record of its own); (c) from `payroll-secure.victim.example` (which does not exist in DNS); (d) is anything in it outdated?

```
"v=DMARC1; p=quarantine; sp=none; np=reject; pct=25; adkim=s; rua=mailto:dmarc-agg@victim.example"
```

??? success "Answer and explanation"
    - **(a)** `p=quarantine` → goes to junk. (Under the old rules `pct=25` would have meant only a quarter of failures were quarantined; see (d).)
    - **(b)** `sp=none` → **no action** for existing subdomains. An attacker can spoof `hr.victim.example` freely — a weak spot, and HR is a believable sender.
    - **(c)** `np=reject` → refused, because the subdomain does not exist. Receivers that do not yet support the 2026 revision will ignore `np=` and fall back to `sp=none`, so this protection is not universal yet.
    - **(d)** `pct=` was **removed** in the 2026 revision; updated receivers ignore it and apply the policy to all failing mail (equivalent to 100). Older receivers may still sample 25%. Remove it, and use `t=y` if a test phase is wanted. Also note `adkim=s` (strict DKIM alignment): mail signed `d=mail.victim.example` with `From: victim.example` will not DKIM-align — make sure every sender signs with the exact `From:` domain, or use relaxed. `aspf` is not set, so it defaults to relaxed.

### Question 3

An aggregate report for `victim.example` contains this record. What is this source, what is wrong, and what should the mail team do?

```xml
<row>
  <source_ip>192.0.2.40</source_ip>
  <count>2950</count>
  <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
</row>
<identifiers><header_from>victim.example</header_from></identifiers>
<auth_results>
  <dkim><domain>ticketdesk.example</domain><selector>td1</selector><result>pass</result></dkim>
  <spf><domain>mail.ticketdesk.example</domain><result>pass</result></spf>
</auth_results>
```

??? success "Answer and explanation"
    Raw SPF and DKIM both **passed**, but for the vendor's own domains (`ticketdesk.example`, `mail.ticketdesk.example`). At the DMARC level both are `fail` because neither is aligned with `victim.example`. Nearly 3,000 messages in a day from a ticketing vendor's IP, with a passing vendor signature, looks like **a legitimate service our organisation uses** (for example the IT help desk's ticket notifications) that was never configured to authenticate as our domain — not an attacker. The consequence is real, though: our own `p=quarantine` is sending those notifications to users' junk folders.

    Fix: configure the vendor to **DKIM-sign with `d=victim.example`** (publish the vendor's public key under a selector like `td1._domainkey.victim.example`), and/or use a bounce subdomain of ours (`tickets.victim.example`) as the envelope sender with the vendor in its SPF. Either one gives an aligned pass. Before declaring it benign, confirm with the business that this vendor is actually in use — an unknown source with this pattern could also be someone abusing the vendor's platform.
