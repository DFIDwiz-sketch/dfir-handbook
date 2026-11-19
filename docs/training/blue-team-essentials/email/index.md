---
title: SMTP & Email Analysis
tags:
  - training
  - blue-team
  - email
---

# SMTP & Email Analysis { #email }

!!! abstract "In one line"
    Email is the most common front door attackers use to get into an organisation. This section covers which servers a message passes through, how those traces end up in the header, and how to read headers to spot impersonation (SPF, DKIM, DMARC).

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Email Delivery and SMTP — MUA, MTA, MDA, Ports, Reading an SMTP Conversation](delivery-smtp.md) | Submission, relay and receiving; MUA/MSA/MTA/MDA; ports by stage; MX records; the unspoofable border MTA IP; an SMTP conversation line by line; envelope vs header addresses; reply codes; Zeek smtp.log; network signals; practice questions |
| 2 | [Reading Email Headers — Trace Headers, Message Headers, Body, Interpreting Received Lines](email-headers.md) | The three parts of a source and who writes them; MIME, attachments and Base64; viewing headers and collecting them safely (forward as attachment); reading Received from bottom to top; the trust boundary (the line our border MTA wrote); forged Received lines; one line field by field; ordering with Python; practice questions |
| 3 | [Email Spoofing and SPF — Why SMTP Trusts Anyone, Spoofed Injection, the Three Defences, How SPF Works](spoofing-spf.md) | Why SMTP never checks the sender; a spoofed SMTP conversation line by line; skipping SMTP AUTH by talking straight to the MX; SPF vs DKIM vs DMARC; the connecting IP and the TCP handshake; SPF checks MAIL FROM/HELO, not From:; reading an SPF record with dig; qualifiers; walking an evaluation; the 10-lookup and void-lookup limits; practice questions |
| 4 | [SPF Results and DKIM — Result Values, Reading Authentication-Results and Received-SPF, How DKIM Signatures Work](spf-results-dkim.md) | The seven SPF results and how to treat them; Authentication-Results field by field (authserv-id, smtp.mailfrom, header.d/s/b); cloud-platform verdicts (bestguesspass, compauth); Received-SPF detail (client-ip, mechanism); unfolding headers with awk; forged results headers; why DKIM; signing and verification step by step; the selector is the key's name; DKIM-Signature tags; over-signing From; body hash demo; the _domainkey key record and revocation; DKIM results; replay and ARC; practice questions |

!!! info "Coming next"
    DMARC — alignment, policy tags and reports — and the email analysis wrap-up, which closes this section.

## Things to remember { #must-know }

1. Servers hand mail to each other over SMTP on port 25, and a Received header is added at each server.
2. The connecting IP recorded by our border MTA cannot be spoofed. It is the anchor for judging origin.
3. Envelope and header addresses can differ. The `From:` on screen can say anything.
4. Server-to-server mail is mostly encrypted and has moved to the cloud. Analysis centres on mail platform logs.

## Related references { #related }

- [DNS records (MX)](../dns/understanding-dns.md#records)
- [Phishing delivery techniques](../../../adversary/phishing-delivery.md)
- [Zeek files.log](../../../network/zeek/files-log.md) — extracting mail attachments
