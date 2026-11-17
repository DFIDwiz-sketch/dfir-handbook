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

!!! info "Coming next"
    Reading email headers (interpreting Received lines, how to view headers and source), spoofed email injection, SPF/DKIM/DMARC, and the email analysis wrap-up.

## Things to remember { #must-know }

1. Servers hand mail to each other over SMTP on port 25, and a Received header is added at each server.
2. The connecting IP recorded by our border MTA cannot be spoofed. It is the anchor for judging origin.
3. Envelope and header addresses can differ. The `From:` on screen can say anything.
4. Server-to-server mail is mostly encrypted and has moved to the cloud. Analysis centres on mail platform logs.

## Related references { #related }

- [DNS records (MX)](../dns/understanding-dns.md#records)
- [Phishing delivery techniques](../../../adversary/phishing-delivery.md)
- [Zeek files.log](../../../network/zeek/files-log.md) — extracting mail attachments
