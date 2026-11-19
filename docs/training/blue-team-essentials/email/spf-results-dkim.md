---
title: "SPF Results and DKIM — Result Values, Reading Authentication-Results and Received-SPF, How DKIM Signatures Work"
tags:
  - training
  - blue-team
  - email
  - spf
  - dkim
---

# SPF Results and DKIM — Result Values, Reading Authentication-Results and Received-SPF, How DKIM Signatures Work { #spf-results-dkim }

!!! abstract "What this page covers"
    What the receiving server writes down after an SPF check: the seven possible results (pass, fail, softfail, neutral, none, temperror, permerror), what each really means and how a receiver and an analyst should treat it. Where those results appear in the trace headers — the short `Authentication-Results:` summary and the detailed `Received-SPF:` line — read field by field, including a cloud-mail-platform style header and a forged header planted by an attacker. Then DKIM: why a signature-based check was needed on top of SPF, how signing and verification actually work step by step, the `DKIM-Signature:` header tag by tag, the public key record at `selector._domainkey`, the DKIM result values, and what a DKIM pass does *not* prove. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. All domains, IPs, keys and signatures are invented for illustration. Continues from [Email Spoofing and SPF](spoofing-spf.md).

## The 8 key points { #key-points }

1. An SPF check always ends in **one of seven results**: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`. The domain owner chooses which one a non-listed sender gets (`-all`, `~all`, `?all`); the last three come from missing or broken records and DNS problems.
2. `neutral` **must be treated exactly like `none`**; `softfail` should **not** cause a rejection on its own but justifies extra suspicion; what to do with `fail` is the **receiver's local policy**.
3. Results appear in two headers: **`Authentication-Results:`** (a short summary of SPF, DKIM, DMARC and more, defined today by RFC 8601) and **`Received-SPF:`** (the full SPF detail — client IP, envelope sender, HELO, the reason — defined in RFC 7208).
4. **Only trust the results header written by your own border server.** It is identified by the name at its start (the *authserv-id*). An attacker can put fake `Authentication-Results: ... pass` lines in the message they send.
5. DKIM is **signature-based**: the sending organisation's mail server signs chosen headers and the body with a **private key**, and publishes the **public key** in DNS so any receiver can verify the signature.
6. **[Correction]** The **selector** is *not* "the part of the message that gets signed." It is **the name of the key** (`s=`), used to find the public key at `<selector>._domainkey.<domain>`. What gets signed is listed in `h=` (headers) and covered by `bh=` (body hash).
7. In an analyst's eyes the three DKIM outcomes that matter are **`dkim=pass`** (signed and verified), **`dkim=none`** (not signed — no proof either way) and **`dkim=fail`** (signed but did not verify — altered in transit or forged).
8. A DKIM pass proves **"the domain in `d=` signed this, and the signed parts did not change."** It does not prove that `d=` is the domain the user sees in `From:`, nor that the message is safe. Linking the two is DMARC's job.

## SPF results: what the receiver concludes { #spf-results }

On the previous page we walked through how the receiving border MTA evaluates an SPF record. Once it has finished, it has to **write down a conclusion**, and the SPF standard (RFC 7208, section 2.6 and 8) gives it a fixed vocabulary of seven words. Think of a **bouncer with a guest list** at a company event:

- Your name is on the list → *come in* (`pass`).
- The company told the bouncer "nobody except people on this list" and you are not on it → *you are not allowed* (`fail`).
- The company said "probably only people on the list, but don't make a scene" → *let them in, but keep an eye on them* (`softfail`).
- The company handed over a list but said "we're not saying anything about people who aren't on it" → *no opinion* (`neutral`).
- The company never gave the bouncer a list at all → *no information* (`none`).
- The bouncer's phone to head office is down right now → *try again later* (`temperror`).
- The list is unreadable — torn, two contradictory lists, too long to check → *the list itself is broken* (`permerror`).

Now the technical reality, one result at a time.

| Result | When it happens | What it means | What a receiver should do | Analyst reading |
| --- | --- | --- | --- | --- |
| `pass` | A mechanism with `+` (or no qualifier) matched the connecting IP | The IP **is authorised** to send for the envelope domain | Accept; the domain can now be held responsible for the message (reputation) | Path is fine **for that domain** — now check whether it is the domain the user sees |
| `fail` | A `-` mechanism matched, usually `-all` | The domain **explicitly says** this IP may not send for it | Local policy: reject, junk or mark. Often left to DMARC | Strong spoofing signal — unless it is forwarded mail |
| `softfail` | A `~` mechanism matched, usually `~all` | "Probably not authorised," but the owner will not make a strong statement | **Should not reject on this alone**; may look harder at the message | Suspicious; very common for real domains still tuning their records |
| `neutral` | A `?` mechanism matched, usually `?all` | A record exists but says nothing definite about this IP | **Must treat exactly like `none`** | No evidence either way |
| `none` | No SPF record at all, or the domain could not be determined (e.g. empty HELO) | The receiver has **no information** | Nothing to act on from SPF | In 2026 a legitimate company domain without SPF is rare — a look-alike or throwaway domain is more likely |
| `temperror` | A DNS timeout or server failure during the lookup | A **temporary** problem; the answer is unknown | Usually defer with a `4xx` code so the sender retries | Rarely meaningful on its own; check whether it repeats |
| `permerror` | Syntax error, two `v=spf1` records, more than 10 lookups, more than 2 void lookups | The **record itself is broken**; it cannot be evaluated | Treated as unauthenticated by most receivers | Usually the sender's own mistake, not an attack — but the domain is now easy to spoof |

Why does the standard bother to separate `neutral` from `none` if they must be handled the same way? Purely **for information**: `neutral` tells you the domain *has* an SPF record but chose `?all`, which is useful when you are diagnosing why a partner's mail keeps landing in junk. For a filtering decision the two are identical.

Why should `softfail` not cause a rejection on its own? Because `~all` is the domain owner saying "I'm not completely sure my list is complete." Many organisations use `~all` while they are still discovering every service that sends mail for them. If receivers rejected softfail outright, those organisations would lose real mail. So the RFC lets the receiver look more closely (raise a spam score, apply stricter content scanning) but not block on that basis alone.

Why is `fail` "a matter of local policy"? The SPF standard deliberately does not order receivers to reject. Each receiving organisation decides, because they know their own situation — for example, how much forwarded mail they accept (forwarded mail fails SPF legitimately, because the forwarder's IP is not on the original domain's list). Today most large receivers let the **DMARC** result make the final call, which can rely on DKIM instead when SPF breaks.

**[Supplement]** Introductory material often lists only the first five results. `temperror` and `permerror` matter in practice: a `permerror` on your own domain means every receiver is treating your mail as unauthenticated, and it shows up only on the receiving side.

## Where the results appear in the headers { #where-results }

The receiving server records its conclusions as **trace headers** it adds to the top of the message, just like its `Received:` line ([trace headers](email-headers.md#three-parts)). Two headers carry SPF results.

### Authentication-Results: the short summary { #authentication-results }

`Authentication-Results:` is a single header that summarises **every** authentication check the receiver ran: SPF, DKIM, DMARC, and sometimes others (ARC, reverse DNS, the provider's own composite verdict). It is defined by RFC 8601 (the version referenced in older material, RFC 7001, has been replaced twice since). It gives **the answers, not the reasoning.**

Here is a typical one written by a self-hosted border server:

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=billing.partner.example;
       dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ;
       dmarc=pass (p=quarantine dis=none) header.from=partner.example
```

Line by line:

- `Authentication-Results: mx1.victim.example;` — the first value is the **authserv-id**: the name of the server that did the checks. This is how you know **who wrote this line**. It should be your own border server (or your cloud mail provider).
- `spf=pass` — the SPF result, one of the seven words above.
- `smtp.mailfrom=billing.partner.example` — **which identity** SPF checked: the domain from the envelope `MAIL FROM`. (If SPF had checked the HELO name instead, you would see `smtp.helo=`.) Note it is a **subdomain** used for bounces — common for billing and marketing systems.
- `dkim=pass` — the DKIM result (explained below).
- `header.d=partner.example` — the domain that **signed** the message (`d=` in the signature).
- `header.s=s2026` — the **selector** of the key used.
- `header.b=Kp3vT9xQ` — the first few characters of the signature value, so you can tell which signature this result refers to when a message has several.
- `dmarc=pass (p=quarantine dis=none)` — the DMARC result; the comment says the domain's policy is `quarantine` and the disposition applied was `none` (nothing, because it passed). Covered on the next page.
- `header.from=partner.example` — the domain in the visible `From:` header, which DMARC compared against.

Cloud mail platforms add their own fields. A message received by a large hosted mail platform might carry something like this (the structure is realistic; the names are invented):

```
Authentication-Results: spf=pass (sender IP is 198.51.100.24)
 smtp.mailfrom=newsletter.shop.example; dkim=none (message not signed)
 header.d=none;dmarc=bestguesspass action=none
 header.from=newsletter.shop.example;compauth=pass reason=109
```

- `spf=pass (sender IP is 198.51.100.24)` — the comment in brackets adds the connecting IP. Here there is no authserv-id at the start; on this kind of platform you identify it by its position (it is the top-most results header, added inside the provider's own network) and by the `Received:` lines around it.
- `dkim=none (message not signed) header.d=none` — **no DKIM signature at all**. Not a failure; simply no evidence.
- `dmarc=bestguesspass action=none` — a **provider-specific** value. The `From:` domain has **no DMARC record**, so the platform guessed what the result would have been if it had one. It is not a real DMARC pass.
- `compauth=pass reason=109` — the provider's own **composite authentication** verdict, combining SPF, DKIM, DMARC and its own reputation signals. The `reason` codes are documented by the provider; treat them as hints, not as standards.

### Received-SPF: the full detail { #received-spf }

If you need to know **why** SPF reached its conclusion, look for `Received-SPF:`. Its format is defined in RFC 7208 section 9.1, and it carries every piece of the evaluation.

```
Received-SPF: Pass (mx1.victim.example: domain of billing.partner.example
    designates 198.51.100.24 as permitted sender)
    receiver=mx1.victim.example; client-ip=198.51.100.24;
    envelope-from="invoices@billing.partner.example";
    helo=out2.partner.example; identity=mailfrom;
    mechanism="ip4:198.51.100.0/27";
```

- `Pass` — the result.
- `( ... designates 198.51.100.24 as permitted sender)` — a human-readable comment explaining the result.
- `receiver=mx1.victim.example` — the server that ran the check.
- `client-ip=198.51.100.24` — **the connecting IP**: the one fact the sender cannot fake ([why](spoofing-spf.md#why-ip)). It should match the bracketed IP in your border `Received:` line.
- `envelope-from="invoices@billing.partner.example"` — the `MAIL FROM` address.
- `helo=out2.partner.example` — what the sending server called itself in `HELO`/`EHLO`.
- `identity=mailfrom` — which identity was checked (`mailfrom` or `helo`).
- `mechanism="ip4:198.51.100.0/27"` — **which part of the record matched.** Very useful: it tells you exactly which authorised range or `include` the IP came from.

Not every server writes every optional field, but `client-ip`, `envelope-from` and `helo` are almost always there. Compare three real-world-shaped variants:

```
Received-SPF: Softfail (mx1.victim.example: domain of transitioning
    partner.example does not designate 203.0.113.66 as permitted sender)
    client-ip=203.0.113.66; envelope-from="ceo@partner.example";
    helo=mail.partner.example;

Received-SPF: PermError (mx1.victim.example: permanent error in processing
    domain of growing-co.example: too many DNS lookups)
    client-ip=192.0.2.17; envelope-from="hello@growing-co.example";

Received-SPF: None (mx1.victim.example: domain of fresh-login.example
    does not designate permitted sender hosts)
    client-ip=203.0.113.200; envelope-from="security@fresh-login.example";
```

- The first: the IP `203.0.113.66` is not in `partner.example`'s list, the record ends `~all` → `Softfail`. Combined with a `From:` claiming the partner's CEO, this deserves a close look.
- The second: the record is broken (`too many DNS lookups`, the 10-lookup limit from the [previous page](spoofing-spf.md#limits)). Probably the sender's misconfiguration, not an attack.
- The third: `fresh-login.example` publishes no SPF at all. Combined with a "security alert" subject, that is typical of a throwaway phishing domain.

### Pulling the results out on the command line { #command-line }

When you have a saved message (`.eml` file, [collected safely](email-headers.md#how-to-view)), you can pull out just these headers. Headers can be **folded** over several lines (continuation lines start with whitespace), so a plain `grep` only shows the first line. This short `awk` unfolds them first:

```
$ awk '/^$/{exit} /^[ \t]/{h=h" "$0; next} {if(h)print h; h=$0} END{if(h)print h}' suspicious.eml \
    | grep -iE '^(Authentication-Results|Received-SPF|DKIM-Signature|Return-Path|From):'
```

- `/^$/{exit}` — stop at the first empty line: that is where the headers end and the body begins.
- `/^[ \t]/{h=h" "$0; next}` — a line starting with a space or tab is a continuation; glue it onto the current header `h`.
- `{if(h)print h; h=$0}` — a new header starts: print the previous one (now complete), start collecting this one.
- `END{if(h)print h}` — print the last header.
- `grep -iE '^(...):'` — keep only the headers we care about, case-insensitively.

Output (one header per line):

```
Return-Path: <invoices@billing.partner.example>
Authentication-Results: mx1.victim.example; spf=pass smtp.mailfrom=billing.partner.example; dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ; dmarc=pass (p=quarantine dis=none) header.from=partner.example
Received-SPF: Pass (mx1.victim.example: domain of billing.partner.example designates 198.51.100.24 as permitted sender) receiver=mx1.victim.example; client-ip=198.51.100.24; envelope-from="invoices@billing.partner.example"; helo=out2.partner.example; identity=mailfrom; mechanism="ip4:198.51.100.0/27";
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner.example; s=s2026; ...
From: "Partner Billing" <billing@partner.example>
```

### [Supplement] Forged results headers { #forged-results }

An attacker controls everything in the message they hand over, **including headers that look like authentication results.** They can simply write:

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=victim.example;
       dkim=pass header.d=victim.example;
       dmarc=pass header.from=victim.example
```

and put it in the message before sending. It looks perfect — it even uses your server's name. This is the same problem as forged `Received:` lines on the [headers page](email-headers.md#trust-boundary), and the defence is the same idea:

1. **Find the results header your own border server added.** It is the one at the **top**, directly above or next to your border `Received:` line. Anything **below** your border `Received:` line arrived *with* the message from outside and was written by someone else.
2. RFC 8601 tells receivers to **remove** any incoming `Authentication-Results:` that carries their own authserv-id, precisely to stop this trick. Most modern servers do; older or misconfigured ones may not. If you see **two** results headers with your server's name, the lower one is a fake that slipped through.
3. Results headers from **other** organisations (for example a partner's server that handled the message earlier) are only as trustworthy as that organisation. Use them as context, not as proof.

## DKIM: signing the message itself { #dkim }

### Why a second check was needed { #why-dkim }

SPF looks only at **the path**: which IP handed the message over. That has two big weaknesses:

- **Forwarding breaks it.** When a university alias or a mailing list forwards a message, it arrives from the forwarder's IP, which is not on the original domain's list → SPF fails even though the message is genuine.
- **It says nothing about the content.** A message could pass SPF and still have been changed along the way.

DKIM (DomainKeys Identified Mail, RFC 6376) solves both by attaching proof **to the message itself** instead of relying on where it came from. Analogy: SPF is checking *which post office van* delivered the parcel. DKIM is a **tamper-evident wax seal stamped with the company's crest**. Whoever carries the parcel, and however many vans it changes, the recipient can look at the seal: if it is intact and matches the crest the company published, the parcel came from that company and has not been opened.

The technical reality behind the "seal" is a **digital signature** using public-key cryptography (RSA, or the newer Ed25519). The sending organisation keeps a **private key** secret on its mail servers and publishes the matching **public key** in DNS. Only the private key can create a valid signature; anyone with the public key can check one.

### How signing works, step by step { #signing }

Setup, done once by the domain owner:

1. Generate a key pair.
2. Pick a **selector** — just a label for this key, such as `s2026`, `mail1` or a vendor's name. Different services can have different keys, each with its own selector.
3. Publish the public key as a TXT record at **`<selector>._domainkey.<domain>`**, e.g. `s2026._domainkey.partner.example`.
4. Install the private key on the **outbound mail server or gateway** (or let the cloud mail provider hold it).

For every message sent:

1. The **sending mail server** — not the user's mail client — prepares to sign. The user never sees or holds the key; signing is done centrally for all outgoing mail of that stream.
2. It **canonicalises** the message: normalises things that harmless relays commonly change, such as extra whitespace or header capitalisation (`c=relaxed`), or changes nothing (`c=simple`, strict).
3. It **hashes the body** (SHA-256) and stores the result in `bh=` (body hash).
4. It takes the **headers it has chosen to protect** — listed in `h=`, for example `From`, `To`, `Subject`, `Date`, `Message-ID` — plus the new `DKIM-Signature:` header itself (with `b=` still empty), hashes them, and **signs that hash with the private key**. The result goes into `b=`.
5. It adds the finished `DKIM-Signature:` header to the top of the message and sends it.

For every message received, the verifier:

1. Reads `d=` and `s=` from the `DKIM-Signature:` header.
2. Fetches the public key from DNS: TXT `s=` + `._domainkey.` + `d=`.
3. Canonicalises and hashes the body itself and compares it with `bh=`. **If they differ, the body was changed → fail.**
4. Canonicalises and hashes the headers listed in `h=` and checks the signature in `b=` with the public key. **If it does not verify, the headers were changed or the signature is not from that key → fail.**
5. Both succeed → **pass**.

**[Correction]** You will often read two simplifications. First, that the selector "chooses which parts of the email are signed." It does not; the selector only names the key. Which parts are covered is set by `h=` (headers) and the body hash `bh=` (always the body, optionally limited by `l=`). Second, that "the hash is encrypted with the private key." That is a loose description of RSA signing; it is better to think of it as a **signature** that only the private key can produce and anyone with the public key can verify. With Ed25519 there is no "encryption" involved at all.

### The DKIM-Signature header tag by tag { #dkim-signature }

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=partner.example;
        s=s2026; t=1795047600; x=1795652400;
        h=from:from:to:subject:date:message-id:mime-version:content-type;
        bh=lNXsHoS7vr6QrKDmysIJdvi6qfRmHA6shFtOVsiEKWc=;
        b=Kp3vT9xQm1Lr8bW0zYc4H6s2nDqPfE7uJ0aVxR5tKyM9...(about 340 characters)...
```

| Tag | Example | Meaning |
| --- | --- | --- |
| `v=` | `1` | Version. Always `1` |
| `a=` | `rsa-sha256` | Algorithm: RSA signature over a SHA-256 hash. Also seen: `ed25519-sha256`. `rsa-sha1` is obsolete and must no longer be used for signing |
| `c=` | `relaxed/relaxed` | Canonicalisation for **headers/body**. `relaxed` tolerates whitespace and case changes; `simple` tolerates nothing |
| `d=` | `partner.example` | **The signing domain** — the domain taking responsibility. The most important tag for an analyst |
| `s=` | `s2026` | **Selector** — the name of the key. Public key is at `s2026._domainkey.partner.example` |
| `t=` | `1795047600` | Signing time, Unix seconds (here 2026-11-19 00:20 UTC) |
| `x=` | `1795652400` | Expiry; after this the signature should not be accepted (here 7 days later) |
| `h=` | `from:from:to:...` | **Which headers are signed**, in order. `from` appears **twice** on purpose — see below |
| `bh=` | `lNXs...KWc=` | Base64 of the SHA-256 hash of the canonicalised body |
| `b=` | `Kp3v...` | Base64 of the signature itself |
| `i=` | `@partner.example` | Optional: the identity (user or subdomain) on whose behalf it was signed |
| `l=` | `1250` | Optional: only the first N bytes of the body are covered. **Dangerous**: anything appended after them is not protected |

The `t=` value converted: `date -u -d @1795047600` prints `Thu Nov 19 00:20:00 UTC 2026`.

Why is `from` listed twice in `h=`? It is called **over-signing**. A verifier processes `h=` from the bottom of the header block upwards; listing `from` twice means "there is exactly one `From:`, and also sign the *absence* of a second one." Without it, an attacker could **add a second `From:` header** to a validly signed message, and some mail clients would display the added one while the signature still verified. Over-signing makes any added `From:` break the signature.

You can see how sensitive the body hash is with a one-line demonstration. Here are two bodies that differ by one character:

```
$ printf 'Please find the March invoice attached.\r\n' | openssl dgst -sha256 -binary | base64
lNXsHoS7vr6QrKDmysIJdvi6qfRmHA6shFtOVsiEKWc=

$ printf 'Please find the March invoice attached!\r\n' | openssl dgst -sha256 -binary | base64
dkZtOlxcLddR9/RIEYqlxeE/GcjT4zZZlrPMk+zMuss=
```

- `printf '...\r\n'` — the body, with the line ending email uses (CR LF).
- `openssl dgst -sha256 -binary` — compute the SHA-256 hash as raw bytes.
- `base64` — encode it the way DKIM writes it in `bh=` ([Base64](../http-analysis/base64.md)).
- Changing `.` to `!` produces a completely different hash. If an attacker (or a mailing list adding a footer) changes a single character of the body, `bh=` no longer matches and DKIM fails with a message such as "body hash did not verify."

(A real signer first applies canonicalisation to the whole body; for a one-line body with no trailing spaces, `simple` and `relaxed` give the same bytes as above.)

### The public key in DNS { #dkim-dns }

```
$ dig +short TXT s2026._domainkey.partner.example
"v=DKIM1; k=rsa; " "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx4Lr2Vq9...(about 390 characters)...IDAQAB"
```

- `s2026._domainkey.partner.example` — selector + the fixed label `_domainkey` + the signing domain.
- The answer comes back as **two quoted strings**. A single TXT string may be at most 255 characters, and a 2048-bit RSA key is longer, so it is split; the receiver joins the pieces.
- `v=DKIM1` — version of the key record.
- `k=rsa` — key type (`ed25519` for Ed25519 keys).
- `p=MIIB...IDAQAB` — the **public key** in Base64. `MIIB...` is the usual start of a 2048-bit RSA public key; `IDAQAB` is the usual end.
- Optional: `t=y` means "testing mode — don't treat failures harshly"; `t=s` means `i=` must not use a subdomain; `h=sha256` restricts hash algorithms.
- **`p=` empty** (`"v=DKIM1; p="`) means the key has been **revoked**. Any signature using that selector fails. Domains do this when they retire a key.

Selectors are also a small source of **recon**: common selector names reveal which mail and marketing services a company uses, in the same way SPF `include`s do.

### DKIM result values { #dkim-results }

`Authentication-Results:` reports one DKIM result per signature. A message may carry **several** signatures (for example one by the company, one by its mail provider), and each gets its own result.

| Result | Meaning | Analyst reading |
| --- | --- | --- |
| `pass` | Signed, key found, body hash and signature both verified | The `d=` domain signed it and the signed parts are unchanged |
| `fail` | Signed, but verification failed (body changed, header changed, wrong key) | Altered in transit (often a mailing list or security gateway rewriting content) **or forged** |
| `none` | No signature at all | No evidence. Not proof of spoofing, but legitimate bulk senders are now required to sign |
| `neutral` | Signature present but could not be processed (e.g. a syntax problem) | Treat like none |
| `policy` | Signature valid, but the receiver will not accept it (e.g. `l=` used, or a weak key) | Look at why — sometimes a sign of a poor signer |
| `temperror` | Key lookup failed temporarily (DNS timeout) | Retry later |
| `permerror` | Key record missing or broken, or key revoked (`p=` empty) | Signer's configuration problem — or a signature naming a selector that never existed |

Typical result lines and how to read them:

```
dkim=pass header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ
dkim=fail (body hash did not verify) header.d=partner.example header.s=s2026 header.b=Kp3vT9xQ
dkim=none (message not signed)
dkim=permerror (no key for signature) header.d=partner.example header.s=old2019
```

- The second line: the signature itself is fine but the **body** changed — classic after a list server adds a footer or a gateway rewrites links.
- The fourth: the message names a selector `old2019` that has no key in DNS. Either the company deleted an old key while something still uses it, or someone copied a signature header without understanding it.

### What DKIM does *not* prove { #dkim-limits }

- **`d=` does not have to match `From:`.** Any domain can sign any message. An attacker can register `lookalike-pay.example`, sign perfectly with `d=lookalike-pay.example`, and write `From: <ceo@victim.example>`. The result is a genuine `dkim=pass` — for the wrong domain. **DMARC alignment** (next page) is what requires the `d=` domain to match the visible `From:` domain.
- **A pass does not mean the content is safe.** A compromised account on a legitimate platform sends perfectly signed phishing.
- **Replay.** Because a signature stays valid until it expires, an attacker who gets **one** genuinely signed message from a reputable domain (for example by signing up for its service and receiving a message whose signed headers and body they can use) can **resend that exact message to thousands of other recipients**. Each copy verifies. Unsigned headers such as `To:` (if not in `h=`) can be changed without breaking it. This is why short `x=` expiry and signing `To:` matter.
- **It does not encrypt anything.** The message is still readable by every server it passes; DKIM only proves origin and integrity.

**[Supplement]** Forwarding that **changes** the message (mailing lists adding subject tags or footers, gateways rewriting URLs) breaks DKIM as well as SPF. The answer to that is **ARC** (Authenticated Received Chain, RFC 8617): each intermediary records the results it saw and seals them, so the final receiver can choose to trust "it passed when the list received it." You will see `ARC-Authentication-Results:`, `ARC-Message-Signature:` and `ARC-Seal:` headers on such messages.

## How the SOC uses SPF results and DKIM { #soc-use }

- **Start every phishing triage at your own results header.** Find the top `Authentication-Results:` written by your border/cloud mail service. Read `spf=`, `dkim=` and `dmarc=` together, and note `smtp.mailfrom`, `header.d` and `header.from`. If the three domains differ from each other, ask why.
- **Use `Received-SPF:` to explain.** `client-ip` + `mechanism` tell you which authorised range or vendor `include` the IP came from. A pass via a big shared platform's `include` only proves "sent through that platform."
- **Treat `dkim=fail` with context.** A body hash failure on a message that went through a mailing list is normal; a failure on a direct message from a bank is not.
- **Ignore results headers below your border.** Any `Authentication-Results:` that came in with the message is attacker-controllable.
- **For your own domains:** monitor that every sending service signs with your domain (not just the vendor's), that keys are 2048-bit RSA or Ed25519, that old selectors are revoked, and that your SPF stays under 10 lookups. DMARC aggregate reports (next page) are the tool for this.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The seven SPF results and how receivers treat them are unchanged; RFC 7208 is still the SPF standard and `Received-SPF:` still has the same format. DKIM is still RFC 6376 with the same tags, the same `selector._domainkey` key lookup and the same pass/fail/none outcomes, and "look for `dkim=pass`, then check which domain passed" is still the right habit. Reading your own border server's `Authentication-Results:` first is still the core of email triage.

!!! info "[Changed] What has changed"
    - **`Authentication-Results:` is now defined by RFC 8601**, which replaced RFC 7001 (via RFC 7601). The header looks the same to an analyst.
    - **DKIM became mandatory for bulk mail.** Since 2024 Gmail and Yahoo require bulk senders to have SPF, DKIM and DMARC with an aligned `From:` domain, and Microsoft applied similar rules for high-volume senders to Outlook.com from May 2025. `dkim=none` on mail from a large, legitimate sender is therefore now unusual.
    - **Stronger keys and a new algorithm.** RFC 8301 (2018) says `rsa-sha1` must not be used for signing and keys must be at least 1024 bits, with 2048 recommended. RFC 8463 added `ed25519-sha256`. In practice 2048-bit RSA is the norm and Ed25519 is usually published alongside RSA rather than instead of it, because not every verifier supports it.
    - **DMARC is now a Proposed Standard** (RFC 9989–9991, replacing RFC 7489), which changes how SPF and DKIM results are combined — covered on the next page.
    - **DKIM replay became a mainstream problem**, and the IETF is working on a redesigned "DKIM2" to resist replay and survive forwarding. As of late 2026 it is still a draft, not a standard; do not expect to see it in production headers yet.
    - **Cloud platforms dominate.** Most organisations' mail is signed by a hosted mail provider, and providers add their own composite verdicts (like `compauth`) alongside the standard results.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Do not trust `dkim=pass` or `spf=pass` on its own.** Always check *which* domain passed (`header.d`, `smtp.mailfrom`) against the visible `From:`. A pass for the attacker's own domain is worthless.
    - **Do not trust an `Authentication-Results:` you did not verify the author of.** Use only the header written by your own border or cloud mail service.
    - **Do not treat `dkim=none` as proof of spoofing, or `dkim=fail` always as an attack.** Context (mailing lists, gateways rewriting links) matters.
    - **Do not keep 1024-bit or `rsa-sha1` keys, never use `l=`, and revoke old selectors** (publish an empty `p=`) instead of leaving keys in DNS forever. A leaked or crackable old key lets anyone sign as you.
    - **Do not describe the selector as "the part of the email that is signed."** It is the key's name; the signed parts are in `h=` and `bh=`.

## Practice questions { #quiz }

### Question 1

A user reports a message that "passed all checks". The top of its header block looks like this (oldest lines are lower). What is wrong, and what is the real authentication result?

```
Authentication-Results: mx1.victim.example;
       spf=softfail smtp.mailfrom=victim.example;
       dkim=none;
       dmarc=fail (p=none dis=none) header.from=victim.example
Received: from mail.victim.example (unknown [203.0.113.66])
        by mx1.victim.example (Postfix) with ESMTP id 7HnQ2c; Thu, 19 Nov 2026 03:05:11 +0000
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=victim.example;
       dkim=pass header.d=victim.example;
       dmarc=pass header.from=victim.example
From: "IT Service Desk" <it-support@victim.example>
Subject: Password expires today - confirm here
```

??? success "Answer and explanation"
    There are **two** results headers with our own authserv-id `mx1.victim.example`. The one **below** our border `Received:` line (the "everything passed" one) arrived **inside the message** from `203.0.113.66` — the attacker wrote it. Our server should have removed it (RFC 8601 says to strip incoming results headers carrying our own name), so this also points to a configuration gap worth fixing.

    The **real** result is the top one, added by `mx1` after the border `Received:` line: `spf=softfail` (the IP `203.0.113.66` is not in victim.example's list, which ends `~all`), `dkim=none` (not signed), `dmarc=fail`. Our own domain's DMARC policy is only `p=none`, so nothing blocked it. Conclusion: an outside server impersonating our IT desk. Next steps: block the IP, search other mailboxes for the same subject/IP, and consider moving our DMARC policy beyond `p=none`.

### Question 2

A message shows `From: "Partner Billing" <billing@partner.example>` and this result. DKIM passed. Is the message proven to come from `partner.example`?

```
Authentication-Results: mx1.victim.example;
       spf=pass smtp.mailfrom=bounce.mailer-hub.example;
       dkim=pass header.d=mailer-hub.example header.s=k1 header.b=Zx81PqWe
```

??? success "Answer and explanation"
    **No.** Both checks passed, but **for `mailer-hub.example`**, not for `partner.example`:

    - `smtp.mailfrom=bounce.mailer-hub.example` — SPF only proved the bulk-mail platform's server was allowed to send for the platform's own bounce domain.
    - `header.d=mailer-hub.example` — the signature was made by the platform's key, not the partner's.
    - The visible `From:` domain `partner.example` was checked by **neither**.

    This could be a legitimate partner who uses that platform but never set up DKIM for its own domain — or anyone else with an account on that platform pretending to be the partner. DKIM proves "the `d=` domain signed this"; whether `d=` matches `From:` is DMARC alignment, which this message would fail. Treat it as unverified: compare with earlier genuine mail from the partner (did it carry `header.d=partner.example`?), and confirm any payment change by phone using a known number.

### Question 3

Two copies of a newsletter from `shop.example` arrive: one directly, one via an internal mailing list that adds `[staff-list]` to the subject and a footer to the body. Results:

```
Direct:     dkim=pass header.d=shop.example header.s=s1
Via list:   dkim=fail (body hash did not verify) header.d=shop.example header.s=s1
```

The DKIM-Signature has `h=from:to:subject:date:message-id`. Why did the list copy fail, and which change alone would already have been enough to break it? Is this an attack?

??? success "Answer and explanation"
    **"Body hash did not verify"** means the verifier's hash of the body no longer matches `bh=`. The list added a **footer** to the body, so the body changed → hash mismatch. That alone is enough to fail.

    The subject tag would **also** have broken it on its own, because `subject` is listed in `h=`: changing a signed header makes the signature in `b=` fail. (Here the verifier reported the body hash first.)

    **This is not an attack.** It is the normal side effect of a mailing list modifying messages, and it is exactly why ARC exists: the list server can record "DKIM passed when I received it" in ARC headers, and the final receiver can choose to trust that chain. As an analyst, the clue is the context: the same `d=` and selector pass on the direct copy, and the list copy shows the list's own `Received:` line and modifications.
