---
title: "Blockchain DNS and IDNs (Punycode)"
tags:
  - training
  - sec450
  - blue-team
  - dns
  - technique
  - phishing
  - idn
---

# Blockchain DNS and IDNs (Punycode)

<div class="dfir-meta" markdown>
**Course:** SANS SEC450 (2022) Book 2 · **Module:** DNS Analysis and Attacks · **Pages:** p.74–79
</div>

!!! abstract "What this page covers"
    Blockchain DNS used to escape domain seizure (EmerDNS, ENS, gateways, EtherHiding) and the detection opportunities it creates; fake domains built from foreign letters (IDN homoglyphs) and how to read Punycode; IDNs inside mail and mobile apps, and real attack examples.

!!! note "Conventions"
    **[Added]** = not in the course, **[Correction]** = course error, **[Changed]** / **[Caution]** = changed since 2022 / risky if done the old way. See the [DNS overview](index.md) and the [triage sheet](triage-sheet.md).

## Blockchain DNS (p.74) { #blockchain }

Attackers use blockchain DNS to avoid domain seizure. The price is that ordinary DNS can't resolve it — and that weakness is the detection opportunity.

### The attacker–defender back-and-forth

| Stage | What goes in the malware | Defender response | Result |
| --- | --- | --- | --- |
| 1 | IP address (hard-coded) | Block IP / take server down | Infected hosts don't know a new address — attacker loses everything |
| 2 | Domain name | Block IP | Attacker just changes the A record and every infected host follows (fast, with short TTL) → whack-a-mole |
| 3 | Domain name | Seize / sinkhole the domain | The name itself is gone → defender wins |
| 4 | Blockchain domain | Can't be seized | Detect the "doesn't resolve in ordinary DNS" weakness |

### Key points

- Blockchain DNS stores records on a public blockchain → no central authority, so no takedown or seizure. But only the **name → IP mapping** is unseizable; the server still sits on the ordinary internet, so takedown and IP blocking still work.
- EmerDNS TLDs: `.coin`, `.emc`, `.lib`, `.bazar` (widely reported as used by BazarLoader/BazarBackdoor for C2).
- Outside the ICANN root, so company DNS and 8.8.8.8 both return **NXDOMAIN**. Using it needs special software, the malware's own resolver, or an alternative DNS (OpenNIC) → which means unauthorised DNS and unusual traces.
- Detection: lookups of blockchain TLDs, **lookups of TLDs not on the IANA list** (exceptions: internal names `.local`/`.corp`, typos, Chrome hijacking test), unauthorised DNS, software and protocol control.

??? question "Review Q&A"
    - What it avoids: domain suspension, seizure, sinkholing. What it can't avoid: server takedown, IP blocking — and the "doesn't resolve in ordinary DNS" trace.
    - Don't close `node3.bazar` NXDOMAIN as "failed, so no problem": the lookup itself is evidence of **malware on the host**, and it may have retried another way (alternative DNS, DoH, direct IP) → check the same host for unauthorised DNS, 853, DoH and direct-IP connections, the process (Sysmon 22), whether other hosts asked, when it started, then isolate.
    - Legitimate false positives for "TLD not on the IANA list": internal names (`.local`, `.corp`, `.lan`; `.home.arpa` *is* official), typos, dot-less single words (Chrome test, NetBIOS-style short names), some VPN and dev tools. What it misses: gateway access (`.eth.limo`, `ipfs.io`), EtherHiding (blockchain node APIs over ordinary HTTPS), lookups wrapped in DoH, blockchain services that use official TLDs.

!!! info "2026 view"
    - OpenNIC reportedly dropped its EmerDNS link around 2019 because of abuse (the course description may be dated).
    - New main players: ENS (`.eth`), Unstoppable Domains (`.crypto` etc.), Handshake + IPFS.
    - **Gateways**: intermediate sites that turn blockchain names into ordinary web addresses (`vitalik.eth.limo`, `ipfs.io/ipfs/Qm...`). They resolve normally through company DNS on official TLDs, bypassing the "unknown TLD" rule. Abused for hard-to-take-down phishing → maintain a gateway-domain list, block if there's no business need, watch for connections right after an email click.
    - **EtherHiding** (Guardio, 2023): C2 addresses or malicious code stored in a smart contract (an undeletable public notice board) and read via blockchain node APIs over ordinary HTTPS. It passes almost the entire DNS triage sheet → context and behaviour detection: who, which process, and what next (a direct-IP connection with no DNS right after the API call).

## IDNs and Punycode (p.75–77) { #idn }

Fake domains built from foreign letters that look identical to English can't be told apart by eye — but in DNS logs they always appear as Punycode starting with `xn--`.

### Key points

- p.75: `yоutube.com` looks identical even on hover, but the second "o" is Cyrillic (U+043E) → "hover over the link" training doesn't catch it.
- DNS originally allows only lowercase ASCII letters, digits and hyphens → other characters are converted to **Punycode** (IDN). E.g. `Καλημέρα.gr` = `xn--ixahbwnhi5b.gr`, `한국.kr` = `xn--3e0b707e.kr`.
- Deceiving with identical-looking characters (Cyrillic О, Latin O, Greek Ο) = a **homoglyph (homograph) attack**. Unlike typo-squats (`micros0ft`) or letter pairs (`rnicrosoft`), even close inspection may not reveal it.
- Punycode structure: `xn--` + the ASCII letters + `-` + encoded info for the non-ASCII letters, e.g. `xn--yutube-wqf.com`. **Every IDN label starts with `xn--`** (any label — subdomain or TLD) → search logs for `xn--`.
- Compare the second part with the real brand: **the missing letter is the swapped position**. `xn--pypal-4ve.com` → `pypal` is paypal minus the first "a" → `pаypal.com` (Cyrillic а U+0430). Swapping the second "a" gives `xn--paypl-7ve.com`.
- Decode locally rather than on an external site: `python3 -c "print(b'xn--yutube-wqf.com'.decode('idna'))"`; find non-ASCII characters with `ord(c) > 127`.
- `xn--` is not automatically malicious: a natural name in a single script (`한국.kr`, `münchen.de`) is usually fine. The strong signal is **imitating an English name + mixed scripts** (`аррӏе.com` has a·p·p·l·e all in Cyrillic).

??? question "Review Q&A"
    - Why "hover over the link" training fails: the link text and the real address are **the same fake address**, rendered just like the genuine one. The problem is not Punycode but that it **displays as the original characters**. Defender measures: alert on `xn--` lookups, monitor IDN variants of your brands (crt.sh), mail security that shows Punycode and warns on IDN links, passkeys and security keys (the machine compares the domain exactly).
    - "Block all `xn--`" blocks legitimate multilingual sites. A better rule: block or alert on **IDNs with mixed scripts**; allow single-script IDNs but alert if **the decoded name resembles a famous brand or our domain**. Caution: look-alikes **within the Latin script itself** such as `ɡ` (U+0261) don't trip the mixed-script rule → brand comparison is also required. Conversely, blocking every "English + non-English letter" name blocks `münchen.de`.

!!! info "2026 view"
    - After the 2017 `аррӏе.com` demonstration, browsers show mixed-script and imitating names as Punycode in the address bar; Chrome also has a look-alike warning page (exact conditions vary by version).
    - [Caution] Mail, chat and documents still show the original characters, so the pre-click stage remains vulnerable. In-app browsers may follow different rules.
    - TLD operators have registration limits such as "no script mixing", but they vary. `ᏚĖC450.com` = `xn--c450-uva139z.com` (Cherokee Ꮪ U+13DA + ė U+0117).
    - The real fix: passkeys and FIDO2 security keys.

## IDNs inside apps, and real attacks (p.78–79) { #idn-in-apps }

The browser shows Punycode only after the page has opened; mail, documents and phone screens show the original characters, so stopping it before the click is hard. Many real attacks also swap characters within the Latin script.

### IDNs inside apps (p.78)

- Timeline: shown as original characters in the email → click → page opens (now the address bar shows Punycode) → user gets suspicious. Browser protection works *after* the page opens, so a malicious download or exploit may already be under way.
- Course screenshots: Outlook desktop, Gmail web, Outlook and Gmail mobile, iOS notifications. How convincing it is depends on the **font**, and the app or device picks the font.
- Phones are especially weak: small text, hidden URLs, no hover, tap straight from the notification.
- Defences sit before the user's screen: mail security (show Punycode, warn, quarantine), link rewriting and time-of-click checks, DNS-layer blocking, passkeys and security keys.

### Real attacks (p.79)

| Displayed as | In DNS logs | Swapped character | Mixed scripts? |
| --- | --- | --- | --- |
| `ᏚĖC450.com` | `xn--c450-uva139z.com` | Ꮪ U+13DA (Cherokee), ė U+0117 | Yes (Latin + Cherokee) |
| `ḟacebook.com` | `xn--acebook-js3c.com` | ḟ U+1E1F | No (Latin only) |
| `morɡanstanley.com` | `xn--moranstanley-0df.com` | ɡ U+0261 | No (Latin only) |
| `lloydsbankingɡroup.com` | `xn--lloydsbankingroup-0ch.com` | ɡ U+0261 | No (Latin only) |

- Targets: Facebook, Morgan Stanley, Lloyds, UnitedHealth — firms tied directly to money and personal data.
- Same-script swaps don't trip the mixed-script rule → **brand-similarity comparison** (map confusable characters to plain Latin, then compare against your brand list — UTS #39 confusables). A Punycode second part that is the brand minus one or two letters (`moranstanley`) is a strong signal.
- **Slash look-alikes**: in `bankofamerica.com∕index.jp` the real registered domain is `com∕index.jp` and `bankofamerica` is a subdomain. With U+2215 it appears in DNS as `bankofamerica.xn--comindex-0f7d.jp`. The extreme case of "read from the right" (owned by a researcher).

??? question "Review Q&A"
    - Correction: the quiz example `xn--micrsoft-07a.com` actually decodes to `miăcrsoft.com` (ă U+0103) — a badly built example. Correct ones: `micrоsoft.com` (first o Cyrillic) = `xn--micrsoft-qbh.com`, `microsоft.com` (second o) = `xn--microsft-sbh.com`. The second part lets you guess the brand and missing letter, but **which script it is only shows when you decode it and look at the code point** (Cyrillic о or Latin ö?).
    - "The browser shows Punycode, so why not relax?": mail (original characters) → click → page opens → only then Punycode in the address bar. Measures: Punycode display and quarantine at the mail layer, time-of-click checks, DNS blocking, passkeys.
    - `paypal.com/login.secure-check.co`: if the `/` is a fake slash, the whole thing is a domain → registered domain `secure-check.co` (subdomain `paypal.com∕login`). If it's a real slash, the registered domain is `paypal.com` and the rest is a path. Same on screen, completely different owner.

!!! info "2026 view"
    - Slash trick: the old rules (IDNA2003) convert it, but current rules (IDNA2008 / UTS #46) reject U+2215 and U+2044 (verified locally) → mostly blocked now. **Same-script swaps (`ɡ`, `ḟ`) are still allowed under current rules** → more important in practice.
    - Time-of-click checking (Safe Links etc.) is standard, but weak against cloaking.
    - SMS and messenger phishing are growing — outside mail security. MDM and mobile Protective DNS.
    - Awareness training is shifting from "check the address carefully" to "don't log in from message links — use passkeys".
