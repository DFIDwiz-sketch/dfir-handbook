---
title: "HTTPS — TLS Decryption, Working Without It, Reading Certificates"
tags:
  - training
  - blue-team
  - http
  - tls
---

# HTTPS — TLS Decryption, Working Without It, Reading Certificates { #https-certificates }

!!! abstract "What this page covers"
    The visibility problem created by near-universal encryption, how TLS decryption (TLS inspection) actually works and where it breaks, what each layer still shows you when you cannot decrypt (IP/ASN, port, SNI and certificate, volume and timing), and how to read a certificate field by field to spot suspicious ones (openssl, Zeek `ssl.log`/`x509.log`). Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The full Zeek TLS field reference is in [Zeek ssl.log & x509.log](../../../network/zeek/ssl-x509.md).

## The 8 key points { #key-points }

1. Encryption protects users but **also blinds the security team** — and with DoH, it hides DNS too, not just HTTP.
2. Even when the network goes dark, the **endpoint** still sees everything. The more encryption grows, the more endpoint telemetry carries the load.
3. TLS decryption works by planting an **organisation-owned root certificate** on every PC; a middle device mints a fake certificate per site on the fly and "unlocks and re-locks" traffic in the middle.
4. Without decryption you still see: **destination IP (ASN, geo), port, SNI, the certificate (TLS 1.2 and below), and volume and timing.**
5. What to read in a certificate: **Subject/CN and SAN (which site), Issuer (who signed), validity period, organisation fields.**
6. Suspicious certificates: **self-signed** (Issuer = Subject), random names, a tool's default certificate, a name that doesn't match the SNI, an odd port instead of 443.
7. [Correction] "Empty organisation fields = malicious" is now a weak signal. Most legitimate sites use DV certificates that carry no organisation data.
8. **TLS 1.3 encrypts the certificate.** Reading certificates without decryption only works for TLS 1.2 and below.

## Almost everything is HTTPS { #https-everywhere }

**Why it matters.** Encryption protects individuals from snooping and man-in-the-middle attacks (intercepting and altering traffic). The same encryption **also blinds the security team.** In most organisations most traffic is encrypted, and many teams have no tooling to open it. With DNS now often carried over HTTPS (DoH), failing to decrypt TLS means losing **DNS as well as HTTP** ([Encrypted DNS](../dns/encrypted-dns.md)).

Free, easy certificates from services like Let's Encrypt, and browsers marking non-https sites as "Not secure", accelerated the shift. Attackers use those same free certificates to hide their own traffic.

It is not hopeless. Even when the network view goes completely dark, **you can still collect directly on the endpoint (PCs and servers).** As encryption grows, endpoint telemetry becomes the main answer to lost network visibility.

You have two broad options: **decrypt and look (TLS decryption), or make the most of what is visible without decrypting.**

## How TLS decryption works { #tls-decryption }

Think of it as **the company mailroom opening every envelope and forwarding the contents in a fresh envelope.** Staff have been told in advance to trust the mailroom's stamp, so they don't question the new envelope.

```
Client PC  ──HTTPS (key 1)──▶  Decryption device  ──HTTPS (key 2)──▶  Web server
           ◀─ org-signed cert ─┤  decrypt → inspect  ├─ original cert ─▶
                                │  → re-encrypt      │
                                └─▶ IDS/IPS, sandbox, metadata, SIEM
```

1. **Preparation:** the organisation creates its own **root certificate authority (Root CA)** and pushes that root certificate into the "trusted certificates" store on every company PC. Without this, browsers reject the fake certificates and the whole scheme fails
2. **PC → decryption device:** when the PC asks to connect to `www.example.com`, the device **mints a certificate for that site on the fly, signed by the company root CA**, and returns it. The PC trusts the company root, so it accepts
3. **Decryption device → site:** on the other side the device connects to the real site like a normal client and establishes encryption with the site's **real certificate**
4. **In the middle:** the device is effectively a "man in the middle". Content passes in the clear **between** the PC-side connection (key 1) and the site-side connection (key 2), so at that point you can run IDS/IPS rules, sandbox files, collect metadata and ship to the SIEM

The user still has an encrypted connection, and the security team can see inside.

**[Supplement] Limits and pitfalls of decryption.**

| Problem | Detail |
| --- | --- |
| Certificate pinning | Some apps (banking apps, updaters, some security products) only trust a specific certificate for a server and drop the connection when they see the company certificate → needs an exception |
| Privacy and law | Categories like banking, health and personal mail are often exempted. Check national/organisational rules and user notification |
| Protecting the company root CA | If that root key leaks, an attacker can mint certificates every company PC trusts → protect it more strictly than anything else |
| Performance and outages | Unwrapping and rewrapping every connection costs CPU; a device failure becomes an internet outage |
| Unmanaged devices | Personal devices and IoT without the root certificate cannot be inspected |
| New protocols | QUIC (HTTP/3) easily bypasses legacy proxies, so UDP 443 is usually blocked to force a fallback to TCP ([QUIC policy](../http/new-standards.md#quic-policy)) |

## What you still see without decryption { #no-decryption }

No decryption device does not mean giving up. Each layer shows something different.

| Layer | What is visible | How to use it |
| --- | --- | --- |
| IP (L3) | Destination IP, its ASN (whose network) and country | Match against bad-IP lists, cheap VPS or unusual countries, Passive DNS for domains tied to that IP |
| TCP (L4) | Destination port | Mostly 443 and unremarkable, but TLS on a port like **4444** (Metasploit's default) is a detection opportunity |
| Session (TLS) | **SNI** (the site name being requested), TLS version and cipher, the **certificate** (TLS 1.2 and below), fingerprints (JA3/JA4) | Judge the site name (domain signals), assess the certificate (below), client fingerprinting |
| Application (L7) | **Nothing** — path, headers and body are all encrypted bytes | — |
| Connection metadata | **Volume** sent and received, **timing**, connection **interval** | Large uploads (exfiltration), beacon intervals |

If you have DNS logs, the name queried just before the connection also tells you the site. But as TLS 1.3 spreads and ECH becomes a standard, even the session layer is shrinking. If you have not yet built a decryption strategy, now is the time to plan one.

## Reading certificates { #reading-certificates }

In TLS 1.2 and below, the server's certificate crosses the wire **unencrypted**, so you can read it in Wireshark or Zeek without decryption. It is the same information you see in a browser's "View certificate" window.

### What each field means { #cert-fields }

| Field | Meaning | What to check |
| --- | --- | --- |
| Subject / Common Name (CN) | The site name the certificate was issued to (required) | The site the user visited. Does it match the SNI? |
| Subject Alternative Name (SAN) | The list of names this certificate is valid for | Modern browsers check the name against **SAN**, not CN |
| Issuer | The certificate authority that signed it (required) | Same as Subject → **self-signed** |
| Certificate chain | Site → intermediate CA → root CA | Does it chain to a root the browser trusts? |
| Not Before / Not After | Validity period | Brand new? Abnormally long (self-signed often 10 years)? |
| Organization / Locality / Country | Organisation, location, country (optional) | If filled, a clue to who made it. If empty, see the [Correction] below |

### Look at it yourself with openssl { #openssl }

**From an isolated analysis environment** you can fetch a server's certificate directly (never connect to a suspicious server from a company PC or company IP).

```
$ openssl s_client -connect update-cdn-sync.example:443 -servername update-cdn-sync.example </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
subject=CN = update-cdn-sync.example
issuer=CN = update-cdn-sync.example
notBefore=Nov  2 08:14:51 2026 GMT
notAfter=Oct 31 08:14:51 2036 GMT
X509v3 Subject Alternative Name:
    DNS:update-cdn-sync.example
```

- `openssl s_client -connect host:443` — opens a TLS connection to the server
- `-servername host` — sends the SNI (without it, a server hosting many sites on one IP may return the wrong certificate)
- `</dev/null 2>/dev/null` — closes the connection immediately and hides progress messages
- `| openssl x509 -noout` — parses the received certificate without printing the raw certificate
- `-subject -issuer -dates -ext subjectAltName` — prints only the name, signer, validity period and SAN

Reading the output: **subject and issuer are identical → self-signed**, issued two days ago with **a 10-year validity** (impossible for a public certificate), no organisation data. A legitimate public service would use a short-lived certificate signed by a public CA.

### Reading it in Zeek { #zeek-tls }

```
ssl.log:
  id.orig_h=10.1.5.77  id.resp_h=203.0.113.58  id.resp_p=4444
  version=TLSv12  cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  server_name=-  established=T  validation_status=self signed certificate

x509.log:
  certificate.subject=CN=xk29fq.local,O=,C=
  certificate.issuer=CN=xk29fq.local,O=,C=
  certificate.not_valid_before=2026-11-02T08:14:51Z
  certificate.not_valid_after=2036-10-31T08:14:51Z
  san.dns=-
```

- `id.resp_p=4444` — TLS on **4444** (Metasploit's default port), not 443
- `server_name=-` — **no SNI** → direct-to-IP connection ([naked IP](files-frequency-naked-ip.md#naked-ip))
- `established=T` — the TLS handshake succeeded
- `validation_status=self signed certificate` — Zeek validated it and found it self-signed (logged when the validation script is enabled)
- `certificate.subject` / `issuer` — both the random-looking `xk29fq.local`, organisation and country empty
- 10-year validity, no SAN

That is a very strong C2 indicator.

### Signs of a suspicious certificate { #suspicious-certs }

| Signal | Why |
| --- | --- |
| Self-signed (Issuer = Subject) | Public services use public CAs. Attackers sometimes generate their own certificate with no details |
| Random or meaningless names, internal names like `.local` | Don't fit a public site |
| A tool's **default certificate** | Attack tools used without configuration send their default certificate (e.g. Cobalt Strike's default keystore `CN=Major Cobalt Strike`, OpenSSL's default `O=Internet Widgits Pty Ltd`) |
| SNI and certificate name mismatch | Someone else's certificate, fronting, or a man in the middle |
| Odd port + certificate | TLS on 4444, 8443, high ports |
| Validity too long for a public certificate | Public certificates have a policy maximum (see [Changed] below) |
| The same certificate fingerprint on several unfamiliar IPs | Attackers copy one certificate across servers → the fingerprint links their infrastructure |

**[Correction] "Empty organisation fields = malicious" is a weak signal.** It used to be treated as a strong clue that malicious certificates left organisation, locality and country blank. Today **DV (domain-validated) certificates** such as Let's Encrypt make up most of the web, so most legitimate sites have no organisation data either (DV only proves "owner of this domain" and adds no company information). OV/EV certificates with organisation data filled in go through company verification at issuance, so **filled-in fields are a small trust signal** and **empty fields mean "no conclusion"**. Likewise **"Let's Encrypt = suspicious" is wrong.** Attackers use it because it is free, and so do most legitimate sites.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    "Encryption blinds visibility", "decryption is a man in the middle using an organisation root CA", "IP, port, SNI, volume and timing are visible without decryption", "self-signed, random-name and odd-port certificates are suspicious" and "the endpoint is a big part of the answer" all still hold.

!!! info "[Changed] What has changed"
    - **Certificate lifetimes keep shrinking.** Under the industry body's (CA/Browser Forum) schedule, the maximum validity of public certificates drops to **200 days** from 15 March 2026, **100 days** from 15 March 2027 and **47 days** from 15 March 2029. That makes "the certificate was just issued" a weak signal (legitimate sites renew constantly). Look instead at **when the domain's first certificate appeared in Certificate Transparency (CT) logs** and the domain registration date. Conversely, a certificate supposedly signed by a public CA but valid longer than these limits is odd.
    - **TLS 1.3 is now the majority.** TLS 1.3 sends the server certificate encrypted, so reading certificates without decryption only works on TLS 1.2 and below. What remains is the SNI and fingerprints (JA3/JA4), and as ECH (RFC 9849, 2026) spreads, the SNI disappears too ([ECH](../http/post-methods-headers.md#domain-fronting)).
    - **EV indicators are gone.** Browsers removed the company name (the green EV bar) from the address bar, reducing what EV means in practice.
    - **Decryption moved to the cloud.** Instead of on-prem appliances, cloud secure web gateways (SWG) and SASE platforms commonly do TLS inspection, with an endpoint agent steering traffic to them.
    - **EDR and browser telemetry fill much of the gap.** Without decryption, EDR still records on the endpoint which process connected where and what it downloaded.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't call something malicious just because it has no organisation data or uses Let's Encrypt.** Most legitimate sites look the same.
    - **Don't treat "recently issued certificate" as a strong signal.** With short lifetimes, legitimate certificates are always recent. Use domain age and the first CT appearance.
    - **Don't make decryption exceptions broad.** Attackers try to hide in exempt categories (sites categorised as finance or health, update services). Keep exceptions as narrow as possible and documented.
    - **Don't treat the company root CA private key like any other server secret.** If it leaks, TLS trust across the whole organisation collapses.

## Practice questions { #quiz }

### Question 1

With no TLS decryption, Zeek logged the following. What is suspicious, and what is your verdict?

```
ssl.log:  id.orig_h=10.1.5.77  id.resp_h=203.0.113.58  id.resp_p=4444  version=TLSv12
          server_name=-  established=T  validation_status=self signed certificate
x509.log: certificate.subject=CN=xk29fq.local  certificate.issuer=CN=xk29fq.local
          not_valid_before=2026-11-02  not_valid_after=2036-10-31
conn.log: same pair every 60 s, ~1.2 KB each way
```

??? success "Answer and explanation"
    Almost every field is suspicious.

    - **Port 4444** — Metasploit's default. Normal web traffic uses 443
    - **No SNI** — direct-to-IP connection
    - **Self-signed** (Subject = Issuer), random-looking `.local` name, no organisation data
    - **10-year validity** — impossible for a public certificate
    - **Every 60 seconds at a similar size** — a beacon

    **Verdict: very likely C2 traffic.** You can't see the content without decryption, but this combination is ample grounds to act.

    Next: isolate the PC, identify the connecting process (Sysmon Event ID 3), block and look up the IP's reputation, and **use the certificate fingerprint (`cert_chain_fps`) to find other IPs using the same certificate** in company logs and internet scan data (expanding the attacker's infrastructure).

### Question 2

After the organisation deploys TLS decryption, one business app and staff banking apps start failing with "cannot connect". Why, and how should it be handled?

??? success "Answer and explanation"
    **Cause: certificate pinning.** These apps decide "this server only trusts this certificate (or this CA)", so when they receive the **company-CA-signed certificate** the decryption device minted on the fly, they treat it as a man-in-the-middle attack and drop the connection. Browsers are configured to trust the company root CA, so they are fine, but pinning apps ignore that setting.

    **Handling:**

    1. Add the app's destinations (domains) as **decryption exceptions** — exempt traffic is only seen as metadata such as SNI, IP and volume
    2. Banking and health categories are often exempted for privacy and legal reasons too. Check organisational rules and user notification
    3. Keep exceptions **to the domains that actually need them**, and record and review the list — so attackers can't hide in exempt categories
    4. Cover exempt traffic with endpoint telemetry (EDR)

### Question 3

The same C2 server now talks **TLS 1.3**. The `x509.log` certificate data you saw before no longer appears. What is still visible, and how do you keep detecting it?

??? success "Answer and explanation"
    TLS 1.3 sends the server certificate **encrypted**, so without decryption you cannot read it (Subject, Issuer, validity).

    **Still visible:**

    - **IP, ASN, country and port** (if it is still 4444, that alone is a clue)
    - **SNI** (unless ECH is used) — here it is empty because of the direct-to-IP connection, which is itself a clue
    - **TLS client and server fingerprints (JA3, JA4, JA4S)** — the distinctive shape produced by the malware's TLS library
    - **Volume, timing and interval** — the 60-second beacon is still visible

    **Keeping up detection:**

    1. Fingerprint- and interval-based detection (JA4 lists, beacon analysis such as RITA)
    2. Find other connections using the same IP, ASN or fingerprint
    3. **Endpoint** — which process made the connection (Sysmon 3, EDR), extracting the C2 config from memory
    4. Consider widening decryption coverage if needed
