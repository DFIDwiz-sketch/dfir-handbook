---
title: Investigations
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
---

# Packet & Log Investigations { #investigations }

Worked investigations of real captures and logs. Each one starts from an unopened PCAP (or log export) and ends with the answers and a short report, showing **every command, the actual output, and why that output answers the question**.

Zeek is the main tool. Where tshark gets the same answer more simply, a **tshark** tab sits next to the Zeek command.

## Cases { #cases }

| Case | Evidence | What it teaches |
|---|---|---|
| [PCAP Lab 06 — Invoice Word macro to Hancitor-style C2](pcap-lab-06-invoice-macro-c2.md) | PCAP, 21 min, one Windows client in an AD domain | Single-host triage, safe handling and hashing of a Word document, finding macros without Office, public IP from an IP-check service, beacon pattern and User-Agent comparison, DHCP and Kerberos for network facts |
| [PCAP Lab 07 — Webmail to AutoIt downloader and multi-C2 traffic](pcap-lab-07-autoit-downloader-multi-c2.md) | PCAP, 18.5 min, one stand-alone Windows 7 PC | OS without a domain (User-Agent, TTL, DHCP vendor class), non-browser downloads, capture loss and why hashes are missing, User-Agents read with destinations, unknown-service connections, SMTP exfiltration signs |
| [Arkime only — script downloader to credential theft, TLS C2 and an incident ticket](arkime-only-credential-theft-tls-c2.md) | PCAP, 44 min, three Windows 10 clients in an AD domain; **Arkime web UI + CyberChef only**, closed network | Sessions and SPI View, start/end time, Kerberos hostnames, reading POST bodies (Hide Images & Files), certificate issuer/subject and self-signed checks, TLS C2 on 447/449, SMB sweep scoping, writing a full incident ticket, copy-ready queries |
| [RedLine Stealer — PowerShell script to net.tcp C2 data theft](redline-stealer-powershell-nettcp-c2.md) | PCAP, 36 s, one Windows 10 client in an AD domain (Unit 42 quiz, July 2023); worked in Arkime terms | DHCP for IP/MAC/hostname, DNS SRV and Kerberos, PowerShell User-Agent check-ins, HTTPS payload behind a `.jpg` name, why JA3 did not change, finding raw-TCP C2 by port, reading .NET net.tcp, server target list vs uploaded loot, screenshot carving and capture loss, comparison with Trickbot |
| [IcedID (Cold as Ice) — redirect, Firebase and fake gzip to HTTPS beacon and BackConnect](icedid-tds-gzip-loader-backconnect.md) | PCAP, about 6 h, three Windows clients in an AD domain (Unit 42 quiz, April 2023); worked in Arkime terms | Identifying PCs without DHCP (Kerberos, NetBIOS, MAC), narrowing down the infected PC with DNS, TDS 302 and Firebase abuse, decoding IcedID cookies (host, user, SID), self-signed `Internet Widgits` certificates, measuring a 5-minute beacon, JA3 inflation from Edge, non-TLS BackConnect on 443 and the attacker's commands, a zip/.wsf on a second PC, comparison with the two earlier cases |
| [Phishing red herring to exploit-kit drive-by — Angler-like EK, Ursnif-like C2 and CAB exfil](phishing-red-herring-ek-driveby-ursnif-c2.md) | 7 phishing `.eml` files + employee list + PCAP (12.5 min, one Windows 7 / IE11 PC); **Splunk (Zeek) + Arkime + Snort**, closed network | Email headers bottom-up, MIME encodings, decoding base64 to read zip internals (zip-in-zip, NTFS times), STARTTLS limits, Splunk traps (`_time` = ingest time, `host` collision, TSV multi-value fields), testing the obvious hypothesis, referrer chain through a Flash gate to an exploit kit, Arkime Body MD5 and natural view, CAB exfil in a POST, round-robin C2 DNS, 11 Snort rules (DNS, flowbits, pcre, no-Accept) tested against the PCAP, full ticket |
| [Back to the Present — network baselining to a .bit C2, a tech support scam pop-up, Snort rules and a ticket](back-to-the-present-chthonic-c2-tech-support-scam.md) | PCAP (12 min, one Windows 10 PC behind a home router, malware-traffic-analysis.net 2017-10-21); **Splunk (Zeek) + Arkime + Snort**, closed network | Full network baselining from scratch (internal range, devices by MAC, router, DNS/DHCP server, no DC/file/mail server, protocols, OS from User-Agent/DHCP/NetBIOS/TTL, external overview), finding requests without a User-Agent, EXE download right after Office start-up, `.bit` (Namecoin) C2 resolved over TCP 53 through external resolvers, encrypted HTTP/1.0 POST C2 and module download, measuring intervals with `streamstats`, injected pop-under script to a tech support scam, scope checks, 14 Snort rules (DNS label format, threshold, flowbits, file_data, pcre) tested against the PCAP, ticket with host-operator leads |
| [Night Dew — Hancitor check-ins to follow-up downloads, credential exfil and a self-signed TLS C2](night-dew-hancitor-pony-zeus-panda-tls-c2.md) | PCAP (43 min, one Windows 7 PC in an AD domain, malware-traffic-analysis.net 2018-05-11); **Arkime + CyberChef + Snort**, closed network | Baseline from DHCP/Kerberos/DNS in a domain, picking suspicious external IPs, api.ipify public-IP lookup tied to the C2 body, reading a Hancitor `GUID=/BUILD=/INFO=` check-in, decoding the C2 reply in CyberChef (Base64 → XOR 0x7A) into download commands, encrypted payloads disguised as `text/plain`, Pony-style `Content-Encoding: binary` exfil POSTs, self-signed `Default Company Ltd` TLS C2 and 5-minute bursts, timeline with unknown initial access, 8 Snort rules tested against the PCAP, one merged ticket (txt download) |

Cases are worked with Zeek unless the table says otherwise.

More cases from the same lab series will be added here as they are completed.

## How each case is written { #case-structure }

1. **Scenario and questions**: what was given and what had to be answered.
2. **Setup**: folders, hashing the evidence, generating Zeek logs.
3. **Big picture**: capture window, internal hosts, DHCP, Kerberos, DC.
4. **Find the suspicious thing**: files, URLs and the first malicious event.
5. **Handle and analyse the sample safely**: extraction, hashes, file type, macros.
6. **Post-infection traffic**: C2, extra downloads, IP checks, beacon timing.
7. **Network facts**: subnet, gateway, domain, DC name.
8. **Timeline, IOCs, answers and report**.
9. **Detection ideas and lessons learned**.

Each finding is marked as **confirmed** (seen directly in the evidence) or **inferred** (a reasonable conclusion that the evidence does not prove by itself). Malware family names are inferred unless an offline hash lookup or a signature confirmed them.

!!! warning "Indicators on these pages are real"
    Domains, IPs and hashes come from real malware traffic. They are written defanged (`hxxp`, `[.]`) in IOC tables. Do not browse to them.

## Method pages { #method-pages }

- [PCAP IR Labs — setup and workflow](../../training/pcap-ir-labs/setup-and-workflow.md): the repeatable method these cases follow
- [Zeek logs](../../network/zeek/index.md) · [Wireshark & tshark](../../network/wireshark-tshark.md) · [Beaconing & C2](../../network/beaconing-c2.md)
- [Arkime offline PCAP guide](../../network/arkime/offline-pcap-guide.md): the same lab questions answered in Arkime
