---
title: Network Forensics
---

# Network Forensics

Packet, flow and log-based analysis: Zeek for structure, Wireshark/tshark for payload, and the hunting techniques that find command-and-control in the noise. Start from the **question**.

## Question → where to look

| Question | Primary | Also check |
|---|---|---|
| **Who talked to whom, how much, how long?** | [Zeek `conn.log`](zeek/conn-log.md) | NetFlow/IPFIX, firewall logs, `tshark -z conv,tcp` |
| **What name did the host look up? What did it resolve to?** | [Zeek `dns.log`](zeek/dns-log.md) | Sysmon 22 on the host, DNS server logs, passive DNS |
| **What URL / user agent / file was fetched over HTTP?** | [Zeek `http.log`](zeek/http-log.md) | Proxy logs (with user), [`files.log`](zeek/files-log.md), pcap export objects |
| **It's encrypted — what can I still know?** | [Zeek `ssl.log` / `x509.log`](zeek/ssl-x509.md) (SNI, JA3/JA4, cert) | Suricata TLS, host process telemetry, decrypting proxy |
| **What files crossed the wire? Hashes?** | [Zeek `files.log` / `pe.log`](zeek/files-log.md) | `smb_files.log`, `smtp.log`, `tshark --export-objects` |
| **Is this host beaconing to C2?** | [Beaconing & C2 detection](beaconing-c2.md) | RITA, JA3 rarity, [SRUM](../windows/srum.md) hourly bytes |
| **Is data being exfiltrated?** | [`conn.log`](zeek/conn-log.md) `orig_bytes` per pair; [`files.log`](zeek/files-log.md) `is_orig=T` | [SRUM](../windows/srum.md), [$UsnJrnl](../windows/mft-usn.md) archive creation, DNS bytes ([`dns.log`](zeek/dns-log.md)) |
| **Lateral movement between internal hosts?** | `conn.log` internal→internal 445/135/3389/5985/22; `smb_files.log`, `dce_rpc.log`, `ntlm.log`, `kerberos.log`, `rdp.log` | Windows `4624` type 3/10, `5140/5145`, `7045` ([Event IDs](../basics/windows-event-ids.md)) |
| **Scanning / recon?** | `conn.log` `S0`/`REJ` counts, `notice.log` `Scan::*`, `ldap.log` query volume | Suricata scan rules, honeypot hits |
| **What was actually said?** | [Arkime](arkime/index.md) session view / pcap export → [Wireshark / tshark](wireshark-tshark.md) | Zeek `extract_files/` |
| **I have an alert / IOC — show me the packets, and who else?** | [Arkime hunting workflows](arkime/hunting-workflows.md) (Sessions → SPIView → Connections → Hunt) | [Arkime search syntax](arkime/search-syntax.md), Suricata `eve.json`, Community ID pivot |
| **Find a string inside weeks of traffic** | Arkime **Hunt** ([workflows](arkime/hunting-workflows.md#workflow-4-hunt-searching-payloads-for-a-string)) | `tshark -Y 'frame contains …'` on a sliced pcap |
| **Which port is that?** | [Well-known ports](../basics/well-known-ports.md) | Zeek `service` field (content-based) |

## Pages

<div class="grid cards" markdown>

-   **[Zeek overview](zeek/index.md)** — how the logs join (`uid`/`fuid`), formats, running on pcaps
-   **[conn.log](zeek/conn-log.md)** — states, history flags, byte fields, scan and exfil queries
-   **[dns.log](zeek/dns-log.md)** — tunnelling, DGA, resolver policy, DoH blind spot
-   **[http.log](zeek/http-log.md)** — user-agent triage, disguised downloads, web shells
-   **[ssl.log & x509.log](zeek/ssl-x509.md)** — SNI, JA3/JA4, certificate red flags, TLS 1.3 limits
-   **[files.log & pe.log](zeek/files-log.md)** — hashes, extraction, SMB copies, PE header tells
-   **[Arkime overview](arkime/index.md)** — full-packet capture + indexed sessions; how it pairs with Zeek/Suricata
-   **[Arkime search syntax](arkime/search-syntax.md)** — operators, field names, recipes, API/URL tricks
-   **[Intrusion detection with Arkime](arkime/hunting-workflows.md)** — alert → proof, beacons in SPIGraph, lateral movement in Connections, Hunts, WISE, Cron Queries
-   **[Wireshark & tshark](wireshark-tshark.md)** — display-filter cheat sheet, tshark recipes, GUI habits
-   **[Beaconing & C2](beaconing-c2.md)** — interval analysis, rarity, fingerprints, modern evasion

</div>

## Analysis order (network side)

1. **Scope the capture**: time range, sensor placement (inside/outside NAT? which VLANs?), drops (`capinfos`, `conn.log missed_bytes`). Write down what you *cannot* see.
2. **Aggregate `conn.log`**: top destinations, rare destinations, long connections, big uploads, scan patterns.
3. **Name it**: `dns.log` for the domains behind the odd IPs; `ssl.log` SNI/cert; `http.log` host/URI/UA.
4. **Fingerprint it**: JA3/JA4, UA, cert fingerprint → search the fleet.
5. **Time it**: interval analysis on the candidate pairs ([Beaconing](beaconing-c2.md)).
6. **Content**: `files.log` hashes → intel; Arkime session payload / Hunt for strings; pcap follow-stream for cleartext; extract files.
7. **Cross to the host**: Sysmon 3/22, Prefetch/Amcache, SRUM, persistence — then back to the network for what else that host touched.

!!! info "Adding a page here"
    `python new.py network/<name> -t artifact` (or `network/zeek/<name>` for another Zeek log) — the file appears in the sidebar automatically.
