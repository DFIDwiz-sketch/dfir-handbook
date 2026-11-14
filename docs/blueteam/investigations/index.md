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
