---
title: "Part 1 — Foundations of Network Evidence"
tags:
  - training
  - network-forensics
---

# Part 1 — Foundations of Network Evidence { #part-1 }

!!! abstract "What Part 1 covers"
    It starts with what the network leaves behind when you can't look at the disk. Then, in order: web proxy logs and caches, pcap files with tcpdump and BPF, Wireshark and tshark, where and with what equipment evidence is collected, and what makes network investigations hard.

## Lessons { #lessons }

Lessons are added one at a time, in order. Entries in the list below without a link are still being prepared. Numbering may shift slightly, for example if one lesson is split in two for length.

| Lesson | Topic | Status |
| --- | --- | --- |
| [1.1](why-network-forensics.md) | Evidence beyond the disk: why network forensics, and the investigator's mindset | Published |
| [1.2](web-proxies.md) | Web proxies: how they work, the main products, why the config file is evidence | Published |
| [1.3](proxy-logs.md) | Reading proxy logs: default and custom formats, Unix time | Published |
| [1.4](proxy-log-walkthrough.md) | Reconstructing an incident from proxy logs alone (investigation walkthrough) | Published |
| 1.5 | Commercial proxy logs, and pulling responses out of the proxy cache | In preparation |
| 1.6 | libpcap, tcpdump, and the pcap/pcapng file format | In preparation |
| 1.7 | Selecting only the packets you need with BPF | In preparation |
| 1.8 | Practical tcpdump options and reading the Wireshark window | In preparation |
| 1.9 | Wireshark display filters and following streams | In preparation |
| 1.10 | Lab guide: getting hands-on with tcpdump and Wireshark | In preparation |
| 1.11 | Evidence acquisition: where, and with what equipment, to collect packets | In preparation |
| 1.12 | Challenges and opportunities in network investigations | In preparation |
| 1.13 | Lab guide: carving exfiltrated data | In preparation |

## Back to the series { #back }

[Network Forensics home](../index.md)
