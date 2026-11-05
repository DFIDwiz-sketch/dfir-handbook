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

All 13 lessons of Part 1 are published. Reading them in order is recommended, but the lab guides (lessons 1.10 and 1.13) can be tried right after skimming the lessons before them.

| Lesson | Topic | Status |
| --- | --- | --- |
| [1.1](why-network-forensics.md) | Evidence beyond the disk: why network forensics, and the investigator's mindset | Published |
| [1.2](web-proxies.md) | Web proxies: how they work, the main products, why the config file is evidence | Published |
| [1.3](proxy-logs.md) | Reading proxy logs: default and custom formats, Unix time | Published |
| [1.4](proxy-log-walkthrough.md) | Reconstructing an incident from proxy logs alone (investigation walkthrough) | Published |
| [1.5](proxy-cache.md) | Commercial proxy logs, and pulling responses out of the proxy cache | Published |
| [1.6](pcap-and-tcpdump.md) | libpcap, tcpdump, and the pcap/pcapng file format | Published |
| [1.7](bpf.md) | Selecting only the packets you need with BPF | Published |
| [1.8](tcpdump-options-wireshark-ui.md) | Practical tcpdump options and reading the Wireshark window | Published |
| [1.9](wireshark-display-filters.md) | Wireshark display filters and following streams | Published |
| [1.10](lab-tcpdump-wireshark-tshark.md) | Lab guide: getting hands-on with tcpdump and Wireshark | Published |
| [1.11](network-evidence-acquisition.md) | Evidence acquisition: where, and with what equipment, to collect packets | Published |
| [1.12](challenges-and-opportunities.md) | Challenges and opportunities in network investigations | Published |
| [1.13](lab-carving-exfiltrated-data.md) | Lab guide: carving exfiltrated data | Published |

## Wrapping up Part 1 { #wrap-up }

After Part 1 you should be able to:

- Build and test hypotheses from evidence along **the path the communication took** (full packets, flows, logs), even when you can't see the disk (lessons 1.1 and 1.11).
- Read proxy log fields, reconstruct the course of an incident from logs alone, and extract responses from the cache (lessons 1.2–1.5).
- Understand pcap structure, capture and reduce with tcpdump and BPF, and dissect and tabulate with Wireshark and tshark (lessons 1.6–1.10).
- Plan where and with what to acquire evidence, and find the clues that remain despite NAT, encryption and tunnels (lessons 1.11–1.12).
- Carve an uploaded file out of a plaintext stream in several steps, show reproducibility with hashes, and report facts separately from interpretation (lesson 1.13).

Each lesson's outputs were produced with the tool versions stated in that lesson; changes are marked **[Changed]** and corrections **[Correction]**.

## Back to the series { #back }

[Network Forensics home](../index.md)
