---
title: "Day 2 — Egress Traffic Analysis (in progress)"
tags:
  - training
  - antisyphon
  - egress
  - beaconing
  - zeek
---

# Day 2 — Egress Traffic Analysis

<div class="dfir-meta" markdown>
**Course:** Information Security Core Skills · **Instructor:** John Strand (BHIS) · **Day 2 so far:** egress analysis → NetFlow → firewall-log analysis → Zeek → beaconing → RITA
</div>

!!! abstract "Day 2 at a glance (parts 1–2)"
    If Day 1 was about *keeping attackers out*, Day 2 is about **finding the ones already in**. The focus is **outbound (egress) traffic** — the conversation an infected host has with its C2 server. You can't read the content (it's encrypted), but you can see the **behaviour** (regular interval + consistent size = a **beacon**). **Zeek** turns traffic into consistent metadata logs; **RITA** finds the beacons in those logs with math.

!!! info "This page is in progress"
    **Parts 1–2** (egress, NetFlow, manual log analysis, Zeek, beaconing, RITA) are written up. Parts 3–5 (AC-Hunter lab, ASN / deny-lists, UEBA, Deep Blue CLI, Sysmon) will follow.

!!! note "Conventions"
    **💡 Note (added)** = my own addition beyond the lecture. **(reconstructed)** = commands the instructor only showed on screen, written out generically — match them to the actual lab handout.

---

## 1. Why "egress" traffic? { #why-egress }

When an attacker owns a host, that host keeps talking to the attacker's **C2 (command-and-control) server**. That conversation flows **outbound** (recall Day 1's reverse connection), so watching egress traffic reveals the infected internal host. In MITRE ATT&CK, C2 / common-port use / exfiltration are areas many orgs miss.

The reason they miss it is **encryption** — most traffic is TLS/SSL, so you can't read the content. Appliances can decrypt TLS in the middle, but that raises privacy / GDPR concerns.

!!! quote ""
    "It's encrypted so we can't see it" is not an acceptable excuse. You can't read the content, but you can still see the **behaviour**.

## 2. NetFlow — connection statistics { #netflow }

Even without content, you can see **who talked to whom, when, and how much**. That's **NetFlow** (connection statistics, created by Cisco):

- **Exporter** — the device sending the connection data (router / firewall)
- **Importer / Collector** — where that data is gathered
- **Analysis engine** — makes sense of the collected data

Once NetFlow became a de-facto standard, many look-alikes followed (sFlow, jFlow, NetStream …) — all different ways of handling connection statistics.

## 3. Lab — analysing Cisco ASA firewall logs by hand { #asa-lab }

John first shows **how painful it is by hand**. Assume some internal IP is compromised (here `192.168.1.6`):

```bash
sudo su -
cd /opt/firewall_log
grep 192.168.1.6 <logfile>        # (reconstructed) pull only lines with that IP
```

- `grep <string>` picks out only the lines containing a string.

The logs are ugly (John calls it "a nightmare"). You refine the data into something you can get statistics from, then use **R tools** to do the math and hunt for a **beacon**. The point: you *can* do it by hand, but it's brutal — hence Zeek / RITA.

## 4. Using AI on the logs — context is everything { #ai-log-analysis }

**① "Look for evil traffic" alone** → AI flags the **wrong things** (what looks like a port scan, Telnet, ACL-blocked traffic) and **misses the real malicious beacon**. Without **context** it tends to **hallucinate**.

**② Give it context** (internal/external IPs, addresses to exclude, completed connections only — the backdoor alternates between two external IPs) → it gets much closer but can still wrongly conclude "looks normal." The decisive clue is **timing**:

```text
1s, 1s, 1s, 1s, 1s …   (a full TCP connect/teardown every second)
```

> Unless it's a remote terminal or keep-alive, almost no legitimate service does a full TCP connect/teardown every second → **malicious beacon**.

R tools confirms it:

```text
min 1816, max 1848, mean 1829, stdev 12
```

A **standard deviation of 12** is tiny — the data size is near-constant, the hallmark of a **beacon**.

!!! tip "The key skill in the AI era"
    "Find evil" rarely works. You have to use what you've learned to **narrow the question**. Knowing how to analyse logs — and asking the right question — is the skill.

---

## 5. Zeek — consistent, and small { #zeek }

Because by-hand is painful, use **Zeek** (formerly Bro). It's fast, widely used, and its **timestamps are dead-consistent** (devices handle time in odd, inconsistent ways; Zeek doesn't).

This is a shift in thinking. Day 1's AV looked for **strings (assembly)** inside an executable — a signature. But traffic is **encrypted**, so there are no strings to match. Instead, the **behaviour in the logs** lets you actively **hunt**. This matters more over time because of **AI** — it can generate malware, new C2 methods and obfuscation, so humans must use AI to hunt traffic patterns.

**Zeek vs full PCAP**

| | Full PCAP | Zeek |
|---|---|---|
| Pro | all content, every tool supports it (most portable) | ~**1/10** the size |
| Con | **very large** | no raw packet content (metadata) |

Zeek doesn't compress packets — it turns them into **metadata**, about one-tenth the size.

!!! warning "Capture pre-NAT"
    Outside the firewall (internet side) every internal host looks like the **one firewall IP**, so you can't identify the infected host. Capture **pre-NAT (inside)** to get the **infected internal private IP**.

The Zeek logs themselves (`conn.log`, `dns.log`, `http.log`, `ssl.log` …) are written up under [Network → Zeek](../../../network/zeek/index.md).

## 6. What is beaconing? { #beaconing }

John's analogy: a child going "mom, mom, mom…" at a steady rhythm — that's a beacon. The infected host repeats "I'm here, give me orders" to C2 on a regular cadence. Analyse it three ways:

1. **Interval** — regular, like a heartbeat?
2. **Data size** — nearly the same each time (small standard deviation)?
3. **Connection timing** — complete/restart repeating at a tight cadence?

**Jitter** — a smart attacker deliberately **varies** the interval (e.g. 7s ±2s → random 5–9s). It isn't perfectly regular, but it still has **beacon characteristics** (a symmetric cluster around 7s). The interval doesn't have to be perfect — it just has to have beacon characteristics.

**Long connections** — instead of beaconing, an attacker can hold **one connection open** for a long time. John's spaghetti analogy: break one long strand (a long connection) into pieces (chopped-up connections), but add the pieces back up and you get the original day's worth. Chopping it up to hide still shows up **when you sum it**.

Full beacon / C2 detection notes: [Network → Beaconing & C2](../../../network/beaconing-c2.md).

## 7. RITA — the beacon-detection engine { #rita }

The math lives in **RITA (Real Intelligence Threat Analytics)** — a **free** BHIS tool, kept open-source via patents. It does two things: **find beacons** and **check deny lists** (compare against known-bad IPs — more in part 3).

**The math**

- **K-means clustering** — finds **patterns (consistency)** in data. Like a CAPTCHA teaching pattern recognition by repeatedly asking you to pick traffic lights / bicycles, it finds **clusters of consistent interval and size**.
- **MADM (median absolute deviation of the mean)** — similarly measures the consistency of the distribution.

**Beacon score** — each connection gets a **0–1 score**; closer to **1 = a more perfect beacon**. You also look at **connection count** (e.g. 108,000 connections at perfect intervals).

!!! warning "A beacon isn't always malware (legit beacons)"
    Regular beaconing isn't only malware — **TeamViewer** (staff may use it to bypass filters), **RDP**, **Nuance / Dragon** (had built-in remote control), **LAN Turtle** (a USB-to-Ethernet-shaped mini Linux). Not all malicious, but **all worth investigating**.

**Other things to look at** — **User-Agent strings** (how an internal system identifies itself), **MIME types** (what kind of data is moving — returns in part 3 as "MIME mismatch"), **JA3/JA4** (fingerprinting the TLS client hello; JA3 broke when browsers randomised the hello, so JA4 now).

**Long-tail analysis** — sort normal vs abnormal and the anomalies cluster in the **rare long tail**. Human traffic is messy and irregular; a **beacon is unusually consistent**, so it stands out in that tail.

### Is there a hands-on RITA lab? { #rita-lab-note }

**Day 2 has no standalone command-line RITA lab.** RITA is taught as the *engine*; the hands-on beacon analysis is done through **AC-Hunter's GUI**, which runs on it (part 3). So **RITA = the free command-line engine**, **AC-Hunter = the paid GUI on top** (a community edition exists). The beacon math in the first ASA-log lab used **R tools**, not RITA.

!!! note "💡 Note (added) — running RITA yourself"
    RITA is free, so you can run it against your home-lab Zeek logs (conceptual flow):

    ```bash
    # import Zeek logs into a RITA database
    rita import /opt/zeek/logs/2026-10-17 mydataset
    # show beacon analysis, highest score first
    rita show-beacons mydataset
    rita show-exploded-dns mydataset
    ```

    `rita import <zeek-log-dir> <name>` loads the logs; `rita show-beacons <name>` shows beacon scores (0–1) and connection counts. Recent RITA (v5+) is configured differently — check the docs. This is a supplement, separate from the actual course lab.

---

That's Day 2 parts 1–2. One-line summary:

> **Even when the content is encrypted, outbound behaviour (regular interval + consistent size = a beacon) reveals C2. Zeek turns traffic into consistent metadata logs (captured pre-NAT); RITA finds the beacons in those logs with math. Jitter or chopped-up connections still show up when you sum them.**

Next (parts 3–5, to be added): **AC-Hunter lab**, **ASN / deny-lists**, **UEBA**, **Deep Blue CLI** (encoding analysis), **Sysmon**.

## References

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [RITA (GitHub)](https://github.com/activecm/rita) · [AC-Hunter](https://www.activecountermeasures.com/ac-hunter/)
- Related: [Network → Zeek](../../../network/zeek/index.md) · [Beaconing & C2](../../../network/beaconing-c2.md) · [Windows Event IDs](../../../basics/windows-event-ids.md)
