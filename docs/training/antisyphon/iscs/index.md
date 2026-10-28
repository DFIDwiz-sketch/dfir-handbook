---
title: Information Security Core Skills
---

# Information Security Core Skills

<div class="dfir-meta" markdown>
**Instructor:** John Strand (Black Hills Information Security) · **By:** [Antisyphon Training](https://www.antisyphontraining.com/) · **Format:** Pay-What-You-Can, 4 days · last 30 min each day is AMA
</div>

!!! abstract "What this course is"
    A "bootstrap" security course. Across 650+ assessments a year, BHIS tracked **"what actually stopped us"** — and it kept coming back to the same ~10 controls. This course is built around those, all mapped to MITRE ATT&CK. One rule: nothing goes in that doesn't directly help stop an attacker. AI-for-defense is woven throughout.

## Controls covered

1. Application allow listing
2. Password controls
3. Egress traffic analysis
4. UEBA (AI / machine-learning user-behaviour analytics)
5. Advanced endpoint protection (EDR)
6. Logging
7. Host firewalls
8. Internet allow listing
9. Vulnerability management
10. Active Directory hardening
11. Cloud (some additions)

Backup & recovery is "something you should just be doing," so it isn't covered separately. OS basics, TCP/IP and crypto are in the sibling **SOC Core Skills** course (on YouTube).

## Day-by-day notes

<div class="grid cards" markdown>

-   **[Day 1 — Allow Listing and Password Attacks](day-1.md)**

    ---

    Compliance (CIS mapping), application allow listing and AppLocker, AV-bypass theory (ghostwriting, LOLBins), password spraying, MFA gaps, Kerberoasting, network credential interception, password cracking (Hashcat).

-   **[Day 2 — Egress Traffic Analysis and Logging](day-2.md)**

    ---

    Egress traffic analysis, NetFlow, manual firewall-log analysis, using AI on logs, Zeek, beaconing / jitter / long connections, RITA, ASN deny-lists, the AC-Hunter lab, UEBA, Deep Blue CLI, Windows logging limits and Sysmon.

-   **[Day 3 — EDR, Threat Emulation and Host Firewalls](day-3.md)**

    ---

    Sysmon lab review, Pass-the-Hash, EDR and defence in depth (why overlap multiplies), threat emulation and Atomic Red Team, writing and validating detections with AI, BloodHound, gap-analysis lab, host firewalls and stopping lateral movement.

-   **[Day 4 — Responder, Internet Allow Listing, Vulnerability Management, Web Security and AD Hardening](day-4.md)**

    ---

    Responder lab walkthrough (deep dives on NTLMv2 cracking, relay and SMB signing), internet allow listing (block "Uncategorized", remove ads, DoH), vulnerability management (CVSS +1, lows and informationals, group by vulnerability), the Nessus report lab, web application security (SAST and DAST, Burp and ZAP, testing detective controls), the ZAP lab, AD hardening (BloodHound and PlumHound, moving staircases, Mimikatz and how to detect it), the Ping Castle lab, and the course wrap-up with a recap of all ten controls.

</div>
