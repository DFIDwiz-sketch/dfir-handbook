---
title: Home
hide:
  - navigation
  - toc
---

# DFIR Handbook

Personal reference for digital forensics and incident response — everything I have studied, in one searchable place. From the fundamentals (ports, status codes, event IDs) through host and network artifacts, to adversary techniques and how to detect them.

Use the **search bar** (press ++slash++ or ++s++) — it is usually faster than browsing.

<div class="grid cards" markdown>

-   :material-book-open-variant:{ .lg .middle } **Basics**

    ---

    Well-known ports, HTTP status codes, Windows Event IDs, encodings — the tables you look up over and over.

    [:octicons-arrow-right-24: Basics](basics/index.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows**

    ---

    Registry, Prefetch, Amcache, Shimcache, event logs, $MFT, USN journal, LNK, Jump Lists, SRUM …

    [:octicons-arrow-right-24: Windows](windows/index.md)

-   :material-linux:{ .lg .middle } **Linux**

    ---

    Auth logs, shell history, cron, systemd, ext4 timestamps, journald.

    [:octicons-arrow-right-24: Linux](linux/index.md)

-   :material-lan:{ .lg .middle } **Network**

    ---

    Zeek logs, pcap analysis, NetFlow, DNS/HTTP/TLS forensics, proxy and firewall logs.

    [:octicons-arrow-right-24: Network](network/index.md)

-   :material-memory:{ .lg .middle } **Memory**

    ---

    Acquisition, Volatility 3 plugins, process/injection/credential analysis.

    [:octicons-arrow-right-24: Memory](memory/index.md)

-   :material-magnify-scan:{ .lg .middle } **Splunk**

    ---

    SPL cheat sheet, useful searches, BOTS write-ups, data model notes.

    [:octicons-arrow-right-24: Splunk](splunk/index.md)

-   :material-sword-cross:{ .lg .middle } **Adversary**

    ---

    Attack techniques mapped to ATT&CK — how they work, what they leave behind, how to detect them.

    [:octicons-arrow-right-24: Adversary](adversary/index.md)

-   :material-account-search:{ .lg .middle } **Threat Intel**

    ---

    Who is behind the techniques — North Korean groups (Lazarus, APT38, TraderTraitor, Kimsuky), major incidents, TTPs and hunts.

    [:octicons-arrow-right-24: Threat Intel](threat-intel/index.md)

-   :material-radar:{ .lg .middle } **Pentesting**

    ---

    Offensive-side notes from HTB CPTS study — recon first (Nmap), more to come. Each page links back to what it leaves in the logs.

    [:octicons-arrow-right-24: Pentesting](pentesting/index.md)

-   :material-toolbox:{ .lg .middle } **Tools**

    ---

    Cheat sheets for KAPE, Velociraptor, Eric Zimmerman tools, Plaso, Wireshark, tshark and friends.

    [:octicons-arrow-right-24: Tools](tools/index.md)

-   :material-clipboard-list:{ .lg .middle } **Playbooks**

    ---

    Step-by-step response procedures for common scenarios.

    [:octicons-arrow-right-24: Playbooks](playbooks/index.md)

-   :material-school:{ .lg .middle } **Learning**

    ---

    Roadmap, the one-technique-a-week purple-team loop, a 24-month curriculum and training resources.

    [:octicons-arrow-right-24: Learning](learning/index.md)

</div>

---

!!! quote ""
    *"Absence of evidence is not evidence of absence."* — but do check whether the log source was actually enabled.
