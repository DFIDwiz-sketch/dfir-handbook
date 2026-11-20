---
title: Blue Team Essentials
tags:
  - training
  - blue-team
---

# Blue Team Essentials

!!! abstract "What this section is"
    The data a SOC analyst looks at every day (DNS, HTTP, email, endpoint logs, …), each explained as **why it matters → what it is → what it actually looks like → when a SOC uses it**. Anything that changed recently is marked **[Changed]**, anything that is commonly stated wrongly or is risky if done the old way is marked **[Caution]** / **[Correction]**, and practical must-knows are marked **[Added]**.

## Topics

<div class="grid cards" markdown>

-   :material-dns:{ .lg .middle } **DNS**

    ---

    DNS structure and record types, log collection and safe investigation, domain signals, unauthorised DNS, tunnelling, blockchain DNS, IDNs, encrypted DNS, and a suspicious-DNS triage sheet.

    [:octicons-arrow-right-24: DNS](dns/index.md)

-   :material-web:{ .lg .middle } **HTTP**

    ---

    Web servers and web shells, URL anatomy and phishing tricks, GET/POST and what gets logged, the other methods (CONNECT, HEAD, OPTIONS, PUT, DELETE, TRACE), reading request headers, judging real malicious requests (exploit kits, URLs inside URLs), response headers and status codes, new standards (HTTP/2, HTTP/3/QUIC, WebSocket), and practice questions with answers.

    [:octicons-arrow-right-24: HTTP](http/index.md)

-   :material-shield-search:{ .lg .middle } **HTTP(S) Analysis & Attacks**

    ---

    Attack stages over HTTP, choosing automated vs manual analysis, URL reputation and OPSEC, with phishing checks, sandboxing, header and content analysis, file extraction and HTTPS analysis to follow.

    [:octicons-arrow-right-24: HTTP(S) Analysis & Attacks](http-analysis/index.md)

-   :material-email-search:{ .lg .middle } **SMTP & Email**

    ---

    The servers mail passes through (MUA, MTA, MDA) and their ports, SMTP conversations and envelope vs header addresses, reading headers, SPF results, DKIM signatures, DMARC alignment, policies and reports, and a triage checklist.

    [:octicons-arrow-right-24: SMTP & Email](email/index.md)

-   :material-lan:{ .lg .middle } **Additional Network Protocols**

    ---

    DHCP for turning an IP into a device and finding rogue devices, then SMB, SSH, RDP/VNC, PowerShell remoting, FTP, ICMP and remote-access tools used for lateral movement and exfiltration, plus why no protocol is "safe" and a summary of the network part.

    [:octicons-arrow-right-24: Additional Network Protocols](other-protocols/index.md)

-   :material-laptop-account:{ .lg .middle } **Endpoint Attacks**

    ---

    What happens on the host after delivery: why the endpoint sees more than the network, initial exploitation (service-side vs client-side) and the evidence each leaves, then execution, persistence, discovery, privilege escalation, credential dumping, lateral movement, collection and exfiltration.

    [:octicons-arrow-right-24: Endpoint Attacks](endpoint-attacks/index.md)

-   :material-shield-lock:{ .lg .middle } **Endpoint Defense**

    ---

    Defence in depth on the host, stage by stage: software inventory and network scanning, continuous vulnerability scanning and patching, exploit protection and ASR rules, Credential Guard, host firewalls and antivirus, application control, FIM and persistence hunting, PAWs, permissions and privileges, EDR, DLP, UEBA and audit policy.

    [:octicons-arrow-right-24: Endpoint Defense](endpoint-defense/index.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows Logging**

    ---

    How Windows produces events: providers, the Event Log service, channels and `.evtx` files, audit policies, Sysmon and custom channels, event metadata (level, provider, event ID, task category, keywords), the General, Friendly and XML views of one event, the System vs EventData/UserData parts field by field, templates and descriptions, and the channels a SOC should collect.

    [:octicons-arrow-right-24: Windows Logging](windows-logging/index.md)

-   :material-linux:{ .lg .middle } **Linux Logging**

    ---

    How Linux and appliances log: the three meanings of "syslog" (format, daemon, network protocol), the RFC 3164 and RFC 5424 headers, free-text parsing, UDP/TCP/TLS transport, rsyslog and syslog-ng configuration, facility, severity and the PRI value, then the log files under `/var/log`, the systemd journal and command-line logging.

    [:octicons-arrow-right-24: Linux Logging](linux-logging/index.md)

</div>

!!! info "Next topic"
    The network part is complete (DNS, HTTP, HTTP(S) analysis, email, additional protocols). On the host part, endpoint attacks, endpoint defence, Windows logging and Linux logging are complete; next come important events, the log pipeline and file analysis.

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
