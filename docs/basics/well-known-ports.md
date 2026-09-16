---
title: Well-Known Ports
tags:
  - concept
  - basics
  - network
---

# Well-Known Ports

<div class="dfir-meta" markdown>
**Category:** basics · **Last updated:** 2026-09-09
</div>

!!! abstract "In one sentence"
    Port numbers hint at the service — but attackers know that too, so always confirm with protocol analysis (Zeek `service` field, Wireshark dissector) rather than trusting the port alone.

## Ranges

| Range | Name | Notes |
|---|---|---|
| 0 – 1023 | Well-known / system | Usually needs root/admin to bind |
| 1024 – 49151 | Registered | Vendor-registered with IANA |
| 49152 – 65535 | Dynamic / ephemeral | Client-side source ports. Windows uses 49152–65535, older Linux 32768–60999 |

## Core services

| Port | Proto | Service | DFIR notes |
|---|---|---|---|
| 20 / 21 | TCP | FTP data / control | Cleartext creds. Passive mode uses high ports |
| 22 | TCP | SSH | Also SFTP/SCP. Check `auth.log` for brute force |
| 23 | TCP | Telnet | Cleartext; still common on IoT/OT |
| 25 | TCP | SMTP | Server-to-server mail. Spam/phish source |
| 53 | UDP/TCP | DNS | TCP for large responses/zone transfers. Watch for tunnelling (long TXT, high entropy subdomains) |
| 67 / 68 | UDP | DHCP server / client | Ties IP ↔ MAC ↔ hostname over time |
| 69 | UDP | TFTP | No auth. Used for firmware, malware staging |
| 80 | TCP | HTTP | Cleartext web |
| 88 | TCP/UDP | Kerberos | Domain auth. Kerberoasting shows as TGS-REQ with RC4 (etype 23) |
| 110 | TCP | POP3 | Legacy mail retrieval |
| 111 | TCP/UDP | RPCbind / portmapper | NFS discovery |
| 123 | UDP | NTP | Time sync — matters for timeline correlation |
| 135 | TCP | MS-RPC endpoint mapper | WMI, DCOM, PsExec-style lateral movement |
| 137 / 138 | UDP | NetBIOS name / datagram | Legacy name resolution; LLMNR/NBT-NS poisoning |
| 139 | TCP | NetBIOS session (SMB over NetBIOS) | Legacy SMB |
| 143 | TCP | IMAP | Mail retrieval |
| 161 / 162 | UDP | SNMP / traps | `public` community string = free recon |
| 389 | TCP/UDP | LDAP | AD queries. BloodHound-style enumeration is heavy 389 traffic |
| 443 | TCP | HTTPS | Also QUIC on UDP 443. Use JA3/JA4, SNI, cert details |
| 445 | TCP | SMB (direct) | File shares, PsExec, lateral movement, ransomware spread |
| 464 | TCP/UDP | Kerberos password change | |
| 465 / 587 | TCP | SMTPS / SMTP submission | Client mail sending |
| 514 | UDP | Syslog | Cleartext; TCP 6514 for TLS |
| 515 | TCP | LPD printing | |
| 548 | TCP | AFP | macOS file sharing |
| 587 | TCP | SMTP submission | Authenticated client mail |
| 636 | TCP | LDAPS | |
| 993 / 995 | TCP | IMAPS / POP3S | |
| 1433 / 1434 | TCP / UDP | MS SQL Server / browser | |
| 1521 | TCP | Oracle DB | |
| 1723 | TCP | PPTP VPN | Weak; also GRE (proto 47) |
| 2049 | TCP/UDP | NFS | |
| 3268 / 3269 | TCP | LDAP Global Catalog / GC-SSL | |
| 3306 | TCP | MySQL / MariaDB | |
| 3389 | TCP/UDP | RDP | Brute force, lateral movement. Correlate with 4624 type 10, 4778/4779, TerminalServices logs |
| 5060 / 5061 | UDP/TCP | SIP / SIP-TLS | VoIP |
| 5432 | TCP | PostgreSQL | |
| 5900+ | TCP | VNC | Often weak/no auth |
| 5985 / 5986 | TCP | WinRM HTTP / HTTPS | PowerShell Remoting. Event 4688 `wsmprovhost.exe` on target |
| 6379 | TCP | Redis | Frequently exposed with no auth |
| 8080 / 8443 | TCP | HTTP alt / HTTPS alt | Proxies, dev servers, C2 |
| 9200 / 9300 | TCP | Elasticsearch | |
| 27017 | TCP | MongoDB | |

## Ports attackers love (default C2 / tooling)

These are **defaults** — anything can be reconfigured. Treat as "worth a look", not proof.

| Port | Associated with |
|---|---|
| 4444 | Metasploit default listener |
| 1080 | SOCKS proxy (Chisel, ssh -D, Cobalt Strike SOCKS) |
| 50050 | Cobalt Strike team server (operator ↔ server, not beacon) |
| 8443 / 443 / 80 | Most modern C2 (Cobalt Strike, Sliver, Mythic, Havoc) blend in here |
| 8000 / 8080 | Python `http.server`, staging servers |
| 3128 | Squid proxy |
| 5555 | Android ADB |
| 6667 / 6697 | IRC (old-school botnets) |
| 31337 | Back Orifice / "elite" — nostalgia, still seen in CTFs |

## IP protocol numbers (not ports, but often confused)

| Number | Protocol |
|---|---|
| 1 | ICMP |
| 2 | IGMP |
| 6 | TCP |
| 17 | UDP |
| 41 | IPv6 encapsulation |
| 47 | GRE |
| 50 | ESP (IPsec) |
| 51 | AH (IPsec) |
| 58 | ICMPv6 |
| 89 | OSPF |
| 132 | SCTP |

## Quick lookups

=== "Linux"

    ```bash
    grep -w 445 /etc/services
    ss -tulpn            # what is listening now
    ```

=== "Windows"

    ```powershell
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort
    netstat -anob        # -b shows the owning binary (admin)
    ```

=== "Zeek"

    ```bash
    # Which services were actually seen on port 443? (should be ssl; anything else is odd)
    zeek-cut id.resp_p service < conn.log | awk '$1==443' | sort | uniq -c | sort -rn
    ```

## References

- [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
- [SANS TCP/IP and tcpdump cheat sheet](https://www.sans.org/posters/tcp-ip-and-tcpdump/)
