---
title: Additional Network Protocols
tags:
  - training
  - blue-team
  - network
---

# Additional Network Protocols { #other-protocols }

!!! abstract "In one line"
    After getting in through email, HTTP or DNS, attackers move sideways and move data out using the same everyday protocols administrators use. This section covers DHCP (the record that turns an IP into a device), then SMB, SSH, RDP/VNC, PowerShell remoting, FTP, ICMP and remote-access tools — what normal looks like, how each is abused, and what to look for.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [DHCP — Protocols to Watch, Turning an IP into a Device, Finding Rogue Devices, DORA Step by Step](dhcp.md) | Why these protocols are grouped (lateral movement, exfiltration); IP → host/MAC → user and why the lease time matters; 4624 and 4768 for the last link; the Windows DHCP audit log field by field (IDs 10/11/12, vendor class, option 82); `Get-DhcpServerv4Lease`; Zeek `dhcp.log`; rogue devices by hostname scheme and MAC OUI; the locally administered bit; why self-reported values can be faked; DORA packet by packet, renewal T1/T2, relays; rogue DHCP servers, starvation, DHCPv6 (mitm6), TunnelVision; practice questions |

!!! info "Coming next"
    SMB (versions and typical attacks), SSH and inbound tunnelling over outbound SSH, RDP/VNC, PowerShell remoting, FTP, malicious ICMP, and any remote access or administration tool.

## Things to remember { #must-know }

1. Ask not "is this protocol bad?" but "is it normal on this device, to this peer, at this time?"
2. An IP is leased. Always map it to a device using the lease that covers the alert time.
3. DHCP logs record hostname, IP and MAC — the network's attendance register — but hostname and MAC are self-reported.
4. A MAC whose second hex digit is 2, 6, A or E is locally administered: there is no OUI to look up.
5. DHCP has no authentication. Watch for DHCP servers you didn't approve, and use DHCP snooping.

## Related references { #related }

- [Identifying hosts in a packet capture](../../pcap-ir-labs/host-identification.md) — DHCP, hostname and MAC from a pcap
- [Well-known ports](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [LLMNR and NTLM relay](../../../adversary/llmnr-ntlm-relay.md)
