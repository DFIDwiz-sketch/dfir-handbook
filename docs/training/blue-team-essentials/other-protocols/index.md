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
| 2 | [SMB — Why Attackers Love It, Versions and Negotiation, Typical Attacks](smb.md) | Ports 445/139 and admin shares (`C$`, `ADMIN$`, `IPC$`); why admin credentials = remote execution (the manual `net use`/`sc` version of PsExec); the shared local admin password problem and worms; dialects 1 → 3.1.1 and NEGOTIATE in tshark; `Get-SmbConnection`, SMB1 checks and SMB1 access auditing; why SMB1 must go and why not to disable "SMB2"; credential-based vs exploit-based attacks; a PsExec hop in 4624/4672/5140/5145/7045/4688 and Sysmon 1/3; Zeek `smb_mapping`/`smb_files`/`dce_rpc` (`svcctl CreateServiceW`); exploit signals; defences; Windows 11 24H2/Server 2025 defaults; practice questions |
| 3 | [SSH, Inbound Tunnelling over Outbound SSH, RDP and VNC](ssh-rdp-vnc.md) | Why SSH is both friend and threat; reading `auth.log` and Zeek `ssh.log`; the four tunnelling tricks (`scp` exfiltration, `-R` remote forwarding, `-L`/`-D` through a dual-homed jump box, X11) flag by flag; `sshd_config` lock-down; `ssh.exe` built into Windows; outbound SSH = inbound RDP: the plink `-R 12345:127.0.0.1:3389` command, Sysmon 1/3, `service=ssh` on 443, 4624 type 10 / 1149 / 21–25 from `127.0.0.1`; RDP prevention and monitoring (event table incl. 4778/4779, RDPClient 1024); VNC/RFB banner and weak auth; OpenSSH 10, tunnelling services, `.rdp` phishing protections; practice questions |

!!! info "Coming next"
    PowerShell remoting, FTP, malicious ICMP, and any remote access or administration tool.

## Things to remember { #must-know }

1. Ask not "is this protocol bad?" but "is it normal on this device, to this peer, at this time?"
2. An IP is leased. Always map it to a device using the lease that covers the alert time.
3. DHCP logs record hostname, IP and MAC — the network's attendance register — but hostname and MAC are self-reported.
4. A MAC whose second hex digit is 2, 6, A or E is locally administered: there is no OUI to look up.
5. DHCP has no authentication. Watch for DHCP servers you didn't approve, and use DHCP snooping.
6. With admin credentials, SMB is remote execution. Unique local admin passwords (LAPS) and no 445 between workstations break most lateral movement.
7. 4624 type 3 + 4672 + `ADMIN$` access + 7045 new service = the PsExec pattern, whatever the service is called.
8. Outbound SSH to anywhere = inbound access for an attacker. An RDP logon from `127.0.0.1` or `::1` means a tunnel.

## Related references { #related }

- [Identifying hosts in a packet capture](../../pcap-ir-labs/host-identification.md) — DHCP, hostname and MAC from a pcap
- [Well-known ports](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [LLMNR and NTLM relay](../../../adversary/llmnr-ntlm-relay.md)
