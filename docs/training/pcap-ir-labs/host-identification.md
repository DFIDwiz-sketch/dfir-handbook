---
title: "2 — Identifying Hosts"
tags:
  - training
  - incident-response
  - dhcp
  - kerberos
  - fingerprinting
---

# 2 — Identifying Hosts { #host-identification }

!!! abstract "Scope of this page"
    - Finding the infected host from alerts and downloads
    - IP, MAC, hostname and Windows user account
    - Finding the Domain Controller and counting active hosts
    - Fingerprinting devices (Ubuntu, Android, Amazon Fire, Apple, smart TVs) and the operating system
    - Key network information (IP range, gateway, domain) and the host's public IP

## Finding the infected host { #infected-host }

The infected host is the internal IP that appears in the malware alerts **and** received the suspicious file. Check both and make sure they point to the same address.

```bash
grep -oE "\{(TCP|UDP)\} [0-9.]+:[0-9]+ -> [0-9.]+:[0-9]+" snort_out/alert | grep -oE "(10|172|192)\.[0-9.]+" | sort | uniq -c | sort -rn | head
zeek-cut -u ts id.orig_h host uri resp_mime_types < zeek_out/http.log | grep -i -E "dosexec|msword|officedocument|ms-office"
```

- Line 1: take `{TCP} source -> destination` from each alert, keep the private-looking addresses, count them. (The regex also matches some public ranges such as `172.217.x.x`, so read the list, do not trust it blindly.)
- Line 2: who requested something that came back as a Windows executable (`application/x-dosexec`) or a Word document. `id.orig_h` is the requester.

```text
     57 172.xx.xx.xx
2019-xx-xxTxx:xx:xx  172.xx.xx.xx  <site>  /<path>/<file>.doc  application/msword
```

Wireshark: **Statistics → Endpoints → IPv4** for the internal addresses, then **File → Export Objects → HTTP**; click a suspicious file's **Packet** number and read the Destination column (the response goes *to* the client). The filter `http.response && http.file_data contains "This program cannot be run in DOS mode"` jumps straight to responses that carry a Windows executable.

## IP, MAC and hostname { #ip-mac-hostname }

DHCP gives IP, MAC and hostname together, so start there. If there is no DHCP in the capture, use the host's own packets and its name announcements.

```bash
zeek-cut client_addr mac host_name < zeek_out/dhcp.log | sort -u
tshark -r case.pcap -Y "dhcp" -T fields -e ip.src -e eth.src -e dhcp.option.hostname -e dhcp.option.vendor_class_id | sort -u
tshark -r case.pcap -Y "ip.src==<infected IP>" -T fields -e eth.src | sort -u
tshark -r case.pcap -Y "(nbns || mdns || llmnr) && ip.src==<infected IP>" -T fields -e nbns.name -e dns.qry.name | sort -u
```

- Lines 1–2: DHCP records. In older Wireshark, use `bootp` instead of `dhcp`.
- Line 3: the MAC address on the host's own packets.
- Line 4: names the host announces: NBNS/LLMNR on Windows (`DESKTOP-XXXX<00>`), mDNS on Apple/Linux/Android (`<name>.local`).
- A Kerberos computer account ending in `$` (next section) is another reliable hostname source.

Wireshark:

1. Filter `dhcp` → click a **Request** → expand **Dynamic Host Configuration Protocol** → right-click **Option (12) Host Name** → **Apply as Column**; do the same for **Option (60) Vendor class identifier**.
2. Filter `ip.src==<infected IP>` → **Ethernet II → Source** is the MAC.
3. Filter `nbns` → the Info column shows `Registration NB <NAME><00>`.

## Windows user account { #user-account }

When a Windows PC logs on to the domain, Kerberos carries the name that logged on. Names ending in `$` are **computer** accounts; names without `$` are **user** accounts.

```bash
tshark -r case.pcap -Y "kerberos.CNameString && ip.src==<infected IP>" -T fields -e kerberos.CNameString -e kerberos.crealm | sort | uniq -c
zeek-cut id.orig_h client < zeek_out/kerberos.log | sort -u
```

```text
      8 DESKTOP-XXXXXXX$   EXAMPLE.LOCAL     ← computer account (hostname)
      5 <username>         EXAMPLE.LOCAL     ← user account
```

Wireshark: filter `kerberos.CNameString && !(kerberos.CNameString contains "$")` → expand **Kerberos → as-req → req-body → cname → cname-string → CNameString** → **Apply as Column**. `!` means "not", so only user names remain. Write the name exactly as it appears, including case.

## Finding the Domain Controller { #domain-controller }

A DC answers Kerberos (88), LDAP (389), DNS (53) and SMB (445). Count which IP receives Kerberos and LDAP requests.

```bash
tshark -r case.pcap -Y "tcp.dstport==88 || udp.dstport==88 || tcp.dstport==389 || udp.dstport==389" -T fields -e ip.dst | sort | uniq -c | sort -rn
zeek-cut id.orig_h id.resp_h service < zeek_out/kerberos.log | sort -u | head
```

- Line 1 usually shows one IP: the DC.
- Line 2: the `service` column shows `krbtgt/<DOMAIN>` and `LDAP/<dc-name>.<domain>`, which also gives the DC's hostname.

Wireshark: apply the line-1 filter → **Statistics → Endpoints → IPv4** with **Limit to display filter** → sort by **Rx Packets**. For the DC name, filter `kerberos`, click a `TGS-REQ` and expand **req-body → sname**.

## Active hosts on the LAN { #active-hosts }

"Active" means an internal IP that **started** connections.

```bash
zeek-cut id.orig_h < zeek_out/conn.log | grep '^172\.16\.' | sort | uniq -c | sort -rn
tshark -r case.pcap -q -z endpoints,ip | grep "172.16."
```

- Adjust the prefix to the lab's subnet. `\.` means a literal dot.
- Remove from the count: the DC (if the question says "besides the DC"), the broadcast address (`.255`), and multicast addresses (`224.x`, `239.255.255.250`). The default gateway usually appears only in ARP, not as an IP talker.

Wireshark: filter `ip.src==172.16.0.0/12` (or the lab's range) → **Statistics → Endpoints → IPv4** → **Limit to display filter** → IPs with **Tx Packets** above zero.

## Fingerprinting devices { #device-fingerprinting }

To say what a device is, combine three clues. One clue alone can mislead.

| Clue | How to get it | What it tells you |
| --- | --- | --- |
| MAC vendor (first 3 bytes, OUI) | `-e eth.src -e eth.src_resolved`; **Statistics → Endpoints → Ethernet** with **Name resolution** | Manufacturer: Apple, Samsung, Amazon Technologies… |
| DHCP vendor class (option 60) and hostname (option 12) | DHCP commands above | `MSFT 5.0` = Windows, `android-dhcp-8.0.0` = Android 8.0.0, `dhcpcd-…` = Linux |
| DNS queries and HTTP User-Agent | commands below | What services it talks to and what software it runs |

```bash
zeek-cut id.orig_h query < zeek_out/dns.log | awk '$1=="<IP>"' | sort | uniq -c | sort -rn | head -30
zeek-cut id.orig_h host user_agent < zeek_out/http.log | awk -F'\t' '$1=="<IP>"' | sort -u
zeek-cut host software_type name unparsed_version < zeek_out/software.log | sort -u
tshark -r case.pcap -Y 'ip.src==<IP> && (mdns || ssdp)' -V | grep -i -E "server:|\.local|_tcp" | sort -u | head -40
```

- `awk -F'\t'`: split on tabs, because User-Agent strings contain spaces.
- `software.log`: Zeek's summary of software seen in User-Agents and banners.
- Last line: TVs, streaming sticks and printers announce themselves over mDNS and SSDP. The SSDP `SERVER:` header and mDNS service names (`_googlecast._tcp.local`, `_airplay._tcp.local`) name the device type.

Typical signs:

- **Ubuntu**: DNS to `connectivity-check.ubuntu.com`, `ntp.ubuntu.com`, `api.snapcraft.io`, `archive/security.ubuntu.com`; User-Agent containing `Ubuntu`.
- **Android**: `connectivitycheck.gstatic.com`, `android.clients.google.com`; User-Agent `Dalvik/2.1.0 (Linux; U; Android 8.0.0; <model code> Build/<build>)`. The model code (for example one starting `SM-` for Samsung) gives brand and model when you search it.
- **Amazon Fire tablet**: many `amazon` domains, User-Agent containing `Silk` or a model code starting `KF`, MAC vendor Amazon Technologies. Echo speakers also talk to Amazon, so check User-Agent and MAC too.
- **Apple**: `apple.com`, `icloud.com`, `push.apple.com`; User-Agent `iPhone` or `Macintosh`.

Wireshark filters: `dns.qry.name contains "ubuntu"`, `http.user_agent contains "Android 8.0.0"`, `dns.qry.name contains "amazon" || http.user_agent contains "Silk"`, `ip.src==<IP> && dns.flags.response==0` (the host's DNS questions only).

## Operating system { #operating-system }

When the question does not say the host is Windows, collect two or three pieces of evidence for the OS.

```bash
tshark -r case.pcap -Y "ip.src==<IP>" -T fields -e ip.ttl | sort | uniq -c
tshark -r case.pcap -Y "ntlmssp.version.major && ip.src==<IP>" -T fields -e ntlmssp.version.major -e ntlmssp.version.minor -e ntlmssp.version.build_number | sort -u
tshark -r case.pcap -Y "smb.native_os && ip.src==<IP>" -T fields -e smb.native_os | sort -u
tshark -r case.pcap -Y "ssh.protocol" -T fields -e ip.src -e ssh.protocol | sort -u
p0f -r case.pcap -o p0f.log && grep "<IP>" p0f.log | grep os=
```

- **TTL**: starting values differ by OS. Windows usually starts at 128, Linux/macOS/Android at 64. Captured on the same LAN, you see the starting value.
- **NTLMSSP version**: NTLM authentication carries the Windows version. `10 0 19045` = Windows 10 22H2, `6 1 7601` = Windows 7 SP1.
- **smb.native_os**: SMB1 hosts announce their OS name.
- **SSH banner**: may include `Ubuntu` or `Debian`.
- **User-Agent**: `Windows NT 10.0` = Windows 10/11, `Windows NT 6.1` = Windows 7, `X11; Linux x86_64` = Linux.
- **p0f**: passive OS fingerprinting from TCP SYN packets.

Wireshark: add **Internet Protocol → Time to Live** as a column; filter `ntlmssp.version.major` and expand **NTLM Secure Service Provider → Version**.

## Key network information { #network-info }

DHCP ACKs and Kerberos describe the network itself.

```bash
tshark -r case.pcap -Y "dhcp.option.dhcp == 5" -T fields -e dhcp.option.subnet_mask -e dhcp.option.router -e dhcp.option.domain_name_server -e dhcp.option.domain_name | sort -u
tshark -r case.pcap -Y "kerberos" -T fields -e kerberos.realm -e kerberos.crealm | tr '\t' '\n' | sort -u
tshark -r case.pcap -Y 'dns.qry.name contains "_msdcs"' -T fields -e ip.src -e dns.qry.name | sort -u
```

- `dhcp.option.dhcp == 5`: DHCP ACK only. Subnet mask `255.255.255.0` = a /24; router = default gateway; DNS server is usually the DC; domain name.
- Kerberos realm = the AD domain.
- `_ldap._tcp.dc._msdcs.<domain>`: Windows clients looking for the DC also reveal the domain.

Wireshark: filter `dhcp.option.dhcp == 5` and read options (1) Subnet Mask, (3) Router, (6) Domain Name Server, (15) Domain Name; filter `kerberos`, open an **AS-REQ** and read **req-body → realm**. Use the [network information template](report-templates.md#network-info-template) for the answer.

## Public IP { #public-ip }

The host uses a private IP inside; the firewall or router translates it (NAT) to a public IP. A capture taken inside never shows the public IP in packet headers. But malware often asks an "what is my IP" service right after infection, and the **response body** contains the answer.

```bash
zeek-cut -u ts id.orig_h host uri < zeek_out/http.log | grep -i -E "ip|myip|whatismy|ifconfig"
zeek-cut -u ts query answers < zeek_out/dns.log | grep -i -E "ipify|checkip|ip-api|icanhazip|myexternalip|ipinfo|wtfismyip|ifconfig"
tshark -r case.pcap -Y 'http.response && http.response_for.uri contains "<ip-check domain>"' -T fields -e frame.number -e http.file_data
```

- `http.file_data`: the HTTP response body, for example `x.x.x.x` or `{"ip":"x.x.x.x"}`. If it prints as hex, append `| xxd -r -p`.
- If the IP check used HTTPS, the body is encrypted. Look for the IP inside other plaintext traffic (for example a C2 POST), or state that it cannot be determined from the PCAP and why.

Wireshark: filter `http.host contains "ip" || dns.qry.name contains "ip"` → right-click the request → **Follow → HTTP Stream** → the blue (server) body shows the IP. Or open **Line-based text data** / **JavaScript Object Notation** in Packet Details.

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
