---
title: "6 — Report Answer Templates"
tags:
  - training
  - incident-response
  - reporting
---

# 6 — Report Answer Templates { #report-templates }

!!! abstract "How to use these"
    Every lab ends with "explain this compromise (keep it short and to the point)", and several ask for facts in a fixed shape. Replace only the parts in angle brackets (`< >`) with your real values. Name a malware family only when a Snort alert or hash lookup confirms it. Delete clauses that do not apply rather than guessing.

## Compromise summaries { #compromise-templates }

Pick the variant that matches the lab, then trim.

### Generic infection { #generic-template }

> At <time> UTC, Windows host <hostname> (<IP>, <MAC>), used by <username>, downloaded <file> from <URL> (<size> bytes; SHA256 <hash>). IDS alerts and hash lookups identify it as <family> (<type>). The host then <contacted <C2 IP/domain> / showed no further malicious traffic in the capture>. The host should be isolated and reimaged, the URL and C2 blocked, and the user's credentials reset.

### Malicious Word document (macro downloader) { #macro-template }

> At <time> UTC, user <username> on Windows client <hostname> (<IP>, <MAC>) in the <domain> domain downloaded a malicious Word document (SHA256 <hash>) from <URL>. When opened, its auto-executing VBA macro downloaded <family / second-stage malware> from <URL>. The host then checked its public IP (<public IP>) via <service> and began C2 traffic to <C2 IP/domain>. The host should be isolated and reimaged, the URLs and C2 blocked, and the user's credentials reset.

### Two families (e.g. a loader followed by a banking trojan) { #two-families-template }

> Windows host <hostname> (<IP>) downloaded a malicious file from <domain> at <time> UTC and was infected with <family A>. The host sent repeated HTTP POST beacons to <family A> C2 at <C2 IP:port>. <Family A> then installed <family B>, which communicated with its C2 over HTTPS at <domain>. No signs of infection were found on the other devices (<list>).

### Spread to the Domain Controller { #dc-template }

> At <time> UTC, user <username> on Windows client <hostname> (<IP>, <MAC>) downloaded a malicious <Word document / EXE> from <URL> and was infected with <family A>. The client then downloaded further executables disguised as image files (<names>), identified as <family B>. At <time> UTC, the client copied <file> to the Domain Controller (<DC IP>, <DC hostname>) over SMB and executed it, spreading <family> to the DC. Both hosts should be isolated and reimaged, and the affected credentials reset.

### Delivery via exploit kit, link or email { #delivery-template }

> At <time> UTC, Windows host <hostname> (<IP>, <MAC>), used by <username>, was infected via <delivery method>. <Delivery sentence>. The payload (SHA256 <hash>) was identified by IDS alerts as <family / type>. After infection, the host began post-infection (C2) traffic to <C2 IP> (<C2 domain>) over <protocol/port>. The host should be isolated and reimaged, the C2 IP and domain blocked, and the user's credentials reset.

Delivery sentence:

- Exploit kit: `The user visited a compromised website, <site>, which redirected the browser to the <EK name> exploit kit at <EK IP>; the EK exploited the browser and delivered the payload.`
- Link download: `The user opened a link, likely from a malicious email, that downloaded <file> from <server IP> (<domain>).`
- Email attachment: `The user received a malicious email from <sender> with the attachment <file>, which installed the malware when opened.`

### Downloads, direction and tool { #direction-template }

> At <time> UTC, host <hostname> (<IP>, <MAC>), running <OS>, downloaded <N> item(s) of concern: <file 1> from <URL/IP 1> and <file 2> from <URL/IP 2>. The downloads were started with <tool, e.g. PowerShell Invoke-WebRequest>, identified from <User-Agent / commands seen in a plaintext shell session>. The malicious communications were with <external/internal> address <IP>, and the connection was initiated by <the compromised host / the remote host>. After the downloads, the host <began beaconing to / scanned / transferred data to> <IP/domain>. The host should be isolated and the files and IPs blocked as IOCs.

### Multiple executables and a failed DC attempt { #multi-exe-template }

> Windows host <hostname> (<IP>, <MAC>), used by <username>, was infected with <family/families>. Starting at <time> UTC, the host downloaded six Windows executables over HTTP from <domains/IPs>, including files disguised as <e.g. images>. The host then <C2 activity>, and at <time> UTC attempted <what was attempted> against the Domain Controller (<DC IP>) over SMB (TCP 445), which failed (<evidence>). The host should be isolated and reimaged, the IOCs blocked, and the DC checked and patched (e.g. MS17-010) if applicable.

## Key network information { #network-info-template }

```text
LAN segment range:     172.xx.xx.0/24 (172.xx.xx.0 - 172.xx.xx.255)
Default gateway:       172.xx.xx.1
Domain:                <domain>
Domain Controller:     172.xx.xx.xx - <DC hostname>
Infected client:       172.xx.xx.xx - <hostname> - <MAC> - <user>
Public IP (NAT):       x.x.x.x
```

## Download key information { #download-template }

```text
Time (UTC):     20xx-xx-xx xx:xx:xx
Source:         <infected IP>:<src port>
Destination:    <server IP>:<dst port>
Protocol:       TCP / HTTP - GET http://<host>/<uri> (200 OK, application/x-dosexec)
Bytes:          orig <x> bytes / resp <x> bytes (file size <x> bytes)
Zeek UID:       <UID>  ->  conn.log, http.log, files.log
File ID:        <fuid> ->  files.log, pe.log, extract-...-<fuid>
Hashes:         MD5 <md5> / SHA1 <sha1> / SHA256 <sha256>
```

## URLs and hashes { #hashes-template }

```text
1. http://<domain>/<path>  (<size> bytes)
   MD5:    <md5>
   SHA1:   <sha1>
   SHA256: <sha256>
2. ...
```

## Safe hashing steps { #safe-handling-template }

```text
Steps (performed in an isolated, snapshotted Linux analysis VM with no network access; the document was never opened):
1. Extracted the document from the PCAP without opening it:
   tshark -r case.pcap -q --export-objects http,objs
2. Identified the file type by content, not extension:
   file objs/*  ->  <file output>
3. Renamed it to .bin and removed execute permissions:
   cp "objs/<name>" evidence.bin; chmod a-x evidence.bin
4. Calculated the hashes:
   MD5:    <md5>
   SHA1:   <sha1>
   SHA256: <sha256>
5. Verified MD5/SHA1 against Zeek files.log, looked up the hash only (no upload) on VirusTotal,
   stored the sample in a password-protected zip (password: infected), then reverted the VM snapshot.
```

## Infection type { #infection-type-template }

```text
1. <file/URL 1> - <family A> (<type>)
2. <file/URL 2> - <family B> (<type>)
...
Conclusion: a multi-stage infection: <family A> followed by <family B>.
```

Short form: `<family> (<type, e.g. information stealer>), per Snort alert "<alert name>" and VirusTotal.`

## Internal or external source { #source-template }

> External. The malicious traffic was between <host IP> and <external IP> (a public, non-RFC1918 address). The compromised host initiated the connection (SYN from <host IP>:<port> to <external IP>:<port> at <time> UTC), so the host reached out to the external source.

## Failed attempt on the DC { #failed-attempt-template }

> At <time> UTC, <host IP> attempted <an MS17-010 (EternalBlue) exploit / SMB logon attempts / copying <file> to \\<DC>\ADMIN$> against the DC (<DC IP>) over TCP 445. It failed: <evidence, e.g. the DC returned STATUS_ACCESS_DENIED / no DoublePulsar response>.

## Public IP { #public-ip-template }

> Public IP: x.x.x.x (returned by <service> in frame <N> when the malware checked the host's external IP).

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
