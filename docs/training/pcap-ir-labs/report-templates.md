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

> At &lt;time&gt; UTC, Windows host &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;), used by &lt;username&gt;, downloaded &lt;file&gt; from &lt;URL&gt; (&lt;size&gt; bytes; SHA256 &lt;hash&gt;). IDS alerts and hash lookups identify it as &lt;family&gt; (&lt;type&gt;). The host then &lt;contacted &lt;C2 IP/domain&gt; / showed no further malicious traffic in the capture&gt;. The host should be isolated and reimaged, the URL and C2 blocked, and the user's credentials reset.

### Malicious Word document (macro downloader) { #macro-template }

> At &lt;time&gt; UTC, user &lt;username&gt; on Windows client &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;) in the &lt;domain&gt; domain downloaded a malicious Word document (SHA256 &lt;hash&gt;) from &lt;URL&gt;. When opened, its auto-executing VBA macro downloaded &lt;family / second-stage malware&gt; from &lt;URL&gt;. The host then checked its public IP (&lt;public IP&gt;) via &lt;service&gt; and began C2 traffic to &lt;C2 IP/domain&gt;. The host should be isolated and reimaged, the URLs and C2 blocked, and the user's credentials reset.

### Two families (e.g. a loader followed by a banking trojan) { #two-families-template }

> Windows host &lt;hostname&gt; (&lt;IP&gt;) downloaded a malicious file from &lt;domain&gt; at &lt;time&gt; UTC and was infected with &lt;family A&gt;. The host sent repeated HTTP POST beacons to &lt;family A&gt; C2 at &lt;C2 IP:port&gt;. &lt;Family A&gt; then installed &lt;family B&gt;, which communicated with its C2 over HTTPS at &lt;domain&gt;. No signs of infection were found on the other devices (&lt;list&gt;).

### Spread to the Domain Controller { #dc-template }

> At &lt;time&gt; UTC, user &lt;username&gt; on Windows client &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;) downloaded a malicious &lt;Word document / EXE&gt; from &lt;URL&gt; and was infected with &lt;family A&gt;. The client then downloaded further executables disguised as image files (&lt;names&gt;), identified as &lt;family B&gt;. At &lt;time&gt; UTC, the client copied &lt;file&gt; to the Domain Controller (&lt;DC IP&gt;, &lt;DC hostname&gt;) over SMB and executed it, spreading &lt;family&gt; to the DC. Both hosts should be isolated and reimaged, and the affected credentials reset.

### Delivery via exploit kit, link or email { #delivery-template }

> At &lt;time&gt; UTC, Windows host &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;), used by &lt;username&gt;, was infected via &lt;delivery method&gt;. &lt;Delivery sentence&gt;. The payload (SHA256 &lt;hash&gt;) was identified by IDS alerts as &lt;family / type&gt;. After infection, the host began post-infection (C2) traffic to &lt;C2 IP&gt; (&lt;C2 domain&gt;) over &lt;protocol/port&gt;. The host should be isolated and reimaged, the C2 IP and domain blocked, and the user's credentials reset.

Delivery sentence:

- Exploit kit: `The user visited a compromised website, <site>, which redirected the browser to the <EK name> exploit kit at <EK IP>; the EK exploited the browser and delivered the payload.`
- Link download: `The user opened a link, likely from a malicious email, that downloaded <file> from <server IP> (<domain>).`
- Email attachment: `The user received a malicious email from <sender> with the attachment <file>, which installed the malware when opened.`

### Downloads, direction and tool { #direction-template }

> At &lt;time&gt; UTC, host &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;), running &lt;OS&gt;, downloaded &lt;N&gt; item(s) of concern: &lt;file 1&gt; from &lt;URL/IP 1&gt; and &lt;file 2&gt; from &lt;URL/IP 2&gt;. The downloads were started with &lt;tool, e.g. PowerShell Invoke-WebRequest&gt;, identified from &lt;User-Agent / commands seen in a plaintext shell session&gt;. The malicious communications were with &lt;external/internal&gt; address &lt;IP&gt;, and the connection was initiated by &lt;the compromised host / the remote host&gt;. After the downloads, the host &lt;began beaconing to / scanned / transferred data to&gt; &lt;IP/domain&gt;. The host should be isolated and the files and IPs blocked as IOCs.

### Multiple executables and a failed DC attempt { #multi-exe-template }

> Windows host &lt;hostname&gt; (&lt;IP&gt;, &lt;MAC&gt;), used by &lt;username&gt;, was infected with &lt;family/families&gt;. Starting at &lt;time&gt; UTC, the host downloaded six Windows executables over HTTP from &lt;domains/IPs&gt;, including files disguised as &lt;e.g. images&gt;. The host then &lt;C2 activity&gt;, and at &lt;time&gt; UTC attempted &lt;what was attempted&gt; against the Domain Controller (&lt;DC IP&gt;) over SMB (TCP 445), which failed (&lt;evidence&gt;). The host should be isolated and reimaged, the IOCs blocked, and the DC checked and patched (e.g. MS17-010) if applicable.

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

> External. The malicious traffic was between &lt;host IP&gt; and &lt;external IP&gt; (a public, non-RFC1918 address). The compromised host initiated the connection (SYN from &lt;host IP&gt;:&lt;port&gt; to &lt;external IP&gt;:&lt;port&gt; at &lt;time&gt; UTC), so the host reached out to the external source.

## Failed attempt on the DC { #failed-attempt-template }

> At &lt;time&gt; UTC, &lt;host IP&gt; attempted &lt;an MS17-010 (EternalBlue) exploit / SMB logon attempts / copying &lt;file&gt; to \\&lt;DC&gt;\ADMIN$&gt; against the DC (&lt;DC IP&gt;) over TCP 445. It failed: &lt;evidence, e.g. the DC returned STATUS_ACCESS_DENIED / no DoublePulsar response&gt;.

## Public IP { #public-ip-template }

> Public IP: x.x.x.x (returned by &lt;service&gt; in frame &lt;N&gt; when the malware checked the host's external IP).

!!! note "About these pages"
    Personal study notes. Not official guidance of any organisation.
