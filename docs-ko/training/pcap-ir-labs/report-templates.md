---
title: "6 — 답안 작성 틀"
tags:
  - training
  - incident-response
  - reporting
---

# 6 — 답안 작성 틀 { #report-templates }

!!! abstract "쓰는 법"
    모든 실습은 "이 침해를 짧게 설명하라"로 끝나고, 몇몇 질문은 정해진 모양의 사실을 묻습니다. 답안은 영어로 쓰므로 틀도 영어로 둡니다. 꺾쇠(`< >`) 안만 실제 값으로 바꾸고, 악성코드 패밀리 이름은 Snort 알림이나 해시 조회로 확인된 것만 씁니다. 해당하지 않는 구절은 추측하지 말고 지웁니다.

## 침해 요약 { #compromise-templates }

실습에 맞는 틀을 골라 줄여서 씁니다.

### 일반 감염 { #generic-template }

> At <time> UTC, Windows host <hostname> (<IP>, <MAC>), used by <username>, downloaded <file> from <URL> (<size> bytes; SHA256 <hash>). IDS alerts and hash lookups identify it as <family> (<type>). The host then <contacted <C2 IP/domain> / showed no further malicious traffic in the capture>. The host should be isolated and reimaged, the URL and C2 blocked, and the user's credentials reset.

### 악성 Word 문서(매크로 다운로더) { #macro-template }

> At <time> UTC, user <username> on Windows client <hostname> (<IP>, <MAC>) in the <domain> domain downloaded a malicious Word document (SHA256 <hash>) from <URL>. When opened, its auto-executing VBA macro downloaded <family / second-stage malware> from <URL>. The host then checked its public IP (<public IP>) via <service> and began C2 traffic to <C2 IP/domain>. The host should be isolated and reimaged, the URLs and C2 blocked, and the user's credentials reset.

### 패밀리 두 개(예: 로더 다음 뱅킹 트로이목마) { #two-families-template }

> Windows host <hostname> (<IP>) downloaded a malicious file from <domain> at <time> UTC and was infected with <family A>. The host sent repeated HTTP POST beacons to <family A> C2 at <C2 IP:port>. <Family A> then installed <family B>, which communicated with its C2 over HTTPS at <domain>. No signs of infection were found on the other devices (<list>).

### 도메인 컨트롤러로 전파 { #dc-template }

> At <time> UTC, user <username> on Windows client <hostname> (<IP>, <MAC>) downloaded a malicious <Word document / EXE> from <URL> and was infected with <family A>. The client then downloaded further executables disguised as image files (<names>), identified as <family B>. At <time> UTC, the client copied <file> to the Domain Controller (<DC IP>, <DC hostname>) over SMB and executed it, spreading <family> to the DC. Both hosts should be isolated and reimaged, and the affected credentials reset.

### 익스플로잇 킷·링크·이메일로 전달 { #delivery-template }

> At <time> UTC, Windows host <hostname> (<IP>, <MAC>), used by <username>, was infected via <delivery method>. <Delivery sentence>. The payload (SHA256 <hash>) was identified by IDS alerts as <family / type>. After infection, the host began post-infection (C2) traffic to <C2 IP> (<C2 domain>) over <protocol/port>. The host should be isolated and reimaged, the C2 IP and domain blocked, and the user's credentials reset.

`<Delivery sentence>` 자리에 넣을 문장:

- 익스플로잇 킷: `The user visited a compromised website, <site>, which redirected the browser to the <EK name> exploit kit at <EK IP>; the EK exploited the browser and delivered the payload.`
- 링크 다운로드: `The user opened a link, likely from a malicious email, that downloaded <file> from <server IP> (<domain>).`
- 이메일 첨부: `The user received a malicious email from <sender> with the attachment <file>, which installed the malware when opened.`

### 다운로드·방향·도구 { #direction-template }

> At <time> UTC, host <hostname> (<IP>, <MAC>), running <OS>, downloaded <N> item(s) of concern: <file 1> from <URL/IP 1> and <file 2> from <URL/IP 2>. The downloads were started with <tool, e.g. PowerShell Invoke-WebRequest>, identified from <User-Agent / commands seen in a plaintext shell session>. The malicious communications were with <external/internal> address <IP>, and the connection was initiated by <the compromised host / the remote host>. After the downloads, the host <began beaconing to / scanned / transferred data to> <IP/domain>. The host should be isolated and the files and IPs blocked as IOCs.

### 실행파일 여러 개와 DC 실패 시도 { #multi-exe-template }

> Windows host <hostname> (<IP>, <MAC>), used by <username>, was infected with <family/families>. Starting at <time> UTC, the host downloaded six Windows executables over HTTP from <domains/IPs>, including files disguised as <e.g. images>. The host then <C2 activity>, and at <time> UTC attempted <what was attempted> against the Domain Controller (<DC IP>) over SMB (TCP 445), which failed (<evidence>). The host should be isolated and reimaged, the IOCs blocked, and the DC checked and patched (e.g. MS17-010) if applicable.

## 핵심 네트워크 정보 { #network-info-template }

```text
LAN segment range:     172.xx.xx.0/24 (172.xx.xx.0 - 172.xx.xx.255)
Default gateway:       172.xx.xx.1
Domain:                <domain>
Domain Controller:     172.xx.xx.xx - <DC hostname>
Infected client:       172.xx.xx.xx - <hostname> - <MAC> - <user>
Public IP (NAT):       x.x.x.x
```

## 다운로드 핵심 정보 { #download-template }

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

## URL과 해시 { #hashes-template }

```text
1. http://<domain>/<path>  (<size> bytes)
   MD5:    <md5>
   SHA1:   <sha1>
   SHA256: <sha256>
2. ...
```

## 안전한 해시 단계 { #safe-handling-template }

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

## 감염 종류 { #infection-type-template }

```text
1. <file/URL 1> - <family A> (<type>)
2. <file/URL 2> - <family B> (<type>)
...
Conclusion: a multi-stage infection: <family A> followed by <family B>.
```

짧게 쓸 때: `<family> (<type, e.g. information stealer>), per Snort alert "<alert name>" and VirusTotal.`

## 내부/외부 출처 { #source-template }

> External. The malicious traffic was between <host IP> and <external IP> (a public, non-RFC1918 address). The compromised host initiated the connection (SYN from <host IP>:<port> to <external IP>:<port> at <time> UTC), so the host reached out to the external source.

## DC에 대한 실패한 시도 { #failed-attempt-template }

> At <time> UTC, <host IP> attempted <an MS17-010 (EternalBlue) exploit / SMB logon attempts / copying <file> to \\<DC>\ADMIN$> against the DC (<DC IP>) over TCP 445. It failed: <evidence, e.g. the DC returned STATUS_ACCESS_DENIED / no DoublePulsar response>.

## 공인 IP { #public-ip-template }

> Public IP: x.x.x.x (returned by <service> in frame <N> when the malware checked the host's external IP).

!!! note "이 섹션의 성격"
    개인 학습 노트입니다. 어떤 기관의 공식 지침도 아닙니다.
